"""
app.py - SOC Blue Team Web Dashboard (Flask)
=============================================
Serves a real-time cybersecurity operations dashboard with:
  - Live file event feed via Server-Sent Events (SSE)
  - Alert notification center
  - DLP violation & integrity chart data APIs
  - File hash verification endpoint
  - Audit report download (JSON / CSV)
  - Attack simulation trigger endpoint
  - Live system stats API
"""

import json
import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from flask import Flask, Response, jsonify, render_template, request, send_file, stream_with_context

from src.core.file_monitor import FileMonitor, load_config
from src.core.alert_manager import get_alert_manager
from src.core.integrity_engine import compute_all_hashes

# ---------------------------------------------------------------------------
# Flask app setup
# ---------------------------------------------------------------------------

app = Flask(__name__, template_folder="templates")
app.secret_key = "sftms-soc-dashboard-2024"

# Global monitor (lazy-initialized)
_monitor: FileMonitor = None
_monitor_lock = threading.Lock()
# Live event buffer for SSE (shared list, max 500 entries)
_live_events = []
_events_lock = threading.Lock()
MAX_LIVE_EVENTS = 500


def get_monitor() -> FileMonitor:
    global _monitor
    with _monitor_lock:
        if _monitor is None:
            config = load_config()
            _monitor = FileMonitor(config=config, on_event_callback=_on_event)
        return _monitor


def _on_event(entry: dict) -> None:
    """Callback from FileMonitor - push new event to SSE buffer."""
    with _events_lock:
        _live_events.append(entry)
        if len(_live_events) > MAX_LIVE_EVENTS:
            _live_events.pop(0)


# ---------------------------------------------------------------------------
# Routes - Pages
# ---------------------------------------------------------------------------

@app.route("/")
def dashboard():
    """Serve the main SOC dashboard HTML page."""
    return render_template("dashboard.html")


# ---------------------------------------------------------------------------
# Routes - API
# ---------------------------------------------------------------------------

@app.route("/api/stats")
def api_stats():
    """Return system-wide statistics."""
    mon = get_monitor()
    return jsonify(mon.get_stats())


@app.route("/api/alerts")
def api_alerts():
    """Return recent alerts, optionally filtered by severity."""
    severity = request.args.get("severity")
    limit    = int(request.args.get("limit", 100))
    mon      = get_monitor()
    alerts   = mon.alert_manager.get_history(severity_filter=severity, limit=limit)
    return jsonify(alerts)


@app.route("/api/events")
def api_events():
    """Return recent audit events from SQLite."""
    limit    = int(request.args.get("limit", 50))
    severity = request.args.get("severity")
    mon      = get_monitor()
    events   = mon.audit_logger.get_recent_events(limit=limit, severity_filter=severity)
    return jsonify(events)


@app.route("/api/alert_stats")
def api_alert_stats():
    """Return alert counts by severity for chart rendering."""
    mon  = get_monitor()
    data = mon.alert_manager.get_stats()
    return jsonify(data)


@app.route("/api/audit_stats")
def api_audit_stats():
    """Return audit database summary statistics."""
    mon  = get_monitor()
    data = mon.audit_logger.get_stats()
    return jsonify(data)


@app.route("/api/hash", methods=["POST"])
def api_hash():
    """
    Compute hashes for an uploaded file or a server-side file path.
    Accepts:
      - multipart/form-data with 'file' field (uploaded file)
      - JSON body with 'path' field (server-side path)
    """
    if request.files.get("file"):
        uploaded = request.files["file"]
        tmp_path = os.path.join(str(PROJECT_ROOT / "logs"), f"_tmp_upload_{uploaded.filename}")
        uploaded.save(tmp_path)
        hashes = compute_all_hashes(tmp_path)
        os.remove(tmp_path)
        return jsonify({"filename": uploaded.filename, "hashes": hashes})
    elif request.is_json:
        path = request.json.get("path", "")
        if not os.path.isfile(path):
            return jsonify({"error": f"File not found: {path}"}), 404
        hashes = compute_all_hashes(path)
        return jsonify({"filename": os.path.basename(path), "hashes": hashes})
    return jsonify({"error": "No file or path provided"}), 400


@app.route("/api/monitor/start", methods=["POST"])
def api_monitor_start():
    """Start the live file system monitor."""
    mon = get_monitor()
    if not mon.is_running():
        t = threading.Thread(target=mon.start, daemon=True)
        t.start()
        time.sleep(0.5)
    return jsonify({"status": "running", "watch_paths": mon.watch_paths})


@app.route("/api/monitor/stop", methods=["POST"])
def api_monitor_stop():
    """Stop the live file system monitor."""
    mon = get_monitor()
    mon.stop()
    return jsonify({"status": "stopped"})


@app.route("/api/monitor/status")
def api_monitor_status():
    """Return current monitor running status."""
    mon = get_monitor()
    return jsonify({
        "running": mon.is_running(),
        "watch_paths": mon.watch_paths,
    })


@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    """Trigger the attack simulation scenarios."""
    def run_sim():
        from src.simulator.simulate_scenarios import run_simulation
        run_simulation(quiet=True)

    t = threading.Thread(target=run_sim, daemon=True)
    t.start()
    return jsonify({"status": "simulation_started", "message": "All 5 scenarios queued."})


@app.route("/api/report/download")
def api_report_download():
    """Export and download the audit report in JSON or CSV format."""
    fmt = request.args.get("format", "json").lower()
    out = str(PROJECT_ROOT / "logs" / f"audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    mon = get_monitor()
    path = mon.audit_logger.export_report(out, fmt=fmt)
    mime = "application/json" if fmt == "json" else "text/csv"
    return send_file(path, mimetype=mime, as_attachment=True, download_name=os.path.basename(path))


# ---------------------------------------------------------------------------
# Server-Sent Events - Live Event Stream
# ---------------------------------------------------------------------------

@app.route("/api/stream")
def api_stream():
    """
    SSE endpoint streaming live file events to the dashboard.
    Clients connect once and receive a continuous stream of JSON event objects.
    """
    def generate():
        last_index = 0
        while True:
            with _events_lock:
                new_events = _live_events[last_index:]
                last_index = len(_live_events)
            for ev in new_events:
                yield f"data: {json.dumps(ev, default=str)}\n\n"
            if not new_events:
                yield ": heartbeat\n\n"
            time.sleep(0.8)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.route("/api/stream/alerts")
def api_stream_alerts():
    """SSE endpoint streaming only HIGH/CRITICAL alerts."""
    def generate():
        mon = get_monitor()
        seen = set()
        while True:
            alerts = mon.alert_manager.get_history(limit=200)
            for a in alerts:
                aid = a.get("id")
                if aid not in seen:
                    seen.add(aid)
                    yield f"data: {json.dumps(a, default=str)}\n\n"
            yield ": heartbeat\n\n"
            time.sleep(1)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import webbrowser

    os.chdir(PROJECT_ROOT)
    config = load_config()
    web_cfg = config.get("web", {})

    host = web_cfg.get("host", "127.0.0.1")
    port = int(web_cfg.get("port", 5000))

    # Pre-init monitor
    mon = get_monitor()
    # Start monitor automatically
    t = threading.Thread(target=mon.start, daemon=True)
    t.start()
    time.sleep(0.8)

    print(f"\n[SOC]  SOC Dashboard -> http://{host}:{port}")
    print(f"   Monitor: {'ACTIVE' if mon.is_running() else 'STOPPED'}")
    print("   Press Ctrl+C to quit.\n")

    if web_cfg.get("auto_open", True):
        threading.Timer(1.5, lambda: webbrowser.open(f"http://{host}:{port}")).start()

    app.run(host=host, port=port, debug=False, threaded=True, use_reloader=False)
