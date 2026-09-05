"""
render_app.py — Production entry point for Render cloud deployment
===================================================================
Wraps the SOC dashboard Flask app with cloud-safe configuration:
  - Binds to 0.0.0.0 (required on Render)
  - Auto-creates required directories (logs/, monitored_storage/)
  - Disables auto-open browser (no display on server)
  - Gracefully handles missing pywin32 (Windows-only, not on Linux)
"""

import os
import sys
from pathlib import Path

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

# Auto-create required directories that are in .gitignore
for d in [
    "logs",
    "monitored_storage/source_zone",
    "monitored_storage/sensitive_vault",
    "monitored_storage/usb_drive_sim",
    "monitored_storage/cloud_sync_sim",
    "monitored_storage/quarantine_zone",
]:
    Path(d).mkdir(parents=True, exist_ok=True)

# Patch config for cloud: disable auto_open and bind to 0.0.0.0
os.environ.setdefault("SFTMS_HOST", "0.0.0.0")
os.environ.setdefault("SFTMS_PORT", os.environ.get("PORT", "5000"))
os.environ.setdefault("SFTMS_AUTO_OPEN", "false")

# Import the Flask app
from src.web.app import app  # noqa: E402

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True, use_reloader=False)
