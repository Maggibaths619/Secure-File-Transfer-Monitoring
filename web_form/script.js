document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('submissionForm');
    const inputs = form.querySelectorAll('input[type="url"]');
    const submitBtn = form.querySelector('.submit-btn');
    const successMessage = document.getElementById('successMessage');

    // Pattern for checking https://
    const httpsPattern = /^https:\/\/.+/i;

    // Validate a single input
    const validateInput = (input) => {
        const formGroup = input.closest('.form-group');
        const isValid = httpsPattern.test(input.value.trim());

        if (input.value.trim() === '') {
            formGroup.classList.remove('valid', 'invalid');
            return false;
        }

        if (isValid) {
            formGroup.classList.remove('invalid');
            formGroup.classList.add('valid');
        } else {
            formGroup.classList.remove('valid');
            formGroup.classList.add('invalid');
        }

        return isValid;
    };

    // Add input event listeners for real-time validation
    inputs.forEach(input => {
        input.addEventListener('input', () => validateInput(input));
        input.addEventListener('blur', () => validateInput(input));
    });

    // Form submission
    form.addEventListener('submit', (e) => {
        e.preventDefault();
        
        let isFormValid = true;

        inputs.forEach(input => {
            if (!validateInput(input)) {
                isFormValid = false;
                // Force show error for empty fields on submit
                if (input.value.trim() === '') {
                    input.closest('.form-group').classList.add('invalid');
                }
            }
        });

        if (isFormValid) {
            // Simulate form submission
            submitBtn.classList.add('loading');
            
            setTimeout(() => {
                submitBtn.classList.remove('loading');
                form.reset();
                inputs.forEach(input => {
                    input.closest('.form-group').classList.remove('valid', 'invalid');
                });
                
                successMessage.style.display = 'block';
                
                // Hide success message after 5 seconds
                setTimeout(() => {
                    successMessage.style.display = 'none';
                }, 5000);
            }, 1500);
        } else {
            // Shake effect on form if invalid
            form.style.animation = 'none';
            form.offsetHeight; // trigger reflow
            form.style.animation = 'shake 0.5s ease';
        }
    });

    // Add shake animation to document
    const style = document.createElement('style');
    style.textContent = `
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            10%, 30%, 50%, 70%, 90% { transform: translateX(-5px); }
            20%, 40%, 60%, 80% { transform: translateX(5px); }
        }
    `;
    document.head.appendChild(style);
});
