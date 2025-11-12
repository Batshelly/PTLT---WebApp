document.addEventListener('DOMContentLoaded', function() {
    // Original password toggle code (keep if you have password field elsewhere)
    const togglePassword = document.getElementById('togglePassword');
    const passwordInput = document.getElementById('password_input');
    const toggleIcon = document.getElementById('toggleIcon');

    if (togglePassword && passwordInput && toggleIcon) {
        togglePassword.addEventListener('click', function() {
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            
            if (type === 'password') {
                toggleIcon.classList.remove('bi-eye-slash');
                toggleIcon.classList.add('bi-eye');
            } else {
                toggleIcon.classList.remove('bi-eye');
                toggleIcon.classList.add('bi-eye-slash');
            }
        });
    }

    // NEW: Login form loading state
    const loginForm = document.getElementById('loginForm');
    const sendOtpBtn = document.getElementById('sendOtpBtn');
    const btnText = document.getElementById('btnText');
    const btnLoading = document.getElementById('btnLoading');
    const emailInput = document.getElementById('email_input');

    if (loginForm && sendOtpBtn) {
        loginForm.addEventListener('submit', function(e) {
            // Check if email is valid before showing loading
            if (emailInput.validity.valid) {
                // Disable button to prevent double submission
                sendOtpBtn.disabled = true;
                
                // Hide normal text, show loading
                btnText.classList.add('d-none');
                btnLoading.classList.remove('d-none');
            }
        });
    }
});
