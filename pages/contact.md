---
title: Contact
---

# Contact

Have a question, found an error, or want to collaborate? Use the form below to get in touch.

For **contributions**, please use our [GitHub repository](https://github.com/hack-wiki/hackwiki-notes) directly — see the [Contribute](contribute.html) page for guidelines.

<style>
.contact-form {
    max-width: 640px;
    margin: 2rem 0;
}
.contact-form .form-group {
    margin-bottom: 1.25rem;
}
.contact-form label {
    display: block;
    margin-bottom: 0.4rem;
    font-weight: 500;
    color: var(--text-primary);
    font-size: 0.95rem;
}
.contact-form input[type="text"],
.contact-form input[type="email"],
.contact-form input[type="number"],
.contact-form select,
.contact-form textarea {
    width: 100%;
    padding: 0.7rem 0.9rem;
    background: var(--tertiary-bg);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    color: var(--text-primary);
    font-family: 'Inter', sans-serif;
    font-size: 0.95rem;
    transition: border-color 0.2s ease, box-shadow 0.2s ease;
}
.contact-form input:focus,
.contact-form select:focus,
.contact-form textarea:focus {
    outline: none;
    border-color: var(--accent-primary);
    box-shadow: var(--glow-primary);
}
.contact-form textarea {
    min-height: 160px;
    resize: vertical;
    line-height: 1.6;
}
.contact-form select {
    cursor: pointer;
    appearance: none;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%23a0a0a0' viewBox='0 0 16 16'%3E%3Cpath d='M8 11L3 6h10z'/%3E%3C/svg%3E");
    background-repeat: no-repeat;
    background-position: right 0.9rem center;
    padding-right: 2.5rem;
}
.contact-form select option {
    background: var(--secondary-bg);
    color: var(--text-primary);
}
.contact-form .form-note {
    font-size: 0.8rem;
    color: var(--text-tertiary);
    margin-top: 0.3rem;
}
.contact-form .btn-submit {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.7rem 1.6rem;
    background: var(--accent-primary);
    color: #000;
    border: none;
    border-radius: 6px;
    font-family: 'Inter', sans-serif;
    font-size: 0.95rem;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.2s ease, transform 0.1s ease;
}
.contact-form .btn-submit:hover:not(:disabled) {
    background: var(--accent-secondary);
    transform: translateY(-1px);
}
.contact-form .btn-submit:active:not(:disabled) {
    transform: translateY(0);
}
.contact-form .btn-submit:disabled {
    opacity: 0.5;
    cursor: not-allowed;
}
.contact-form .hp-field {
    position: absolute;
    left: -9999px;
    opacity: 0;
    height: 0;
    width: 0;
    overflow: hidden;
}
.contact-form .form-status {
    margin-top: 1rem;
    padding: 0.8rem 1rem;
    border-radius: 6px;
    font-size: 0.9rem;
    display: none;
}
.contact-form .form-status.success {
    display: block;
    background: rgba(0, 212, 255, 0.1);
    border: 1px solid var(--accent-primary);
    color: var(--accent-primary);
}
.contact-form .form-success-banner {
    text-align: center;
    padding: 2.5rem 1.5rem;
}
.contact-form .form-success-banner i {
    font-size: 2.5rem;
    color: var(--accent-primary);
    margin-bottom: 1rem;
    display: block;
}
.contact-form .form-success-banner h3 {
    margin: 0 0 0.5rem;
    font-size: 1.25rem;
    color: var(--text-primary);
}
.contact-form .form-success-banner p {
    color: var(--text-secondary);
    margin: 0 0 1.5rem;
    font-size: 0.95rem;
}
.contact-form .btn-reset {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.5rem 1.2rem;
    background: transparent;
    color: var(--accent-primary);
    border: 1px solid var(--accent-primary);
    border-radius: 6px;
    font-family: 'Inter', sans-serif;
    font-size: 0.85rem;
    cursor: pointer;
    transition: background 0.2s ease;
}
.contact-form .btn-reset:hover {
    background: rgba(0, 212, 255, 0.1);
}
.contact-form .form-status.error {
    display: block;
    background: rgba(255, 71, 87, 0.1);
    border: 1px solid var(--error-color);
    color: var(--error-color);
}
/* Captcha */
.captcha-group {
    margin-top: 0.5rem;
}
.captcha-box {
    display: inline-flex;
    align-items: center;
    gap: 1rem;
    background: var(--secondary-bg);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    padding: 0.5rem 1rem;
}
.captcha-question {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-family: 'JetBrains Mono', monospace;
    font-size: 1rem;
}
.captcha-num {
    color: var(--accent-primary);
    font-weight: 600;
}
.captcha-op, .captcha-eq {
    color: var(--text-tertiary);
}
.captcha-input {
    width: 52px;
    padding: 0.4rem 0.5rem;
    background: var(--tertiary-bg);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    color: var(--text-primary);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.95rem;
    text-align: center;
    transition: border-color 0.2s, box-shadow 0.2s;
}
.captcha-input:focus {
    outline: none;
    border-color: var(--accent-primary);
    box-shadow: var(--glow-primary);
}
.captcha-input:disabled {
    opacity: 0.5;
    cursor: not-allowed;
}
.captcha-input::placeholder {
    color: var(--text-tertiary);
}
/* Hide number spinners */
.captcha-input::-webkit-outer-spin-button,
.captcha-input::-webkit-inner-spin-button {
    -webkit-appearance: none;
    margin: 0;
}
.captcha-input[type=number] {
    -moz-appearance: textfield;
}
.captcha-hint {
    font-size: 0.8rem;
    color: var(--text-tertiary);
    margin-top: 0.3rem;
}
</style>

<form class="contact-form" id="contactForm" method="POST" action="api/contact.php">
    <div class="form-group">
        <label for="cf-name">Name</label>
        <input type="text" id="cf-name" name="name" required maxlength="100" placeholder="Your name">
    </div>
    <div class="form-group">
        <label for="cf-email">Email</label>
        <input type="email" id="cf-email" name="email" required maxlength="200" placeholder="your@email.com">
    </div>
    <div class="form-group">
        <label for="cf-topic">Topic</label>
        <select id="cf-topic" name="topic" required>
            <option value="" disabled selected>Select a topic</option>
            <option value="error">Bug / Error Report</option>
            <option value="content">Content Suggestion</option>
            <option value="partnership">Partnership / Collaboration</option>
            <option value="question">General Question</option>
            <option value="other">Other</option>
        </select>
    </div>
    <div class="form-group">
        <label for="cf-message">Message</label>
        <textarea id="cf-message" name="message" required maxlength="5000" placeholder="Your message..."></textarea>
    </div>
    <!-- Honeypot -->
    <div class="hp-field" aria-hidden="true">
        <label for="cf-website">Website</label>
        <input type="text" id="cf-website" name="website" tabindex="-1" autocomplete="off">
    </div>
    <!-- Human verification (XOR-decoded math, same pattern as HackForge) -->
    <div class="form-group captcha-group">
        <label>Human Verification</label>
        <div class="captcha-box">
            <div class="captcha-question">
                <span class="captcha-num" id="captchaNum1">?</span>
                <span class="captcha-op">+</span>
                <span class="captcha-num" id="captchaNum2">?</span>
                <span class="captcha-eq">=</span>
            </div>
            <input type="number" name="human_check" class="captcha-input" id="captchaInput" required placeholder="?" disabled>
        </div>
        <p class="captcha-hint">Quick math to prove you're not a bot</p>
    </div>
    <button type="submit" class="btn-submit" id="submitBtn" disabled>
        <i class="fas fa-paper-plane"></i> Send Message
    </button>
    <div class="form-status" id="formStatus"></div>
</form>

<script>
(function() {
    var n1El = document.getElementById('captchaNum1');
    var n2El = document.getElementById('captchaNum2');
    var captchaInput = document.getElementById('captchaInput');
    var submitBtn = document.getElementById('submitBtn');
    var form = document.getElementById('contactForm');
    var status = document.getElementById('formStatus');

    // Fetch XOR-encoded captcha challenge from server
    function loadCaptcha() {
        n1El.textContent = '?';
        n2El.textContent = '?';
        captchaInput.disabled = true;
        captchaInput.value = '';
        submitBtn.disabled = true;

        fetch('api/captcha.php', { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                // XOR decode (bots scraping static HTML can't see actual numbers)
                var num1 = data.a ^ data.k;
                var num2 = data.b ^ data.k;
                n1El.textContent = num1;
                n2El.textContent = num2;
                // Enable after short delay (extra bot deterrent)
                setTimeout(function() {
                    captchaInput.disabled = false;
                    captchaInput.placeholder = '?';
                    submitBtn.disabled = false;
                }, 400);
            })
            .catch(function() {
                n1El.textContent = '!';
                n2El.textContent = '!';
            });
    }

    // Load captcha on page load
    loadCaptcha();

    // Form submission
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';
        status.className = 'form-status';
        status.style.display = 'none';

        fetch(form.action, {
            method: 'POST',
            body: new FormData(form),
            credentials: 'same-origin'
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.success) {
                // Replace form with a clear success banner
                form.innerHTML = '<div class="form-success-banner">' +
                    '<i class="fas fa-check-circle"></i>' +
                    '<h3>Message Sent</h3>' +
                    '<p>Thank you! We\'ll get back to you as soon as possible.</p>';
                form.querySelector('#sendAnother').addEventListener('click', function() {
                    window.location.reload();
                });
            } else {
                status.className = 'form-status error';
                status.textContent = data.message || 'Something went wrong. Please try again.';
                // Reload captcha on failed validation (answer is one-time use)
                loadCaptcha();
            }
        })
        .catch(function() {
            status.className = 'form-status error';
            status.textContent = 'Network error. Please try again later.';
            loadCaptcha();
        })
        .finally(function() {
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<i class="fas fa-paper-plane"></i> Send Message';
        });
    });
})();
</script>
