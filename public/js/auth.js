(function () {
  'use strict';

  const statusMessage = document.getElementById('status-message');

  function showMessage(message, type) {
    if (!statusMessage) return;
    statusMessage.textContent = message;
    statusMessage.className = `status-message ${type === 'success' ? 'success-message' : 'error-message'}`;
  }

  function clearMessage() {
    if (!statusMessage) return;
    statusMessage.textContent = '';
    statusMessage.className = 'status-message';
  }

  async function apiFetch(url, options) {
    const response = await fetch(url, {
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      ...options,
    });

    let body = null;
    try {
      body = await response.json();
    } catch {
      body = null;
    }

    if (!response.ok) {
      const message = (body && body.error && body.error.message) || 'Request failed';
      const error = new Error(message);
      error.code = body && body.error && body.error.code;
      throw error;
    }

    return body;
  }

  // Fetches a fresh CSRF token immediately before a state-changing request.
  // The raw token only ever lives in a JS variable, never in the DOM,
  // localStorage, or sessionStorage.
  async function getCsrfToken() {
    const result = await apiFetch('/api/csrf-token', { method: 'GET' });
    return result.data.csrfToken;
  }

  async function csrfHeaders() {
    const csrfToken = await getCsrfToken();
    return { 'X-CSRF-Token': csrfToken };
  }

  async function redirectByRole() {
    try {
      const result = await apiFetch('/api/auth/me', { method: 'GET' });
      window.location.href = result.data.user.role === 'admin' ? '/admin.html' : '/notes.html';
    } catch {
      window.location.href = '/login.html';
    }
  }

  // --- reCAPTCHA loading -----------------------------------------------------

  let recaptchaReadyPromise = null;

  function loadRecaptcha() {
    if (recaptchaReadyPromise) return recaptchaReadyPromise;

    recaptchaReadyPromise = new Promise((resolve) => {
      window.__onRecaptchaLoad = resolve;
      const script = document.createElement('script');
      script.src = 'https://www.google.com/recaptcha/api.js?onload=__onRecaptchaLoad&render=explicit';
      script.async = true;
      script.defer = true;
      document.head.appendChild(script);
    });

    return recaptchaReadyPromise;
  }

  async function renderRecaptcha(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return null;

    const config = await apiFetch('/api/config', { method: 'GET' });
    await loadRecaptcha();

    return window.grecaptcha.render(containerId, {
      sitekey: config.data.captchaSiteKey,
    });
  }

  function getRecaptchaResponse(widgetId) {
    if (!window.grecaptcha) return '';
    return window.grecaptcha.getResponse(widgetId);
  }

  function resetRecaptcha(widgetId) {
    if (window.grecaptcha) {
      window.grecaptcha.reset(widgetId);
    }
  }

  // --- Registration page -------------------------------------------------------

  const registerForm = document.getElementById('register-form');

  if (registerForm) {
    let widgetId = null;
    renderRecaptcha('recaptcha-container').then((id) => { widgetId = id; });

    registerForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      clearMessage();

      const username = document.getElementById('username').value.trim();
      const email = document.getElementById('email').value.trim();
      const password = document.getElementById('password').value;
      const passwordConfirm = document.getElementById('password-confirm').value;

      if (password !== passwordConfirm) {
        showMessage('Passwords do not match.');
        document.getElementById('password').value = '';
        document.getElementById('password-confirm').value = '';
        return;
      }

      const captchaToken = getRecaptchaResponse(widgetId);

      try {
        await apiFetch('/api/auth/register', {
          method: 'POST',
          body: JSON.stringify({ username, email, password, captchaToken }),
        });

        window.location.href = '/login.html';
      } catch (error) {
        showMessage(error.message);
        // Never repopulate the password after an error.
        document.getElementById('password').value = '';
        document.getElementById('password-confirm').value = '';
        resetRecaptcha(widgetId);
      }
    });
  }

  // --- Login page ----------------------------------------------------------------

  const loginForm = document.getElementById('login-form');

  if (loginForm) {
    const mfaForm = document.getElementById('mfa-form');
    const mfaCancelButton = document.getElementById('mfa-cancel');
    let widgetId = null;
    let pendingMfaTicket = null;

    renderRecaptcha('recaptcha-container').then((id) => { widgetId = id; });

    loginForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      clearMessage();

      const email = document.getElementById('email').value.trim();
      const password = document.getElementById('password').value;
      const captchaToken = getRecaptchaResponse(widgetId);

      try {
        const result = await apiFetch('/api/auth/login', {
          method: 'POST',
          body: JSON.stringify({ email, password, captchaToken }),
        });

        if (result.data.mfaRequired) {
          pendingMfaTicket = result.data.mfaTicket;
          loginForm.classList.add('hidden');
          mfaForm.classList.remove('hidden');
          document.getElementById('mfa-token').focus();
          return;
        }

        await redirectByRole();
      } catch (error) {
        showMessage(error.message);
        document.getElementById('password').value = '';
        resetRecaptcha(widgetId);
      }
    });

    if (mfaForm) {
      mfaForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        clearMessage();

        const mfaToken = document.getElementById('mfa-token').value.trim();

        try {
          await apiFetch('/api/auth/mfa/verify-login', {
            method: 'POST',
            body: JSON.stringify({ mfaTicket: pendingMfaTicket, mfaToken }),
          });

          await redirectByRole();
        } catch (error) {
          showMessage(error.message);
          document.getElementById('mfa-token').value = '';
        }
      });
    }

    if (mfaCancelButton) {
      mfaCancelButton.addEventListener('click', () => {
        pendingMfaTicket = null;
        mfaForm.classList.add('hidden');
        loginForm.classList.remove('hidden');
        clearMessage();
      });
    }
  }

  // --- MFA management page (mfa.html) ---------------------------------------------

  const enableSection = document.getElementById('mfa-enable-section');
  const disableSection = document.getElementById('mfa-disable-section');

  if (enableSection && disableSection) {
    const statusText = document.getElementById('mfa-status-text');
    const startSetupButton = document.getElementById('start-setup-button');
    const enrollmentPanel = document.getElementById('enrollment-panel');
    const qrImage = document.getElementById('mfa-qr-image');
    const manualKey = document.getElementById('mfa-manual-key');
    const confirmForm = document.getElementById('confirm-form');
    const disableForm = document.getElementById('disable-form');

    function clearEnrollmentSecrets() {
      qrImage.removeAttribute('src');
      manualKey.textContent = '';
      enrollmentPanel.classList.add('hidden');
    }

    function renderState(mfaEnabled) {
      if (mfaEnabled) {
        statusText.textContent = 'Two-factor authentication is enabled on your account.';
        enableSection.classList.add('hidden');
        disableSection.classList.remove('hidden');
      } else {
        statusText.textContent = 'Two-factor authentication is not yet enabled.';
        disableSection.classList.add('hidden');
        enableSection.classList.remove('hidden');
        clearEnrollmentSecrets();
      }
    }

    (async function loadStatus() {
      try {
        const result = await apiFetch('/api/auth/me', { method: 'GET' });
        renderState(result.data.user.mfaEnabled);
      } catch {
        window.location.href = '/login.html';
      }
    })();

    startSetupButton.addEventListener('click', async () => {
      clearMessage();

      try {
        const headers = await csrfHeaders();
        const result = await apiFetch('/api/auth/mfa/setup', {
          method: 'POST',
          headers,
          body: JSON.stringify({}),
        });

        qrImage.src = result.data.qrCode;
        manualKey.textContent = result.data.manualEntryKey;
        enrollmentPanel.classList.remove('hidden');
      } catch (error) {
        showMessage(error.message);
      }
    });

    confirmForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      clearMessage();

      const mfaToken = document.getElementById('confirm-token').value.trim();

      try {
        const headers = await csrfHeaders();
        await apiFetch('/api/auth/mfa/confirm', {
          method: 'POST',
          headers,
          body: JSON.stringify({ mfaToken }),
        });

        clearEnrollmentSecrets();
        showMessage('Two-factor authentication is now enabled.', 'success');
        renderState(true);
      } catch (error) {
        showMessage(error.message);
        document.getElementById('confirm-token').value = '';
      }
    });

    disableForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      clearMessage();

      const password = document.getElementById('disable-password').value;
      const mfaToken = document.getElementById('disable-token').value.trim();

      try {
        const headers = await csrfHeaders();
        await apiFetch('/api/auth/mfa/disable', {
          method: 'POST',
          headers,
          body: JSON.stringify({ password, mfaToken }),
        });

        disableForm.reset();
        showMessage('Two-factor authentication has been disabled.', 'success');
        renderState(false);
      } catch (error) {
        showMessage(error.message);
        document.getElementById('disable-password').value = '';
        document.getElementById('disable-token').value = '';
      }
    });
  }
})();
