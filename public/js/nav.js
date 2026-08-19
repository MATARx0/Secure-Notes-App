// Small shared chrome script: wires up the logout button on any page that
// includes one (currently notes.html). Deliberately independent of
// notes.js/auth.js/admin.js so it can be dropped into any page with a
// single extra <script> tag and no ownership overlap with another
// member's file.
(function () {
  'use strict';

  const logoutButton = document.getElementById('logout-button');
  if (!logoutButton) return;

  async function apiFetch(url, options) {
    const response = await fetch(url, {
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      ...options,
    });

    if (!response.ok) {
      throw new Error('Request failed');
    }

    return response.json();
  }

  logoutButton.addEventListener('click', async () => {
    try {
      const csrfResult = await apiFetch('/api/csrf-token', { method: 'GET' });
      await apiFetch('/api/auth/logout', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrfResult.data.csrfToken },
      });
    } catch {
      // Even if the request fails, still send the user back to the login
      // page rather than leaving them looking logged in.
    }
    window.location.href = '/login.html';
  });
})();
