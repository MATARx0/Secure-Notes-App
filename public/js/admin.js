(function () {
  'use strict';

  const statusMessage = document.getElementById('status-message');
  const loadingState = document.getElementById('loading-state');
  const emptyState = document.getElementById('empty-state');
  const usersTable = document.getElementById('users-table');
  const usersTableBody = document.getElementById('users-table-body');
  const prevPageButton = document.getElementById('prev-page-button');
  const nextPageButton = document.getElementById('next-page-button');
  const pageIndicator = document.getElementById('page-indicator');
  const logoutButton = document.getElementById('logout-button');

  const confirmDialog = document.getElementById('confirm-dialog');
  const confirmDialogText = document.getElementById('confirm-dialog-text');
  const confirmCancelButton = document.getElementById('confirm-cancel-button');
  const confirmAcceptButton = document.getElementById('confirm-accept-button');

  const PAGE_SIZE = 20;
  let currentPage = 1;
  let totalUsers = 0;
  let currentUserId = null;

  function showMessage(message, type) {
    statusMessage.textContent = message;
    statusMessage.className = `status-message ${type === 'success' ? 'success-message' : 'error-message'}`;
  }

  function clearMessage() {
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
      throw new Error(message);
    }

    return body;
  }

  async function csrfHeaders() {
    const result = await apiFetch('/api/csrf-token', { method: 'GET' });
    return { 'X-CSRF-Token': result.data.csrfToken };
  }

  function askForConfirmation(message) {
    return new Promise((resolve) => {
      confirmDialogText.textContent = message;
      confirmDialog.classList.remove('hidden');

      function cleanup(result) {
        confirmDialog.classList.add('hidden');
        confirmAcceptButton.removeEventListener('click', onAccept);
        confirmCancelButton.removeEventListener('click', onCancel);
        resolve(result);
      }

      function onAccept() { cleanup(true); }
      function onCancel() { cleanup(false); }

      confirmAcceptButton.addEventListener('click', onAccept);
      confirmCancelButton.addEventListener('click', onCancel);
    });
  }

  function renderRow(user) {
    const row = document.createElement('tr');

    const cells = {
      username: user.username,
      email: user.email,
    };

    Object.keys(cells).forEach((key) => {
      const cell = document.createElement('td');
      cell.textContent = cells[key];
      row.appendChild(cell);
    });

    const roleCell = document.createElement('td');
    const roleBadge = document.createElement('span');
    roleBadge.className = `badge ${user.role === 'admin' ? 'badge-admin' : 'badge-user'}`;
    roleBadge.textContent = user.role;
    roleCell.appendChild(roleBadge);
    row.appendChild(roleCell);

    const statusCell = document.createElement('td');
    const statusBadge = document.createElement('span');
    statusBadge.className = `badge ${user.status === 'disabled' ? 'badge-disabled' : 'badge-active'}`;
    statusBadge.textContent = user.status;
    statusCell.appendChild(statusBadge);
    row.appendChild(statusCell);

    const mfaCell = document.createElement('td');
    mfaCell.textContent = user.mfaEnabled ? 'Enabled' : 'Disabled';
    row.appendChild(mfaCell);

    const createdCell = document.createElement('td');
    createdCell.textContent = new Date(user.createdAt).toLocaleDateString();
    row.appendChild(createdCell);

    const actionsCell = document.createElement('td');

    if (user.id === currentUserId) {
      const note = document.createElement('span');
      note.textContent = 'This is you';
      actionsCell.appendChild(note);
    } else {
      const toggleButton = document.createElement('button');
      toggleButton.type = 'button';
      toggleButton.className = 'secondary-button';
      toggleButton.textContent = user.status === 'disabled' ? 'Enable' : 'Disable';
      toggleButton.addEventListener('click', () => toggleStatus(user));
      actionsCell.appendChild(toggleButton);

      actionsCell.appendChild(document.createTextNode(' '));

      const deleteButton = document.createElement('button');
      deleteButton.type = 'button';
      deleteButton.className = 'danger-button';
      deleteButton.textContent = 'Delete';
      deleteButton.addEventListener('click', () => deleteUser(user));
      actionsCell.appendChild(deleteButton);
    }

    row.appendChild(actionsCell);

    return row;
  }

  async function loadUsers() {
    clearMessage();
    loadingState.classList.remove('hidden');
    usersTable.classList.add('hidden');
    emptyState.classList.add('hidden');

    try {
      const result = await apiFetch(`/api/admin/users?page=${currentPage}&limit=${PAGE_SIZE}`, {
        method: 'GET',
      });

      totalUsers = result.data.total;
      const users = result.data.users;

      loadingState.classList.add('hidden');

      if (users.length === 0) {
        emptyState.classList.remove('hidden');
      } else {
        usersTableBody.replaceChildren();
        users.forEach((user) => usersTableBody.appendChild(renderRow(user)));
        usersTable.classList.remove('hidden');
      }

      const totalPages = Math.max(1, Math.ceil(totalUsers / PAGE_SIZE));
      pageIndicator.textContent = `Page ${currentPage} of ${totalPages}`;
      prevPageButton.disabled = currentPage <= 1;
      nextPageButton.disabled = currentPage >= totalPages;
    } catch (error) {
      loadingState.classList.add('hidden');
      showMessage(error.message);
    }
  }

  async function toggleStatus(user) {
    const nextStatus = user.status === 'disabled' ? 'enabled' : 'disabled';
    const confirmed = await askForConfirmation(
      `${nextStatus === 'disabled' ? 'Disable' : 'Enable'} the account "${user.username}"?`,
    );

    if (!confirmed) return;

    try {
      const headers = await csrfHeaders();
      await apiFetch(`/api/admin/users/${encodeURIComponent(user.id)}/status`, {
        method: 'PATCH',
        headers,
        body: JSON.stringify({ status: nextStatus }),
      });

      showMessage('Account status updated.', 'success');
      await loadUsers();
    } catch (error) {
      showMessage(error.message);
    }
  }

  async function deleteUser(user) {
    const confirmed = await askForConfirmation(
      `Permanently delete the account "${user.username}" and all of their notes? This cannot be undone.`,
    );

    if (!confirmed) return;

    try {
      const headers = await csrfHeaders();
      await apiFetch(`/api/admin/users/${encodeURIComponent(user.id)}`, {
        method: 'DELETE',
        headers,
      });

      showMessage('Account deleted.', 'success');

      if (usersTableBody.children.length === 1 && currentPage > 1) {
        currentPage -= 1;
      }

      await loadUsers();
    } catch (error) {
      showMessage(error.message);
    }
  }

  prevPageButton.addEventListener('click', () => {
    if (currentPage > 1) {
      currentPage -= 1;
      loadUsers();
    }
  });

  nextPageButton.addEventListener('click', () => {
    const totalPages = Math.max(1, Math.ceil(totalUsers / PAGE_SIZE));
    if (currentPage < totalPages) {
      currentPage += 1;
      loadUsers();
    }
  });

  logoutButton.addEventListener('click', async () => {
    try {
      const headers = await csrfHeaders();
      await apiFetch('/api/auth/logout', { method: 'POST', headers });
    } catch {
      // Even if the logout call fails, still send the admin back to the
      // login page rather than leaving them on a broken dashboard.
    }
    window.location.href = '/login.html';
  });

  (async function init() {
    try {
      const me = await apiFetch('/api/auth/me', { method: 'GET' });

      if (me.data.user.role !== 'admin') {
        window.location.href = '/notes.html';
        return;
      }

      currentUserId = me.data.user.id;
      await loadUsers();
    } catch {
      window.location.href = '/login.html';
    }
  })();
})();
