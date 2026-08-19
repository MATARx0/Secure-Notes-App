const notesContainer = document.getElementById('notes-container');
const noteForm = document.getElementById('note-form');
const noteIdInput = document.getElementById('note-id');
const titleInput = document.getElementById('note-title');
const contentInput = document.getElementById('note-content');
const editor = document.getElementById('editor');
const editorTitle = document.getElementById('editor-title');
const statusMessage = document.getElementById('status-message');
const newNoteButton = document.getElementById('new-note-button');
const cancelButton = document.getElementById('cancel-button');

function showMessage(message, type = 'error') {
  statusMessage.textContent = message;
  statusMessage.className = `status-message ${type === 'success' ? 'success-message' : 'error-message'}`;
}

function clearMessage() {
  statusMessage.textContent = '';
  statusMessage.className = 'status-message';
}

function openCreateEditor() {
  noteIdInput.value = '';
  titleInput.value = '';
  contentInput.value = '';
  editorTitle.textContent = 'Create Note';
  editor.classList.remove('hidden');
  titleInput.focus();
  clearMessage();
}

function closeEditor() {
  noteForm.reset();
  editor.classList.add('hidden');
  clearMessage();
}

// Built with createElement and textContent rather than an innerHTML template.
//
// The earlier version interpolated note.title straight into innerHTML, so a
// note saved with the title `<img src=x onerror=...>` was parsed as markup
// when the list rendered — stored XSS, sitting in the database rather than
// reflected off a URL.
//
// It was not exploitable as shipped: the Content Security Policy sets
// script-src 'self' with no 'unsafe-inline', which blocks inline event
// handlers, and img-src 'self' data:, which blocks the usual exfiltration
// image. But a CSP is the second line of defence, not the first. Any future
// relaxation of that header would silently re-open the hole, and by then the
// payload is already stored. Assigning through textContent means the value can
// never be markup at all, whatever the CSP happens to say.
//
// Listeners are attached to each button as it is built, which also removes the
// need to round-trip the note id through a data attribute and read it back.
function createNoteCard(note) {
  const card = document.createElement('article');
  card.className = 'note-card';
  card.dataset.id = note.id;

  const heading = document.createElement('h3');
  heading.textContent = note.title;

  const updated = document.createElement('p');
  updated.textContent = `Updated: ${new Date(note.updatedAt).toLocaleString()}`;

  const actions = document.createElement('div');
  actions.className = 'note-card-actions';

  const openButton = document.createElement('button');
  openButton.type = 'button';
  openButton.className = 'primary-button';
  openButton.textContent = 'Open';
  openButton.addEventListener('click', () => openExistingNote(note.id));

  const deleteButton = document.createElement('button');
  deleteButton.type = 'button';
  deleteButton.className = 'secondary-button';
  deleteButton.textContent = 'Delete';
  deleteButton.addEventListener('click', () => deleteNote(note.id));

  actions.append(openButton, deleteButton);
  card.append(heading, updated, actions);

  return card;
}

function renderNotes(notes) {
  notesContainer.replaceChildren();

  if (!notes || notes.length === 0) {
    const empty = document.createElement('p');
    empty.textContent = 'No notes yet.';
    notesContainer.append(empty);
    return;
  }

  notesContainer.append(...notes.map(createNoteCard));
}

// Every state-changing request has to carry the CSRF token, or
// verifyCsrfToken rejects it with 403 before the controller is ever reached.
//
// GET /api/csrf-token does two things in one call: it returns the raw token in
// the JSON body and sets the matching signed sn_csrf cookie. The cookie rides
// along automatically on the next request because of credentials: 'include';
// the raw value has to be attached by hand as the X-CSRF-Token header. Both
// halves are required, and that pairing is the entire point of a double-submit
// token — a cross-site page can make the browser send the cookie, but cannot
// read the response body to learn the header value.
//
// Fetched per write rather than cached. The cookie lasts two hours, but a
// stale token after a logout/login cycle produces a confusing 403, and one
// extra same-origin GET is not worth optimising away. Mirrors the same helper
// in public/js/admin.js.
async function csrfHeaders() {
  const response = await fetch('/api/csrf-token', {
    method: 'GET',
    credentials: 'include',
    headers: { Accept: 'application/json' },
  });

  if (!response.ok) {
    throw new Error('Could not obtain a CSRF token. Please reload the page.');
  }

  const body = await response.json();

  return { 'X-CSRF-Token': body.data.csrfToken };
}

async function loadNotes() {
  try {
    clearMessage();
    const response = await fetch('/api/notes', {
      method: 'GET',
      credentials: 'include',
      headers: {
        Accept: 'application/json',
      },
    });

    const result = await response.json();

    if (!response.ok) {
      throw new Error(result?.error?.message || 'Unable to load notes');
    }

    renderNotes(result.data.notes);
  } catch (error) {
    notesContainer.replaceChildren();
    showMessage(error.message);
  }
}

async function openExistingNote(noteId) {
  try {
    clearMessage();

    const response = await fetch(`/api/notes/${encodeURIComponent(noteId)}`, {
      method: 'GET',
      credentials: 'include',
      headers: {
        Accept: 'application/json',
      },
    });

    const result = await response.json();

    if (!response.ok) {
      throw new Error(result?.error?.message || 'Unable to load note');
    }

    const note = result.data.note;
    noteIdInput.value = note.id;
    titleInput.value = note.title;
    contentInput.value = note.content;
    editorTitle.textContent = 'Edit Note';
    editor.classList.remove('hidden');
    titleInput.focus();
  } catch (error) {
    showMessage(error.message);
  }
}

async function deleteNote(noteId) {
  try {
    clearMessage();

    const response = await fetch(`/api/notes/${encodeURIComponent(noteId)}`, {
      method: 'DELETE',
      credentials: 'include',
      headers: {
        Accept: 'application/json',
        ...(await csrfHeaders()),
      },
    });

    const result = await response.json();

    if (!response.ok) {
      throw new Error(result?.error?.message || 'Unable to delete note');
    }

    showMessage('Note deleted successfully.', 'success');
    await loadNotes();
  } catch (error) {
    showMessage(error.message);
  }
}

noteForm.addEventListener('submit', async (event) => {
  event.preventDefault();

  try {
    clearMessage();

    const payload = {
      title: titleInput.value.trim(),
      content: contentInput.value,
    };

    const noteId = noteIdInput.value;
    const method = noteId ? 'PUT' : 'POST';
    const url = noteId ? `/api/notes/${encodeURIComponent(noteId)}` : '/api/notes';

    const response = await fetch(url, {
      method,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...(await csrfHeaders()),
      },
      body: JSON.stringify(payload),
    });

    const result = await response.json();

    if (!response.ok) {
      throw new Error(result?.error?.message || 'Unable to save note');
    }

    closeEditor();
    showMessage(
      noteId ? 'Note updated successfully.' : 'Note created successfully.',
      'success',
    );
    await loadNotes();
  } catch (error) {
    showMessage(error.message);
  }
});

newNoteButton.addEventListener('click', openCreateEditor);
cancelButton.addEventListener('click', closeEditor);

loadNotes();
