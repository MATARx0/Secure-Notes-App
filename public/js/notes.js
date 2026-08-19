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

function renderNotes(notes) {
  if (!notes || notes.length === 0) {
    notesContainer.innerHTML = '<p>No notes yet.</p>';
    return;
  }

  notesContainer.innerHTML = notes
    .map(
      (note) => `
        <article class="note-card" data-id="${note.id}">
          <h3>${note.title}</h3>
          <p>Updated: ${new Date(note.updatedAt).toLocaleString()}</p>
          <div class="note-card-actions">
            <button type="button" class="primary-button" data-action="open" data-id="${note.id}">
              Open
            </button>
            <button type="button" class="secondary-button" data-action="delete" data-id="${note.id}">
              Delete
            </button>
          </div>
        </article>
      `,
    )
    .join('');

  notesContainer.querySelectorAll('[data-action="open"]').forEach((button) => {
    button.addEventListener('click', () => openExistingNote(button.dataset.id));
  });

  notesContainer.querySelectorAll('[data-action="delete"]').forEach((button) => {
    button.addEventListener('click', () => deleteNote(button.dataset.id));
  });
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
