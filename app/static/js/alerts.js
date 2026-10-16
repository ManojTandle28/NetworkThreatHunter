/**
 * Alert status and analyst note update logic
 */

function updateAlertStatus(alertId, newStatus) {
  fetch(`/api/alerts/${alertId}/status`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status: newStatus })
  })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        const badge = document.getElementById(`status-badge-${alertId}`);
        if (badge) {
          badge.innerText = newStatus;
          badge.className = `badge badge-status badge-status-${newStatus.toLowerCase()}`;
        }
        showNotification('Alert status updated successfully.', 'success');
      } else {
        showNotification(data.error || 'Failed to update alert status.', 'error');
      }
    })
    .catch(() => {
      showNotification('Network error while updating alert status.', 'error');
    });
}

function saveAnalystNotes(alertId) {
  const notesText = document.getElementById(`analyst-notes-${alertId}`)?.value || '';
  const statusMsg = document.getElementById(`notes-save-status-${alertId}`);

  if (statusMsg) {
    statusMsg.innerText = 'Saving notes...';
    statusMsg.style.color = 'var(--text-muted)';
  }

  fetch(`/api/alerts/${alertId}/notes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ notes: notesText })
  })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        if (statusMsg) {
          statusMsg.innerText = 'Notes saved successfully.';
          statusMsg.style.color = '#34d399';
          setTimeout(() => { statusMsg.innerText = ''; }, 3000);
        }
      } else {
        if (statusMsg) {
          statusMsg.innerText = data.error || 'Failed to save notes.';
          statusMsg.style.color = '#f87171';
        }
      }
    })
    .catch(() => {
      if (statusMsg) {
        statusMsg.innerText = 'Network error saving notes.';
        statusMsg.style.color = '#f87171';
      }
    });
}

function showNotification(msg, type = 'info') {
  const container = document.querySelector('.container');
  if (!container) return;

  const notif = document.createElement('div');
  notif.className = `flash-msg flash-${type}`;
  notif.innerHTML = `<span>${msg}</span><button class="flash-close" onclick="this.parentElement.remove()">&times;</button>`;

  let flashContainer = document.querySelector('.flash-container');
  if (!flashContainer) {
    flashContainer = document.createElement('div');
    flashContainer.className = 'flash-container';
    container.prepend(flashContainer);
  }
  flashContainer.prepend(notif);

  setTimeout(() => {
    if (notif.parentElement) notif.remove();
  }, 4000);
}
