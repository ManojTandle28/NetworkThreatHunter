/**
 * NetworkThreatHunter core app interactivity
 */
document.addEventListener('DOMContentLoaded', () => {
  // Modal toggles
  const uploadBtn = document.getElementById('open-upload-modal');
  const uploadModal = document.getElementById('upload-modal');
  const closeModals = document.querySelectorAll('[data-close-modal]');

  if (uploadBtn && uploadModal) {
    uploadBtn.addEventListener('click', () => uploadModal.classList.add('active'));
  }

  closeModals.forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));
    });
  });

  window.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-overlay')) {
      e.target.classList.remove('active');
    }
  });

  // Flash message dismissal
  document.querySelectorAll('.flash-close').forEach(btn => {
    btn.addEventListener('click', function() {
      const parent = this.closest('.flash-msg');
      if (parent) parent.remove();
    });
  });
});
