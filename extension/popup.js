document.addEventListener('DOMContentLoaded', () => {
  const toggle = document.getElementById('toggleState');

  // Load saved state
  chrome.storage.local.get(['autoScanEnabled'], (result) => {
    toggle.checked = result.autoScanEnabled !== false; // Default: ON
  });

  // Save state on change
  toggle.addEventListener('change', (e) => {
    chrome.storage.local.set({ autoScanEnabled: e.target.checked });
  });
});
