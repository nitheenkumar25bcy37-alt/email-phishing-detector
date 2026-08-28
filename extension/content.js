// Function to check if auto-scanning is enabled
async function isAutoScanEnabled() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['autoScanEnabled'], (res) => {
      resolve(res.autoScanEnabled !== false);
    });
  });
}

// Function to inject the threat banner inside Gmail
function injectThreatBanner(targetElement, threatData) {
  if (document.getElementById('agentic-mx-banner')) return; // Avoid duplicate banners

  const score = threatData.threat_score.score;
  const level = threatData.threat_score.risk_level;

  const colorMap = {
    LOW: '#22c55e',
    MEDIUM: '#eab308',
    HIGH: '#f97316',
    CRITICAL: '#ef4444'
  };

  const banner = document.createElement('div');
  banner.id = 'agentic-mx-banner';
  banner.style.cssText = `
    background-color: ${colorMap[level] || '#3b82f6'};
    color: white;
    padding: 10px 16px;
    margin: 10px 0;
    border-radius: 6px;
    font-family: sans-serif;
    font-weight: bold;
    display: flex;
    justify-content: space-between;
    align-items: center;
  `;

  banner.innerHTML = `
    <span>🛡️ Agentic MX: <strong>${level} RISK</strong> (Threat Score: ${score}/100)</span>
    <small style="opacity: 0.9;">Vector: ${threatData.ai_briefing?.attack_vector_identified || 'N/A'}</small>
  `;

  targetElement.prepend(banner);
}

// Automatically scan open email body
async function scanActiveEmail() {
  if (!(await isAutoScanEnabled())) return;

  // Gmail view selector target
  const emailContainer = document.querySelector('.a3s.aiL'); 
  const emailHeader = document.querySelector('.ha');

  if (emailContainer && emailHeader && !document.getElementById('agentic-mx-banner')) {
    const emailText = emailContainer.innerText;

    try {
      const response = await fetch('http://localhost:8000/api/v1/analyze/text', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email_text: emailText })
      });

      const data = await response.json();
      injectThreatBanner(emailHeader, data);
    } catch (err) {
      console.error('Agentic MX Auto-scan error:', err);
    }
  }
}

// Dynamic DOM Observer to trigger scan when switching emails
const observer = new MutationObserver(() => scanActiveEmail());
observer.observe(document.body, { childList: true, subtree: true });
