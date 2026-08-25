// Agentic MX - Real-Time Webmail Guard (Manifest V3)
// Production Cloud Endpoints
const API_BASE_URL = "https://email-phishing-detector-vbg5.onrender.com";
const SOC_DASHBOARD_URL = "https://email-phishing-detector-agentic-mx-v2.streamlit.app";

let lastScannedId = "";

// Observe DOM mutations to trigger zero-click scans when opening emails in Gmail
const observer = new MutationObserver(() => {
  scanCurrentEmail();
});

observer.observe(document.body, { childList: true, subtree: true });

async function scanCurrentEmail() {
  // Target Gmail DOM selectors for active message view
  const subjectEl = document.querySelector("h2.hP");
  const senderEl = document.querySelector("span.gD, span[email]");
  const bodyEl = document.querySelector("div.a3s.aiL, div[role='listitem'] div.a3s");

  if (!subjectEl || !senderEl || !bodyEl) return;

  const subject = subjectEl.innerText.trim();
  const sender = senderEl.getAttribute("email") || senderEl.innerText.trim();
  const body = bodyEl.innerText.trim();
  const emailId = subject + sender;

  // Prevent duplicate redundant scans on the active email
  if (lastScannedId === emailId) return;
  lastScannedId = emailId;

  // Render initial scanning status
  renderBanner("⏳ Agentic MX: Running real-time threat scan...", "#1e293b", "#38bdf8", null);

  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/analyze/text`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ subject, sender, body })
    });

    if (!response.ok) throw new Error("Cloud API error");

    const data = await response.json();
    const report = data.report;
    const score = report.threat_score.score;
    const riskLevel = report.threat_score.risk_level;
    const mlVerdict = report.ml_assessment.ml_classification;

    // Severity color mapping
    let bgColor = "#14532d"; // Low Risk / Safe (Green)
    let textColor = "#bbf7d0";

    if (score >= 60) {
      bgColor = "#7f1d1d"; // High / Critical Risk (Red)
      textColor = "#fecaca";
    } else if (score >= 40) {
      bgColor = "#78350f"; // Medium Risk (Yellow)
      textColor = "#fef08a";
    }

    const message = `🛡️ <strong>Agentic MX:</strong> ${riskLevel} RISK (${score}/100) — [${mlVerdict}]`;
    renderBanner(message, bgColor, textColor, report);

  } catch (err) {
    console.error("[Agentic MX] Cloud API Error:", err);
    renderBanner("⚠️ Agentic MX: Unable to connect to Threat Intelligence Cloud", "#334155", "#94a3b8", null);
  }
}

function renderBanner(htmlContent, bgColor, textColor, report) {
  let banner = document.getElementById("agentic-mx-banner");
  
  if (!banner) {
    banner = document.createElement("div");
    banner.id = "agentic-mx-banner";
    const container = document.querySelector("div.ha, h2.hP");
    if (container && container.parentNode) {
      container.parentNode.insertBefore(banner, container);
    }
  }

  // Pass cryptographic hash to auto-load forensic dossier in the dashboard
  const hash = report && report.evidence_seal ? report.evidence_seal.sha256_hash : "";
  const dashUrl = hash ? `${SOC_DASHBOARD_URL}/?hash=${hash}` : SOC_DASHBOARD_URL;

  Object.assign(banner.style, {
    backgroundColor: bgColor,
    color: textColor,
    padding: "10px 16px",
    margin: "10px 0",
    borderRadius: "6px",
    fontSize: "13px",
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    border: "1px solid rgba(255,255,255,0.1)",
    boxShadow: "0 2px 8px rgba(0,0,0,0.15)",
    transition: "all 0.3s ease"
  });

  banner.innerHTML = `
    <div style="display: flex; align-items: center; gap: 8px;">
      ${htmlContent}
    </div>
    <a href="${dashUrl}" target="_blank" style="color: #ffffff; text-decoration: underline; font-size: 12px; font-weight: bold; margin-left: 12px; white-space: nowrap;">
      SOC Dashboard ↗
    </a>
  `;
}
