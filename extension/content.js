let lastScannedId = "";

const observer = new MutationObserver(() => {
  scanCurrentEmail();
});

observer.observe(document.body, { childList: true, subtree: true });

async function scanCurrentEmail() {
  const subjectEl = document.querySelector("h2.hP");
  const senderEl = document.querySelector("span.gD, span[email]");
  const bodyEl = document.querySelector("div.a3s.aiL, div[role='listitem'] div.a3s");

  if (!subjectEl || !senderEl || !bodyEl) return;

  const subject = subjectEl.innerText.trim();
  const sender = senderEl.getAttribute("email") || senderEl.innerText.trim();
  const body = bodyEl.innerText.trim();
  const emailId = subject + sender;

  if (lastScannedId === emailId) return;
  lastScannedId = emailId;

  renderBanner("⏳ Agentic MX: Scanning email security...", "#1e293b", "#38bdf8", null);

  try {
    const response = await fetch("http://127.0.0.1:8000/api/v1/analyze/text", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ subject, sender, body })
    });

    if (!response.ok) throw new Error("Backend offline");

    const data = await response.json();
    const report = data.report;
    const score = report.threat_score.score;
    const riskLevel = report.threat_score.risk_level;
    const mlVerdict = report.ml_assessment.ml_classification;

    let bgColor = "#14532d"; // Green / Low
    let textColor = "#bbf7d0";

    if (score >= 60) {
      bgColor = "#7f1d1d"; // Red / High or Critical
      textColor = "#fecaca";
    } else if (score >= 40) {
      bgColor = "#78350f"; // Yellow / Medium
      textColor = "#fef08a";
    }

    const message = `🛡️ <strong>Agentic MX:</strong> ${riskLevel} RISK (${score}/100) — [${mlVerdict}]`;
    renderBanner(message, bgColor, textColor, report);

  } catch (err) {
    renderBanner("⚠️ Agentic MX: Backend offline (Ensure port 8000 is active)", "#334155", "#94a3b8", null);
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

  // Pass hash parameter to automatically load the specific incident
  const hash = report && report.evidence_seal ? report.evidence_seal.sha256_hash : "";
  const dashUrl = hash ? `http://localhost:8501/?hash=${hash}` : "http://localhost:8501";

  Object.assign(banner.style, {
    backgroundColor: bgColor,
    color: textColor,
    padding: "10px 16px",
    margin: "10px 0",
    borderRadius: "6px",
    fontSize: "13px",
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    border: "1px solid rgba(255,255,255,0.1)"
  });

  banner.innerHTML = `
    <div>${htmlContent}</div>
    <a href="${dashUrl}" target="_blank" style="color:#ffffff; text-decoration:underline; font-size:12px; font-weight:bold;">
      SOC Dashboard ↗
    </a>
  `;
}
