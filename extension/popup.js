document.addEventListener("DOMContentLoaded", () => {
  const fileInput = document.getElementById("eml-input");
  const uploadLabel = document.getElementById("upload-label");
  const scanBtn = document.getElementById("scan-btn");
  const resultBox = document.getElementById("result-box");
  const badgeContainer = document.getElementById("badge-container");
  const scoreVal = document.getElementById("score-val");
  const mlVal = document.getElementById("ml-val");
  const ipVal = document.getElementById("ip-val");
  const hashVal = document.getElementById("hash-val");

  let selectedFile = null;

  fileInput.addEventListener("change", (e) => {
    if (e.target.files.length > 0) {
      selectedFile = e.target.files[0];
      uploadLabel.textContent = `📄 ${selectedFile.name}`;
      uploadLabel.style.borderColor = "#38bdf8";
    }
  });

  scanBtn.addEventListener("click", async () => {
    if (!selectedFile) {
      alert("Please choose an .eml file first.");
      return;
    }

    scanBtn.textContent = "Scanning...";
    scanBtn.disabled = true;

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const response = await fetch("http://127.0.0.1:8000/api/v1/analyze/file", {
        method: "POST",
        body: formData
      });

      if (!response.ok) throw new Error("API request failed");

      const data = await response.json();
      const report = data.report;

      const score = report.threat_score.score;
      const riskLevel = report.threat_score.risk_level;
      const mlClassification = report.ml_assessment.ml_classification;
      const confidence = report.ml_assessment.confidence_score;
      const originIp = report.routing_forensics.origin_ip || "Unknown";
      const hash = report.evidence_seal.sha256_hash.substring(0, 12) + "...";

      badgeContainer.innerHTML = `<span class="badge ${score >= 60 ? 'badge-critical' : 'badge-safe'}">${riskLevel} RISK (${score}/100)</span>`;
      scoreVal.textContent = `${score}/100`;
      mlVal.textContent = `${mlClassification} (${confidence}%)`;
      ipVal.textContent = originIp;
      hashVal.textContent = hash;

      resultBox.style.display = "block";
    } catch (err) {
      alert("Could not connect to Agentic MX Backend (http://127.0.0.1:8000). Ensure the server is running.");
      console.error(err);
    } finally {
      scanBtn.textContent = "⚡ Run Forensic Scan";
      scanBtn.disabled = false;
    }
  });
});
