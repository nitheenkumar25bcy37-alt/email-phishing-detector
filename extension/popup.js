const toggle = document.getElementById("protectionToggle");
const statusText = document.getElementById("statusText");
const statusDot = document.getElementById("statusDot");
const analyzeButton = document.getElementById("analyzeButton");
const result = document.getElementById("result");


// ============================================================
// UPDATE UI
// ============================================================

function updateUI(enabled) {

    toggle.checked = enabled;
    analyzeButton.disabled = !enabled;

    if (enabled) {

        statusText.textContent = "ON";

        statusDot.classList.remove("off");
        statusDot.classList.add("on");

    } else {

        statusText.textContent = "OFF";

        statusDot.classList.remove("on");
        statusDot.classList.add("off");
    }
}


// ============================================================
// LOAD CURRENT STATE
// ============================================================

chrome.storage.local.get(
    ["netraProtectionEnabled"],
    (result) => {

        const enabled =
            result.netraProtectionEnabled === true;

        updateUI(enabled);
    }
);


// ============================================================
// TOGGLE
// ============================================================

toggle.addEventListener(
    "change",
    () => {

        const enabled = toggle.checked;

        chrome.storage.local.set(
            {
                netraProtectionEnabled: enabled
            },
            () => {

                updateUI(enabled);
            }
        );
    }
);

analyzeButton.addEventListener("click", async () => {
    result.textContent = "Requesting the current Gmail message...";
    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    if (!tab?.id) {
        result.textContent = "No active tab is available.";
        return;
    }
    chrome.tabs.sendMessage(tab.id, {type: "NETRA_ANALYZE_CURRENT_EMAIL"}, (response) => {
        if (chrome.runtime.lastError) {
            result.textContent = "Open a Gmail message before analyzing.";
            return;
        }
        if (!response?.ok) {
            result.textContent = response?.error || "Email content is unavailable.";
            return;
        }
        const data = response.result || {};
        result.textContent = `Score ${data.score ?? "Unavailable"}/100 · ${data.risk || "Unknown"}. Full details are shown in Gmail.`;
    });
});