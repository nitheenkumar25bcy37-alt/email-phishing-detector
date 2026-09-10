// ============================================================
// NETRA-MAIL SHIELD
// Gmail Real-Time Protection + SOC Dashboard
// ============================================================

const API_BASE_URL =
    "http://127.0.0.1:8000";

const SOC_DASHBOARD_URL =
    "http://localhost:8501";


// ============================================================
// STATE
// ============================================================

let protectionEnabled = false;

let lastEmailKey = "";

let scanning = false;

let scanTimer = null;

let progressTimer = null;


// ============================================================
// LOAD PROTECTION STATE
// ============================================================

function loadProtectionState() {

    chrome.storage.local.get(
        ["netraProtectionEnabled"],
        (result) => {

            protectionEnabled =
                result.netraProtectionEnabled === true;

            if (!protectionEnabled) {

                removeNetraUI();

                lastEmailKey = "";

                return;
            }
        }
    );
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type !== "NETRA_ANALYZE_CURRENT_EMAIL") {
        return;
    }
    if (!protectionEnabled) {
        sendResponse({ok: false, error: "Enable Email Protection first."});
        return;
    }
    scanCurrentEmail(true).then((result) => sendResponse({ok: Boolean(result), result: result || null, error: result ? null : "Open a Gmail message before analyzing."}));
    return true;
});


// ============================================================
// PROTECTION STATE CHANGE
// ============================================================

chrome.storage.onChanged.addListener(
    (changes, areaName) => {

        if (
            areaName !== "local" ||
            !changes.netraProtectionEnabled
        ) {
            return;
        }

        protectionEnabled =
            changes.netraProtectionEnabled.newValue === true;

        lastEmailKey = "";

        if (!protectionEnabled) {

            removeNetraUI();

            return;
        }

            removeNetraUI();
    }
);


// ============================================================
// INITIALIZE
// ============================================================

loadProtectionState();


// ============================================================
// OBSERVER
// ============================================================

const observer =
    new MutationObserver(() => {
    });


function startObserver() {

    if (!document.body) {

        setTimeout(
            startObserver,
            500
        );

        return;
    }

    observer.observe(
        document.body,
        {
            childList: true,
            subtree: true
        }
    );
}

startObserver();


// ============================================================
// DEBOUNCE
// ============================================================

function scheduleScan() {

    clearTimeout(
        scanTimer
    );

    scanTimer = setTimeout(
        () => {

            scanCurrentEmail();

        },
        700
    );
}


// ============================================================
// FIND SUBJECT
// ============================================================

function findSubjectElement() {

    const selectors = [
        "h2.hP",
        "h2[data-thread-perm-id]",
        "div.hP"
    ];

    for (
        const selector of selectors
    ) {

        const element =
            document.querySelector(
                selector
            );

        if (
            element &&
            element.innerText &&
            element.innerText.trim()
        ) {

            return element;
        }
    }

    return null;
}


// ============================================================
// FIND SENDER
// ============================================================

function findSenderElement() {

    const selectors = [
        "span.gD[email]",
        "span[email]",
        ".gD"
    ];

    for (
        const selector of selectors
    ) {

        const elements =
            document.querySelectorAll(
                selector
            );

        for (
            const element of elements
        ) {

            const email =
                element.getAttribute(
                    "email"
                );

            if (
                email &&
                email.includes("@")
            ) {

                return element;
            }
        }
    }

    return null;
}


// ============================================================
// FIND BODY
// ============================================================

function findBodyElement() {

    const bodies =
        document.querySelectorAll(
            "div.a3s"
        );

    if (!bodies.length) {
        return null;
    }

    for (
        let i = bodies.length - 1;
        i >= 0;
        i--
    ) {

        const body =
            bodies[i];

        if (
            body.innerText &&
            body.innerText.trim()
        ) {

            return body;
        }
    }

    return bodies[
        bodies.length - 1
    ];
}


// ============================================================
// EMAIL EXTRACTION
// ============================================================

function getCurrentEmail() {

    const subjectEl =
        findSubjectElement();

    const senderEl =
        findSenderElement();

    const bodyEl =
        findBodyElement();

    if (!subjectEl || !bodyEl) {

        return null;
    }

    const subject =
        subjectEl.innerText.trim();

    const sender =
        senderEl
            ? (
                senderEl.getAttribute(
                    "email"
                ) ||
                senderEl.innerText ||
                ""
            ).trim()
            : "";

    const body =
        bodyEl.innerText.trim();

    if (
        !subject &&
        !body
    ) {

        return null;
    }

    return {
        subjectEl,
        senderEl,
        bodyEl,
        subject,
        sender,
        body
    };
}


// ============================================================
// SCAN
// ============================================================

async function scanCurrentEmail(force = false) {

    if (
        !protectionEnabled ||
        scanning
    ) {
        return;
    }

    const email =
        getCurrentEmail();

    if (!email) {
        return;
    }

    const emailKey =
        createEmailKey(
            email.subject,
            email.sender,
            email.body
        );

    if (!force && lastEmailKey === emailKey) {
        return;
    }

    lastEmailKey =
        emailKey;

    scanning = true;

    showScanningBar(
        email.subjectEl
    );

    try {

        updateScanningStage(
            "EXTRACTING EMAIL",
            20,
            "Reading sender, subject and message body..."
        );

        await sleep(120);


        updateScanningStage(
            "ANALYZING CONTENT",
            40,
            "Checking phishing language and indicators..."
        );

        await sleep(120);


        updateScanningStage(
            "THREAT INTELLIGENCE",
            60,
            "Checking domains, URLs and threat signals..."
        );


        const response =
            await fetch(
                `${API_BASE_URL}/api/v2/emails/analyze`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({

                        subject:
                            email.subject,

                        sender:
                            email.sender,

                        body:
                            email.body
                    })
                }
            );


        if (!response.ok) {

            throw new Error(
                `Backend returned HTTP ${response.status}`
            );
        }


        updateScanningStage(
            "CALIBRATING RESULT",
            80,
            "Combining independent threat signals..."
        );


        const data =
            await response.json();


        await sleep(150);


            const result =
            normalizeResult(
                data
            );


        if (!result) {

            throw new Error(
                "Invalid NETRA response"
            );
        }


        updateScanningStage(
            "ASSESSMENT COMPLETE",
            100,
            "Threat assessment generated."
        );


        await sleep(200);


        renderThreatBar(
            email.subjectEl,
            result
        );

            return result;


    } catch (error) {

        console.error(
            "[NETRA] Scan failed:",
            error
        );

        renderErrorBar(
            email.subjectEl
        );

    } finally {

        scanning = false;

        stopProgressAnimation();
    }
}


// ============================================================
// NORMALIZE RESULT
// ============================================================

function normalizeResult(
    data
) {

    if (!data) {
        return null;
    }

    if (data.risk_score !== undefined || data.classification) {
        return {
            score: Number(data.risk_score || 0),
            risk: String(data.classification || "UNKNOWN").toUpperCase(),
            action: Number(data.risk_score || 0) >= 75 ? "BLOCK" : Number(data.risk_score || 0) >= 50 ? "QUARANTINE" : "REVIEW",
            confidence: Number(data.confidence || 0) * 100,
            caseId: data.email_id || "",
            findingCount: Array.isArray(data.findings) ? data.findings.length : 0
        };
    }


    if (
        data.decision
    ) {

        const decision =
            data.decision;

        return {

            score:
                Number(
                    decision.score ||
                    data.threat_score?.threat_score ||
                    0
                ),

            risk:
                String(
                    decision.risk ||
                    "UNKNOWN"
                ).toUpperCase(),

            action:
                String(
                    decision.action ||
                    "REVIEW"
                ).toUpperCase(),

            confidence:
                Number(
                    decision.confidence ||
                    data.threat_score?.confidence ||
                    0
                ),

            caseId:
                data.case_id || ""
        };
    }


    if (
        data.netra_result
    ) {

        return {

            score:
                Number(
                    data.netra_result.score ||
                    0
                ),

            risk:
                String(
                    data.netra_result.risk ||
                    "UNKNOWN"
                ).toUpperCase(),

            action:
                String(
                    data.netra_result.action ||
                    "REVIEW"
                ).toUpperCase(),

            confidence:
                Number(
                    data.netra_result.confidence ||
                    0
                ),

            caseId:
                data.netra_result.case_id ||
                data.case_id ||
                ""
        };
    }


    return null;
}


// ============================================================
// EMAIL KEY
// ============================================================

function createEmailKey(
    subject,
    sender,
    body
) {

    return [
        subject,
        sender,
        body.substring(
            0,
            700
        )
    ].join("|");
}


// ============================================================
// REMOVE UI
// ============================================================

function removeNetraUI() {

    const ids = [
        "netra-threat-bar",
        "netra-scanning-bar"
    ];

    ids.forEach(
        id => {

            const element =
                document.getElementById(
                    id
                );

            if (element) {
                element.remove();
            }
        }
    );

    stopProgressAnimation();
}


// ============================================================
// STOP PROGRESS
// ============================================================

function stopProgressAnimation() {

    if (progressTimer) {

        clearInterval(
            progressTimer
        );

        progressTimer =
            null;
    }
}


// ============================================================
// SUBJECT CONTAINER
// ============================================================

function getSubjectContainer(
    subjectEl
) {

    if (!subjectEl) {
        return null;
    }

    return (
        subjectEl.closest(
            "div.ha"
        ) ||
        subjectEl.parentElement ||
        subjectEl
    );
}


// ============================================================
// INSERT
// ============================================================

function insertBar(
    subjectEl,
    bar
) {

    const container =
        getSubjectContainer(
            subjectEl
        );

    if (!container) {
        return;
    }

    container
        .parentElement
        ?.insertBefore(
            bar,
            container
        );
}


// ============================================================
// SCANNING BAR
// ============================================================

function showScanningBar(
    subjectEl
) {

    const old =
        document.getElementById(
            "netra-scanning-bar"
        );

    if (old) {
        old.remove();
    }


    const bar =
        document.createElement(
            "div"
        );

    bar.id =
        "netra-scanning-bar";


    Object.assign(
        bar.style,
        {

            width: "100%",

            minHeight: "48px",

            boxSizing: "border-box",

            margin: "0 0 10px 0",

            padding: "8px 14px",

            borderRadius: "8px",

            background:
                "#0f172a",

            border:
                "1px solid #1e40af",

            color:
                "#e2e8f0",

            fontFamily:
                "Arial, sans-serif",

            fontSize:
                "12px",

            position:
                "relative",

            overflow:
                "hidden",

            zIndex:
                "999999"
        }
    );


    bar.innerHTML = `

        <div style="
            display:flex;
            justify-content:space-between;
            align-items:center;
        ">

            <div>

                <div
                    id="netra-stage-title"
                    style="
                        font-weight:700;
                        font-size:12px;
                    "
                >
                    NETRA • SCANNING
                </div>

                <div
                    id="netra-stage-message"
                    style="
                        color:#94a3b8;
                        font-size:10px;
                        margin-top:2px;
                    "
                >
                    Initializing threat analysis...
                </div>

            </div>

            <div
                id="netra-stage-percent"
                style="
                    font-weight:700;
                    font-size:11px;
                "
            >
                0%
            </div>

        </div>

        <div style="
            margin-top:7px;
            width:100%;
            height:3px;
            background:#1e293b;
            border-radius:10px;
        ">

            <div
                id="netra-progress"
                style="
                    height:3px;
                    width:0%;
                    background:#38bdf8;
                    border-radius:10px;
                    transition:width .25s ease;
                "
            ></div>

        </div>
    `;


    insertBar(
        subjectEl,
        bar
    );
}


// ============================================================
// UPDATE STAGE
// ============================================================

function updateScanningStage(
    title,
    percent,
    message
) {

    const titleEl =
        document.getElementById(
            "netra-stage-title"
        );

    const messageEl =
        document.getElementById(
            "netra-stage-message"
        );

    const percentEl =
        document.getElementById(
            "netra-stage-percent"
        );

    const progress =
        document.getElementById(
            "netra-progress"
        );


    if (titleEl) {
        titleEl.textContent =
            `NETRA • ${title}`;
    }

    if (messageEl) {
        messageEl.textContent =
            message;
    }

    if (percentEl) {
        percentEl.textContent =
            `${percent}%`;
    }

    if (progress) {
        progress.style.width =
            `${percent}%`;
    }
}


// ============================================================
// THREAT BAR
// ============================================================

function renderThreatBar(
    subjectEl,
    result
) {

    removeNetraUI();


    const score =
        Math.max(
            0,
            Math.min(
                100,
                Math.round(
                    Number(
                        result.score
                    ) || 0
                )
            )
        );


    const risk =
        normalizeRisk(
            result.risk,
            score
        );


    const action =
        result.action ||
        "REVIEW";


    const bar =
        document.createElement(
            "div"
        );

    bar.id =
        "netra-threat-bar";


    Object.assign(
        bar.style,
        {

            width: "100%",

            minHeight: "48px",

            boxSizing: "border-box",

            margin: "0 0 10px 0",

            padding: "9px 14px",

            borderRadius: "8px",

            fontFamily:
                "Arial, sans-serif",

            fontSize: "12px",

            position:
                "relative",

            zIndex:
                "999999",

            background:
                getRiskBackground(
                    risk
                ),

            border:
                `1px solid ${getRiskBorder(risk)}`,

            color:
                "#ffffff"
        }
    );


    const caseLink =
        result.caseId
            ? `${SOC_DASHBOARD_URL}?case_id=${encodeURIComponent(result.caseId)}`
            : SOC_DASHBOARD_URL;


    bar.innerHTML = `

        <div style="
            display:flex;
            align-items:center;
            justify-content:space-between;
            gap:15px;
            flex-wrap:wrap;
        ">

            <div style="
                display:flex;
                align-items:center;
                gap:8px;
            ">

                <span style="
                    font-size:16px;
                ">
                    ${getRiskIcon(risk)}
                </span>

                <strong>
                    NETRA • ${getRiskLabel(risk)}
                </strong>

                <span style="
                    opacity:.9;
                    font-weight:700;
                ">
                    ${score}%
                </span>

                <span style="
                    opacity:.75;
                ">
                    ${action}
                </span>

            </div>

            <a
                href="${caseLink}"
                target="_blank"
                rel="noopener noreferrer"
                style="
                    color:#ffffff;
                    text-decoration:none;
                    font-weight:700;
                    border:1px solid rgba(255,255,255,.45);
                    padding:5px 9px;
                    border-radius:6px;
                    background:rgba(255,255,255,.10);
                "
            >
                View Full SOC Investigation →
            </a>

        </div>
    `;


    insertBar(
        subjectEl,
        bar
    );
}


// ============================================================
// ERROR
// ============================================================

function renderErrorBar(
    subjectEl
) {

    removeNetraUI();


    const bar =
        document.createElement(
            "div"
        );

    bar.id =
        "netra-threat-bar";


    Object.assign(
        bar.style,
        {

            width: "100%",

            minHeight: "42px",

            margin: "0 0 10px 0",

            padding: "10px 14px",

            boxSizing: "border-box",

            borderRadius: "8px",

            background:
                "#334155",

            border:
                "1px solid #64748b",

            color:
                "#e2e8f0",

            fontFamily:
                "Arial, sans-serif",

            fontSize:
                "11px",

            zIndex:
                "999999"
        }
    );


    bar.innerHTML =
        `
        🛡️ NETRA • SCAN UNAVAILABLE
        `;


    insertBar(
        subjectEl,
        bar
    );
}


// ============================================================
// RISK
// ============================================================

function normalizeRisk(
    risk,
    score
) {

    const normalized =
        String(
            risk || ""
        ).toUpperCase();


    if (
        [
            "SAFE",
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL"
        ].includes(
            normalized
        )
    ) {

        return normalized;
    }


    if (score >= 75) {
        return "CRITICAL";
    }

    if (score >= 50) {
        return "HIGH";
    }

    if (score >= 25) {
        return "LOW";
    }

    return "SAFE";
}


// ============================================================
// LABEL
// ============================================================

function getRiskLabel(
    risk
) {

    switch (risk) {

        case "SAFE":
            return "LEGITIMATE";

        case "LOW":
            return "LOW RISK";

        case "MEDIUM":
            return "MEDIUM RISK";

        case "HIGH":
            return "HIGH RISK";

        case "CRITICAL":
            return "CRITICAL";

        default:
            return "UNKNOWN";
    }
}


// ============================================================
// ICON
// ============================================================

function getRiskIcon(
    risk
) {

    switch (risk) {

        case "SAFE":
            return "✓";

        case "LOW":
            return "✓";

        case "MEDIUM":
            return "⚠";

        case "HIGH":
            return "⚠";

        case "CRITICAL":
            return "⛔";

        default:
            return "•";
    }
}


// ============================================================
// COLORS
// ============================================================

function getRiskBackground(
    risk
) {

    switch (risk) {

        case "SAFE":
            return "#166534";

        case "LOW":
            return "#365314";

        case "MEDIUM":
            return "#92400e";

        case "HIGH":
            return "#991b1b";

        case "CRITICAL":
            return "#7f1d1d";

        default:
            return "#334155";
    }
}


function getRiskBorder(
    risk
) {

    switch (risk) {

        case "SAFE":
            return "#22c55e";

        case "LOW":
            return "#84cc16";

        case "MEDIUM":
            return "#f59e0b";

        case "HIGH":
            return "#ef4444";

        case "CRITICAL":
            return "#f87171";

        default:
            return "#64748b";
    }
}


// ============================================================
// SLEEP
// ============================================================

function sleep(ms) {

    return new Promise(
        resolve =>
            setTimeout(
                resolve,
                ms
            )
    );
}