// ============================================================
// NETRA-MAIL SHIELD
// Gmail Real-Time Protection
// ============================================================

let protectionEnabled = false;

let lastEmailKey = "";

let scanning = false;

let scanTimer = null;


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

                removeNetraBadge();

                lastEmailKey = "";

                return;
            }


            scheduleScan();
        }
    );
}


// ============================================================
// STORAGE CHANGE LISTENER
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


        if (!protectionEnabled) {

            removeNetraBadge();

            lastEmailKey = "";

            return;
        }


        lastEmailKey = "";

        scheduleScan();
    }
);


// ============================================================
// INITIALIZE
// ============================================================

loadProtectionState();


// ============================================================
// MUTATION OBSERVER
// ============================================================

const observer =
    new MutationObserver(() => {

        if (!protectionEnabled) {
            return;
        }

        scheduleScan();
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

    clearTimeout(scanTimer);


    scanTimer =
        setTimeout(
            () => {
                scanCurrentEmail();
            },
            700
        );
}


// ============================================================
// SUBJECT
// ============================================================

function findSubjectElement() {

    const selectors = [
        "h2.hP",
        "h2[data-thread-perm-id]",
        "div.hP"
    ];


    for (const selector of selectors) {

        const element =
            document.querySelector(selector);


        if (
            element &&
            (
                element.innerText ||
                element.textContent
            )
        ) {

            return element;
        }
    }


    return null;
}


// ============================================================
// SENDER
// ============================================================

function findSenderElement() {

    const selectors = [
        "span.gD[email]",
        "span[email]",
        ".gD"
    ];


    for (const selector of selectors) {

        const elements =
            document.querySelectorAll(selector);


        for (const element of elements) {

            const email =
                element.getAttribute("email");


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
// BODY
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


        const text =
            body.innerText ||
            body.textContent ||
            "";


        if (
            text.trim().length > 10 &&
            isVisible(body)
        ) {

            return body;
        }
    }


    return null;
}


// ============================================================
// VISIBILITY
// ============================================================

function isVisible(element) {

    if (!element) {
        return false;
    }


    const rect =
        element.getBoundingClientRect();


    return (
        rect.width > 0 &&
        rect.height > 0
    );
}


// ============================================================
// EMAIL EXTRACTION
// ============================================================

function extractCurrentEmail() {

    const subjectEl =
        findSubjectElement();

    const senderEl =
        findSenderElement();

    const bodyEl =
        findBodyElement();


    if (
        !subjectEl ||
        !senderEl ||
        !bodyEl
    ) {
        return null;
    }


    const subject =
        (
            subjectEl.innerText ||
            subjectEl.textContent ||
            ""
        ).trim();


    let sender =
        senderEl.getAttribute(
            "email"
        );


    if (!sender) {

        sender =
            (
                senderEl.innerText ||
                ""
            ).trim();
    }


    const body =
        (
            bodyEl.innerText ||
            bodyEl.textContent ||
            ""
        ).trim();


    if (
        !subject ||
        !sender ||
        !body
    ) {
        return null;
    }


    // --------------------------------------------------------
    // Gmail recipient
    // --------------------------------------------------------

    let recipient = "";

    const recipientSelectors = [
        "[email][data-hovercard-id]",
        "span[email]"
    ];


    for (
        const selector
        of recipientSelectors
    ) {

        const elements =
            document.querySelectorAll(
                selector
            );


        for (
            const element
            of elements
        ) {

            const email =
                element.getAttribute(
                    "email"
                );


            if (
                email &&
                email.includes("@") &&
                email !== sender
            ) {

                recipient = email;

                break;
            }
        }


        if (recipient) {
            break;
        }
    }


    // --------------------------------------------------------
    // HTML
    // --------------------------------------------------------

    let html = "";

    if (bodyEl) {

        html =
            bodyEl.innerHTML ||
            "";
    }


    // Limit payload size before sending
    html =
        html.slice(
            0,
            500000
        );


    return {
        subject,
        sender,
        recipient,
        reply_to: "",
        body: body.slice(0, 500000),
        html
    };
}


// ============================================================
// EMAIL KEY
// ============================================================

function createEmailKey(
    subject,
    sender,
    body
) {

    const raw =
        `${subject}|${sender}|${body.slice(0, 500)}`;

    let hash = 0;


    for (
        let i = 0;
        i < raw.length;
        i++
    ) {

        hash =
            (
                (
                    hash << 5
                ) -
                hash
            ) +
            raw.charCodeAt(i);


        hash |= 0;
    }


    return String(hash);
}


// ============================================================
// MAIN SCAN
// ============================================================

async function scanCurrentEmail() {

    if (!protectionEnabled) {
        return;
    }


    if (scanning) {
        return;
    }


    const email =
        extractCurrentEmail();


    if (!email) {
        return;
    }


    const emailKey =
        createEmailKey(
            email.subject,
            email.sender,
            email.body
        );


    if (
        lastEmailKey === emailKey
    ) {

        return;
    }


    lastEmailKey =
        emailKey;


    showScanningBadge(
        email.subjectEl
    );


    scanning = true;


    try {

        const result =
            await analyzeThroughBackground(
                email
            );


        const normalized =
            normalizeResult(
                result
            );


        if (!normalized) {

            throw new Error(
                "Invalid NETRA response."
            );
        }


        renderThreatBadge(
            findSubjectElement(),
            normalized
        );

    }
    catch (error) {

        console.error(
            "[NETRA] Scan failed:",
            error
        );


        renderErrorBadge(
            findSubjectElement(),
            error.message
        );

    }
    finally {

        scanning = false;
    }
}


// ============================================================
// BACKGROUND API BRIDGE
// ============================================================

function analyzeThroughBackground(
    email
) {

    return new Promise(
        (
            resolve,
            reject
        ) => {

            chrome.runtime.sendMessage(
                {
                    type:
                        "NETRA_ANALYZE_EMAIL",

                    email
                },

                (response) => {

                    if (
                        chrome.runtime.lastError
                    ) {

                        reject(
                            new Error(
                                chrome.runtime.lastError.message
                            )
                        );

                        return;
                    }


                    if (
                        !response
                    ) {

                        reject(
                            new Error(
                                "No response from NETRA background service."
                            )
                        );

                        return;
                    }


                    if (
                        !response.success
                    ) {

                        reject(
                            new Error(
                                response.error ||
                                "NETRA backend request failed."
                            )
                        );

                        return;
                    }


                    resolve(
                        response.data
                    );
                }
            );
        }
    );
}


// ============================================================
// RESULT NORMALIZATION
// ============================================================

function normalizeResult(data) {

    if (!data) {
        return null;
    }


    const decision =
        data.decision ||
        {};


    const score =
        Number(
            decision.score ??
            data.risk_score ??
            data.score ??
            0
        );


    const riskLevel =
        String(
            decision.risk_level ??
            decision.risk ??
            data.classification ??
            "UNKNOWN"
        ).toUpperCase();


    const action =
        String(
            decision.action ??
            "REVIEW"
        ).toUpperCase();


    const confidence =
        Number(
            decision.confidence ??
            data.confidence ??
            0
        );


    const classification =
        String(
            decision.attack_classification ??
            decision.classification ??
            data.classification ??
            "Unknown"
        );


    return {
        score,
        riskLevel,
        action,
        confidence,
        classification,
        raw: data
    };
}


// ============================================================
// SCANNING BADGE
// ============================================================

function showScanningBadge(
    subjectEl
) {

    if (!subjectEl) {
        return;
    }


    let badge =
        document.getElementById(
            "netra-mail-badge"
        );


    if (!badge) {

        badge =
            document.createElement(
                "span"
            );

        badge.id =
            "netra-mail-badge";


        badge.style.cssText = `
            display:inline-flex;
            align-items:center;
            margin-left:12px;
            padding:5px 10px;
            border-radius:999px;
            background:#1e293b;
            color:#7dd3fc;
            font-family:Arial,sans-serif;
            font-size:12px;
            font-weight:700;
            z-index:999999;
        `;


        subjectEl.appendChild(
            badge
        );
    }


    badge.textContent =
        "🛡️ NETRA SCANNING...";
}


// ============================================================
// THREAT BADGE
// ============================================================

function renderThreatBadge(
    subjectEl,
    result
) {

    if (!subjectEl) {
        return;
    }


    let badge =
        document.getElementById(
            "netra-mail-badge"
        );


    if (!badge) {

        badge =
            document.createElement(
                "span"
            );

        badge.id =
            "netra-mail-badge";


        subjectEl.appendChild(
            badge
        );
    }


    let background =
        "#166534";

    let foreground =
        "#dcfce7";


    if (
        result.score >= 75 ||
        result.riskLevel === "CRITICAL"
    ) {

        background =
            "#991b1b";

        foreground =
            "#fee2e2";

    }
    else if (
        result.score >= 50 ||
        result.riskLevel === "HIGH"
    ) {

        background =
            "#9a3412";

        foreground =
            "#ffedd5";

    }
    else if (
        result.score >= 25 ||
        result.riskLevel === "LOW"
    ) {

        background =
            "#854d0e";

        foreground =
            "#fef9c3";
    }


    badge.style.cssText = `
        display:inline-flex;
        align-items:center;
        gap:5px;
        margin-left:12px;
        padding:5px 10px;
        border-radius:999px;
        background:${background};
        color:${foreground};
        font-family:Arial,sans-serif;
        font-size:12px;
        font-weight:700;
        z-index:999999;
    `;


    badge.textContent =
        `🛡️ NETRA ${result.riskLevel} • ${result.score}/100 • ${result.action}`;


    badge.title =
        `${result.classification} | Confidence ${result.confidence}%`;
}


// ============================================================
// ERROR BADGE
// ============================================================

function renderErrorBadge(
    subjectEl,
    message
) {

    if (!subjectEl) {
        return;
    }


    let badge =
        document.getElementById(
            "netra-mail-badge"
        );


    if (!badge) {

        badge =
            document.createElement(
                "span"
            );

        badge.id =
            "netra-mail-badge";


        subjectEl.appendChild(
            badge
        );
    }


    badge.style.cssText = `
        display:inline-flex;
        align-items:center;
        margin-left:12px;
        padding:5px 10px;
        border-radius:999px;
        background:#334155;
        color:#cbd5e1;
        font-family:Arial,sans-serif;
        font-size:12px;
        font-weight:700;
        z-index:999999;
    `;


    badge.textContent =
        "⚠️ NETRA SCAN UNAVAILABLE";


    badge.title =
        message ||
        "NETRA backend is unavailable.";
}


// ============================================================
// REMOVE BADGE
// ============================================================

function removeNetraBadge() {

    const badge =
        document.getElementById(
            "netra-mail-badge"
        );


    if (badge) {
        badge.remove();
    }
}