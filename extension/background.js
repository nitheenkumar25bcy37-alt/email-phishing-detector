// ============================================================
// NETRA-MAIL SHIELD
// Background Service Worker
// ============================================================

const API_BASE_URL = "http://127.0.0.1:8000";


// ============================================================
// API HEALTH CHECK
// ============================================================

async function checkBackendHealth() {
    try {
        const response = await fetch(
            `${API_BASE_URL}/health`,
            {
                method: "GET",
                cache: "no-store"
            }
        );

        if (!response.ok) {
            return {
                available: false,
                status: response.status
            };
        }

        const data = await response.json();

        return {
            available: data.status === "healthy",
            status: response.status,
            data
        };

    } catch (error) {

        console.error(
            "[NETRA Background] Health check failed:",
            error
        );

        return {
            available: false,
            error: error.message
        };
    }
}


// ============================================================
// V2 EMAIL ANALYSIS
// ============================================================

async function analyzeEmail(email) {

    if (!email || typeof email !== "object") {
        throw new Error("Invalid email payload.");
    }

    const payload = {
        subject: String(email.subject || ""),
        sender: String(email.sender || ""),
        recipient: String(email.recipient || ""),
        reply_to: String(email.reply_to || ""),
        body: String(email.body || ""),
        html: String(email.html || ""),
        headers: String(email.headers || ""),
        received_headers: String(
            email.received_headers || ""
        )
    };


    if (
        !payload.subject &&
        !payload.sender &&
        !payload.body &&
        !payload.html
    ) {
        throw new Error(
            "No usable email content was extracted."
        );
    }


    const response = await fetch(
        `${API_BASE_URL}/api/v2/emails/analyze`,
        {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify(payload),

            cache: "no-store"
        }
    );


    let data = null;

    try {
        data = await response.json();
    } catch {
        data = null;
    }


    if (!response.ok) {

        const detail =
            data &&
            (
                data.detail ||
                data.message ||
                data.error
            );

        throw new Error(
            detail ||
            `NETRA backend returned HTTP ${response.status}.`
        );
    }


    if (!data) {
        throw new Error(
            "NETRA returned an empty response."
        );
    }


    return data;
}


// ============================================================
// MESSAGE ROUTER
// ============================================================

chrome.runtime.onMessage.addListener(
    (message, sender, sendResponse) => {

        if (!message || !message.type) {
            return;
        }


        // ----------------------------------------------------
        // HEALTH
        // ----------------------------------------------------

        if (message.type === "NETRA_HEALTH") {

            checkBackendHealth()
                .then(result => {

                    sendResponse({
                        success: true,
                        ...result
                    });

                })
                .catch(error => {

                    sendResponse({
                        success: false,
                        error: error.message
                    });

                });

            return true;
        }


        // ----------------------------------------------------
        // ANALYZE EMAIL
        // ----------------------------------------------------

        if (message.type === "NETRA_ANALYZE_EMAIL") {

            analyzeEmail(message.email)
                .then(result => {

                    sendResponse({
                        success: true,
                        data: result
                    });

                })
                .catch(error => {

                    console.error(
                        "[NETRA Background] Analysis failed:",
                        error
                    );

                    sendResponse({
                        success: false,
                        error: error.message
                    });

                });

            return true;
        }


        // ----------------------------------------------------
        // UNKNOWN MESSAGE
        // ----------------------------------------------------

        sendResponse({
            success: false,
            error: "Unknown NETRA message type."
        });

        return false;
    }
);


// ============================================================
// STARTUP LOG
// ============================================================

console.log(
    "[NETRA Background] NETRA-Mail Shield service worker loaded."
);