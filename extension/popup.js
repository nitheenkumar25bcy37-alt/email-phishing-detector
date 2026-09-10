// ============================================================
// NETRA-MAIL SHIELD POPUP
// ============================================================

const toggle =
    document.getElementById(
        "protectionToggle"
    );

const statusText =
    document.getElementById(
        "statusText"
    );

const statusDot =
    document.getElementById(
        "statusDot"
    );


// ============================================================
// UPDATE PROTECTION UI
// ============================================================

function updateUI(enabled) {

    toggle.checked =
        enabled;


    if (enabled) {

        statusText.textContent =
            "ON";

        statusDot.classList.remove(
            "off"
        );

        statusDot.classList.add(
            "on"
        );

    }
    else {

        statusText.textContent =
            "OFF";

        statusDot.classList.remove(
            "on"
        );

        statusDot.classList.add(
            "off"
        );
    }
}


// ============================================================
// LOAD STATE
// ============================================================

chrome.storage.local.get(
    ["netraProtectionEnabled"],
    (result) => {

        updateUI(
            result.netraProtectionEnabled === true
        );
    }
);


// ============================================================
// TOGGLE
// ============================================================

toggle.addEventListener(
    "change",
    () => {

        const enabled =
            toggle.checked;


        chrome.storage.local.set(
            {
                netraProtectionEnabled:
                    enabled
            },
            () => {

                updateUI(
                    enabled
                );
            }
        );
    }
);