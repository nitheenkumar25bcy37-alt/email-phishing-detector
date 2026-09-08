# Phishing Evaluation Implementation Report

## Actual Architecture

```text
EML upload or direct JSON email
        |
        v
backend/main.py
        |
        +-- ForensicEmailParser: MIME bodies, URLs, headers, attachments
        +-- HeaderForensicAnalyzer: SPF, DKIM, DMARC, Reply-To alignment
        +-- NLPEngine: urgency, financial, credential, social-engineering cues
        +-- Local ML classifier: phishing probability from text features
        +-- URLAnalyzer and DomainForensics: URL/domain intelligence
        +-- GeoIP/infrastructure enrichment
        +-- ThreatScoringEngine: weighted signals and bounded correlations
        +-- DecisionEngine: risk band, action, reasons
        |
        v
API response, forensic ledger, Chrome extension/dashboard consumers
```

## Verified Baseline

Before changes, the automated scenario runner recorded **14/24 (58.3%)**.
Failures included fake password reset, inheritance scam, executable attachment,
legitimate bank reset, shortener, homograph, misleading subdomain, HTTPS phishing,
Reply-To mismatch, and the JavaScript redirect case.

## Changes Implemented

### Attachment analysis

`backend/attachment_analyzer.py` performs static analysis only. It detects
executables, macro-enabled documents, archives, executable MIME types, and double
extensions. It contributes a bounded score to the active `threat_engine` and
returns structured reasons. No attachment is opened or executed.

### Text and HTML handling

`backend/main.py` now converts HTML to visible text before NLP analysis and correctly
reads the nested `NLPEngine` category result. Explicit legitimate-reset disclaimers
are capped as content risk, while URL, domain, and authentication evidence remains
available to detect a malicious reset message.

### URL and domain signals

The URL analyzer now records explicit phishing/fake hostnames and misleading terms
in subdomains such as `bank-login.attacker.com`. Existing IDN and typosquatting
signals are preserved. Corroborated URL/content evidence receives a bounded floor,
not an unconditional phishing verdict.

### Header and scoring behavior

Corroborated From/Reply-To or Return-Path mismatches now reach the final decision.
SPF/DKIM/DMARC remains a signal rather than an allow-list. High-risk executable
attachments and explicit phishing hostnames cannot remain `SAFE` through weighted
averaging alone.

### Safe shortener expansion

`backend/url_expander.py` provides opt-in HEAD-only expansion with URL scheme
validation, timeout, redirect limit, and failure recording. It is disabled by
default because it makes outbound network requests. Enable it only for authorized
testing with `NETRA_EXPAND_SHORT_URLS=1`.

## Validation

- Focused feature tests: **8 passed**
- Final API scenario suite: **23/24 (95.8%)**
- Final average latency: approximately **2.10 seconds per case**
- HTML/form scenarios: **4/4 passed**
- False-positive scenarios: **5/5 passed**
- Backend modules compile successfully

The remaining 2.2 failure is expected from the supplied fixture: it contains only
`bit.ly/abc123`, while the description asserts an external destination that is not
encoded in the email. Without fetching that URL, the detector must not claim to
know the destination. The opt-in expander is now available for a live authorized
test.

## Confidence Limitation

The current confidence value is a heuristic derived from signal strength and
agreement. It is not a calibrated probability. A calibrated confidence model needs
an unseen validation set with labels and should be implemented only after that data
is available.

## Existing Repository Test Issue

`backend.test_scoring_engine` and `backend.test_three_components` currently fail to
import because they request `MLClassifier` from `backend.ml_classifier`, but that
symbol is not defined there. This is an existing test/API mismatch and was not
changed blindly because the active API uses the local classifier path already wired
in `backend/main.py`.

## Next Recommended Work

1. Add an authorized shortener fixture with a local mock redirect server, then run
   the opt-in expansion path without relying on public URLs.
2. Repair or update the stale `MLClassifier` regression tests to the current model
   API.
3. Build a labelled, previously unseen validation set for confidence calibration
   and threshold selection.
4. Add real domain-age/reputation fixtures with mocked DNS/WHOIS responses so tests
   remain deterministic and offline.