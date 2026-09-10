# NETRA-Mail Baseline Audit

## Scope

The repository contains a FastAPI backend, SQLite tamper-evident ledger, static attachment analysis, URL intelligence, NLP heuristics, local ML integration, a dashboard, and a browser extension.

## Current API surface

- `GET /`
- `GET /health`
- `POST /api/v1/analyze/eml`
- `POST /api/v1/analyze/email`
- `POST /api/v1/analyze/text`
- `GET /api/v1/forensics/case/{case_id}`
- `GET /api/v1/forensics/audit`
- Additional legacy forensic and dashboard routes are defined in `backend/main.py`.

## Strengths

- Existing v1 analysis pipeline is preserved.
- `.eml` parsing calculates SHA-256 and extracts bodies, URLs, headers, and attachment hashes.
- Attachments are analyzed statically and are never executed.
- The SQLite ledger chains records with previous/current hashes.
- Existing privacy masking and extension-compatible response fields are already present.

## Weaknesses addressed first

- Analysis decisions were coupled to a very large API module.
- Findings were not represented as stable structured objects with confidence and limitations.
- Risk score, classification, and confidence were not consistently separated.
- There was no versioned v2 façade for secure ingestion and machine-readable findings.
- Authentication and urgency signals needed explicit non-proof limitations.

## Validation baseline

The system Python and repository `.venv` both lack the `pytest` package, so the existing pytest suite could not be executed in this environment. The initial command failures were:

- `pytest -q`: command not found
- `.venv\\Scripts\\python.exe -m pytest -q`: `No module named pytest`

Executable validation is performed with Python compilation and API smoke checks instead. No accuracy improvement is claimed without a runnable labeled evaluation.

## Proposed data model

The existing ledger remains backward compatible. The v2 model is represented first through stable IDs and structured payloads: emails/evidence, findings, indicators, attachments, URLs, cases, relationships, reports, and audit events. A later migration can normalize these into SQLite tables without changing the v1 contract.

## Implementation order

1. Baseline audit and compatibility preservation.
2. Structured findings, evidence records, risk engine, and v2 orchestration.
3. Secure upload/analyze routes and focused tests.
4. Header/origin, URL, attachment, domain, and authentication refinements.
5. Cases, graph correlation, reports, privacy controls, and dashboard integration.
6. Reproducible evaluation with measured precision, recall, F1, false positives, and latency.

## Phase 2 detection intelligence completed

- The parser now preserves original bytes, complete sender metadata, authentication headers, ordered Received headers, visible HTML text, forms, hidden fields, links, inline images, MIME structure, attachment hashes, and safe archive member metadata.
- Header analysis now produces authentication, alignment, sender-identity, relay, timestamp, IP-classification, and origin-candidate findings.
- URL analysis now produces structured findings for visible/href mismatch, shorteners, IDN or mixed-script hosts, IP URLs, ports, and suspicious URL features without fetching remote content.
- Attachment analysis now checks executable/script/macro/HTML/shortcut/archive content, double extensions, MIME mismatch, embedded URLs, encrypted archive members, and nested executable-looking names without execution.
- All analyzer findings use the existing `Finding` schema and flow through the existing `RiskEngine`, v2 response, and SQLite persistence.

## Phase 2 non-goals and limitations

- Redirect expansion and live reputation are deliberately disabled; no remote URLs are fetched.
- Authentication pass results do not establish message safety.
- Relay origin candidates describe observed infrastructure and do not identify a human sender.
- Static attachment inspection does not establish malicious execution.
- Campaign correlation, PDF reports, geolocation maps, and frontend redesign remain future phases.

## Phase 3 origin traceability and infrastructure intelligence completed

- `Received` hops now preserve header order, source and destination hostnames, source and destination IP slots, timestamps, IP classifications, malformed-header status, and timestamp reliability signals.
- Origin traces rank multiple public candidates with confidence, basis, per-hop reliability, and explicit non-attribution limitations.
- `IPIntelligenceProvider` supports IPv4/IPv6 validation, private/reserved/documentation filtering, optional environment-configured providers, bounded timeouts, caching, rate-limit handling, and structured unavailable results.
- `DomainIntelligenceProvider` performs bounded DNS A, AAAA, MX, NS, SPF, and DMARC lookups with caching, registered-domain data, sender/infrastructure relationships, and explainable findings.
- v2 analysis persists `origin_trace`, `ip_intelligence`, and `domain_intelligence` in the existing SQLite analysis payload.
- Added `GET /api/v2/intelligence/ip/{ip}` and `GET /api/v2/intelligence/domain/{domain}`. The trace endpoint now returns the structured origin trace.
- SQLite connections now close deterministically for reliable persistence and Windows test cleanup.

## Phase 3 limitations

- No external IP provider is queried unless `NETRA_IP_INTEL_URL` is configured; unavailable data is never replaced with fake geolocation.
- DNS and IP intelligence are time-dependent observations, not ownership or attribution proof.
- Cloud hosting alone does not produce a critical verdict.
- The future frontend map, campaign correlation, PDF reports, and case-management graph remain unimplemented.

## Phase 4 campaign correlation and case management completed

### Architecture

- `backend/campaign_correlator.py` extracts normalized indicators from persisted v2 analyses and creates deterministic relationships.
- `backend/services/campaign_service.py` stores relationships, creates suspected campaigns when strong evidence exists, and reuses candidate campaigns.
- `backend/services/case_service.py` manages case validation, email/campaign links, notes, tags, and timeline events.
- `backend/database.py` adds non-destructive SQLite tables for campaigns, campaign emails, campaign relationships, cases, case emails, case campaigns, notes, and timelines.

### Correlation behavior

Supported evidence includes sender, Reply-To, public origin/relay IP, suspicious URL, URL domain, registered domain, attachment hash, Message-ID domain, normalized subject/body similarity, impersonated brand, ASN, and authentication pattern. Strong indicators receive higher bounded confidence; weak indicators alone are ignored or require additional evidence. Generic DNS, email-provider, cloud, private, and documentation values are excluded from meaningful relationships.

Every relationship includes evidence, confidence, `requires_review`, and limitations. Correlation never claims common human ownership or attacker attribution.

### Case-management API

- `POST/GET /api/v2/campaigns`
- `GET/PATCH /api/v2/campaigns/{campaign_id}`
- `GET /api/v2/campaigns/{campaign_id}/emails`
- `GET /api/v2/campaigns/{campaign_id}/relationships`
- `GET/POST /api/v2/emails/{email_id}/relationships`
- `POST /api/v2/emails/{email_id}/correlate`
- `POST/GET /api/v2/cases`
- `GET/PATCH /api/v2/cases/{case_id}`
- `POST /api/v2/cases/{case_id}/emails`
- `POST/DELETE /api/v2/cases/{case_id}/emails/{email_id}`
- `POST /api/v2/cases/{case_id}/campaigns/{campaign_id}`
- `POST /api/v2/cases/{case_id}/notes`
- `POST /api/v2/cases/{case_id}/tags`
- `GET /api/v2/cases/{case_id}/timeline`

Automatic correlation runs after successful v2 persistence and is non-fatal to email analysis.

### Privacy and limitations

- Relationship records store indicator values and hashes, not complete message bodies.
- Campaign membership remains `suspected` or `under_review` until analyst confirmation.
- Shared infrastructure can be reused by unrelated actors.
- Text similarity can create false positives.
- Provider data may be unavailable or stale.
- No human or organizational attacker attribution is performed.

### Phase 4 validation

- Maintained Phase 2, Phase 3, and Phase 4 suites: **18 passed**.
- Backend compilation: passed.
- Automatic two-email correlation and candidate campaign creation: passed.
- Case creation, email/campaign linking, notes, tags, timeline, and SQLite reopen persistence: passed.
- Full `pytest -q`: still has seven legacy collection failures unrelated to Phase 4: missing historical `MLClassifier`, `HeaderAnalyzer`, and `ComplianceEngine` symbols; an old NLP fixture expecting `urgency_cues`; a binary `test_results.txt` collected as a test; and related legacy collection errors. These tests were not deleted or weakened.

## Phase 5 evidence preservation, chain of custody, and forensic reporting completed

### Evidence lifecycle

- `backend/evidence_service.py` registers raw EML, attachment, and report evidence with SHA-256, safe filenames, bounded storage, version metadata, integrity status, and explicit limitations.
- Evidence is stored once under `NETRA_EVIDENCE_STORAGE_DIR`; case links reference the same record and do not duplicate raw bytes.
- v2 text and upload analysis automatically preserve the generated/original RFC email bytes as additive `evidence_reference` metadata. Registration failures remain non-fatal to analysis.
- Evidence versions use new version paths and never overwrite the original version.

### Chain of custody

- `chain_of_custody` records collection, registration, hash verification, integrity failure, case attachment, export, and report events.
- Integrity verification computes actual stored bytes and returns `verified`, `failed`, or `unavailable`; failures are never converted to success.
- Case evidence links create both case timeline events and custody events.

### Reports

- `backend/report_service.py` produces JSON, escaped HTML, and PDF reports when ReportLab is available.
- Reports distinguish observed evidence, analytical findings, correlation results, evidence inventory, custody, limitations, recommended actions, and attribution disclaimer.
- Reports include evidence hashes and state that hashes verify integrity, not truthfulness, and that human attribution cannot be established.

### Phase 5 API

- `POST /api/v2/evidence/register`
- `GET /api/v2/evidence/{evidence_id}`
- `GET /api/v2/evidence/{evidence_id}/verify`
- `GET/POST /api/v2/evidence/{evidence_id}/versions`
- `GET /api/v2/evidence/{evidence_id}/custody`
- `GET /api/v2/cases/{case_id}/evidence`
- `POST /api/v2/cases/{case_id}/evidence/{evidence_id}`
- `GET /api/v2/cases/{case_id}/custody`
- `POST /api/v2/cases/{case_id}/reports`
- `GET /api/v2/cases/{case_id}/reports`
- `GET /api/v2/reports/{report_id}`
- `GET /api/v2/reports/{report_id}/download`

### Phase 5 database tables

Added non-destructive SQLite tables for `evidence`, `evidence_versions`, `evidence_case_links`, `chain_of_custody`, and `reports`, with indexes for hashes, email/case IDs, custody timestamps, and report cases.

### Phase 5 security and privacy

- Path traversal and directory-component filenames are rejected.
- Evidence size is bounded by `NETRA_MAX_EVIDENCE_SIZE_MB`.
- Raw evidence is not returned in ordinary metadata, case, or report list responses.
- HTML report values are escaped and reports never execute content.
- Attachments remain static and remote URLs are never downloaded.
- Storage references are relative controlled references, not arbitrary filesystem paths.

### Phase 5 validation

- Maintained Phase 2–5 suites: **24 passed**.
- Backend compilation: passed.
- Application import and route registration: passed.
- Manual EML registration, SHA-256 verification, case linking, JSON/HTML/PDF generation, tamper detection, restoration, SQLite reopen, and custody persistence: passed.
- Full `pytest -q`: seven unchanged legacy collection failures remain: missing historical `MLClassifier`, `HeaderAnalyzer`, and `ComplianceEngine` symbols; an old NLP fixture expecting `urgency_cues`; and binary `test_results.txt` collection. No Phase 5 test failed.

### Phase 5 limitations

- Chain of custody records application-level handling and is not by itself a legal-admissibility guarantee.
- Evidence integrity depends on storage availability and permissions.
- PDF output is summary-focused and does not embed raw email or attachment content.
- No human attacker attribution is performed.

## Phase 6 dashboard, visual investigation, and extension integration completed

### Dashboard architecture

- The Streamlit dashboard in `dashboard/app.py` now uses `dashboard/api_client.py` and the v2 HTTP APIs instead of reading an obsolete SQLite file directly.
- Views include Overview, Email analysis, Campaigns, Cases, and Reports.
- Email investigations display score, confidence, evidence hash, structured findings, relay trace, origin candidates, relationships, and limitations.
- Cases support creation, status updates, notes, tags, evidence verification, timeline review, and report generation.
- Missing data is shown as unavailable/unknown; the UI does not create map markers or relationships from frontend guesses.

### Backend support

- Added `GET /api/v2/dashboard/summary` for persisted email, risk, case, campaign, integrity, and provider status metrics.
- Added `GET /api/v2/emails` with bounded pagination and optional risk filtering.
- Existing Phase 1–5 APIs remain unchanged.

### Visual and privacy behavior

- Relay hops are rendered as an ordered technical timeline with hostnames, IP classification, timestamps, candidate confidence, and limitations.
- No geographic map marker is drawn when provider coordinates are unavailable. The dashboard labels infrastructure location as non-attribution evidence.
- Reports and email results are displayed through backend-provided structured data; raw email bodies and attachments are not exposed by default.

### Chrome extension

- Manifest V3 and existing Gmail-only host permissions are preserved; no broad `<all_urls>` permission was added.
- The popup now has an explicit `Analyze current email` action and shows score/risk or clear unavailable errors.
- The content script calls `/api/v2/emails/analyze` only after that user action and links to the existing investigation surface.
- Gmail DOM changes no longer trigger automatic uploads.
- The extension collects only the currently opened Gmail message fields needed for the user-requested analysis.

### Phase 6 validation

- Maintained Phase 2–6 suites: **27 passed**.
- Backend and dashboard compilation: passed.
- Extension JavaScript syntax checks: passed.
- Streamlit import: passed (`1.62.0`).
- Dashboard summary, paginated email list, provider-unavailable state, and unknown-email errors: passed.
- Full `pytest -q`: seven unchanged legacy collection failures remain from obsolete symbols/fixtures and binary `test_results.txt`; no Phase 6 test failed.

### Phase 6 limitations

- The dashboard has no frontend framework build step because the repository uses Streamlit.
- The extension was syntax-validated but could not be loaded interactively in Chrome in this environment.
- The dashboard intentionally does not add a map dependency or external map requests; coordinates remain available through the API for a later isolated visualization.
- Campaign graph visualization is represented through stored relationship evidence and investigation panels; no speculative frontend edges are created.
