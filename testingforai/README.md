# Testing For AI

This folder automates the 24 numbered scenarios in `test_cases_and_examples.md`.
The source document calls them 25 cases, but its five groups contain 24 cases.

## Run

From the project root, install the existing dependencies and start the API:

```powershell
python -m uvicorn backend.main:app --reload --port 8000
```

In a second terminal, run:

```powershell
python testingforai/run_tests.py
```

The runner will:

1. Generate one RFC 822 `.eml` file per scenario under `testingforai/cases/`.
2. Include HTML, reply-to, authentication headers, and the executable attachment scenario.
3. Upload every file to `POST /api/v1/analyze/eml`.
4. Save `results.csv`, `results.json`, and `report.md` under `testingforai/results/`.

To only generate the input files:

```powershell
python testingforai/run_tests.py --generate-only
```

To use another backend address:

```powershell
python testingforai/run_tests.py --api-url http://127.0.0.1:8000
```

Shortener expansion is intentionally opt-in because it makes outbound network
requests. Enable bounded `HEAD`-only expansion for an authorized test run with:

```powershell
$env:NETRA_EXPAND_SHORT_URLS = "1"
python testingforai/run_tests.py
```

Expansion uses a timeout, a redirect limit, and never downloads attachments or
executes JavaScript. Failed expansion remains visible in the URL result.

## Interpretation

The result is a scenario/regression report. It is not a production accuracy claim.
The shortener and domain-age cases retain notes because the backend does not visit
arbitrary URLs and the claimed registration date is not supplied by an EML file.