# NETRA-Mail Backend — Final Integrated Prototype

## 1. Install

```bash
python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
```

Linux/macOS:

```bash
source .venv/bin/activate
```

```bash
pip install -r requirements.txt
```

## 2. Train the local ML model

```bash
python train_model.py
```

The repository contains a small bootstrap dataset so the backend works immediately. For a serious evaluation, replace `data/training_data.csv` with a properly labelled phishing/legitimate dataset and report precision, recall and F1.

## 3. Start the API

```bash
uvicorn main:app --reload
```

Open:

http://127.0.0.1:8000/docs

## 4. API

### Analyze an EML

`POST /api/v1/analyze/eml`

Upload an `.eml` file.

The response contains:

- decision/risk/action
- ML probability
- NLP/social-engineering findings
- URL intelligence
- domain intelligence
- authentication analysis
- origin infrastructure/GeoIP when available
- attack classifications
- evidence reasons
- SHA-256 evidence seal
- tamper-evident ledger block hash

### Audit the ledger

`GET /api/v1/forensics/audit`

Expected result after successful analyses:

```json
{
  "status": "INTEGRAL",
  "valid": true
}
```

## Important security design

- URLs are analyzed statically and are never visited.
- Raw email bytes are hashed before privacy sanitization.
- Sanitized content is used for NLP/AI-facing analysis.
- GeoIP is enrichment, not proof of maliciousness.
- Authentication header parsing reports header results; it does not claim to cryptographically re-verify DKIM.
- The bundled ML dataset is only a functional bootstrap. It must not be presented as a production-quality benchmark.

## Recommended final pipeline

EML -> parser -> privacy-safe content -> headers + NLP + ML + URL + domain + infrastructure -> weighted score -> decision -> explanation -> evidence seal -> hash-chain ledger.
