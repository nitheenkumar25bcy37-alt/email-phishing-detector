# NETRA-Mail Evaluation Package

## Run

1. Keep the NETRA-Mail project root as the folder containing `backend/`.
2. Put these files in that project root:
   - `evaluate_netra.py`
   - `requirements-evaluation.txt`
   - `RUN_EVALUATION.bat`
3. Install dependencies once:
   `pip install -r requirements-evaluation.txt`
4. Start the existing backend:
   `python -m uvicorn backend.main:app --reload --port 8000`
5. In a second terminal run:
   `python evaluate_netra.py`

Or double-click `RUN_EVALUATION.bat`.

## Output

`evaluation_results/` contains:
- `email_api_results.csv`
- `ml_holdout_results.csv`
- `url_results.csv`
- `metrics.json`
- `metrics_report.txt`

## Important interpretation

The current backend's `/api/v1/analyze/email` endpoint accepts subject, sender,
recipient, reply_to, body, html, headers and received_headers and returns decision,
ML, NLP, URL, domain, authentication and infrastructure results.

The included 5-email test is a functional smoke test only. It must not be presented
as the project's dataset accuracy.

If `data/training_data.csv` exists, the script independently trains a TF-IDF +
Logistic Regression model using an 80/20 stratified hold-out and reports metrics for
that ML component.

If PhishTank and Tranco CSVs are present under `data/`, the script evaluates the
existing URLAnalyzer and sweeps risk thresholds.

A statistically defensible FINAL NETRA-Mail email accuracy requires a labelled,
previously-unseen email dataset. The script intentionally refuses to invent that
number.
