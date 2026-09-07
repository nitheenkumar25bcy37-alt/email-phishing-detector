#!/usr/bin/env python3
"""
NETRA-Mail - One-Command Evaluation Runner

Run from the NETRA-Mail project root:
    python evaluate_netra.py

What this script does:
1. Checks the running NETRA-Mail FastAPI backend.
2. Runs the built-in 5-email functional benchmark.
3. If data/training_data.csv exists, evaluates the LOCAL ML classifier
   with a proper stratified hold-out split (80/20) WITHOUT changing the
   running backend model.
4. If PhishTank/Tranco files are found under data/, evaluates URLAnalyzer
   on a balanced sample.
5. Writes machine-readable and presentation-ready reports to:
       evaluation_results/
       - email_api_results.csv
       - ml_holdout_results.csv
       - url_results.csv
       - metrics.json
       - metrics_report.txt

IMPORTANT:
- The 5-email API test is a functional smoke test, NOT a statistical accuracy claim.
- The ML holdout metric is for the LocalMLClassifier component.
- The URL benchmark is for URLAnalyzer.
- A statistically valid FINAL NETRA-Mail email accuracy requires a labelled,
  previously-unseen email dataset. This script will never invent such a metric.
"""

import csv
import json
import math
import os
import random
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    import requests
except ImportError:
    print("ERROR: requests is missing. Run: pip install requests")
    sys.exit(1)

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "evaluation_results"
OUT.mkdir(exist_ok=True)

API_BASE_URL = os.getenv("NETRA_API_URL", "http://localhost:8000").rstrip("/")
RANDOM_SEED = 42
URL_SAMPLE_PER_CLASS = int(os.getenv("NETRA_URL_SAMPLE", "5000"))

# ---------------------------------------------------------------------
# Existing backend-compatible 5-email functional benchmark
# ---------------------------------------------------------------------

EMAILS = [
    {
        "id": "E001",
        "name": "Bank Phishing",
        "label": "PHISHING",
        "payload": {
            "subject": "URGENT: Your Bank Account Has Been Compromised - Immediate Action Required",
            "sender": "security@bankofamerica-verify.com",
            "recipient": "test-user@example.com",
            "body": """We have detected SUSPICIOUS ACTIVITY on your Bank of America account.
Our security team has identified multiple unauthorized login attempts from an unfamiliar location.
Your account has been LOCKED for security purposes.
ACTION REQUIRED: You must verify your identity within the next 24 hours to unlock your account
and prevent it from being permanently disabled.
Sensitive Information Detected: We have reason to believe your Social Security Number,
credit card details, and password may have been compromised. Immediate verification is essential.
Please verify your full name, email, Social Security Number, card number and password.""",
            "html": "<html><body><h2>CRITICAL SECURITY ALERT</h2><p>Verify your account immediately at bankofamerica-security-alerts.com</p></body></html>",
        },
    },
    {
        "id": "E002",
        "name": "PayPal Phishing",
        "label": "PHISHING",
        "payload": {
            "subject": "Confirm Your PayPal Account - Action Required",
            "sender": "noreply@paypal-security-alert.com",
            "recipient": "test-user@example.com",
            "body": """We recently detected unusual login activity on your PayPal account.
New Device Detected: iPhone 14 Pro, Location: Lagos, Nigeria, IP Address: 196.223.15.78
For your security, we need to verify your identity before you can access your account again.
What you'll need: PayPal email address, PayPal password, date of birth, SSN last 4 digits,
credit card number and CVV.
If you don't verify your account within 48 hours, we'll be forced to suspend your account permanently.""",
            "html": "<html><body><a href='https://paypal-verify-account.com/confirm?user=cust_829'>CONFIRM MY ACCOUNT</a></body></html>",
        },
    },
    {
        "id": "E003",
        "name": "CEO Fraud",
        "label": "PHISHING",
        "payload": {
            "subject": "Wire Transfer - Urgent & Confidential",
            "sender": "john.mitchell@companynamehere.com",
            "recipient": "sarah@example.com",
            "reply_to": "j.mitchell@ceo-private-email.com",
            "body": """Hi Sarah,
I'm currently in a meeting and need your immediate assistance with a confidential matter.
We have an urgent acquisition deal that needs to be finalized TODAY. I need you to wire $185,000
to our new partner's account without notifying anyone else in the company - this is highly confidential.
Bank Name: First International Banking Corp
Account Holder: David Chen
Account Number: 4782159630
IMPORTANT: Do NOT discuss this with anyone else. I will be handling all approvals directly.
Please also purchase $2,000 in Google Play cards for employee bonuses.
Time is of the essence. Please confirm you've completed this within the hour.
Thanks,
John Mitchell
CEO""",
            "html": "<html><body><h2>Wire Transfer Request</h2><p>$185,000 urgent transfer needed TODAY</p></html>",
        },
    },
    {
        "id": "E004",
        "name": "Microsoft Phishing",
        "label": "PHISHING",
        "payload": {
            "subject": "Microsoft Account Security Alert - Verify Your Identity",
            "sender": "security-alerts@microsoft-account-verify.com",
            "recipient": "test-user@example.com",
            "body": """Dear User,
We've detected multiple suspicious activities on your Microsoft account. Your account may have been compromised.
You have 24 hours to verify your account or it may be permanently disabled.
Please sign in and verify your identity immediately.""",
            "html": "<html><body><h2>Account Security Alert</h2><p><a href='https://microsoft-account-verify-secure.com/security/verify'>VERIFY YOUR ACCOUNT</a></p></body></html>",
        },
    },
    {
        "id": "E005",
        "name": "GitHub Legitimate",
        "label": "LEGITIMATE",
        "payload": {
            "subject": "Welcome to GitHub - Verify Your Email Address",
            "sender": "support@github.com",
            "recipient": "test-user@example.com",
            "body": """Thanks for signing up for GitHub. We're excited to have you on board!
To get started, please verify your email address.
Here's what you can do next:
- Set up your profile with a profile picture and bio
- Explore repositories and find projects to contribute to
- Follow developers and organizations
Questions? Check out our documentation.
Sincerely,
GitHub Account Team""",
            "html": "<html><body><h2>Welcome to GitHub!</h2><p><a href='https://github.com/email_verification'>Verify Email</a></p></body></html>",
        },
    },
]

def pct(x):
    return f"{100.0*x:.2f}%"

def safe_float(x, default=0.0):
    try:
        return float(x)
    except Exception:
        return default

def safe_int(x, default=0):
    try:
        return int(x)
    except Exception:
        return default

def classification_from_risk(risk: str) -> str:
    r = str(risk or "").upper()
    return "PHISHING" if r in {"MEDIUM", "HIGH", "CRITICAL", "SUSPICIOUS", "MALICIOUS", "PHISHING"} else "LEGITIMATE"

def binary_metrics(y_true: List[str], y_pred: List[str]) -> Dict[str, Any]:
    tp = tn = fp = fn = 0
    for a, p in zip(y_true, y_pred):
        a = "PHISHING" if str(a).upper() in {"PHISHING", "1", "TRUE"} else "LEGITIMATE"
        p = "PHISHING" if str(p).upper() in {"PHISHING", "1", "TRUE"} else "LEGITIMATE"
        if a == "PHISHING" and p == "PHISHING": tp += 1
        elif a == "LEGITIMATE" and p == "LEGITIMATE": tn += 1
        elif a == "LEGITIMATE" and p == "PHISHING": fp += 1
        else: fn += 1
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "samples": total,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "specificity": specificity,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
    }

def check_health():
    try:
        r = requests.get(f"{API_BASE_URL}/health", timeout=10)
        if r.status_code != 200:
            print(f"ERROR: /health returned HTTP {r.status_code}")
            return None
        return r.json()
    except Exception as e:
        print(f"ERROR: Cannot reach {API_BASE_URL}")
        print(f"       {e}")
        print("Start the backend first:")
        print("       python -m uvicorn backend.main:app --reload --port 8000")
        return None

def run_api_functional():
    print("\n" + "="*78)
    print("1. NETRA-MAIL EMAIL API FUNCTIONAL BENCHMARK")
    print("="*78)
    rows = []
    for item in EMAILS:
        t0 = time.perf_counter()
        try:
            r = requests.post(
                f"{API_BASE_URL}/api/v1/analyze/email",
                json=item["payload"],
                timeout=60,
            )
            elapsed = time.perf_counter() - t0
            if r.status_code != 200:
                rows.append({
                    "id": item["id"], "name": item["name"], "actual": item["label"],
                    "predicted": "ERROR", "risk": "", "score": "",
                    "confidence": "", "latency_seconds": round(elapsed, 4),
                    "http_status": r.status_code, "error": r.text[:500],
                })
                print(f"{item['id']} {item['name']:<22} ERROR HTTP {r.status_code}")
                continue

            data = r.json()
            decision = data.get("decision") or {}
            netra = data.get("netra_result") or {}
            risk = decision.get("risk", netra.get("risk", "UNKNOWN"))
            score = decision.get("score", netra.get("score", 0))
            confidence = decision.get("confidence", netra.get("confidence", 0))
            predicted = classification_from_risk(risk)

            rows.append({
                "id": item["id"], "name": item["name"], "actual": item["label"],
                "predicted": predicted, "risk": str(risk),
                "score": safe_int(score), "confidence": safe_float(confidence),
                "latency_seconds": round(elapsed, 4), "http_status": r.status_code,
                "case_id": data.get("case_id", ""),
            })
            ok = predicted == item["label"]
            print(
                f"{item['id']} {item['name']:<22} "
                f"{'PASS' if ok else 'FAIL'} | "
                f"actual={item['label']:<10} predicted={predicted:<10} "
                f"score={safe_int(score):>3} risk={str(risk):<8} "
                f"time={elapsed:.2f}s"
            )
        except Exception as e:
            elapsed = time.perf_counter() - t0
            rows.append({
                "id": item["id"], "name": item["name"], "actual": item["label"],
                "predicted": "ERROR", "risk": "", "score": "",
                "confidence": "", "latency_seconds": round(elapsed, 4),
                "http_status": "", "error": str(e),
            })
            print(f"{item['id']} {item['name']:<22} ERROR {e}")

    write_csv(OUT / "email_api_results.csv", rows)
    valid = [x for x in rows if x.get("predicted") in {"PHISHING", "LEGITIMATE"}]
    if valid:
        m = binary_metrics([x["actual"] for x in valid], [x["predicted"] for x in valid])
        times = [safe_float(x["latency_seconds"]) for x in valid]
        m["average_latency_seconds"] = statistics.mean(times)
        m["median_latency_seconds"] = statistics.median(times)
        m["p95_latency_seconds"] = percentile(times, 95)
        m["functional_pass_rate"] = sum(x["actual"] == x["predicted"] for x in valid) / len(valid)
        m["warning"] = "Only 5 hand-crafted emails; do NOT present this as dataset accuracy."
    else:
        m = {"samples": 0}
    return m

def percentile(values, p):
    if not values:
        return 0.0
    values = sorted(values)
    if len(values) == 1:
        return values[0]
    k = (len(values)-1) * p/100
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return values[int(k)]
    return values[f] * (c-k) + values[c] * (k-f)

def load_text_label_csv(path: Path):
    rows = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fields = [str(x).strip().lower() for x in (reader.fieldnames or [])]
        text_field = next((reader.fieldnames[i] for i,x in enumerate(fields) if x in {"text","email","body","content","message"}), None)
        label_field = next((reader.fieldnames[i] for i,x in enumerate(fields) if x in {"label","class","category","target","is_phishing"}), None)
        if not text_field or not label_field:
            return []
        for row in reader:
            text = (row.get(text_field) or "").strip()
            label = (row.get(label_field) or "").strip().upper()
            if not text:
                continue
            if label in {"PHISHING","LEGITIMATE","1","0","TRUE","FALSE","PHISH","BENIGN","SAFE"}:
                label = "PHISHING" if label in {"PHISHING","1","TRUE","PHISH"} else "LEGITIMATE"
                rows.append((text, label))
    return rows

def run_ml_holdout():
    print("\n" + "="*78)
    print("2. LOCAL ML CLASSIFIER — PROPER 80/20 HOLD-OUT")
    print("="*78)
    path = ROOT / "data" / "training_data.csv"
    if not path.exists():
        print("SKIPPED: data/training_data.csv was not found.")
        return {"status": "SKIPPED", "reason": "training_data.csv not found"}

    rows = load_text_label_csv(path)
    if len(rows) < 20 or len(set(y for _,y in rows)) < 2:
        print("SKIPPED: dataset is too small or does not contain both classes.")
        return {"status": "SKIPPED", "reason": "insufficient labelled data", "rows": len(rows)}

    try:
        from sklearn.model_selection import train_test_split
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline
    except ImportError:
        print("SKIPPED: scikit-learn not installed.")
        return {"status": "SKIPPED", "reason": "scikit-learn missing"}

    texts = [x[0] for x in rows]
    labels = [x[1] for x in rows]
    x_train, x_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.20, random_state=RANDOM_SEED, stratify=labels
    )

    model = Pipeline([
        ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1,2), sublinear_tf=True)),
        ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced")),
    ])
    t0 = time.perf_counter()
    model.fit(x_train, y_train)
    train_seconds = time.perf_counter() - t0
    preds = model.predict(x_test)
    m = binary_metrics(y_test, list(preds))
    m.update({
        "status": "OK",
        "dataset": str(path.relative_to(ROOT)),
        "total_rows": len(rows),
        "train_rows": len(x_train),
        "test_rows": len(x_test),
        "train_time_seconds": train_seconds,
        "note": "This evaluates the TF-IDF + Logistic Regression component with an unseen 20% hold-out. It is NOT the final multi-signal NETRA-Mail ensemble metric.",
    })
    out = []
    for text, actual, pred in zip(x_test, y_test, preds):
        out.append({
            "actual": actual, "predicted": str(pred),
            "correct": actual == str(pred),
            "text_preview": text[:160].replace("\n"," "),
        })
    write_csv(OUT / "ml_holdout_results.csv", out)
    print(f"Dataset: {len(rows)} rows")
    print(f"Train:   {len(x_train)}")
    print(f"Test:    {len(x_test)}")
    print(f"Accuracy:    {pct(m['accuracy'])}")
    print(f"Precision:   {pct(m['precision'])}")
    print(f"Recall:      {pct(m['recall'])}")
    print(f"F1:          {pct(m['f1'])}")
    print(f"FPR:         {pct(m['false_positive_rate'])}")
    print(f"FNR:         {pct(m['false_negative_rate'])}")
    print(f"TP/TN/FP/FN: {m['tp']}/{m['tn']}/{m['fp']}/{m['fn']}")
    return m

def find_dataset(candidates):
    for p in candidates:
        if p.exists():
            return p
    return None

def load_url_file(path: Path, limit=None):
    urls = []
    with path.open("r", encoding="utf-8-sig", errors="ignore") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            # Find first URL/domain-like field.
            value = None
            for cell in row:
                s = str(cell).strip()
                if "." in s and len(s) < 2048 and not s.lower().startswith(("http://","https://")):
                    value = s
                    break
                if s.lower().startswith(("http://","https://")):
                    value = s
                    break
            if value and value.lower() not in {"url","domain","domain_name"}:
                urls.append(value)
                if limit and len(urls) >= limit:
                    break
    return urls

def run_url_benchmark():
    print("\n" + "="*78)
    print("3. URL ANALYZER — PHISHTANK vs TRANCO")
    print("="*78)
    phish = find_dataset([
        ROOT/"data"/"phishtank.csv",
        ROOT/"data"/"PhishTank.csv",
        ROOT/"data"/"phishing_urls.csv",
    ])
    tranco = find_dataset([
        ROOT/"data"/"tranco.csv",
        ROOT/"data"/"Tranco.csv",
        ROOT/"data"/"tranco_domains.csv",
    ])
    if not phish or not tranco:
        print("SKIPPED: expected PhishTank and Tranco files were not found under data/.")
        return {"status": "SKIPPED", "reason": "URL datasets not found"}

    try:
        from backend.url_analyzer import URLAnalyzer
    except Exception:
        try:
            from url_analyzer import URLAnalyzer
        except Exception as e:
            print(f"SKIPPED: URLAnalyzer import failed: {e}")
            return {"status": "SKIPPED", "reason": "URLAnalyzer import failed"}

    random.seed(RANDOM_SEED)
    phishing_urls = load_url_file(phish, URL_SAMPLE_PER_CLASS)
    legitimate_domains = load_url_file(tranco, URL_SAMPLE_PER_CLASS)
    phishing_urls = list(dict.fromkeys(phishing_urls))
    legitimate_domains = list(dict.fromkeys(legitimate_domains))
    n = min(len(phishing_urls), len(legitimate_domains), URL_SAMPLE_PER_CLASS)
    phishing_urls = phishing_urls[:n]
    legitimate_domains = legitimate_domains[:n]

    # Threshold sweep. URLAnalyzer returns risk_score; evaluate several thresholds
    # rather than pretending one threshold is objectively correct.
    all_items = [(u, "PHISHING") for u in phishing_urls] + [(u, "LEGITIMATE") for u in legitimate_domains]
    results = []
    for url, actual in all_items:
        try:
            if not url.lower().startswith(("http://","https://")):
                target = "https://" + url
            else:
                target = url
            r = URLAnalyzer.analyze_url(target)
            results.append({
                "url": url,
                "actual": actual,
                "risk_score": safe_float(r.get("risk_score",0)),
                "risk_level": r.get("risk_level",""),
                "brand_impersonation": "|".join(r.get("brand_impersonation",[]) or []),
                "typosquatting": "|".join(r.get("typosquatting",[]) or []),
            })
        except Exception as e:
            results.append({"url": url, "actual": actual, "risk_score": 0, "error": str(e)})

    write_csv(OUT / "url_results.csv", results)

    best = None
    for threshold in range(10, 91, 5):
        preds = ["PHISHING" if x["risk_score"] >= threshold else "LEGITIMATE" for x in results]
        m = binary_metrics([x["actual"] for x in results], preds)
        candidate = (m["f1"], threshold, m)
        if best is None or candidate[0] > best[0]:
            best = candidate

    _, best_threshold, best_m = best
    best_m.update({
        "status": "OK",
        "phishing_samples": len(phishing_urls),
        "legitimate_samples": len(legitimate_domains),
        "total_samples": len(results),
        "best_threshold_by_f1": best_threshold,
        "note": "Threshold selected by F1 on this benchmark. For publication, use a separate validation set to select a threshold and a final unseen test set to report performance.",
    })
    print(f"PhishTank sample: {len(phishing_urls)}")
    print(f"Tranco sample:    {len(legitimate_domains)}")
    print(f"Best F1 threshold on this benchmark: risk >= {best_threshold}")
    print(f"Accuracy:    {pct(best_m['accuracy'])}")
    print(f"Precision:   {pct(best_m['precision'])}")
    print(f"Recall:      {pct(best_m['recall'])}")
    print(f"F1:          {pct(best_m['f1'])}")
    print(f"FPR:         {pct(best_m['false_positive_rate'])}")
    print(f"FNR:         {pct(best_m['false_negative_rate'])}")
    print(f"TP/TN/FP/FN: {best_m['tp']}/{best_m['tn']}/{best_m['fp']}/{best_m['fn']}")
    return best_m

def write_csv(path, rows):
    if not rows:
        return
    fields = []
    for row in rows:
        for k in row:
            if k not in fields:
                fields.append(k)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

def write_report(all_metrics):
    (OUT / "metrics.json").write_text(json.dumps(all_metrics, indent=2), encoding="utf-8")

    lines = []
    lines.append("="*78)
    lines.append("NETRA-MAIL EVALUATION REPORT")
    lines.append("="*78)
    lines.append("")
    health = all_metrics.get("health", {})
    lines.append("BACKEND")
    lines.append(f"  status:  {health.get('status','UNKNOWN')}")
    lines.append(f"  version: {health.get('version','UNKNOWN')}")
    lines.append(f"  mode:    {health.get('mode','UNKNOWN')}")
    lines.append(f"  model:   {health.get('model_available','UNKNOWN')}")
    lines.append("")

    api = all_metrics.get("email_api", {})
    lines.append("EMAIL API FUNCTIONAL TEST (5 hand-crafted cases)")
    if api.get("samples"):
        lines.append(f"  pass rate: {pct(api.get('functional_pass_rate',0))}")
        lines.append(f"  latency avg/median/p95: {api.get('average_latency_seconds',0):.3f}s / {api.get('median_latency_seconds',0):.3f}s / {api.get('p95_latency_seconds',0):.3f}s")
        lines.append("  NOTE: This is a functional smoke test, not statistical dataset accuracy.")
    else:
        lines.append("  no valid API results")
    lines.append("")

    ml = all_metrics.get("ml_holdout", {})
    lines.append("LOCAL ML COMPONENT — 80/20 HOLD-OUT")
    if ml.get("status") == "OK":
        for key,label in [
            ("accuracy","Accuracy"),("precision","Precision"),("recall","Recall"),
            ("f1","F1"),("specificity","Specificity"),
            ("false_positive_rate","False Positive Rate"),
            ("false_negative_rate","False Negative Rate")
        ]:
            lines.append(f"  {label:<20}: {pct(ml.get(key,0))}")
        lines.append(f"  TP/TN/FP/FN          : {ml.get('tp')}/{ml.get('tn')}/{ml.get('fp')}/{ml.get('fn')}")
    else:
        lines.append(f"  {ml.get('status','SKIPPED')}: {ml.get('reason','')}")
    lines.append("")

    url = all_metrics.get("url_benchmark", {})
    lines.append("URL ANALYZER — PHISHTANK vs TRANCO")
    if url.get("status") == "OK":
        for key,label in [
            ("accuracy","Accuracy"),("precision","Precision"),("recall","Recall"),
            ("f1","F1"),("specificity","Specificity"),
            ("false_positive_rate","False Positive Rate"),
            ("false_negative_rate","False Negative Rate")
        ]:
            lines.append(f"  {label:<20}: {pct(url.get(key,0))}")
        lines.append(f"  TP/TN/FP/FN          : {url.get('tp')}/{url.get('tn')}/{url.get('fp')}/{url.get('fn')}")
        lines.append(f"  Best benchmark threshold: risk >= {url.get('best_threshold_by_f1')}")
    else:
        lines.append(f"  {url.get('status','SKIPPED')}: {url.get('reason','')}")
    lines.append("")
    lines.append("INTERPRETATION")
    lines.append("  Do not claim a final NETRA-Mail email accuracy unless the final API is")
    lines.append("  evaluated on a labelled, previously-unseen email test set.")
    lines.append("  The current 5-email suite is useful for prototype functionality only.")
    lines.append("")
    (OUT / "metrics_report.txt").write_text("\n".join(lines), encoding="utf-8")
    print("\n" + "\n".join(lines))

def main():
    print("\nNETRA-MAIL — AUTOMATED EVALUATION")
    print("Project-root execution | seed=42")
    health = check_health()
    if health is None:
        sys.exit(2)

    all_metrics = {"health": health}
    all_metrics["email_api"] = run_api_functional()
    all_metrics["ml_holdout"] = run_ml_holdout()
    all_metrics["url_benchmark"] = run_url_benchmark()
    write_report(all_metrics)

    print("\nFiles written to:")
    print(f"  {OUT}")
    print("  - email_api_results.csv")
    print("  - ml_holdout_results.csv (if training_data.csv exists)")
    print("  - url_results.csv (if PhishTank + Tranco exist)")
    print("  - metrics.json")
    print("  - metrics_report.txt")

if __name__ == "__main__":
    main()
