import requests

URL = "http://127.0.0.1:8000/api/v1/analyze/text"

adversarial_payloads = [
    {
        "name": "Zero-Width Space BEC",
        "sender": "ceo@malicious-corp.com",
        "subject": "Urgent",
        "body": "Please process an immediate w\u200bi\u200br\u200be t\u200br\u200ba\u200bn\u200bs\u200bf\u200be\u200br."
    },
    {
        "name": "Cyrillic Homoglyph Injection",
        "sender": "admin@раураl-update.com", # Cyrillic 'а' and 'р'
        "subject": "Ассоunt Suspended",
        "body": "Click here to verify credentials."
    },
    {
        "name": "Excessive Whitespace & Formatting",
        "sender": "finance@fake-invoices.com",
        "subject": "   INVOICE    ",
        "body": "W I R E   T R A N S F E R   N O W"
    }
]

for test in adversarial_payloads:
    res = requests.post(URL, json=test)
    data = res.json()
    score = data["report"]["threat_score"]["score"]
    cues = data["report"]["nlp_indicators"]
    print(f"[{test['name']}] -> Score: {score}/100 | NLP Cues Detected: {cues}")
