# NETRA Multilingual Indian-Language Upgrade

This upgrade adds dependency-free language/script intelligence for Tamil, Hindi, Malayalam, Telugu and Kannada, plus common Romanized/code-mixed cues. It complements the existing NLP/ML, URL, header and attachment signals.

## 1. Copy the module

Copy:

`backend/multilingual_detector.py`

to your NETRA repository's `backend/` directory.

## 2. Modify `backend/main.py`

In both import branches, add:

```python
from backend.multilingual_detector import MultilingualLanguageDetector
```

and in the fallback branch:

```python
from multilingual_detector import MultilingualLanguageDetector
```

Inside `_build_nlp_result(text)`, immediately after the existing `raw = NLPEngine.analyze_text(...)` and `raw = raw or {}` lines, add:

```python
multilingual = MultilingualLanguageDetector.analyze(text or "")
```

Before the function returns its NLP dictionary, add:

```python
multilingual_score = int(multilingual.get("multilingual_score", 0) or 0)
if multilingual_score:
    score = max(score, multilingual_score)
    for category, values in multilingual.get("multilingual_findings", {}).items():
        categories.setdefault(category, [])
        categories[category] = sorted(set(categories[category] + [str(v) for v in values]))

    urgency = categories.get("urgency", urgency)
    financial = categories.get("financial_fraud", financial)
    credentials = categories.get("credential_harvesting", credentials)
    social = categories.get("social_engineering", social)
```

Also add these fields to the returned NLP dictionary:

```python
"language": multilingual.get("language", "Unknown"),
"language_code": multilingual.get("language_code", "unknown"),
"language_confidence": multilingual.get("language_confidence", 0.0),
"script": multilingual.get("script", "unknown"),
"is_multilingual": multilingual.get("is_multilingual", False),
"detection_method": multilingual.get("detection_method", "unknown"),
"detected_scripts": multilingual.get("detected_scripts", []),
"multilingual_findings": multilingual.get("multilingual_findings", {}),
"multilingual_score": multilingual_score,
```

## 3. Test before touching the deterministic corpus

Run:

```powershell
python -m py_compile backend/multilingual_detector.py backend/main.py
```

Then test the detector directly:

```powershell
python -c "from backend.multilingual_detector import analyze; print(analyze('உங்கள் வங்கி கணக்கு முடக்கப்படும். உடனடியாக சரிபார்க்கவும். இங்கே கிளிக் செய்யவும்.'))"
python -c "from backend.multilingual_detector import analyze; print(analyze('आपका बैंक खाता निलंबित है। तुरंत सत्यापित करें। यहाँ क्लिक करें।'))"
python -c "from backend.multilingual_detector import analyze; print(analyze('നിങ്ങളുടെ ബാങ്ക് അക്കൗണ്ട് സസ്പെൻഡ് ചെയ്യും. ഉടൻ സ്ഥിരീകരിക്കുക. ഇവിടെ ക്ലിക്ക് ചെയ്യുക.'))"
python -c "from backend.multilingual_detector import analyze; print(analyze('మీ బ్యాంక్ ఖాతా నిలిపివేయబడుతుంది. వెంటనే ధృవీకరించండి. ఇక్కడ క్లిక్ చేయండి.'))"
python -c "from backend.multilingual_detector import analyze; print(analyze('ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಖಾತೆ ಸ್ಥಗಿತಗೊಳ್ಳುತ್ತದೆ. ತಕ್ಷಣ ಪರಿಶೀಲಿಸಿ. ಇಲ್ಲಿ ಕ್ಲಿಕ್ ಮಾಡಿ.'))"
python -c "from backend.multilingual_detector import analyze; print(analyze('Ungal vangi kanakku mudakkappadum, udane verify pannunga, inga click pannunga.'))"
```

Expected language labels should be Tamil, Hindi, Malayalam, Telugu, Kannada and Tamil (Romanized), respectively, with non-zero multilingual scores for the phishing-like examples.

## 4. Regression safety

Do **not** change the existing deterministic corpus or its expected results. Run the existing evaluation and regression suite after integration. The multilingual layer is additive and should not be used to claim 100% real-world accuracy.
