#!/usr/bin/env python3
"""
NETRA-Mail Test Suite - API Testing Script
Test your phishing detection system with all 5 test emails
"""

import json
import requests
import time
from pathlib import Path

# Configuration
API_BASE_URL = "http://localhost:8000"
TEST_EMAIL_1 = {
    "subject": "URGENT: Your Bank Account Has Been Compromised - Immediate Action Required",
    "sender": "security@bankofamerica-verify.com",
    "body": """We have detected SUSPICIOUS ACTIVITY on your Bank of America account. 
    Our security team has identified multiple unauthorized login attempts from an unfamiliar location. 
    Your account has been LOCKED for security purposes. 
    ACTION REQUIRED: You must verify your identity within the next 24 hours to unlock your account 
    and prevent it from being permanently disabled.
    Sensitive Information Detected: We have reason to believe your Social Security Number, 
    credit card details, and password may have been compromised. Immediate verification is essential.
    Please verify: Your full name, email, Social Security Number, 16-digit card number, and password.""",
    "html": "<html><body><h2>CRITICAL SECURITY ALERT</h2><p>Verify your account immediately at bankofamerica-security-alerts.com</p></body></html>"
}

TEST_EMAIL_2 = {
    "subject": "Confirm Your PayPal Account - Action Required",
    "sender": "noreply@paypal-security-alert.com",
    "body": """We recently detected unusual login activity on your PayPal account. 
    New Device Detected: iPhone 14 Pro, Location: Lagos, Nigeria, IP Address: 196.223.15.78
    For your security, we need to verify your identity before you can access your account again.
    What you'll need: PayPal email address, PayPal password, date of birth, SSN last 4 digits, 
    credit card number and CVV.
    If you don't verify your account within 48 hours, we'll be forced to suspend your account permanently.""",
    "html": "<html><body><a href='https://paypal-verify-account.com/confirm?user=cust_829'>CONFIRM MY ACCOUNT</a></body></html>"
}

TEST_EMAIL_3 = {
    "subject": "Wire Transfer - Urgent & Confidential",
    "sender": "john.mitchell@companynamehere.com",
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
    "html": "<html><body><h2>Wire Transfer Request</h2><p>$185,000 urgent transfer needed TODAY</p></body></html>"
}

TEST_EMAIL_4 = {
    "subject": "Microsoft Account Security Alert - Verify Your Identity",
    "sender": "security-alerts@microsoft-account-verify.com",
    "body": """Dear User,

We've detected multiple suspicious activities on your Microsoft account. Your account may have been compromised.

SUSPICIOUS ACTIVITY DETECTED:
• Login from IP: 103.145.23.78 (China)
• Device: Unknown Android Phone
• Location: Shanghai, China
• Time: Aug 29, 2026 11:15 AM UTC

For your security, we've temporarily locked your account. To regain access and protect your information, 
you must verify your identity immediately.

What you need to verify:
- Microsoft email address
- Password
- Phone number
- Date of birth
- Last 4 digits of credit/debit card
- Security PIN

You have 24 hours to verify your account. After this period, your account will be permanently disabled.""",
    "html": "<html><body><h2>Account Security Alert</h2><p><a href='https://microsoft-account-verify-secure.com/security/verify'>VERIFY YOUR ACCOUNT</a></p></body></html>"
}

TEST_EMAIL_5 = {
    "subject": "Welcome to GitHub - Verify Your Email Address",
    "sender": "support@github.com",
    "body": """Thanks for signing up for GitHub. We're excited to have you on board!

To get started, please verify your email address.

Here's what you can do next:
- Set up your profile with a profile picture and bio
- Explore repositories and find projects to contribute to
- Create your first repository
- Follow developers and organizations

Questions? Check out our documentation.

Sincerely,
GitHub Account Team""",
    "html": "<html><body><h2>Welcome to GitHub!</h2><p><a href='https://github.com/email_verification'>Verify Email</a></p></body></html>"
}

EMAILS = [
    ("Email 1 - Bank Phishing", TEST_EMAIL_1, "PHISHING", 85, 100),
    ("Email 2 - PayPal Phishing", TEST_EMAIL_2, "PHISHING", 75, 90),
    ("Email 3 - CEO Fraud", TEST_EMAIL_3, "PHISHING", 80, 100),
    ("Email 4 - Microsoft Phishing", TEST_EMAIL_4, "PHISHING", 70, 85),
    ("Email 5 - GitHub Legitimate", TEST_EMAIL_5, "SAFE", 0, 15),
]

def print_header(text):
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70 + "\n")

def test_email(name, payload, expected_class, min_score, max_score):
    """Test a single email and report results"""
    
    print(f"\n Testing: {name}")
    print(f"   Expected: {expected_class} ({min_score}-{max_score}/100)")
    print(f"   Endpoint: POST /api/v1/analyze/email")
    
    try:
        # Send request
        start_time = time.time()
        response = requests.post(
            f"{API_BASE_URL}/api/v1/analyze/email",
            json=payload,
            timeout=30
        )
        elapsed = time.time() - start_time
        
        if response.status_code != 200:
            print(f"   ❌ ERROR: HTTP {response.status_code}")
            print(f"   Response: {response.text[:200]}")
            return False
        
        data = response.json()
        
        # Extract results
        decision = data.get("decision", {})
        netra_result = data.get("netra_result", {})
        
        threat_score = decision.get("score", netra_result.get("score", 0))
        risk = decision.get("risk", netra_result.get("risk", "UNKNOWN"))
        action = decision.get("action", netra_result.get("action", "REVIEW"))
        confidence = decision.get("confidence", netra_result.get("confidence", 0))
        case_id = data.get("case_id", netra_result.get("case_id", "N/A"))
        
        # Check if results match expectations
        score_ok = min_score <= threat_score <= max_score
        class_ok = (
            (expected_class == "PHISHING" and risk in ["HIGH", "CRITICAL"]) or
            (expected_class == "SAFE" and risk == "SAFE")
        )
        
        # Print results
        print(f"   ✓ Status: {response.status_code} OK")
        print(f"   ✓ Time: {elapsed:.2f}s")
        print(f"    Results:")
        print(f"      Case ID: {case_id}")
        print(f"      Risk Score: {threat_score}/100 (expected: {min_score}-{max_score})")
        print(f"      Risk Level: {risk}")
        print(f"      Recommended Action: {action}")
        print(f"      Confidence: {confidence}%")
        
        # Validation
        if score_ok and class_ok:
            print(f"    PASS - Results match expectations")
            return True
        else:
            print(f"     WARNING - Results may not match expectations")
            if not score_ok:
                print(f"      Score {threat_score} outside expected range {min_score}-{max_score}")
            if not class_ok:
                print(f"      Classification '{risk}' doesn't match expected '{expected_class}'")
            return score_ok and class_ok
        
    except requests.exceptions.ConnectionError:
        print(f"    ERROR: Cannot connect to {API_BASE_URL}")
        print(f"      Make sure FastAPI is running on port 8000")
        return False
    except requests.exceptions.Timeout:
        print(f"    ERROR: Request timed out")
        return False
    except Exception as e:
        print(f"    ERROR: {str(e)}")
        return False

def test_health():
    """Test if backend is healthy"""
    print_header("CHECKING BACKEND HEALTH")
    
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f" Backend Status: HEALTHY")
            print(f"   Version: {data.get('version', 'Unknown')}")
            print(f"   Mode: {data.get('mode', 'Unknown')}")
            print(f"   Model Available: {data.get('model_available', False)}")
            return True
        else:
            print(f" Backend returned {response.status_code}")
            return False
    except Exception as e:
        print(f" Cannot reach backend: {str(e)}")
        print(f"\n   Make sure to:")
        print(f"   1. Start FastAPI: python -m uvicorn backend.main:app --reload --port 8000")
        print(f"   2. Verify port 8000 is accessible")
        return False

def run_all_tests():
    """Run all email tests"""
    print_header("NETRA-MAIL TEST SUITE - AUTOMATED TESTING")
    
    # Check health
    if not test_health():
        print("\n❌ Cannot proceed - backend is not running")
        return False
    
    # Run tests
    print_header("RUNNING EMAIL ANALYSIS TESTS")
    
    results = []
    for email_info in EMAILS:
        name, payload, expected_class, min_score, max_score = email_info
        result = test_email(name, payload, expected_class, min_score, max_score)
        results.append((name, result))
        time.sleep(1)  # Rate limiting
    
    # Summary
    print_header("TEST SUMMARY")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = " PASS" if result else "❌ FAIL"
        print(f"{status}: {name}")
    
    print(f"\n Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n ALL TESTS PASSED! Your phishing detection system is working correctly.")
        return True
    else:
        print(f"\n  {total - passed} test(s) failed. Review the output above for details.")
        return False

if __name__ == "__main__":
    print("\n" + " "*10)
    print("NETRA-MAIL PHISHING DETECTION - TEST SUITE")
    print(" "*10)
    
    success = run_all_tests()
    
    print("\n" + "="*70)
    if success:
        print(" All tests passed! Your system is ready for deployment.")
    else:
        print(" Some tests failed. Please review the errors above.")
    print("="*70 + "\n")
