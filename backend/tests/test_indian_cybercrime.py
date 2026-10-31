"""
Indian cybersecurity scenario tests.
All DB-writing functions receive the isolated in-memory `db` fixture from
conftest.py — zero writes reach the production scamsentry.db file.

Classification tiers and their invariants:
  CONFIRMED_MALICIOUS  – REQUIRES a URL structurally verified as deceptive (URL Deception
                         indicator) AND a critical credential/impersonation indicator.
                         Cannot be reached from heuristic pattern counts alone.
  LIKELY_SCAM          – Strong pattern convergence across ≥2 categories; no URL needed.
  SUSPICIOUS           – Indicators present but insufficient for confident assertion.
  LOW_RISK / BENIGN    – Few or no indicators.

Key invariant:
  A message with zero embedded URLs must NEVER be classified CONFIRMED_MALICIOUS,
  regardless of how many heuristic patterns fire or how high the score is.
"""
import pytest
from app.core.message_scanner import MessageScanner
from app.core.risk_engine import RiskEngine
from app.schemas.scan import MessageScanRequest
from app.api.v1.scan import scan_message
from app.api.v1.history import get_scan_history
from app.api.v1.stats import get_dashboard_stats

# Convenience sets used in assertions
SCAM_CLASSES = {"CONFIRMED_MALICIOUS", "LIKELY_SCAM", "SUSPICIOUS"}
URL_REQUIRED_FOR_CONFIRMED = True   # documents the policy, referenced in comments


# ===========================================================================
# POLICY INVARIANT: CONFIRMED_MALICIOUS requires independent URL verification
# ===========================================================================

def test_confirmed_malicious_requires_url_deception():
    """
    Core policy test.
    A message with NO embedded URL — no matter how many critical heuristic patterns
    fire or how high its risk score — must NOT be classified CONFIRMED_MALICIOUS.
    The ceiling without an independent URL signal is LIKELY_SCAM.
    """
    # Highly suspicious message: PhonePe + KYC expiry + UPI PIN — but NO hyperlink
    msg_no_url = (
        "Your PhonePe account will be blocked today. "
        "Your KYC verification has expired. "
        "Enter your UPI PIN immediately to reactivate your account."
    )
    ind, _, _, url_a, _ = MessageScanner.scan(msg_no_url)
    result = RiskEngine.evaluate(indicators=ind, ml_score=85.0, url_analyses=url_a)

    url_indicators = [i for i in ind if i.category == "URL Deception"]
    assert len(url_indicators) == 0, "No URL in message — URL Deception category must not fire"
    assert result["classification"] != "CONFIRMED_MALICIOUS", (
        "CONFIRMED_MALICIOUS must not be assigned when no URL deception signal is present. "
        "Got: %s (score=%s)" % (result["classification"], result["risk_score"])
    )
    # Score may be HIGH/CRITICAL — that is correct; only the classification label is constrained
    assert result["classification"] in {"LIKELY_SCAM", "SUSPICIOUS"}, (
        "Without a URL, a high-scoring scam message should be LIKELY_SCAM or SUSPICIOUS. "
        "Got: %s" % result["classification"]
    )


def test_confirmed_malicious_requires_critical_credential_indicator():
    """
    A deceptive URL alone (no credential/impersonation indicator) must not produce
    CONFIRMED_MALICIOUS. Both signals are required simultaneously.
    """
    # URL that is structurally suspicious (shortener) but message text has no credential demand
    msg_url_only = (
        "Check out the latest news: https://bit.ly/breaking-news-today"
    )
    ind, _, _, url_a, _ = MessageScanner.scan(msg_url_only)
    result = RiskEngine.evaluate(indicators=ind, ml_score=10.0, url_analyses=url_a)

    # There is a URL deception signal (shortener) but no critical credential indicator
    has_critical_cred = any(
        i.category in {"Credential Theft", "Impersonation", "UPI Fraud",
                       "Bank Impersonation", "Government Impersonation"}
        and i.severity == "critical"
        for i in ind
    )
    assert not has_critical_cred, "Pure-URL-shortener message should not fire a critical credential indicator"
    assert result["classification"] != "CONFIRMED_MALICIOUS", (
        "URL shortener alone without a critical credential indicator must not produce CONFIRMED_MALICIOUS"
    )


def test_confirmed_malicious_when_both_url_and_credential_present():
    """
    When BOTH signals are present — a structurally deceptive URL AND a critical
    credential/impersonation indicator — and score >= 75, CONFIRMED_MALICIOUS is correct.
    This is the only scenario where that label is permitted.
    """
    # SBI KYC phishing with a lookalike domain URL
    msg = (
        "Dear SBI user, your YONO account is blocked due to pending KYC update. "
        "Click http://sbi-kyc-pan-update.xyz to update PAN and Aadhaar immediately."
    )
    ind, _, _, url_a, _ = MessageScanner.scan(msg)
    result = RiskEngine.evaluate(indicators=ind, ml_score=90.0, url_analyses=url_a)

    has_url_deception = any(i.category == "URL Deception" for i in ind)
    has_critical_cred = any(
        i.category in {"Credential Theft", "Impersonation", "UPI Fraud",
                       "Bank Impersonation", "Government Impersonation"}
        and i.severity == "critical"
        for i in ind
    )
    assert has_url_deception, "Lookalike domain should produce URL Deception indicator"
    assert has_critical_cred, "SBI KYC phishing should produce critical credential/impersonation indicator"
    assert result["risk_score"] >= 75.0
    assert result["classification"] == "CONFIRMED_MALICIOUS", (
        "With both URL deception and critical credential indicator at score>=75, "
        "CONFIRMED_MALICIOUS is the correct and required label. Got: %s" % result["classification"]
    )


# ===========================================================================
# THREAT DETECTION TESTS (8 Indian scenarios)
# ===========================================================================

# 1. Fake PhonePe KYC Suspension — no embedded URL
def test_fake_phonepe_kyc_suspension():
    """
    'Your PhonePe account will be blocked today. Your KYC verification has expired.
     Click the link below and enter your UPI PIN to reactivate your account immediately.'
    No real URL in the text → ceiling is LIKELY_SCAM.
    Expected: CRITICAL risk, LIKELY_SCAM, UPI Fraud + KYC indicators.
    """
    msg = (
        "Your PhonePe account will be blocked today. "
        "Your KYC verification has expired. "
        "Click the link below and enter your UPI PIN to reactivate your account immediately."
    )
    ind, _, _, url_a, meta = MessageScanner.scan(msg)
    result = RiskEngine.evaluate(indicators=ind, ml_score=63.6, url_analyses=url_a)

    upi = [i for i in ind if i.category == "UPI Fraud"]
    kyc = [i for i in ind if "KYC" in i.name or "Account Blocking" in i.name or "PhonePe" in i.name]

    assert len(upi) > 0, "Must detect at least one UPI Fraud indicator"
    assert len(kyc) > 0, "Must detect KYC expiry or PhonePe blocking indicator"
    assert result["risk_score"] >= 60.0
    assert result["risk_level"] in ["HIGH", "CRITICAL"]
    # No URL in message → must NOT be CONFIRMED_MALICIOUS
    assert result["classification"] != "CONFIRMED_MALICIOUS", (
        "No embedded URL → CONFIRMED_MALICIOUS must not be assigned"
    )
    assert result["classification"] in {"LIKELY_SCAM", "SUSPICIOUS"}


# 2. Fake Google Pay UPI PIN Request — has deceptive URL
def test_fake_google_pay_upi_pin_request():
    """
    Google Pay impersonation with lookalike URL asking for UPI PIN.
    URL present → CONFIRMED_MALICIOUS is reachable if all conditions met.
    """
    msg = (
        "Google Pay Alert: Your GPay account has been suspended due to incomplete KYC. "
        "Enter your Google Pay UPI PIN at http://gpay-kyc-verify.xyz/india to reactivate immediately."
    )
    ind, _, _, url_a, _ = MessageScanner.scan(msg)
    result = RiskEngine.evaluate(indicators=ind, ml_score=75.0, url_analyses=url_a)

    assert any(i.category == "UPI Fraud" for i in ind), "Must detect UPI Fraud"
    assert result["risk_score"] >= 65.0
    assert result["classification"] in SCAM_CLASSES


# 3. Fake Paytm Reward / Cashback — no URL
def test_fake_paytm_reward():
    """
    Paytm impersonation with fake cashback — no embedded URL.
    Ceiling: LIKELY_SCAM.
    """
    msg = (
        "Paytm: Congratulations! Rs 2,500 cashback has been credited to your Paytm wallet. "
        "Your Paytm account is suspended — verify KYC immediately to claim your reward."
    )
    ind, _, _, url_a, _ = MessageScanner.scan(msg)
    result = RiskEngine.evaluate(indicators=ind, ml_score=65.0)

    assert any(i.category == "UPI Fraud" for i in ind), "Must detect Paytm impersonation"
    assert result["risk_score"] >= 45.0
    assert result["classification"] != "CONFIRMED_MALICIOUS", (
        "No URL → must not be CONFIRMED_MALICIOUS"
    )
    assert result["classification"] in {"LIKELY_SCAM", "SUSPICIOUS"}


# 4. Digital Arrest Scam — no URL
def test_digital_arrest_scam():
    """
    CBI digital arrest extortion — no embedded URL.
    Score will be CRITICAL; classification ceiling is LIKELY_SCAM.
    """
    msg = (
        "CBI & Cyber Crime Cell Notice: A courier package containing 250g MDMA narcotics "
        "in your name was intercepted at Mumbai airport. You are under Digital Arrest. "
        "Transfer Rs 2,50,000 immediately to RBI security escrow to clear charges."
    )
    ind, se, _, url_a, _ = MessageScanner.scan(msg)
    result = RiskEngine.evaluate(indicators=ind, ml_score=90.0)

    assert any("Digital Arrest" in i.name or i.category == "Government Impersonation" for i in ind)
    assert any(t.category in ["Fear", "Authority"] for t in se)
    assert result["risk_score"] >= 75.0
    # No URL → ceiling is LIKELY_SCAM
    assert result["classification"] != "CONFIRMED_MALICIOUS", (
        "No URL → CONFIRMED_MALICIOUS must not be assigned"
    )
    assert result["classification"] in {"LIKELY_SCAM", "SUSPICIOUS"}


# 5. Fake Courier Delivery Fee — has deceptive URL
def test_fake_courier_delivery_fee():
    """
    India Post phishing with lookalike URL. URL present → CONFIRMED_MALICIOUS possible.
    """
    msg = (
        "India Post Notice: Consignment #IN82019 failed delivery due to incorrect pin code. "
        "Pay Rs 25 redelivery charge at http://indiapost-parcel-redelivery.xyz to avoid return."
    )
    ind, _, _, url_a, _ = MessageScanner.scan(msg)
    result = RiskEngine.evaluate(indicators=ind, ml_score=80.0, url_analyses=url_a)

    assert any("Courier" in i.name or i.category == "Package Phishing" for i in ind)
    assert result["risk_score"] >= 50.0
    assert result["classification"] in SCAM_CLASSES


# 6. Fake UPI Collect Request + QR Code — no URL
def test_fake_upi_collect_request():
    """
    Collect request / QR bait with no embedded URL.
    Ceiling: LIKELY_SCAM.
    """
    msg = (
        "PhonePe Reward: You have received a cash reward of Rs 25,000! "
        "Accept the UPI collect request sent to your number to claim money instantly. "
        "Or scan the QR code to receive your cashback payment."
    )
    ind, _, _, url_a, _ = MessageScanner.scan(msg)
    result = RiskEngine.evaluate(indicators=ind, ml_score=85.0)

    assert any(i.category == "UPI Fraud" for i in ind)
    assert result["risk_score"] >= 60.0
    assert result["classification"] != "CONFIRMED_MALICIOUS", (
        "No URL → must not be CONFIRMED_MALICIOUS"
    )
    assert result["classification"] in {"LIKELY_SCAM", "SUSPICIOUS"}


# 7. Fake Bank KYC + Lookalike URL — CONFIRMED_MALICIOUS expected
def test_fake_bank_kyc_suspension_with_url():
    """
    SBI KYC phishing with a lookalike domain URL.
    Both conditions for CONFIRMED_MALICIOUS are present.
    """
    msg = (
        "Dear SBI user, your YONO account is blocked today due to pending KYC update. "
        "Click http://sbi-kyc-pan-update.xyz to update PAN and Aadhaar immediately "
        "to avoid permanent deactivation."
    )
    ind, _, _, url_a, _ = MessageScanner.scan(msg)
    result = RiskEngine.evaluate(indicators=ind, ml_score=90.0, url_analyses=url_a)

    assert any(i.category == "Bank Impersonation" for i in ind)
    assert result["risk_score"] >= 75.0
    assert result["risk_level"] == "CRITICAL"
    # URL present + critical impersonation indicator → CONFIRMED_MALICIOUS
    assert result["classification"] == "CONFIRMED_MALICIOUS", (
        "SBI KYC phishing with a lookalike URL satisfies all CONFIRMED_MALICIOUS conditions. "
        "Got: %s" % result["classification"]
    )


# 8. Harmless Urgency Words — false-positive guard
def test_harmless_urgency_words():
    """
    Ordinary sentences containing urgency-related words in benign context.
    Must not push classification above SUSPICIOUS and score must be LOW/MEDIUM.
    """
    msg1 = "Urgent meeting reminder: Quarterly review rescheduled to 4 PM in room 302."
    ind1, _, _, _, _ = MessageScanner.scan(msg1)
    r1 = RiskEngine.evaluate(indicators=ind1, ml_score=0.0)
    assert r1["risk_score"] < 30.0
    assert r1["risk_level"] in ["LOW", "MEDIUM"]
    assert r1["classification"] not in {"CONFIRMED_MALICIOUS", "LIKELY_SCAM"}

    msg2 = "Hi, the road near our office is blocked due to construction. Please use the alternate route."
    ind2, _, _, _, _ = MessageScanner.scan(msg2)
    r2 = RiskEngine.evaluate(indicators=ind2, ml_score=0.0)
    assert r2["risk_score"] < 25.0
    assert r2["risk_level"] == "LOW"


# ===========================================================================
# FALSE POSITIVE TESTS
# ===========================================================================

def test_genuine_upi_payment_notification():
    """Real bank debit SMS must be classified BENIGN."""
    msg = (
        "SBI Alert: Your A/C xx9812 is debited by Rs 450.00 on 31-Oct via UPI "
        "Ref 410291. Avail Bal: Rs 14,210.00. If not you, SMS BLOCK to 567676."
    )
    ind, _, _, url_a, meta = MessageScanner.scan(msg)
    result = RiskEngine.evaluate(
        indicators=ind, ml_score=0.0, url_analyses=url_a,
        is_benign_exempt=meta.get("is_legitimate_bank_alert", False),
    )
    assert result["risk_score"] < 25.0
    assert result["risk_level"] == "LOW"
    assert result["classification"] == "BENIGN"


def test_legitimate_kyc_reminder_no_link():
    """Legitimate KYC reminder without URL or credential demand must not be HIGH risk."""
    msg = (
        "Dear HDFC Bank customer, your KYC documents are due for renewal by Dec 31. "
        "Please visit your nearest HDFC branch or log in to NetBanking to complete your KYC. "
        "For assistance, call our official helpline 1800-202-6161."
    )
    ind, _, _, url_a, _ = MessageScanner.scan(msg)
    result = RiskEngine.evaluate(indicators=ind, ml_score=0.0, url_analyses=url_a)
    assert result["risk_score"] < 55.0
    assert result["risk_level"] in ["LOW", "MEDIUM"]
    assert result["classification"] != "CONFIRMED_MALICIOUS"


def test_genuine_gpay_received_notification():
    """Real Google Pay received-payment notification must not trigger UPI Fraud."""
    msg = (
        "You have received Rs 500.00 from Ravi Kumar (ravikumar@okicici) via Google Pay. "
        "Transaction ID: UPI/231031/123456. Check Google Pay app for details."
    )
    ind, _, _, url_a, _ = MessageScanner.scan(msg)
    result = RiskEngine.evaluate(indicators=ind, ml_score=0.0, url_analyses=url_a)
    assert result["risk_score"] < 50.0
    assert result["risk_level"] in ["LOW", "MEDIUM"]
    assert result["classification"] not in {"CONFIRMED_MALICIOUS"}


def test_legitimate_internship_announcement():
    """Campus internship announcement with no Telegram / advance fee must not flag Employment Fraud."""
    msg = (
        "Internship Opportunity at Infosys: Applications open for Summer 2025 in Bangalore. "
        "Duration: 2 months. Apply via campus placement portal by Nov 15. "
        "No fees required. Stipend: Rs 15,000/month."
    )
    ind, _, _, url_a, _ = MessageScanner.scan(msg)
    result = RiskEngine.evaluate(indicators=ind, ml_score=0.0)
    employment_fraud = [i for i in ind if i.category == "Employment Fraud"]
    assert len(employment_fraud) == 0, "Legitimate campus internship must not trigger Employment Fraud"
    assert result["risk_score"] < 25.0
    assert result["risk_level"] == "LOW"


# ===========================================================================
# DB ISOLATION VERIFICATION
# ===========================================================================

def test_history_filtering_and_stats(db):
    """Uses isolated in-memory test DB — never writes to production scamsentry.db."""
    req = MessageScanRequest(
        message="PhonePe Reward: Enter your secret UPI PIN to claim money instantly.",
        source_type="sms",
    )
    res = scan_message(payload=req, db=db)
    assert res.id is not None
    assert res.classification in SCAM_CLASSES | {"SUSPICIOUS"}

    filtered = get_scan_history(limit=10, scan_type="message", db=db)
    assert len(filtered) > 0
    assert all(r.scan_type == "message" for r in filtered)

    search_res = get_scan_history(limit=10, search="PhonePe", db=db)
    assert len(search_res) > 0

    stats = get_dashboard_stats(db=db)
    assert stats.total_scans > 0
    assert len(stats.activity_over_time) > 0
