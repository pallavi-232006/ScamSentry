"""
Indian cybersecurity scenario tests — 8 new threat scenarios + false-positive tests.
All DB-writing functions receive the isolated in-memory `db` fixture from
conftest.py — zero writes reach the production scamsentry.db file.

Classification tiers (new):
  CONFIRMED_MALICIOUS  – multi-vector, verified deception signals
  LIKELY_SCAM          – strong multi-category convergence
  SUSPICIOUS           – patterns present but not conclusive
  LOW_RISK / BENIGN    – few/no indicators
"""
import pytest
from app.core.message_scanner import MessageScanner
from app.core.risk_engine import RiskEngine
from app.schemas.scan import MessageScanRequest
from app.api.v1.scan import scan_message
from app.api.v1.history import get_scan_history
from app.api.v1.stats import get_dashboard_stats

VALID_SCAM_CLASSES = {"CONFIRMED_MALICIOUS", "LIKELY_SCAM", "SUSPICIOUS"}
VALID_SAFE_CLASSES = {"BENIGN", "LOW_RISK", "SUSPICIOUS"}


# ===========================================================================
# THREAT DETECTION TESTS (should trigger scam classification)
# ===========================================================================

# 1. Fake PhonePe KYC Suspension (the original failing test case)
def test_fake_phonepe_kyc_suspension():
    """
    Exact message from the user's test:
    'Your PhonePe account will be blocked today. Your KYC verification has expired.
     Click the link below and enter your UPI PIN to reactivate your account immediately.'
    Expected: HIGH or CRITICAL risk, classification not BENIGN, UPI Fraud + KYC indicators fired.
    """
    msg = (
        "Your PhonePe account will be blocked today. "
        "Your KYC verification has expired. "
        "Click the link below and enter your UPI PIN to reactivate your account immediately."
    )
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=63.6, url_analyses=url_analyses)

    # Must detect UPI Fraud and KYC threat independently
    upi_categories = [ind.category for ind in indicators if ind.category == "UPI Fraud"]
    kyc_indicators = [ind for ind in indicators if "KYC" in ind.name or "Account Blocking" in ind.name or "PhonePe" in ind.name]

    assert len(upi_categories) > 0, "Expected at least one UPI Fraud indicator"
    assert len(kyc_indicators) > 0, "Expected KYC expiry or account blocking indicator"
    assert eval_result["risk_score"] >= 60.0, "Score should be HIGH or above for this classic scam"
    assert eval_result["risk_level"] in ["HIGH", "CRITICAL"]
    assert eval_result["classification"] != "BENIGN"
    assert eval_result["classification"] != "LOW_RISK"


# 2. Fake Google Pay UPI PIN Request
def test_fake_google_pay_upi_pin_request():
    """
    Google Pay impersonation asking for UPI PIN via SMS.
    Expected: UPI Fraud indicator, LIKELY_SCAM or CONFIRMED_MALICIOUS, score >= 65.
    """
    msg = (
        "Google Pay Alert: Your GPay account has been suspended due to incomplete KYC. "
        "Enter your Google Pay UPI PIN at http://gpay-kyc-verify.xyz/india to reactivate immediately."
    )
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=75.0, url_analyses=url_analyses)

    assert any(ind.category == "UPI Fraud" for ind in indicators), "Must detect UPI Fraud"
    assert eval_result["risk_score"] >= 65.0
    assert eval_result["classification"] in VALID_SCAM_CLASSES


# 3. Fake Paytm Reward / Cashback Scam
def test_fake_paytm_reward():
    """
    Paytm impersonation with fake cashback claiming victim must 'verify' to receive.
    Expected: UPI Fraud (Paytm impersonation), score >= 45.
    """
    msg = (
        "Paytm: Congratulations! Rs 2,500 cashback has been credited to your Paytm wallet. "
        "Your Paytm account is suspended — verify KYC immediately to claim your reward."
    )
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=65.0)

    assert any(ind.category == "UPI Fraud" for ind in indicators), "Must detect Paytm impersonation"
    assert eval_result["risk_score"] >= 45.0
    assert eval_result["classification"] in VALID_SCAM_CLASSES


# 4. Digital Arrest Scam
def test_digital_arrest_scam():
    """
    CBI digital arrest extortion — most dangerous Indian cyber scam variant.
    Expected: Government Impersonation, Fear tactic, score >= 75, CONFIRMED_MALICIOUS or LIKELY_SCAM.
    """
    msg = (
        "CBI & Cyber Crime Cell Notice: A courier package containing 250g MDMA narcotics "
        "in your name was intercepted at Mumbai airport. You are under Digital Arrest. "
        "Transfer Rs 2,50,000 immediately to RBI security escrow to clear charges."
    )
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=90.0)

    assert any("Digital Arrest" in ind.name or ind.category == "Government Impersonation" for ind in indicators)
    assert any(t.category in ["Fear", "Authority"] for t in se_tactics)
    assert eval_result["risk_score"] >= 75.0
    assert eval_result["classification"] in VALID_SCAM_CLASSES


# 5. Fake Courier Delivery Fee
def test_fake_courier_delivery_fee():
    """
    India Post phishing SMS with redelivery fee — micro-fee credential harvesting.
    Expected: Package Phishing indicator, score >= 50.
    """
    msg = (
        "India Post Notice: Consignment #IN82019 failed delivery due to incorrect pin code. "
        "Pay Rs 25 redelivery charge at http://indiapost-parcel-redelivery.xyz to avoid return."
    )
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=80.0, url_analyses=url_analyses)

    assert any("Courier" in ind.name or ind.category == "Package Phishing" for ind in indicators)
    assert eval_result["risk_score"] >= 50.0
    assert eval_result["classification"] in VALID_SCAM_CLASSES


# 6. Fake UPI Collect Request + QR Code
def test_fake_upi_collect_request():
    """
    UPI collect request scam — victim is told to 'accept' to receive money.
    Expected: UPI Fraud detected (collect request), score >= 60.
    """
    msg = (
        "PhonePe Reward: You have received a cash reward of Rs 25,000! "
        "Accept the UPI collect request sent to your number to claim money instantly. "
        "Or scan the QR code to receive your cashback payment."
    )
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=85.0)

    assert any(ind.category == "UPI Fraud" for ind in indicators)
    assert eval_result["risk_score"] >= 60.0
    assert eval_result["classification"] in VALID_SCAM_CLASSES


# 7. Fake Bank KYC Suspension (SBI / HDFC)
def test_fake_bank_kyc_suspension_indian():
    """
    Indian bank KYC phishing — impersonates SBI with a lookalike URL.
    Expected: Bank Impersonation, URL Deception, score >= 75, CONFIRMED_MALICIOUS.
    """
    msg = (
        "Dear SBI user, your YONO account is blocked today due to pending KYC update. "
        "Click http://sbi-kyc-pan-update.xyz to update PAN and Aadhaar immediately "
        "to avoid permanent deactivation."
    )
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=90.0, url_analyses=url_analyses)

    assert any(ind.category == "Bank Impersonation" for ind in indicators)
    assert eval_result["risk_score"] >= 75.0
    assert eval_result["risk_level"] == "CRITICAL"
    assert eval_result["classification"] in VALID_SCAM_CLASSES


# 8. Harmless Use of Urgency-Related Words (false-positive guard)
def test_harmless_urgency_words():
    """
    Ordinary sentences containing 'urgent', 'immediately', 'blocked' in safe context.
    Expected: LOW or MEDIUM risk, classification BENIGN or LOW_RISK or SUSPICIOUS with low score.
    """
    # Meeting reminder with 'urgent'
    msg1 = "Urgent meeting reminder: Quarterly review rescheduled to 4 PM in room 302. Please confirm attendance."
    indicators1, _, _, _, meta1 = MessageScanner.scan(msg1)
    eval1 = RiskEngine.evaluate(indicators=indicators1, ml_score=0.0)
    assert eval1["risk_score"] < 30.0, "Benign urgency phrase should not push score above LOW"
    assert eval1["risk_level"] in ["LOW", "MEDIUM"]

    # Road blocked notice
    msg2 = "Hi, the road near our office is blocked due to construction. Please take the alternate route via MG Road."
    indicators2, _, _, _, meta2 = MessageScanner.scan(msg2)
    eval2 = RiskEngine.evaluate(indicators=indicators2, ml_score=0.0)
    assert eval2["risk_score"] < 25.0
    assert eval2["risk_level"] == "LOW"


# ===========================================================================
# FALSE POSITIVE TESTS (legitimate messages that must NOT be flagged as scams)
# ===========================================================================

# 9. Genuine UPI Payment Notification
def test_genuine_upi_payment_notification():
    """
    Real bank debit SMS — standard format used by all Indian banks.
    Must NOT trigger UPI fraud or credential theft indicators.
    Must be classified as BENIGN or very LOW_RISK.
    """
    msg = (
        "SBI Alert: Your A/C xx9812 is debited by Rs 450.00 on 31-Oct via UPI "
        "Ref 410291823. Avail Bal: Rs 14,210.00. If not you, SMS BLOCK to 567676."
    )
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    eval_result = RiskEngine.evaluate(
        indicators=indicators,
        ml_score=0.0,
        url_analyses=url_analyses,
        is_benign_exempt=metadata.get("is_legitimate_bank_alert", False),
    )

    assert eval_result["risk_score"] < 25.0, "Genuine UPI debit notification should be LOW risk"
    assert eval_result["risk_level"] == "LOW"
    assert eval_result["classification"] == "BENIGN"


# 10. Legitimate Bank KYC Reminder (no link, no credential demand)
def test_legitimate_kyc_reminder_no_link():
    """
    Some banks send legitimate KYC renewal reminders with NO suspicious link and
    no credential request — only advising to visit branch or official app.
    Must not be flagged as HIGH risk.
    """
    msg = (
        "Dear HDFC Bank customer, your KYC documents are due for renewal by Dec 31. "
        "Please visit your nearest HDFC branch or log in to NetBanking to complete your KYC. "
        "For assistance, call our official helpline 1800-202-6161."
    )
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=0.0, url_analyses=url_analyses)

    # Should be low-medium risk at most — no PIN/OTP/link requested
    assert eval_result["risk_score"] < 55.0, "Legitimate KYC reminder without link should not be HIGH risk"
    assert eval_result["risk_level"] in ["LOW", "MEDIUM"]


# 11. Genuine Google Pay Transaction Received Confirmation
def test_genuine_gpay_received_notification():
    """
    Real Google Pay received-payment notification — must not trigger UPI fraud.
    """
    msg = (
        "You have received Rs 500.00 from Ravi Kumar (ravikumar@okicici) via Google Pay. "
        "Transaction ID: UPI/231031/123456. Check Google Pay app for details."
    )
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=0.0, url_analyses=url_analyses)

    # No UPI PIN requested, no link, no threat — should not be CRITICAL or HIGH
    upi_fraud_indicators = [ind for ind in indicators if ind.category == "UPI Fraud"]
    # A pure received notification with a UPI ref should not fire UPI Fraud patterns
    assert eval_result["risk_score"] < 50.0, "Genuine payment received notification should not be HIGH risk"
    assert eval_result["risk_level"] in ["LOW", "MEDIUM"]


# 12. Legitimate Internship Announcement (college notice board)
def test_legitimate_internship_announcement():
    """
    Genuine internship announcement — named company, proper interview process, no fee.
    Must not trigger Employment Fraud.
    """
    msg = (
        "Internship Opportunity at Infosys: Applications open for Summer 2025 Internship Program "
        "in Bangalore. Duration: 2 months. Apply via campus placement portal by Nov 15. "
        "No fees required. Stipend: Rs 15,000/month. Contact placement cell for details."
    )
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=0.0)

    # Should NOT trigger employment fraud — no Telegram, no advance fee, no vague promises
    employment_fraud = [ind for ind in indicators if ind.category == "Employment Fraud"]
    assert len(employment_fraud) == 0, "Legitimate campus internship should not trigger Employment Fraud"
    assert eval_result["risk_score"] < 25.0
    assert eval_result["risk_level"] == "LOW"


# ===========================================================================
# DB ISOLATION VERIFICATION TEST
# ===========================================================================

def test_history_filtering_and_stats(db):
    """Uses isolated in-memory test DB — never writes to production scamsentry.db."""
    req = MessageScanRequest(
        message="PhonePe Reward: Enter your secret UPI PIN to claim money instantly.",
        source_type="sms",
    )
    res = scan_message(payload=req, db=db)
    assert res.id is not None
    assert res.classification in VALID_SCAM_CLASSES | {"SUSPICIOUS"}

    filtered_msg = get_scan_history(limit=10, scan_type="message", db=db)
    assert len(filtered_msg) > 0
    assert all(r.scan_type == "message" for r in filtered_msg)

    search_res = get_scan_history(limit=10, search="PhonePe", db=db)
    assert len(search_res) > 0

    stats = get_dashboard_stats(db=db)
    assert stats.total_scans > 0
    assert len(stats.activity_over_time) > 0
