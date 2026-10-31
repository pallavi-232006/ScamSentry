"""
Indian cybercrime scenario tests.
All DB-writing functions receive the isolated in-memory `db` fixture from
conftest.py — zero writes reach the production scamsentry.db file.
"""
import pytest
from app.core.message_scanner import MessageScanner
from app.core.risk_engine import RiskEngine
from app.schemas.scan import MessageScanRequest
from app.api.v1.scan import scan_message
from app.api.v1.history import get_scan_history
from app.api.v1.stats import get_dashboard_stats


# 1. Fake UPI Collect Request
def test_fake_upi_collect_request():
    msg = "PhonePe Reward: You have received a cash reward of Rs 25,000! Enter your secret UPI PIN to claim money instantly into your bank account or accept collect request."
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=85.0)
    assert any("UPI PIN" in ind.name or ind.category == "UPI Fraud" for ind in indicators)
    assert eval_result["risk_score"] >= 60.0


# 2. Fake Bank KYC Suspension
def test_fake_bank_kyc_suspension():
    msg = "Dear SBI user, your YONO account is blocked today due to pending KYC update. Click http://sbi-kyc-pan-update.xyz to update PAN and Aadhaar immediately to avoid permanent deactivation."
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=90.0, url_analyses=url_analyses)
    assert any("KYC" in ind.name or ind.category == "Bank Impersonation" for ind in indicators)
    assert eval_result["risk_score"] >= 75.0
    assert eval_result["risk_level"] == "CRITICAL"


# 3. Digital Arrest Threat
def test_digital_arrest_threat():
    msg = "CBI & Cyber Crime Cell Notice: A courier package containing 250g MDMA narcotics in your name was intercepted at Mumbai airport. You are under Digital Arrest. Transfer Rs 2,50,000 immediately to RBI security escrow to clear charges."
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=90.0)
    assert any("Digital Arrest" in ind.name or "CBI" in str(ind) for ind in indicators)
    assert any(t.category in ["Fear", "Authority"] for t in se_tactics)
    assert eval_result["risk_score"] >= 75.0


# 4. Fake Courier Delivery Fee
def test_fake_courier_delivery_fee():
    msg = "India Post Notice: Consignment #IN82019 failed delivery due to incorrect pin code. Pay Rs 25 redelivery charge at http://indiapost-parcel-redelivery.xyz to avoid return."
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=80.0, url_analyses=url_analyses)
    assert any("Postal" in ind.name or ind.category == "Package Phishing" for ind in indicators)
    assert eval_result["risk_score"] >= 50.0


# 5. Fraudulent Internship Offer
def test_fraudulent_internship_offer():
    msg = "Work From Home Internship at Tata Consultancy Services! Earn Rs 2,500 daily for data entry. Pay Rs 499 refundable equipment fee via UPI to start. Contact HR manager on Telegram @remote_career_now."
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=75.0)
    assert any(ind.category == "Employment Fraud" for ind in indicators)
    assert eval_result["risk_score"] >= 40.0


# 6. OTP Harvesting Message
def test_indian_otp_harvesting():
    msg = "Dear customer, Rs 48,500 debited from your HDFC account. If not done by you, forward the 6-digit verification OTP code received to cancel transfer immediately."
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=85.0)
    assert any(ind.category == "Credential Theft" for ind in indicators)
    assert eval_result["risk_score"] >= 65.0


# 7. Fake Government Subsidy
def test_fake_government_subsidy():
    msg = "PM Kisan Samman Nidhi: Your DBT subsidy of Rs 6,000 has been approved. Click to verify your Aadhaar and bank details at http://pmkisan-dbt-subsidy.top"
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=80.0, url_analyses=url_analyses)
    assert any("DBT" in ind.name or "Subsidy" in ind.name or ind.category == "Government Impersonation" for ind in indicators)
    assert eval_result["risk_score"] >= 50.0


# 8. Legitimate Bank Notification (False Positive Test)
def test_legitimate_indian_bank_alert():
    msg = "SBI Alert: Your A/C 9812 is debited by Rs 450.00 on 31-Oct-26 via UPI Ref 410291. Avail Bal: Rs 14,210.00. If not you, SMS BLOCK to 567676."
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    eval_result = RiskEngine.evaluate(
        indicators=indicators,
        ml_score=0.0,
        url_analyses=url_analyses,
        is_benign_exempt=metadata.get("is_legitimate_bank_alert", False),
    )
    assert eval_result["risk_score"] < 25.0
    assert eval_result["risk_level"] == "LOW"
    assert eval_result["classification"] == "BENIGN"


# 9. History Filtering and Clear All Endpoints (uses isolated in-memory test DB)
def test_history_filtering_and_stats(db):
    """Uses isolated in-memory test DB — never writes to production scamsentry.db."""
    req = MessageScanRequest(
        message="PhonePe Reward: Enter your secret UPI PIN to claim money instantly.",
        source_type="sms",
    )
    res = scan_message(payload=req, db=db)
    assert res.id is not None

    # Verify filtering by scan_type
    filtered_msg = get_scan_history(limit=10, scan_type="message", db=db)
    assert len(filtered_msg) > 0
    assert all(r.scan_type == "message" for r in filtered_msg)

    # Verify search filter
    search_res = get_scan_history(limit=10, search="PhonePe", db=db)
    assert len(search_res) > 0

    # Verify dashboard stats aggregation
    stats = get_dashboard_stats(db=db)
    assert stats.total_scans > 0
    assert len(stats.activity_over_time) > 0
