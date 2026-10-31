import pytest
from app.core.message_scanner import MessageScanner
from app.core.url_scanner import UrlScanner
from app.core.social_engineering import SocialEngineeringAnalyzer
from app.core.ml_classifier import MLScamClassifier
from app.core.risk_engine import RiskEngine
from app.schemas.scan import MessageScanRequest, UrlScanRequest
from app.api.v1.scan import scan_message, scan_url
from app.database import SessionLocal


# 1. Genuine Bank Notifications (False Positive Test)
def test_genuine_bank_notification():
    msg = "Chase Bank: Your debit card ending in 4102 was charged $14.20 at Starbucks on 10/31. If this was you, no response is needed."
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


# 2. Fake Bank Account Suspension Messages
def test_fake_bank_account_suspension():
    msg = "Bank of America Alert: Your debit card access is suspended due to suspicious login activity. Verify your PIN and CVV immediately at http://boa-security-auth.xyz/verify to restore access."
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    eval_result = RiskEngine.evaluate(
        indicators=indicators,
        ml_score=85.0,
        url_analyses=url_analyses,
    )
    assert eval_result["risk_score"] >= 75.0
    assert eval_result["risk_level"] == "CRITICAL"
    assert eval_result["classification"] == "CONFIRMED_THREAT"
    assert any(ind.category in ["Credential Theft", "Impersonation"] for ind in indicators)


# 3. OTP Harvesting
def test_otp_harvesting():
    msg = "WhatsApp Security: Someone tried to register with your number. Reply with your 6-digit verification code immediately or your account will be disabled."
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=90.0)
    assert eval_result["risk_score"] >= 70.0
    assert any("OTP" in ind.name or ind.category == "Credential Theft" for ind in indicators)


# 4. Fake Job Offers
def test_fake_job_offers():
    msg = "Amazon is hiring remote product reviewers! Earn $500 daily working 1-2 hours from home. No experience needed. Contact HR manager on Telegram @amazon_reviewer."
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    assert any(ind.category == "Employment Fraud" for ind in indicators)
    assert any(t.category in ["Scarcity", "Procedure Evasion", "Fake Rewards"] for t in se_tactics)


# 5. Lottery & Sweepstakes Scams
def test_lottery_scam():
    msg = "Congratulations! You have won £1,500,000 in the 2026 International Lottery. Send your bank details and passport to lottery-agent@claim-payout.xyz to claim your cash."
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    assert any(ind.category in ["Lottery / Prize", "Financial Fraud"] for ind in indicators)
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=80.0)
    assert eval_result["risk_score"] >= 50.0


# 6. Investment Fraud
def test_investment_fraud():
    msg = "Guaranteed 400% profit in 48 hours with automated crypto AI arbitrage bot! Deposit minimum $500 Bitcoin now. Risk-free passive income."
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    assert any(ind.category == "Investment Scam" for ind in indicators)
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=85.0)
    assert eval_result["risk_score"] >= 50.0


# 7. Government Impersonation
def test_government_impersonation():
    msg = "IRS FINAL NOTICE: An arrest warrant has been issued in your name for unpaid federal taxes. Call 1-800-482-0199 immediately or federal agents will detain you today."
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    assert any(ind.category in ["Impersonation", "Government Impersonation"] for ind in indicators)
    assert any(t.category in ["Fear", "Authority"] for t in se_tactics)
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=90.0)
    assert eval_result["risk_score"] >= 75.0


# 8. Legitimate URLs
def test_legitimate_url():
    indicators, phrases, metadata, analysis = UrlScanner.scan("https://www.google.com/search?q=cybersecurity")
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=0.0, url_analyses=[analysis])
    assert eval_result["risk_score"] < 25.0
    assert eval_result["risk_level"] == "LOW"
    assert eval_result["classification"] == "BENIGN"
    assert analysis.has_https is True
    assert analysis.domain == "google.com"


# 9. IP-Based URLs
def test_ip_based_url():
    indicators, phrases, metadata, analysis = UrlScanner.scan("http://192.168.1.1/admin")
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=0.0, url_analyses=[analysis])
    assert any(ind.name == "IP Address Hostname" for ind in indicators)
    assert eval_result["risk_score"] >= 50.0
    assert analysis.is_ip_address is True


# 10. Lookalike Domains
def test_lookalike_domain():
    indicators, phrases, metadata, analysis = UrlScanner.scan("https://paypal.secure-login.xyz/auth")
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=0.0, url_analyses=[analysis])
    assert any("Lookalike" in ind.name or "Brand" in ind.name for ind in indicators)
    assert eval_result["risk_score"] >= 50.0
    assert analysis.has_brand_lookalike is True


# 11. URL Shorteners
def test_url_shortener():
    indicators, phrases, metadata, analysis = UrlScanner.scan("https://bit.ly/claim-prize")
    assert any(ind.category == "Shortener" for ind in indicators)
    assert analysis.is_shortener is True


# 12. Empty Message Handling
def test_empty_message_handling():
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan("")
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=0.0)
    assert eval_result["risk_score"] == 0.0
    assert eval_result["risk_level"] == "LOW"
    assert eval_result["classification"] == "BENIGN"


# 13. Malformed URLs
def test_malformed_url():
    indicators, phrases, metadata, analysis = UrlScanner.scan("htp:/invalid url @@ %%")
    assert any("Malformed" in ind.name for ind in indicators) or analysis.scheme != "https"


# 14. Extremely Long Inputs
def test_extremely_long_input():
    long_msg = "Hello, this is a test. " * 600  # ~14,000 characters
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(long_msg)
    eval_result = RiskEngine.evaluate(indicators=indicators, ml_score=0.0)
    assert eval_result["risk_score"] < 25.0
    assert eval_result["risk_level"] == "LOW"


# 15. Legitimate Messages with 'urgent' or 'free' in Harmless Context
def test_harmless_urgent_and_free_context():
    msg1 = "Feel free to stop by my desk whenever you have time this afternoon. I have the wireframes ready."
    indicators1, se1, _, _, _ = MessageScanner.scan(msg1)
    eval1 = RiskEngine.evaluate(indicators=indicators1, ml_score=0.0)
    assert eval1["risk_score"] < 25.0
    assert eval1["risk_level"] == "LOW"
    assert eval1["classification"] == "BENIGN"

    msg2 = "Urgent meeting reminder: Quarterly review rescheduled to 4 PM in room 302."
    indicators2, se2, _, _, _ = MessageScanner.scan(msg2)
    eval2 = RiskEngine.evaluate(indicators=indicators2, ml_score=0.0)
    assert eval2["risk_score"] < 25.0
    assert eval2["risk_level"] == "LOW"
    assert eval2["classification"] == "BENIGN"


# 16. Full Explainable Threat Report Schema Compliance via API
def test_explainable_threat_report_api_endpoint():
    db = SessionLocal()
    try:
        req = MessageScanRequest(
            message="URGENT: Chase Bank alert. Your debit card is locked due to unauthorized charges. Verify immediately at http://chase-security-login.xyz to restore access.",
            source_type="sms",
        )
        res = scan_message(payload=req, db=db)
        
        # Verify Module 6 Explainable Threat Report contract
        assert hasattr(res, "risk_score")
        assert hasattr(res, "risk_level")
        assert hasattr(res, "classification")
        assert hasattr(res, "summary")
        assert hasattr(res, "detected_indicators")
        assert hasattr(res, "social_engineering_tactics")
        assert hasattr(res, "url_analysis")
        assert hasattr(res, "ml_analysis")
        assert hasattr(res, "explanations")
        assert hasattr(res, "recommendations")
        assert hasattr(res, "limitations")

        assert res.risk_level in ["HIGH", "CRITICAL"]
        assert len(res.detected_indicators) > 0
        assert len(res.explanations) > 0
        assert len(res.recommendations) > 0
        assert len(res.limitations) > 0
    finally:
        db.close()

