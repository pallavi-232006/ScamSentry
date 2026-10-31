import pytest
from app.core.url_scanner import UrlScanner
from app.core.message_scanner import MessageScanner
from app.core.risk_engine import RiskEngine


def test_url_scanner_ip_detection():
    indicators, phrases, metadata, analysis = UrlScanner.scan("http://192.168.1.1/login")
    assert any(ind.name == "IP Address Hostname" for ind in indicators)
    assert "192.168.1.1" in phrases
    assert analysis.is_ip_address is True


def test_url_scanner_shortener_detection():
    indicators, phrases, metadata, analysis = UrlScanner.scan("https://bit.ly/secure-account")
    assert any(ind.category == "Shortener" for ind in indicators)
    assert analysis.is_shortener is True


def test_message_scanner_otp_harvest():
    msg = "Your account is temporarily suspended. Please send your OTP verification code immediately."
    indicators, se_tactics, phrases, url_analyses, metadata = MessageScanner.scan(msg)
    assert any(ind.category == "Credential Theft" for ind in indicators)
    assert any(ind.category == "Urgency" for ind in indicators)
    assert len(se_tactics) > 0


def test_risk_engine_classification():
    assert RiskEngine.classify_score(90) == "CRITICAL"
    assert RiskEngine.classify_score(70) == "HIGH"
    assert RiskEngine.classify_score(45) == "MEDIUM"
    assert RiskEngine.classify_score(15) == "LOW"
