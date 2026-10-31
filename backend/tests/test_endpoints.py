import pytest
from app.main import health_check, root
from app.api.v1.scan import scan_message, scan_url
from app.api.v1.stats import get_dashboard_stats
from app.api.v1.history import get_scan_history
from app.schemas.scan import MessageScanRequest, UrlScanRequest
from app.database import SessionLocal


def test_health_check_endpoint():
    res = health_check()
    assert res["status"] == "healthy"
    assert res["service"] == "ScamSentry"
    assert res["version"] == "1.0.0"


def test_root_endpoint():
    res = root()
    assert "ScamSentry" in res["message"]
    assert res["docs_url"] == "/docs"


def test_scan_message_endpoint():
    db = SessionLocal()
    try:
        req = MessageScanRequest(
            message="URGENT: Your bank account is suspended. Send OTP code immediately to verify.",
            source_type="sms",
        )
        res = scan_message(payload=req, db=db)
        assert res.risk_score >= 60.0
        assert res.threat_level in ["HIGH", "CRITICAL"]
        assert len(res.indicators) > 0
        assert len(res.recommendations) > 0
    finally:
        db.close()


def test_scan_url_endpoint():
    db = SessionLocal()
    try:
        req = UrlScanRequest(url="http://192.168.1.1:9090/fake-login")
        res = scan_url(payload=req, db=db)
        assert res.risk_score >= 60.0
        assert any(ind.name == "IP Address Hostname" for ind in res.indicators)
        assert any(ind.name == "Non-Standard Port" for ind in res.indicators)
    finally:
        db.close()


def test_stats_and_history_endpoints():
    db = SessionLocal()
    try:
        stats = get_dashboard_stats(db=db)
        assert stats.total_scans >= 2

        history = get_scan_history(limit=10, db=db)
        assert len(history) >= 2
    finally:
        db.close()
