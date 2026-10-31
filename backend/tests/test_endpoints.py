"""
Endpoint-level tests.
All DB-writing functions receive the isolated in-memory `db` fixture from
conftest.py — zero writes reach the production scamsentry.db file.
"""
import pytest
from app.main import health_check, root
from app.api.v1.scan import scan_message, scan_url
from app.api.v1.stats import get_dashboard_stats
from app.api.v1.history import get_scan_history
from app.schemas.scan import MessageScanRequest, UrlScanRequest


def test_health_check_endpoint():
    res = health_check()
    assert res["status"] == "healthy"
    assert res["service"] == "ScamSentry"
    assert res["version"] == "1.0.0"


def test_root_endpoint():
    res = root()
    assert "ScamSentry" in res["message"]
    assert res["docs_url"] == "/docs"


def test_scan_message_endpoint(db):
    req = MessageScanRequest(
        message="URGENT: Your bank account is suspended. Send OTP code immediately to verify.",
        source_type="sms",
    )
    res = scan_message(payload=req, db=db)
    assert res.risk_score >= 60.0
    assert res.threat_level in ["HIGH", "CRITICAL"]
    assert len(res.indicators) > 0
    assert len(res.recommendations) > 0


def test_scan_url_endpoint(db):
    req = UrlScanRequest(url="http://192.168.1.1:9090/fake-login")
    res = scan_url(payload=req, db=db)
    assert res.risk_score >= 60.0
    assert any(ind.name == "IP Address Hostname" for ind in res.indicators)
    assert any(ind.name == "Non-Standard Port" for ind in res.indicators)


def test_stats_and_history_endpoints(db):
    # Seed two records into the isolated test DB, then verify stats
    req1 = MessageScanRequest(
        message="URGENT: Your bank account is suspended. Send OTP code immediately to verify.",
        source_type="sms",
    )
    req2 = UrlScanRequest(url="http://192.168.1.1:9090/fake-login")
    scan_message(payload=req1, db=db)
    scan_url(payload=req2, db=db)

    stats = get_dashboard_stats(db=db)
    assert stats.total_scans >= 2

    history = get_scan_history(limit=10, db=db)
    assert len(history) >= 2
