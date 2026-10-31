from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan_record import ScanRecord
from app.schemas.scan import (
    MessageScanRequest,
    UrlScanRequest,
    ScanResponse,
    ThreatIndicator,
)
from app.core.message_scanner import MessageScanner
from app.core.url_scanner import UrlScanner
from app.core.risk_engine import RiskEngine
from app.core.ml_classifier import MLScamClassifier

router = APIRouter(prefix="/scan", tags=["Scanning"])

# Instantiate ML classifier once
ml_classifier = MLScamClassifier()


@router.post("/message", response_model=ScanResponse, status_code=status.HTTP_200_OK)
def scan_message(payload: MessageScanRequest, db: Session = Depends(get_db)):
    """
    Analyzes an incoming SMS, Email, or WhatsApp message for scam patterns,
    social engineering tactics, credential requests, and suspicious links.
    """
    message_text = payload.message.strip()
    if not message_text:
        raise HTTPException(status_code=400, detail="Message text cannot be empty.")

    # 1. Rule-based & heuristic analysis
    indicators, phrases, metadata = MessageScanner.scan(message_text, payload.source_type)

    # 2. Machine learning statistical probability
    ml_probability = ml_classifier.predict_proba(message_text)
    metadata["ml_scam_probability"] = ml_probability

    # 3. Intelligent Risk Evaluation
    final_score, threat_level, recommendations = RiskEngine.evaluate(
        indicators=indicators,
        base_ml_score=ml_probability if ml_probability > 30 else 0.0,
    )

    # Determine primary threat category
    primary_category = "General"
    if indicators:
        primary_category = indicators[0].category
    elif final_score < 30.0:
        primary_category = "Safe / Legitimate"

    # Truncate summary preview
    summary = message_text[:80] + ("..." if len(message_text) > 80 else "")

    # 4. Save to Database
    record = ScanRecord(
        scan_type="message",
        target_summary=summary,
        raw_content=message_text,
        risk_score=final_score,
        threat_level=threat_level,
        category=primary_category,
        created_at=datetime.now(timezone.utc),
    )
    record.indicators = [ind.model_dump() for ind in indicators]
    record.phrases = phrases
    record.recommendations = recommendations

    db.add(record)
    db.commit()
    db.refresh(record)

    return ScanResponse(
        id=record.id,
        scan_type="message",
        target_summary=summary,
        risk_score=final_score,
        threat_level=threat_level,
        category=primary_category,
        indicators=indicators,
        suspicious_phrases=phrases,
        recommendations=recommendations,
        metadata=metadata,
        created_at=record.created_at,
    )


@router.post("/url", response_model=ScanResponse, status_code=status.HTTP_200_OK)
def scan_url(payload: UrlScanRequest, db: Session = Depends(get_db)):
    """
    Performs safe, offline structural analysis of a URL.
    Checks for lookalike domains, deceptive IP hostnames, URL shorteners, and abnormal ports.
    NEVER visits the target link.
    """
    raw_url = payload.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    # 1. Structural URL scan
    indicators, phrases, metadata = UrlScanner.scan(raw_url)

    # 2. Risk evaluation
    final_score, threat_level, recommendations = RiskEngine.evaluate(
        indicators=indicators,
        base_ml_score=0.0,
    )

    primary_category = "URL Deception" if indicators else "Safe Link"
    summary = raw_url[:80] + ("..." if len(raw_url) > 80 else "")

    # 3. Save to Database
    record = ScanRecord(
        scan_type="url",
        target_summary=summary,
        raw_content=raw_url,
        risk_score=final_score,
        threat_level=threat_level,
        category=primary_category,
        created_at=datetime.now(timezone.utc),
    )
    record.indicators = [ind.model_dump() for ind in indicators]
    record.phrases = phrases
    record.recommendations = recommendations

    db.add(record)
    db.commit()
    db.refresh(record)

    return ScanResponse(
        id=record.id,
        scan_type="url",
        target_summary=summary,
        risk_score=final_score,
        threat_level=threat_level,
        category=primary_category,
        indicators=indicators,
        suspicious_phrases=phrases,
        recommendations=recommendations,
        metadata=metadata,
        created_at=record.created_at,
    )
