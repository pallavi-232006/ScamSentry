from datetime import datetime, timezone
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan_record import ScanRecord
from app.schemas.scan import (
    MessageScanRequest,
    UrlScanRequest,
    ScanResponse,
    ThreatIndicator,
    SocialEngineeringTactic,
    UrlAnalysisItem,
)
from app.core.message_scanner import MessageScanner
from app.core.url_scanner import UrlScanner
from app.core.risk_engine import RiskEngine
from app.core.ml_classifier import MLScamClassifier

router = APIRouter(prefix="/scan", tags=["Scanning"])

# Initialize ML classifier once (singleton pattern)
ml_classifier = MLScamClassifier()


@router.post("/message", response_model=ScanResponse, status_code=status.HTTP_200_OK)
def scan_message(payload: MessageScanRequest, db: Session = Depends(get_db)):
    """
    Analyzes an incoming SMS, Email, or WhatsApp message for scam patterns,
    psychological social engineering vectors, credential theft, and embedded URL threats.
    """
    message_text = payload.message.strip()
    if not message_text:
        raise HTTPException(status_code=400, detail="Message text cannot be empty.")

    # 1. Advanced Message & Contextual Heuristic Analysis (Modules 1, 2, 3)
    (
        indicators,
        se_tactics,
        suspicious_phrases,
        url_analyses,
        metadata,
    ) = MessageScanner.scan(message_text, payload.source_type)

    # 2. Local Machine Learning Analysis (Module 4)
    ml_analysis = ml_classifier.get_analysis(message_text)
    ml_probability = ml_analysis.get("scam_probability", 0.0)
    metadata["ml_scam_probability"] = ml_probability

    # 3. Intelligent Risk Evaluation (Module 5)
    is_benign_exempt = metadata.get("is_legitimate_bank_alert", False)
    eval_result = RiskEngine.evaluate(
        indicators=indicators,
        ml_score=ml_probability,
        url_analyses=url_analyses,
        is_benign_exempt=is_benign_exempt,
    )

    final_score = eval_result["risk_score"]
    risk_level = eval_result["risk_level"]
    classification = eval_result["classification"]
    explanations = eval_result["explanations"]
    recommendations = eval_result["recommendations"]
    limitations = eval_result["limitations"]
    metadata["confidence_score"] = eval_result["confidence_score"]
    metadata["confidence_label"] = eval_result["confidence_label"]
    metadata["uncertainty_notes"] = eval_result["uncertainty_notes"]
    metadata["score_breakdown"] = eval_result["score_breakdown"]

    # Determine primary category for UI badge & DB storage
    primary_category = "General"
    if indicators:
        primary_category = indicators[0].category
    elif is_benign_exempt or final_score < 25.0:
        primary_category = "Safe / Legitimate"

    summary = message_text[:80] + ("..." if len(message_text) > 80 else "")

    # 4. Save to Database
    record = ScanRecord(
        scan_type="message",
        target_summary=summary,
        raw_content=message_text,
        risk_score=final_score,
        threat_level=risk_level,
        category=primary_category,
        created_at=datetime.now(timezone.utc),
    )
    record.indicators = [ind.model_dump() for ind in indicators]
    record.phrases = suspicious_phrases
    record.recommendations = recommendations

    db.add(record)
    db.commit()
    db.refresh(record)

    # Return Explainable Threat Report (Module 6)
    return ScanResponse(
        id=record.id,
        scan_type="message",
        target_summary=summary,
        summary=summary,
        risk_score=final_score,
        risk_level=risk_level,
        threat_level=risk_level,
        classification=classification,
        category=primary_category,
        indicators=indicators,
        detected_indicators=indicators,
        social_engineering_tactics=se_tactics,
        url_analysis=url_analyses,
        ml_analysis=ml_analysis,
        suspicious_phrases=suspicious_phrases,
        explanations=explanations,
        recommendations=recommendations,
        limitations=limitations,
        metadata=metadata,
        created_at=record.created_at,
    )


@router.post("/url", response_model=ScanResponse, status_code=status.HTTP_200_OK)
def scan_url(payload: UrlScanRequest, db: Session = Depends(get_db)):
    """
    Performs safe, offline structural analysis of a URL.
    Checks for lookalike domains, deceptive IP hostnames, URL shorteners, and abnormal ports.
    NEVER visits, resolves, or executes the target link.
    """
    raw_url = payload.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    # 1. Structural URL scan (Module 3)
    indicators, phrases, metadata, analysis_item = UrlScanner.scan(raw_url)

    # 2. Risk evaluation (Module 5)
    eval_result = RiskEngine.evaluate(
        indicators=indicators,
        ml_score=0.0,
        url_analyses=[analysis_item] if analysis_item.hostname else [],
        is_benign_exempt=False,
    )

    final_score = eval_result["risk_score"]
    risk_level = eval_result["risk_level"]
    classification = eval_result["classification"]
    explanations = eval_result["explanations"]
    recommendations = eval_result["recommendations"]
    limitations = eval_result["limitations"]
    metadata["confidence_score"] = eval_result["confidence_score"]
    metadata["confidence_label"] = eval_result["confidence_label"]
    metadata["uncertainty_notes"] = eval_result["uncertainty_notes"]
    metadata["score_breakdown"] = eval_result["score_breakdown"]

    primary_category = "URL Deception" if indicators else "Safe Link"
    summary = raw_url[:80] + ("..." if len(raw_url) > 80 else "")

    # 3. Save to Database
    record = ScanRecord(
        scan_type="url",
        target_summary=summary,
        raw_content=raw_url,
        risk_score=final_score,
        threat_level=risk_level,
        category=primary_category,
        created_at=datetime.now(timezone.utc),
    )
    record.indicators = [ind.model_dump() for ind in indicators]
    record.phrases = phrases
    record.recommendations = recommendations

    db.add(record)
    db.commit()
    db.refresh(record)

    # Return Explainable Threat Report (Module 6)
    return ScanResponse(
        id=record.id,
        scan_type="url",
        target_summary=summary,
        summary=summary,
        risk_score=final_score,
        risk_level=risk_level,
        threat_level=risk_level,
        classification=classification,
        category=primary_category,
        indicators=indicators,
        detected_indicators=indicators,
        social_engineering_tactics=[],
        url_analysis=[analysis_item] if analysis_item.hostname else [],
        ml_analysis={
            "status": "not_applicable",
            "reason": "URL targets evaluated structurally via air-gapped deterministic engine.",
        },
        suspicious_phrases=phrases,
        explanations=explanations,
        recommendations=recommendations,
        limitations=limitations,
        metadata=metadata,
        created_at=record.created_at,
    )
