from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_

from app.database import get_db
from app.models.scan_record import ScanRecord
from app.schemas.scan import ScanRecordSummary, ScanResponse, ThreatIndicator

router = APIRouter(prefix="/history", tags=["Scan History"])


@router.get("/", response_model=List[ScanRecordSummary])
def get_scan_history(
    limit: int = 50,
    scan_type: Optional[str] = None,
    threat_level: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Retrieve filtered scan history ordered by timestamp descending."""
    query = db.query(ScanRecord)

    if isinstance(scan_type, str) and scan_type.lower() != "all":
        query = query.filter(ScanRecord.scan_type == scan_type.lower())

    if isinstance(threat_level, str) and threat_level.upper() != "ALL":
        query = query.filter(ScanRecord.threat_level == threat_level.upper())

    if isinstance(search, str) and search.strip():
        term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                ScanRecord.target_summary.ilike(term),
                ScanRecord.category.ilike(term),
                ScanRecord.raw_content.ilike(term),
            )
        )

    records = query.order_by(desc(ScanRecord.created_at)).limit(limit).all()
    return records


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan_detail(scan_id: int, db: Session = Depends(get_db)):
    """Retrieve comprehensive threat report details for a specific scan."""
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    indicators = [ThreatIndicator(**item) for item in record.indicators]

    classification = "BENIGN"
    if record.risk_score >= 75.0:
        classification = "CONFIRMED_THREAT"
    elif record.risk_score >= 25.0 or len(indicators) > 0:
        classification = "SUSPICIOUS"

    return ScanResponse(
        id=record.id,
        scan_type=record.scan_type,
        target_summary=record.target_summary,
        summary=record.target_summary,
        risk_score=record.risk_score,
        risk_level=record.threat_level,
        threat_level=record.threat_level,
        classification=classification,
        category=record.category,
        indicators=indicators,
        detected_indicators=indicators,
        social_engineering_tactics=[],
        url_analysis=[],
        ml_analysis={},
        suspicious_phrases=record.phrases,
        explanations=[f"Archived scan record evaluated with {record.threat_level} risk level ({record.risk_score}/100)."],
        recommendations=record.recommendations,
        limitations=[],
        metadata={"raw_content": record.raw_content},
        created_at=record.created_at,
    )


@router.delete("/clear-all", status_code=status.HTTP_200_OK)
@router.delete("/", status_code=status.HTTP_200_OK)
def clear_all_history(db: Session = Depends(get_db)):
    """Clear all stored scan history records."""
    deleted_count = db.query(ScanRecord).delete()
    db.commit()
    return {"status": "success", "deleted_count": deleted_count}


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """Remove a scan record from history."""
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    db.delete(record)
    db.commit()
    return None
