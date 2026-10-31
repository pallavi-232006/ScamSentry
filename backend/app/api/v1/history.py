from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db
from app.models.scan_record import ScanRecord
from app.schemas.scan import ScanRecordSummary, ScanResponse, ThreatIndicator

router = APIRouter(prefix="/history", tags=["Scan History"])


@router.get("/", response_model=List[ScanRecordSummary])
def get_scan_history(limit: int = 50, db: Session = Depends(get_db)):
    """Retrieve recent scan history ordered by timestamp descending."""
    records = db.query(ScanRecord).order_by(desc(ScanRecord.created_at)).limit(limit).all()
    return records


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan_detail(scan_id: int, db: Session = Depends(get_db)):
    """Retrieve comprehensive threat report details for a specific scan."""
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    indicators = [ThreatIndicator(**item) for item in record.indicators]

    return ScanResponse(
        id=record.id,
        scan_type=record.scan_type,
        target_summary=record.target_summary,
        risk_score=record.risk_score,
        threat_level=record.threat_level,
        category=record.category,
        indicators=indicators,
        suspicious_phrases=record.phrases,
        recommendations=record.recommendations,
        metadata={"raw_content": record.raw_content},
        created_at=record.created_at,
    )


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """Remove a scan record from history."""
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    db.delete(record)
    db.commit()
    return None
