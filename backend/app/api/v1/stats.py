from collections import Counter
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.scan_record import ScanRecord
from app.schemas.stats import DashboardStats, ThreatCategoryCount, ThreatLevelCount

router = APIRouter(prefix="/stats", tags=["Dashboard Statistics"])


@router.get("/", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Computes aggregated metrics for the dashboard view."""
    records = db.query(ScanRecord).all()
    total_scans = len(records)

    if total_scans == 0:
        return DashboardStats(
            total_scans=0,
            high_risk_detections=0,
            safe_scans=0,
            average_risk_score=0.0,
            category_distribution=[],
            threat_level_distribution=[
                ThreatLevelCount(level="LOW", count=0),
                ThreatLevelCount(level="MEDIUM", count=0),
                ThreatLevelCount(level="HIGH", count=0),
                ThreatLevelCount(level="CRITICAL", count=0),
            ],
        )

    high_risk_count = sum(1 for r in records if r.threat_level in ["HIGH", "CRITICAL"])
    safe_count = sum(1 for r in records if r.threat_level == "LOW")
    avg_score = round(sum(r.risk_score for r in records) / total_scans, 1)

    cat_counts = Counter(r.category for r in records)
    category_distribution = [
        ThreatCategoryCount(category=cat, count=cnt) for cat, cnt in cat_counts.most_common(6)
    ]

    level_counts = Counter(r.threat_level for r in records)
    threat_level_distribution = [
        ThreatLevelCount(level="LOW", count=level_counts.get("LOW", 0)),
        ThreatLevelCount(level="MEDIUM", count=level_counts.get("MEDIUM", 0)),
        ThreatLevelCount(level="HIGH", count=level_counts.get("HIGH", 0)),
        ThreatLevelCount(level="CRITICAL", count=level_counts.get("CRITICAL", 0)),
    ]

    return DashboardStats(
        total_scans=total_scans,
        high_risk_detections=high_risk_count,
        safe_scans=safe_count,
        average_risk_score=avg_score,
        category_distribution=category_distribution,
        threat_level_distribution=threat_level_distribution,
    )

