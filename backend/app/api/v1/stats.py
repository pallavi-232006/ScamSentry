from datetime import datetime, timedelta, timezone
from collections import Counter, defaultdict
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db
from app.models.scan_record import ScanRecord
from app.schemas.stats import (
    DashboardStats,
    ThreatCategoryCount,
    ThreatLevelCount,
    ActivityTimePoint,
)

router = APIRouter(prefix="/stats", tags=["Dashboard Statistics"])


@router.get("/", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Computes aggregated metrics for the dashboard view."""
    records = db.query(ScanRecord).all()
    total_scans = len(records)

    # Fallback / Empty database response
    if total_scans == 0:
        # Generate an empty 7-day baseline so charts display cleanly
        now = datetime.now(timezone.utc)
        baseline_activity = [
            ActivityTimePoint(
                date=(now - timedelta(days=i)).strftime("%b %d"),
                scans=0,
                high_risk=0,
                safe=0,
            )
            for i in range(6, -1, -1)
        ]

        return DashboardStats(
            total_scans=0,
            high_risk_detections=0,
            suspicious_scans=0,
            safe_scans=0,
            average_risk_score=0.0,
            category_distribution=[],
            threat_level_distribution=[
                ThreatLevelCount(level="LOW", count=0),
                ThreatLevelCount(level="MEDIUM", count=0),
                ThreatLevelCount(level="HIGH", count=0),
                ThreatLevelCount(level="CRITICAL", count=0),
            ],
            activity_over_time=baseline_activity,
        )

    high_risk_count = sum(1 for r in records if r.threat_level in ["HIGH", "CRITICAL"])
    suspicious_count = sum(1 for r in records if r.threat_level == "MEDIUM")
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

    # Generate timeline activity points (last 7 distinct days or anchored dates)
    now = datetime.now(timezone.utc)
    day_buckets = defaultdict(lambda: {"scans": 0, "high_risk": 0, "safe": 0})

    # Pre-populate last 7 days keys
    for i in range(6, -1, -1):
        d_str = (now - timedelta(days=i)).strftime("%b %d")
        day_buckets[d_str] = {"scans": 0, "high_risk": 0, "safe": 0}

    for r in records:
        if r.created_at:
            d_str = r.created_at.strftime("%b %d")
            day_buckets[d_str]["scans"] += 1
            if r.threat_level in ["HIGH", "CRITICAL"]:
                day_buckets[d_str]["high_risk"] += 1
            elif r.threat_level == "LOW":
                day_buckets[d_str]["safe"] += 1

    activity_over_time = [
        ActivityTimePoint(
            date=d_key,
            scans=vals["scans"],
            high_risk=vals["high_risk"],
            safe=vals["safe"],
        )
        for d_key, vals in sorted(day_buckets.items(), key=lambda x: datetime.strptime(x[0], "%b %d").replace(year=now.year) if "%b %d" else now)
    ]

    # Keep last 7 to 10 points
    activity_over_time = activity_over_time[-7:]

    return DashboardStats(
        total_scans=total_scans,
        high_risk_detections=high_risk_count,
        suspicious_scans=suspicious_count,
        safe_scans=safe_count,
        average_risk_score=avg_score,
        category_distribution=category_distribution,
        threat_level_distribution=threat_level_distribution,
        activity_over_time=activity_over_time,
    )
