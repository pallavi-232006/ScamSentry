from typing import List, Dict
from pydantic import BaseModel


class ThreatCategoryCount(BaseModel):
    category: str
    count: int


class ThreatLevelCount(BaseModel):
    level: str  # LOW, MEDIUM, HIGH, CRITICAL
    count: int


class DashboardStats(BaseModel):
    total_scans: int
    high_risk_detections: int
    safe_scans: int
    average_risk_score: float
    category_distribution: List[ThreatCategoryCount]
    threat_level_distribution: List[ThreatLevelCount]

