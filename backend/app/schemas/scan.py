from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class MessageScanRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=10000, description="Message text (SMS, email, WhatsApp) to analyze")
    source_type: Optional[str] = Field("auto", description="Source type: sms, email, whatsapp, or auto")


class UrlScanRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048, description="URL to inspect structurally without network requests")


class ThreatIndicator(BaseModel):
    name: str
    category: str  # Urgency, Credential Theft, Financial, Impersonation, URL Deception, etc.
    severity: str  # info, warning, high, critical
    score_impact: float
    description: str


class ScanResponse(BaseModel):
    id: Optional[int] = None
    scan_type: str  # "message" or "url"
    target_summary: str
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Risk score from 0 to 100")
    threat_level: str = Field(..., description="LOW, MEDIUM, HIGH, or CRITICAL")
    category: str
    indicators: List[ThreatIndicator] = []
    suspicious_phrases: List[str] = []
    recommendations: List[str] = []
    metadata: Dict[str, Any] = {}
    created_at: datetime


class ScanRecordSummary(BaseModel):
    id: int
    scan_type: str
    target_summary: str
    risk_score: float
    threat_level: str
    category: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
