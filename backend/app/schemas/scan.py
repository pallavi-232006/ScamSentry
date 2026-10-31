from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class MessageScanRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=10000, description="Message text (SMS, email, WhatsApp) to analyze")
    source_type: Optional[str] = Field("auto", description="Source type: sms, email, whatsapp, or auto")


class UrlScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="URL to inspect structurally without network requests")


class ThreatIndicator(BaseModel):
    name: str
    category: str  # Urgency, Credential Theft, Financial, Impersonation, URL Deception, etc.
    severity: str  # info, warning, high, critical
    score_impact: float
    description: str

    model_config = ConfigDict(from_attributes=True)


class SocialEngineeringTactic(BaseModel):
    name: str
    category: str
    evidence: str
    explanation: str
    severity: str
    score_impact: float

    model_config = ConfigDict(from_attributes=True)


class UrlAnalysisItem(BaseModel):
    raw_url: str
    scheme: str
    hostname: str
    domain: str
    port: Optional[int] = None
    path: str
    query_params: Dict[str, Any] = {}
    is_ip_address: bool = False
    is_shortener: bool = False
    has_https: bool = True
    has_homoglyphs: bool = False
    has_brand_lookalike: bool = False
    suspicious_indicators: List[ThreatIndicator] = []

    model_config = ConfigDict(from_attributes=True)


class ScanResponse(BaseModel):
    # Existing legacy contract fields (preserves frontend & existing tests)
    id: Optional[int] = None
    scan_type: str = "message"  # "message" or "url"
    target_summary: str
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Risk score from 0 to 100")
    threat_level: str = Field(..., description="LOW, MEDIUM, HIGH, or CRITICAL")
    category: str
    indicators: List[ThreatIndicator] = []
    suspicious_phrases: List[str] = []
    recommendations: List[str] = []
    metadata: Dict[str, Any] = {}
    created_at: datetime

    # Module 6 Explainable Threat Report extensions
    risk_level: str = "LOW"
    classification: str = "BENIGN"  # BENIGN, SUSPICIOUS, or CONFIRMED_THREAT
    summary: str = ""
    detected_indicators: List[ThreatIndicator] = []
    social_engineering_tactics: List[SocialEngineeringTactic] = []
    url_analysis: List[UrlAnalysisItem] = []
    ml_analysis: Dict[str, Any] = {}
    explanations: List[str] = []
    limitations: List[str] = []

    model_config = ConfigDict(from_attributes=True)


class ScanRecordSummary(BaseModel):
    id: int
    scan_type: str
    target_summary: str
    risk_score: float
    threat_level: str
    category: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
