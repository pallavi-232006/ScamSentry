from datetime import datetime, timezone
import json
from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from app.database import Base


class ScanRecord(Base):
    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    scan_type = Column(String(50), nullable=False)  # "message", "url", "combined"
    target_summary = Column(String(255), nullable=False)  # Truncated or redacted preview
    raw_content = Column(Text, nullable=False)  # Stored content or URL
    risk_score = Column(Float, nullable=False)  # 0.0 to 100.0
    threat_level = Column(String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    category = Column(String(100), nullable=False, default="General")  # Phishing, Urgency, Credential Harvest, Safe, etc.
    indicators_json = Column(Text, nullable=False, default="[]")  # List of detected indicators
    phrases_json = Column(Text, nullable=False, default="[]")  # Suspicious phrases
    recommendations_json = Column(Text, nullable=False, default="[]")  # Safety recommendations
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    @property
    def indicators(self):
        try:
            return json.loads(self.indicators_json)
        except Exception:
            return []

    @indicators.setter
    def indicators(self, val):
        self.indicators_json = json.dumps(val or [])

    @property
    def phrases(self):
        try:
            return json.loads(self.phrases_json)
        except Exception:
            return []

    @phrases.setter
    def phrases(self, val):
        self.phrases_json = json.dumps(val or [])

    @property
    def recommendations(self):
        try:
            return json.loads(self.recommendations_json)
        except Exception:
            return []

    @recommendations.setter
    def recommendations(self, val):
        self.recommendations_json = json.dumps(val or [])
