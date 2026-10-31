import re
from typing import List, Dict, Any, Tuple
from app.schemas.scan import ThreatIndicator
from app.core.social_engineering import SocialEngineeringAnalyzer
from app.core.url_scanner import UrlScanner

# Credential & OTP solicitation patterns
CREDENTIAL_PATTERNS = [
    (r"\b(one-time\s+passcode|otp|verification\s+code|2fa\s+code)\b", "OTP Harvesting Request", 40.0),
    (r"\b(password|pin\s+number|security\s+answer|secret\s+key)\b", "Direct Credential Request", 45.0),
    (r"\b(verify\s+your\s+identity|confirm\s+your\s+ssn|social\s+security)\b", "Identity Theft Solicitation", 40.0),
]

# Financial manipulation patterns
FINANCIAL_PATTERNS = [
    (r"\b(bank\s+transfer|wire\s+transfer|crypto|bitcoin|gift\s+card\s+payment)\b", "Unconventional Payment Demand", 35.0),
    (r"\b(account\s+suspended|unauthorized\s+charge|overdue\s+invoice|refund\s+pending)\b", "Financial Panic Baiting", 30.0),
    (r"\b(billing\s+failure|payment\s+declined|update\s+billing\s+info)\b", "Billing Fraud Phishing", 35.0),
]


class MessageScanner:
    """
    Message threat analyzer for SMS, WhatsApp, and email messages.
    Combines regex heuristics, social engineering detection, and embedded URL extraction.
    """

    @classmethod
    def scan(cls, message: str, source_type: str = "auto") -> Tuple[List[ThreatIndicator], List[str], Dict[str, Any]]:
        indicators: List[ThreatIndicator] = []
        suspicious_phrases: List[str] = []
        metadata: Dict[str, Any] = {"char_count": len(message), "source_type": source_type}

        lower_message = message.lower()

        # 1. Credential & OTP solicitation
        for pattern, name, score_impact in CREDENTIAL_PATTERNS:
            matches = re.findall(pattern, lower_message)
            if matches:
                indicators.append(
                    ThreatIndicator(
                        name=name,
                        category="Credential Theft",
                        severity="critical",
                        score_impact=score_impact,
                        description=f"Message solicits sensitive credentials ({', '.join(set(matches))}) which reputable services never ask via text.",
                    )
                )
                suspicious_phrases.extend(matches)

        # 2. Financial manipulation
        for pattern, name, score_impact in FINANCIAL_PATTERNS:
            matches = re.findall(pattern, lower_message)
            if matches:
                indicators.append(
                    ThreatIndicator(
                        name=name,
                        category="Financial",
                        severity="high",
                        score_impact=score_impact,
                        description=f"Manipulative financial trigger detected: '{matches[0]}'.",
                    )
                )
                suspicious_phrases.extend(matches)

        # 3. Social engineering & psychological manipulation
        se_indicators, se_phrases = SocialEngineeringAnalyzer.analyze(message)
        indicators.extend(se_indicators)
        suspicious_phrases.extend(se_phrases)

        # 4. Embedded URL detection and cross-scan
        url_regex = r"(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.(?:com|org|net|xyz|top|ru|cn|tk)[^\s]*)"
        found_urls = re.findall(url_regex, message)
        metadata["embedded_urls"] = found_urls

        if found_urls:
            indicators.append(
                ThreatIndicator(
                    name="Embedded External Link",
                    category="URL Deception",
                    severity="warning",
                    score_impact=15.0,
                    description=f"Contains {len(found_urls)} hyperlink(s). Phishing campaigns consistently rely on embedded links to steal credentials.",
                )
            )
            for raw_u in found_urls[:3]:  # Deep inspect up to 3 links
                url_indicators, url_phrases, _ = UrlScanner.scan(raw_u)
                indicators.extend(url_indicators)
                suspicious_phrases.extend(url_phrases)

        return indicators, list(set(suspicious_phrases)), metadata
