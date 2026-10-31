from typing import List, Dict, Any, Tuple
from app.schemas.scan import ThreatIndicator


class RiskEngine:
    """
    Intelligent Risk Engine.
    Aggregates multi-source threat indicators, computes a normalized score (0-100),
    and assigns a contextual threat classification without claiming false certainty.
    """

    @staticmethod
    def classify_score(score: float) -> str:
        if score >= 85.0:
            return "CRITICAL"
        elif score >= 60.0:
            return "HIGH"
        elif score >= 30.0:
            return "MEDIUM"
        return "LOW"

    @classmethod
    def evaluate(
        cls,
        indicators: List[ThreatIndicator],
        base_ml_score: float = 0.0,
    ) -> Tuple[float, str, List[str]]:
        """
        Calculates cumulative risk score, assigns threat level, and provides actionable recommendations.
        """
        # Sum rule-based impacts
        rule_score = sum(ind.score_impact for ind in indicators)

        # Blend rule-based heuristic score with ML model probability if available
        # ML score is 0-100
        if base_ml_score > 0:
            blended_score = (rule_score * 0.65) + (base_ml_score * 0.35)
        else:
            blended_score = rule_score

        # Clamp score between 0.0 and 100.0
        final_score = round(max(0.0, min(100.0, blended_score)), 1)
        threat_level = cls.classify_score(final_score)

        # Build contextual recommendations based on detected categories
        recommendations = cls.generate_recommendations(indicators, threat_level)

        return final_score, threat_level, recommendations

    @staticmethod
    def generate_recommendations(indicators: List[ThreatIndicator], threat_level: str) -> List[str]:
        recommendations = []
        categories = {ind.category.lower() for ind in indicators}

        if threat_level in ["CRITICAL", "HIGH"]:
            recommendations.append("Do NOT click any links, download attachments, or call provided phone numbers.")
            recommendations.append("Do NOT reply with OTP codes, passwords, or personal identification details.")
        
        if "financial" in categories or "credential theft" in categories:
            recommendations.append("Verify the transaction or request directly through your bank or service provider's official app.")
        
        if "urgency" in categories or "fear" in categories:
            recommendations.append("Be wary of artificial deadlines: legitimate institutions rarely demand immediate action under penalty threats.")
            
        if "url deception" in categories or "shortener" in categories:
            recommendations.append("Check the root domain name in your browser address bar before interacting with any web page.")

        if not recommendations:
            recommendations.append("No obvious threat patterns detected. Always remain vigilant before sharing sensitive information.")

        return recommendations
