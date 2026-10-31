from typing import List, Dict, Any, Tuple, Optional
from collections import defaultdict
from app.schemas.scan import ThreatIndicator, SocialEngineeringTactic, UrlAnalysisItem


class RiskEngine:
    """
    Intelligent Risk Scoring and Assessment Engine.
    Combines rule-based indicators, psychological tactics, structural URL analyses,
    and local ML classification. Avoids double counting, normalizes scores (0-100),
    and computes explainable threat levels, confidence ratings, and safety guidance.
    """

    @staticmethod
    def classify_score(score: float) -> str:
        """
        Maps numerical score (0-100) to standardized risk tiers:
        - LOW: 0–24
        - MEDIUM: 25–49
        - HIGH: 50–74
        - CRITICAL: 75–100
        """
        if score >= 75.0:
            return "CRITICAL"
        elif score >= 50.0:
            return "HIGH"
        elif score >= 25.0:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def determine_threat_classification(score: float, indicators: List[ThreatIndicator]) -> str:
        """
        Distinguishes confirmed threats from suspicious anomalies or benign traffic.
        Returns: 'CONFIRMED_THREAT', 'SUSPICIOUS', or 'BENIGN'.
        """
        has_critical_indicators = any(ind.severity == "critical" for ind in indicators)
        has_credential_harvest = any(ind.category in ["Credential Theft", "Impersonation"] and ind.score_impact >= 40 for ind in indicators)

        if score >= 75.0 or (has_critical_indicators and has_credential_harvest):
            return "CONFIRMED_THREAT"
        elif score >= 25.0 or len(indicators) > 0:
            return "SUSPICIOUS"
        return "BENIGN"

    @classmethod
    def evaluate(
        cls,
        indicators: List[ThreatIndicator],
        ml_score: float = 0.0,
        url_analyses: Optional[List[UrlAnalysisItem]] = None,
        is_benign_exempt: bool = False,
    ) -> Dict[str, Any]:
        """
        Computes composite risk score, explanations, confidence rating, and safety guidance.
        """
        if is_benign_exempt:
            return {
                "risk_score": 0.0,
                "risk_level": "LOW",
                "classification": "BENIGN",
                "confidence_score": 0.95,
                "confidence_label": "HIGH",
                "explanations": ["Message matched verified transactional alert structure with no embedded links or credential demands."],
                "recommendations": ["No safety actions required. Legitimate transactional message."],
                "limitations": [],
                "score_breakdown": [],
            }

        # 1. Deduplication & Diminishing Returns across indicator categories
        # Prevents double-counting duplicate phrases across social engineering and message scanners
        category_groups = defaultdict(list)
        seen_names = set()

        for ind in indicators:
            # Dedup exact same name + category combinations
            key = f"{ind.category}::{ind.name}"
            if key not in seen_names:
                seen_names.add(key)
                category_groups[ind.category].append(ind)

        category_scores: Dict[str, float] = {}
        score_breakdown: List[Dict[str, Any]] = []

        for category, group_inds in category_groups.items():
            # Sort indicators in category by impact descending
            sorted_inds = sorted(group_inds, key=lambda x: x.score_impact, reverse=True)
            # Primary indicator gets full impact (100%)
            cat_score = sorted_inds[0].score_impact
            score_breakdown.append({
                "source": sorted_inds[0].name,
                "category": category,
                "contribution": round(cat_score, 1),
                "type": "primary_indicator"
            })

            # Secondary indicators in same category get diminishing returns (40% weight) to avoid inflation
            for secondary in sorted_inds[1:]:
                diminished = secondary.score_impact * 0.40
                cat_score += diminished
                score_breakdown.append({
                    "source": secondary.name,
                    "category": category,
                    "contribution": round(diminished, 1),
                    "type": "diminishing_secondary"
                })

            category_scores[category] = cat_score

        heuristic_raw_score = sum(category_scores.values())

        # 2. Blend Heuristic Score with ML Classification Output
        # Rule-based heuristics carry 70% weight; ML carries 30% weight
        if ml_score > 0 and heuristic_raw_score > 0:
            blended = (heuristic_raw_score * 0.70) + (ml_score * 0.30)
            score_breakdown.append({
                "source": "Local ML TF-IDF Classifier",
                "category": "Machine Learning",
                "contribution": round(ml_score * 0.30, 1),
                "type": "ml_blend"
            })
        elif heuristic_raw_score > 0:
            blended = heuristic_raw_score
        elif ml_score >= 60.0:
            # Only ML fired strongly (unfamiliar phrasing with high vocabulary similarity)
            # Cap at 45.0 (MEDIUM) so purely statistical ML never accuses without corroborating rules
            blended = min(45.0, ml_score * 0.45)
            score_breakdown.append({
                "source": "Local ML TF-IDF Classifier (Uncorroborated)",
                "category": "Machine Learning",
                "contribution": round(blended, 1),
                "type": "ml_standalone_capped"
            })
        else:
            blended = 0.0

        # Enforce hard critical floor if severe combinations are present
        has_critical_indicators = any(ind.severity == "critical" for ind in indicators)
        has_spoofed_link = False
        if url_analyses:
            has_spoofed_link = any(
                u.is_ip_address or u.has_brand_lookalike or u.has_homoglyphs or len(u.suspicious_indicators) > 0
                for u in url_analyses
            )

        if has_critical_indicators and has_spoofed_link:
            blended = max(80.0, blended)
        elif has_critical_indicators and ml_score >= 70.0:
            blended = max(78.0, blended)

        final_score = round(max(0.0, min(100.0, blended)), 1)
        risk_level = cls.classify_score(final_score)
        classification = cls.determine_threat_classification(final_score, indicators)

        # 3. Calculate Confidence & Uncertainty
        confidence_score, confidence_label, uncertainty_notes = cls._calculate_confidence(
            indicators=indicators,
            ml_score=ml_score,
            final_score=final_score,
            url_analyses=url_analyses or [],
        )

        # 4. Formulate Detailed Explanations
        explanations = cls._generate_explanations(
            final_score=final_score,
            risk_level=risk_level,
            classification=classification,
            category_scores=category_scores,
            indicators=indicators,
            ml_score=ml_score,
            url_analyses=url_analyses or [],
        )

        # 5. Formulate Actionable Safety Recommendations
        recommendations = cls._generate_recommendations(indicators, risk_level, url_analyses or [])

        # 6. Document System Limitations
        limitations = [
            "URL structural inspection is conducted offline without active network resolution; live domain status or newly parked domains cannot be verified without outbound network queries.",
            "Local machine learning model provides statistical pattern recognition over vocabulary; novel obfuscation techniques may require heuristic indicator review.",
            "Threat classifications are advisory and designed to empower users, not to replace official enterprise identity verification."
        ]

        return {
            "risk_score": final_score,
            "risk_level": risk_level,
            "classification": classification,
            "confidence_score": confidence_score,
            "confidence_label": confidence_label,
            "uncertainty_notes": uncertainty_notes,
            "explanations": explanations,
            "recommendations": recommendations,
            "limitations": limitations,
            "score_breakdown": score_breakdown,
        }

    @staticmethod
    def _calculate_confidence(
        indicators: List[ThreatIndicator],
        ml_score: float,
        final_score: float,
        url_analyses: List[UrlAnalysisItem],
    ) -> Tuple[float, str, str]:
        """Calculates confidence score (0.0 to 1.0) and uncertainty descriptions."""
        if final_score == 0.0 and len(indicators) == 0:
            return 0.95, "HIGH", "No suspicious indicators detected across structural, heuristic, and linguistic analysis vectors."

        distinct_categories = len(set(ind.category for ind in indicators))
        has_url_analysis = len(url_analyses) > 0

        # Multi-vector convergence yields highest confidence
        if distinct_categories >= 3 and has_url_analysis and ml_score >= 50.0:
            return 0.95, "HIGH", "High confidence: Multi-vector convergence across heuristics, psychological triggers, deceptive URL structure, and ML linguistic patterns."
        elif distinct_categories >= 2 or (distinct_categories >= 1 and ml_score >= 50.0):
            return 0.85, "HIGH", "Solid confidence: Multiple corroborating threat indicators detected across independent analysis engines."
        elif distinct_categories == 1:
            return 0.65, "MEDIUM", "Moderate confidence: Threat score driven by isolated category markers without full multi-vector corroboration."
        else:
            return 0.50, "LOW", "Higher uncertainty: Limited feature overlap detected; verify independently before taking critical action."

    @staticmethod
    def _generate_explanations(
        final_score: float,
        risk_level: str,
        classification: str,
        category_scores: Dict[str, float],
        indicators: List[ThreatIndicator],
        ml_score: float,
        url_analyses: List[UrlAnalysisItem],
    ) -> List[str]:
        explanations = []

        if final_score == 0:
            explanations.append("The analyzed content contains standard conversational or transactional vocabulary with zero threat indicators.")
            return explanations

        explanations.append(
            f"Assigned a {risk_level} risk level ({final_score}/100) and classified as {classification} based on {len(indicators)} detected threat indicator(s)."
        )

        # Highlight top category contributors
        for cat, sc in sorted(category_scores.items(), key=lambda x: x[1], reverse=True)[:3]:
            explanations.append(f"Significant risk contribution (+{round(sc, 1)} pts) from '{cat}' tactics.")

        if ml_score >= 60.0:
            explanations.append(f"Local ML model independently flagged text structure as matching known phishing campaigns with {ml_score}% statistical probability.")

        for url_item in url_analyses:
            if url_item.is_ip_address:
                explanations.append(f"Deceptive structural hazard: URL targets raw IP address ({url_item.hostname}) rather than a verified domain name.")
            if url_item.has_brand_lookalike:
                explanations.append(f"Impersonation risk: Domain or subdomain appears to spoof brand identity on host '{url_item.hostname}'.")
            if url_item.has_homoglyphs:
                explanations.append("Visual deception: URL contains non-standard homoglyph characters designed to deceive human eyes.")

        return explanations

    @staticmethod
    def _generate_recommendations(
        indicators: List[ThreatIndicator],
        risk_level: str,
        url_analyses: List[UrlAnalysisItem],
    ) -> List[str]:
        recommendations = []
        categories = {ind.category.lower() for ind in indicators}

        if risk_level in ["CRITICAL", "HIGH"]:
            recommendations.append("Do NOT click any hyperlinks, download attachments, or call phone numbers listed in this message.")
            recommendations.append("Do NOT reply with SMS verification codes, OTPs, debit card PINs, or personal identity details.")
        
        if "credential theft" in categories or "otp" in categories:
            recommendations.append("Remember: Official services (Google, WhatsApp, Chase, PayPal) will NEVER ask you to forward an SMS OTP code.")

        if "impersonation" in categories or "financial institution impersonation" in categories:
            recommendations.append("If concerned about your account status, independently open your bank or provider's official app or type their known URL directly into your browser.")

        if "fear" in categories or "urgency" in categories:
            recommendations.append("Disregard artificial time limits: Threat actors manufacture urgency and legal threats to prevent you from consulting others.")

        if "fake rewards" in categories or "lottery / prize" in categories or "employment fraud" in categories:
            recommendations.append("Be skeptical of unsolicited prizes or high-paying remote job offers requiring upfront fees or communication on Telegram.")

        if any(u.is_ip_address or u.has_brand_lookalike or u.is_shortener for u in url_analyses):
            recommendations.append("Inspect the address bar domain carefully before entering credentials. Never enter passwords on numeric IP addresses or shortened links.")

        if not recommendations:
            recommendations.append("No obvious threat indicators detected. Continue practicing general security vigilance before sharing sensitive data.")

        return recommendations
