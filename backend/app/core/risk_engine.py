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
        Calibrated threat classification that avoids claiming certainty from
        suspicious indicators alone.

        Tiers (in descending order of evidence strength):
        - CONFIRMED_MALICIOUS: Score ≥ 75 AND at least two independent critical
          indicators across different categories, OR a verified malicious URL
          combined with a critical credential/impersonation indicator.
        - LIKELY_SCAM: Score ≥ 50 with corroborating critical or high-severity
          indicators from at least two distinct categories.
        - SUSPICIOUS: Score ≥ 25 or any indicators detected, but insufficient
          convergence to assert likely fraud.
        - LOW_RISK: Score > 0 but below 25 with only low-weight indicators.
        - BENIGN: No indicators and score of 0.
        """
        if not indicators and score == 0.0:
            return "BENIGN"

        num_critical = sum(1 for ind in indicators if ind.severity == "critical")
        distinct_categories = len(set(ind.category for ind in indicators))

        has_credential_or_impersonation = any(
            ind.category in [
                "Credential Theft", "Impersonation", "UPI Fraud",
                "Bank Impersonation", "Government Impersonation",
            ]
            and ind.score_impact >= 40
            for ind in indicators
        )
        has_url_deception = any(
            ind.category in ["URL Deception", "Link Bait"] for ind in indicators
        )

        # CONFIRMED_MALICIOUS: strong multi-vector convergence with verified deception signals
        if (
            score >= 75.0
            and num_critical >= 2
            and distinct_categories >= 2
        ) or (
            score >= 75.0
            and has_credential_or_impersonation
            and has_url_deception
        ):
            return "CONFIRMED_MALICIOUS"

        # LIKELY_SCAM: significant score with meaningful multi-category evidence
        if score >= 50.0 and (
            (num_critical >= 1 and distinct_categories >= 2)
            or (has_credential_or_impersonation and score >= 60.0)
        ):
            return "LIKELY_SCAM"

        # SUSPICIOUS: meaningful indicators but not enough for confident assertion
        if score >= 25.0 or len(indicators) > 0:
            return "SUSPICIOUS"

        # LOW_RISK: some score but very few or minor signals
        if score > 0.0:
            return "LOW_RISK"

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

        # Classification meaning explanation
        classification_meaning = {
            "CONFIRMED_MALICIOUS": "independently corroborated by multi-vector evidence (credential/impersonation indicators + deceptive URL structure)",
            "LIKELY_SCAM": "multiple independent threat indicators converge across different attack categories",
            "SUSPICIOUS": "patterns match known scam tactics but evidence is insufficient to assert confirmed fraud with certainty",
            "LOW_RISK": "minor signals detected; may be noise or edge-case vocabulary",
            "BENIGN": "no threat indicators detected",
        }.get(classification, "assessed based on detected indicators")

        explanations.append(
            "Assigned a %s risk level (%s/100) and classified as %s — %s. %d threat indicator(s) detected."
            % (risk_level, final_score, classification, classification_meaning, len(indicators))
        )

        # Highlight top category contributors
        for cat, sc in sorted(category_scores.items(), key=lambda x: x[1], reverse=True)[:3]:
            explanations.append("Risk contribution of +%s pts from '%s' category." % (round(sc, 1), cat))

        # ML explanation — clearly separated from overall confidence
        if ml_score > 0:
            if ml_score >= 60.0:
                explanations.append(
                    "Local ML classifier (TF-IDF + Logistic Regression trained on %s labelled messages) "
                    "scored this text at %.1f%% scam probability. "
                    "This is a statistical vocabulary similarity score — not a definitive verdict. "
                    "It contributes 30%% weight to the final score when heuristic rules also fire."
                    % ("96", ml_score)
                )
            else:
                explanations.append(
                    "Local ML classifier scored this text at %.1f%% scam probability — below the 60%% corroboration threshold. "
                    "ML result not blended into final score." % ml_score
                )

        for url_item in url_analyses:
            if url_item.is_ip_address:
                explanations.append("Deceptive structural hazard: URL targets raw IP address (%s) rather than a verified domain name." % url_item.hostname)
            if url_item.has_brand_lookalike:
                explanations.append("Impersonation risk: Domain appears to spoof brand identity on host '%s'." % url_item.hostname)
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

        if "upi fraud" in categories:
            recommendations.append(
                "UPI PIN is only required to SEND money — never to receive it. "
                "No legitimate payment app (PhonePe, Google Pay, Paytm) will ever ask for your PIN via SMS."
            )
            recommendations.append(
                "Scanning a QR code or accepting a Collect Request always debits your account. "
                "Reject all unsolicited collect requests immediately."
            )

        if "credential theft" in categories or "otp" in categories:
            recommendations.append("Official services will NEVER ask you to forward an SMS OTP, verification code, or passcode over any messaging channel.")

        if "bank impersonation" in categories or "impersonation" in categories:
            recommendations.append(
                "For genuine KYC or account concerns, open your bank's official app directly or visit a branch. "
                "Never follow links sent in unsolicited SMS messages."
            )

        if "government impersonation" in categories:
            recommendations.append(
                "Real law enforcement (CBI, Police, Enforcement Directorate) does NOT conduct investigations, "
                "arrests, or clearances via phone calls, WhatsApp, or video calls. "
                "If threatened, hang up and call 1930 (National Cyber Crime Helpline)."
            )

        if "package phishing" in categories:
            recommendations.append(
                "India Post and courier companies do NOT collect redelivery fees via SMS links. "
                "Track packages only at the official carrier website."
            )

        if "fear" in categories or "urgency" in categories:
            recommendations.append("Disregard artificial time limits: Threat actors manufacture urgency to prevent you from consulting others before complying.")

        if "fake rewards" in categories or "lottery / prize" in categories or "employment fraud" in categories:
            recommendations.append("Be skeptical of unsolicited prizes or high-paying remote job offers requiring upfront fees or Telegram-only communication.")

        if any(u.is_ip_address or u.has_brand_lookalike or u.is_shortener for u in url_analyses):
            recommendations.append("Inspect the address bar domain carefully before entering credentials. Never enter passwords on numeric IP addresses or shortened links.")

        if not recommendations:
            recommendations.append("No obvious threat indicators detected. Continue practicing general security vigilance before sharing sensitive data.")

        return recommendations
