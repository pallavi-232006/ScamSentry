import re
from typing import List, Tuple
from app.schemas.scan import ThreatIndicator


class SocialEngineeringAnalyzer:
    """
    Identifies psychological persuasion techniques such as:
    - Artificial Urgency
    - Fear & Intimidation
    - Authority Impersonation
    - Fake Rewards / Greed Triggers
    - Account Suspension Threats
    """

    PSYCHOLOGICAL_PATTERNS = [
        {
            "name": "Artificial Urgency Trigger",
            "category": "Urgency",
            "severity": "high",
            "score_impact": 30.0,
            "patterns": [
                r"\b(within\s+\d+\s+(hours?|minutes?|days?))\b",
                r"\b(immediate(ly)?|act\s+now|urgent(ly)?|deadline|expires?\s+today)\b",
                r"\b(don't\s+wait|time\s+is\s+running\s+out|last\s+chance)\b",
                r"\b(24\s+hours|48\s+hours|limited\s+time)\b"
            ],
            "description": "Applies artificial time pressure to induce panic and force impulsive compliance before the victim can reflect.",
        },
        {
            "name": "Fear & Intimidation Tactics",
            "category": "Fear",
            "severity": "critical",
            "score_impact": 40.0,
            "patterns": [
                r"\b(suspended|arrest\s+warrant|lawsuit|legal\s+action|police)\b",
                r"\b(terminated|permanently\s+closed|locked|confiscated)\b",
                r"\b(unauthorized\s+activity|security\s+breach|fraud\s+detected)\b"
            ],
            "description": "Uses punitive threats (legal action, arrest, account termination) to provoke anxiety and overcome caution.",
        },
        {
            "name": "Authority & Brand Impersonation",
            "category": "Impersonation",
            "severity": "high",
            "score_impact": 35.0,
            "patterns": [
                r"\b(internal\s+revenue|irs|fbi|federal\s+reserve|supreme\s+court)\b",
                r"\b(security\s+department|customer\s+support\s+desk|fraud\s+prevention\s+team)\b",
                r"\b(head\s+of\s+security|it\s+department|system\s+administrator)\b"
            ],
            "description": "Impersonates recognized institutions, law enforcement, or corporate IT staff to command obedience.",
        },
        {
            "name": "Fake Financial Rewards / Lottery",
            "category": "Greed / Reward",
            "severity": "high",
            "score_impact": 35.0,
            "patterns": [
                r"\b(congratulations|you\s+have\s+won|selected\s+as\s+the\s+winner|prize)\b",
                r"\b(lottery|jackpot|free\s+gift\s+card|crypto\s+giveaway|claim\s+your\s+\$?\d+)\b",
                r"\b(inheritance|unclaimed\s+funds|100%\s+free|bonus\s+credit)\b"
            ],
            "description": "Appeals to greed or unexpected fortune, baiting victims into disclosing bank accounts or paying processing fees.",
        },
    ]

    @classmethod
    def analyze(cls, text: str) -> Tuple[List[ThreatIndicator], List[str]]:
        indicators: List[ThreatIndicator] = []
        matched_phrases: List[str] = []
        lower_text = text.lower()

        for group in cls.PSYCHOLOGICAL_PATTERNS:
            found_matches = []
            for pat in group["patterns"]:
                matches = re.finditer(pat, lower_text, re.IGNORECASE)
                for m in matches:
                    found_matches.append(m.group(0))

            if found_matches:
                unique_matches = list(set(found_matches))
                indicators.append(
                    ThreatIndicator(
                        name=group["name"],
                        category=group["category"],
                        severity=group["severity"],
                        score_impact=group["score_impact"],
                        description=group["description"],
                    )
                )
                matched_phrases.extend(unique_matches)

        return indicators, list(set(matched_phrases))
