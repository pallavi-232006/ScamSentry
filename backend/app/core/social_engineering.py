import re
from typing import List, Tuple, Dict, Any
from app.schemas.scan import ThreatIndicator, SocialEngineeringTactic

# Defined Psychological Persuasion Vectors
TACTIC_DEFINITIONS = [
    {
        "name": "Artificial Urgency Trigger",
        "category": "Urgency",
        "severity": "high",
        "score_impact": 22.0,
        "patterns": [
            r"\b(within\s+\d+\s+(?:hours?|minutes?|days?))\b",
            r"\b(immediate(?:ly)?|act\s+now|urgent(?:ly)?|deadline|expires?\s+today)\b",
            r"\b(don'?t\s+wait|time\s+is\s+running\s+out|last\s+chance|closing\s+soon)\b",
            r"\b(24\s+hours|48\s+hours|limited\s+time|in\s+\d+\s+minutes?)\b",
            r"\b(before\s+midnight|within\s+2\s+hours)\b",
        ],
        "explanation": "Applies artificial time pressure to induce panic and force impulsive compliance before the victim can reflect or verify with official sources.",
    },
    {
        "name": "Fear & Intimidation Tactics",
        "category": "Fear",
        "severity": "critical",
        "score_impact": 30.0,
        "patterns": [
            r"\b(arrest\s+warrant|lawsuit|legal\s+action|police|sheriff|felony\s+charges)\b",
            r"\b(face\s+detention|prosecution|subpoena|confiscated|seized)\b",
            r"\b(permanently\s+(?:closed|suspended|disabled|deleted)|account\s+locked)\b",
            r"\b(power\s+service\s+will\s+be\s+disconnected|service\s+disconnected)\b",
            r"\b(malware\s+and\s+illegal\s+footage|webcam|video\s+evidence)\b",
            r"\b(license\s+will\s+be\s+revoked|digital\s+arrest|drugs\s+in\s+your\s+courier)\b",
        ],
        "explanation": "Uses punitive threats (arrest, lawsuit, extortion, account termination) to provoke severe anxiety and overpower critical judgment.",
    },
    {
        "name": "Authority Impersonation",
        "category": "Authority",
        "severity": "high",
        "score_impact": 25.0,
        "patterns": [
            r"\b(internal\s+revenue(?:\s+service)?|irs|fbi|federal\s+reserve|homeland\s+security)\b",
            r"\b(social\s+security\s+administration|immigration\s+officer|state\s+police)\b",
            r"\b(cbi|central\s+bureau\s+of\s+investigation|enforcement\s+directorate|cyber\s+crime\s+cell|narcotics\s+control\s+bureau|mumbai\s+police)\b",
            r"\b(fraud\s+prevention\s+department|security\s+(?:desk|team|department))\b",
            r"\b(head\s+of\s+security|it\s+administrator|system\s+administrator)\b",
            r"\b(customs\s+clearance|barrister|federal\s+agent)\b",
        ],
        "explanation": "Impersonates recognized government agencies, legal entities, or institutional security departments to command unquestioned compliance.",
    },
    {
        "name": "Fake Financial Rewards & Greed",
        "category": "Fake Rewards",
        "severity": "high",
        "score_impact": 25.0,
        "patterns": [
            r"\b(you\s+won|selected\s+as\s+(?:the\s+)?winner|lottery\s+jackpot|claim\s+your\s+prize)\b",
            r"\b(free\s+\$?\d+[\d,]*\s+(?:walmart\s+)?gift\s+card|crypto\s+giveaway)\b",
            r"\b(giving\s+away\s+\d+\s+ethereum|unclaimed\s+(?:funds|assets))\b",
            r"\b(million\s+(?:dollars|pounds|euro|usd)|sweepstakes\s+winner)\b",
            r"\b(guaranteed\s+\d+%\s+profit|passive\s+income|1000x\s+gem)\b",
        ],
        "explanation": "Exploits financial aspiration or greed through fabricated sweepstakes, unearned wealth, or deceptive high-yield investment claims.",
    },
    {
        "name": "Scarcity & Exclusivity Tactics",
        "category": "Scarcity",
        "severity": "warning",
        "score_impact": 18.0,
        "patterns": [
            r"\b(limited\s+to\s+(?:the\s+)?first\s+\d+\s+(?:participants|respondents|users))\b",
            r"\b(exclusive\s+vip|only\s+\d+\s+spots?\s+left|pre-?sale\s+closes\s+in)\b",
            r"\b(do\s+not\s+miss\s+out|once\s+in\s+a\s+lifetime)\b",
        ],
        "explanation": "Manufactures artificial scarcity to create FOMO (Fear Of Missing Out), nudging victims into hasty commitments.",
    },
    {
        "name": "Emotional & Distress Manipulation",
        "category": "Emotional Manipulation",
        "severity": "critical",
        "score_impact": 28.0,
        "patterns": [
            r"\b(dropped\s+my\s+phone\s+in\s+water|this\s+is\s+my\s+temporary\s+number)\b",
            r"\b(in\s+hospital|car\s+repair\s+shop\s+and\s+my\s+card\s+is\s+declined)\b",
            r"\b(urgent(?:ly)?\s+need\s+(?:cash|money)|please\s+send\s+\$?\d+\s+via\s+zelle)\b",
            r"\b(emergency\s+situation|stranded\s+at\s+the\s+airport)\b",
        ],
        "explanation": "Impersonates a family member or friend in crisis to exploit emotional empathy and bypass financial verification routines.",
    },
    {
        "name": "Confidentiality & Secrecy Pressure",
        "category": "Confidentiality Pressure",
        "severity": "high",
        "score_impact": 22.0,
        "patterns": [
            r"\b(keep\s+this\s+matter\s+strictly\s+(?:secret|confidential))\b",
            r"\b(do\s+not\s+(?:discuss|tell|mention\s+this\s+to)\s+(?:anyone|your\s+bank(?:\s+teller)?|family))\b",
            r"\b(strictly\s+private\s+and\s+confidential|keep\s+it\s+between\s+us)\b",
        ],
        "explanation": "Coerces the victim to isolate themselves from third-party advice, preventing friends, family, or bank staff from intervening.",
    },
    {
        "name": "Procedure Evasion & Unorthodox Channels",
        "category": "Procedure Evasion",
        "severity": "critical",
        "score_impact": 28.0,
        "patterns": [
            r"\b(pay\s+(?:via|with|using)\s+(?:apple|target|google\s+play|steam|amazon)?\s*gift\s+cards?)\b",
            r"\b(greendot\s+moneypak|western\s+union|wire\s+transfer\s+to\s+personal)\b",
            r"\b(send\s+(?:bitcoin|btc|usdt|eth|sol)\s+directly\s+to\s+wallet)\b",
            r"\b((?:whatsapp|telegram)\s+(?:recruitment|recruiter|hr)|contact.*?(?:on\s+)?(?:telegram|whatsapp)\s+@\w+|telegram\s+@\w+)\b",
            r"\b(skip\s+verification|bypass\s+security\s+check)\b",
        ],
        "explanation": "Instructs victims to route transactions through non-refundable, anonymous, or unconventional channels outside protected payment systems.",
    },
]

# Innocent context suppressors (phrases that often match trigger words harmlessly)
INNOCENT_EXEMPTIONS = [
    r"\b(feel\s+free\s+to)\b",
    r"\b(free\s+admission\s+to)\b",
    r"\b(free\s+(?:coffee|donuts|parking|wifi|trial))\b",
    r"\b(are\s+you\s+(?:still\s+)?free\s+for\s+lunch)\b",
    r"\b(urgent\s+meeting\s+reminder)\b",
    r"\b(urgent\s+bug\s+fix)\b",
    r"\b(urgent\s+weather\s+advisory)\b",
    r"\b(urgent\s+reminder\s+from\s+hr)\b",
    r"\b(congratulations\s+to\s+our\s+employee)\b",
    r"\b(congratulations\s+on\s+passing)\b",
]


class SocialEngineeringAnalyzer:
    """
    Analyzes psychological persuasion and social engineering tactics:
    - Artificial Urgency
    - Fear & Threats
    - Authority Impersonation
    - Fake Financial Rewards & Greed
    - Scarcity & Exclusivity
    - Emotional & Distress Manipulation
    - Confidentiality Pressure
    - Procedure Evasion & Unorthodox Channels
    """

    @classmethod
    def analyze(cls, text: str) -> Tuple[List[ThreatIndicator], List[SocialEngineeringTactic], List[str]]:
        indicators: List[ThreatIndicator] = []
        tactics: List[SocialEngineeringTactic] = []
        matched_phrases: List[str] = []

        if not text or not text.strip():
            return indicators, tactics, matched_phrases

        lower_text = text.lower()

        # Check for pure innocent context without phishing markers
        innocent_hits = []
        for pat in INNOCENT_EXEMPTIONS:
            matches = re.findall(pat, lower_text)
            if matches:
                innocent_hits.extend(matches)

        for definition in TACTIC_DEFINITIONS:
            found_evidence = []
            for pat in definition["patterns"]:
                matches = re.finditer(pat, lower_text, re.IGNORECASE)
                for m in matches:
                    matched_str = m.group(0).strip()
                    # Filter out if matched word is embedded in an innocent context
                    # e.g., 'free' inside 'feel free to'
                    if definition["category"] in ["Urgency", "Fake Rewards"] and innocent_hits:
                        # Check if match is part of the innocent hit
                        if any(matched_str in hit for hit in innocent_hits):
                            continue
                    found_evidence.append(matched_str)

            if found_evidence:
                unique_evidence = list(dict.fromkeys(found_evidence))  # preserve order
                evidence_summary = ", ".join(f'"{e}"' for e in unique_evidence[:3])

                # Build SocialEngineeringTactic object
                tactic_obj = SocialEngineeringTactic(
                    name=definition["name"],
                    category=definition["category"],
                    evidence=evidence_summary,
                    explanation=definition["explanation"],
                    severity=definition["severity"],
                    score_impact=definition["score_impact"],
                )
                tactics.append(tactic_obj)

                # Build ThreatIndicator for pipeline compatibility
                indicator_obj = ThreatIndicator(
                    name=definition["name"],
                    category=definition["category"],
                    severity=definition["severity"],
                    score_impact=definition["score_impact"],
                    description=f"{definition['explanation']} Evidence: {evidence_summary}",
                )
                indicators.append(indicator_obj)
                matched_phrases.extend(unique_evidence)

        return indicators, tactics, list(set(matched_phrases))
