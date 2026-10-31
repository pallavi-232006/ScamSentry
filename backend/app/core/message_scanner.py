import re
from typing import List, Dict, Any, Tuple
from app.schemas.scan import ThreatIndicator, SocialEngineeringTactic, UrlAnalysisItem
from app.core.social_engineering import SocialEngineeringAnalyzer
from app.core.url_scanner import UrlScanner

# 1. OTP Harvesting Patterns
OTP_HARVEST_PATTERNS = [
    (r"\b(?:reply\s+with|forward|send|share|enter)\s+(?:(?:your|the)\s+)?(?:[\w-]+\s+){0,3}(?:otp|verification\s+code|sms\s+code|passcode|token)\b", "OTP Harvesting Request", 45.0, "Credential Theft", "Message explicitly solicits a one-time verification passcode, which legitimate identity systems instruct users never to share."),
    (r"\b(?:whatsapp|google|uber|telegram)\s+(?:security\s+)?code\s+was\s+requested\b", "Unsolicited 2FA Request Baiting", 35.0, "Credential Theft", "Alerts about an unsolicited security code to induce the recipient into forwarding it."),
    (r"\b(?:accidentally|by\s+mistake)\s+sent\s+(?:my\s+)?(?:\d+[- ]digit\s+)?(?:code|otp)\b", "Accidental Code Forwarding Trick", 45.0, "Credential Theft", "Classic social engineering trick claiming a verification code was sent by mistake to steal the victim's account registration."),
]

# 2. Password & Credential Theft
CREDENTIAL_THEFT_PATTERNS = [
    (r"\b(?:enter|provide|confirm|verify)\s+(?:your\s+)?(?:[\w\s,]+)?(?:password|pin|cvv|security\s+code|ssn|social\s+security)\b", "Direct Sensitive Credential Request", 48.0, "Credential Theft", "Explicitly demands passwords, PIN codes, or SSN, which legitimate entities never request over unauthenticated messaging channels."),
    (r"\b(?:email\s+password\s+expires\s+today|keep\s+your\s+current\s+password)\b", "Credential Expiration Phish", 40.0, "Credential Theft", "Phishing pretext claiming credentials will expire to harvest authentication logins."),
    (r"\b(?:upload\s+(?:your\s+)?(?:driver\s+license|credit\s+card\s+photos?))\b", "Identity Document Exfiltration", 42.0, "Credential Theft", "Demands photographic copies of government ID or payment cards."),
]

# 3. Bank Impersonation
BANK_IMPERSONATION_PATTERNS = [
    (r"\b(?:chase|wells\s+fargo|bank\s+of\s+america|citibank|paypal)\s+(?:alert|notice|security|fraud)?[:\- ]+(?:your\s+)?(?:account|card|profile|online\s+access)\b", "Financial Institution Impersonation", 40.0, "Impersonation", "Impersonates a major banking institution to simulate an authoritative security alert."),
    (r"\b(?:debit\s+card|bank\s+account)\s+(?:has\s+been\s+)?(?:locked|suspended|blocked|on\s+hold|terminated)\b", "Account Suspension Panic Hook", 35.0, "Impersonation", "Claims financial access has been terminated to trigger panic."),
]

# 4. Government & Law Enforcement Impersonation
GOVERNMENT_IMPERSONATION_PATTERNS = [
    (r"\b(?:internal\s+revenue(?:\s+service)?|irs|social\s+security\s+administration|ssa|homeland\s+security|immigration\s+officer|state\s+police|local\s+sheriff)\b", "Government Agency Impersonation", 45.0, "Impersonation", "Impersonates federal or state law enforcement agencies."),
    (r"\b(?:arrest\s+warrant|federal\s+felony|unpaid\s+federal\s+taxes|customs\s+package\s+contains\s+illegal)\b", "Fabricated Legal Coercion", 42.0, "Government Impersonation", "Fabricates legal liability or arrest warrants to force financial settlement."),
]

# 5. Fake Job Offers
FAKE_JOB_PATTERNS = [
    (r"\b(?:work\s+from\s+home(?:\s+internship)?|internship\s+at|remote\s+(?:assistant|job|product\s+reviewers?|internship))\b.*?\b(?:(?:rs\.?|inr|\$)\s*\d+[\d,]*\s*(?:daily|per\s+day|an\s+hour)?|earn\s+(?:rs\.?|inr|\$)?\s*\d+)\b", "High-Yield Work-From-Home Scam", 38.0, "Employment Fraud", "Offers unrealistic compensation for minimal work with no formal interview process."),
    (r"\b(?:equipment\s+registration\s+fee|paid\s+via\s+usdt|contact\s+(?:hr|recruiter)\s+on\s+telegram|refundable\s+equipment\s+fee)\b", "Unorthodox Recruitment Funnel", 35.0, "Employment Fraud", "Directs job applicants to unverified chat apps (Telegram/WhatsApp) or demands advance equipment fees."),
    (r"\b(?:earn\s+\$\d+\s+every\s+\d+\s+minutes\s+by\s+liking\s+youtube\s+videos)\b", "Task-Based Phishing Scam", 38.0, "Employment Fraud", "Promotes fraudulent task-based click-farming with promised instant payouts."),
]

# 6. Lottery & Prize Scams
LOTTERY_PRIZE_PATTERNS = [
    (r"\b(?:congratulations|selected\s+as\s+(?:the\s+)?winner)\b.*?\b(?:won\s+[£$€]\d+|international\s+lottery|sweepstakes|mega\s+millions)\b", "Unsolicited Lottery / Sweepstakes Claim", 42.0, "Lottery / Prize", "Claims recipient won a large cash lottery or sweepstakes they never entered."),
    (r"\b(?:free\s+\$?\d+[\d,]*\s+(?:walmart|amazon|apple|target)?\s*gift\s+card)\b", "Bait Gift Card Voucher", 32.0, "Lottery / Prize", "Offers free high-value gift cards to entice victims into surveys or credential entry."),
]

# 7. Financial Fraud & Wire Requests
FINANCIAL_FRAUD_PATTERNS = [
    (r"\b(?:wire\s+transfer|western\s+union|greendot\s+moneypak|transfer\s+\d+\s+btc)\b", "Irreversible Payment Mechanism", 38.0, "Financial Fraud", "Requests payment through irreversible, non-traceable settlement networks."),
    (r"\b(?:deceased\s+client\s+with\s+\$\d+m|barrister\s+\w+\s+representing|unclaimed\s+funds)\b", "Inheritance / Advance-Fee Phish", 40.0, "Financial Fraud", "Promotes classic 419 advance-fee inheritance fraud."),
]

# 8. Fake Payment Demands
FAKE_PAYMENT_PATTERNS = [
    (r"\b(?:unpaid\s+shipping\s+tax\s+of\s+\$\d+|redelivery\s+(?:fee|surcharge)\s+of\s+\$\d+)\b", "Micro-Fee Package Phishing", 35.0, "Payment Phish", "Lures victims with nominal shipping fees ($1-$5) to capture full credit card details on fake postal gateways."),
    (r"\b(?:power\s+service\s+will\s+be\s+disconnected\s+in\s+\d+\s+minutes|pay\s+fine\s+today\s+via\s+bitcoin)\b", "Utility Disconnection Extortion", 40.0, "Payment Phish", "Threatens immediate utility disconnection unless settled through unorthodox channels."),
]

# 9. Suspicious Account Verification
ACCOUNT_VERIFICATION_PATTERNS = [
    (r"\b(?:verify\s+immediately\s+at\s+https?://|confirm\s+your\s+account\s+details\s+immediately)\b", "Urgent Phishing Redirection Link", 36.0, "Suspicious Verification", "Pressures recipient to verify account details via external embedded web link."),
    (r"\b(?:placed\s+on\s+hold\s+due\s+to\s+unusual|account\s+will\s+be\s+deleted\s+within\s+\d+\s+hours)\b", "Account Deletion / Hold Bait", 34.0, "Suspicious Verification", "Uses artificial countdowns to force authentication on spoofed portals."),
]

# 10. Malicious Link Invitations
LINK_INVITATION_PATTERNS = [
    (r"\b(?:click\s+(?:here|link)\s+to\s+(?:cancel|dispute|view|restore|unlock))\b", "Deceptive Call-To-Action Link", 30.0, "Link Bait", "Urges immediate hyperlink clicks to resolve a fabricated problem."),
]

# 11. Fake Customer Support
CUSTOMER_SUPPORT_PATTERNS = [
    (r"\b(?:geek\s+squad|norton\s+lifelock|mcafee\s+security|paypal\s+dispute\s+line)\b.*?\b(?:renewed\s+automatically|annual\s+subscription|call\s+(?:billing\s+support|cancellation\s+desk))\b", "Tech Support Renewal Scam", 40.0, "Fake Support", "Impersonates antivirus or tech support with fabricated invoices and fake call center numbers."),
    (r"\b(?:call\s+(?:our\s+)?(?:fraud\s+line|agent\s+now|billing\s+support)\s+(?:at\s+)?1?-?8\d{2}[- ]\d{3}[- ]\d{4})\b", "Inbound Call-Center Lure", 32.0, "Fake Support", "Provides fraudulent toll-free phone number designed to connect victims to offshore call-center scammers."),
]

# 12. Investment & Crypto Scams
INVESTMENT_SCAM_PATTERNS = [
    (r"\b(?:guaranteed\s+\d+%\s+(?:profit|return)|crypto\s+ai\s+arbitrage|1000x\s+gem)\b", "Guaranteed Yield Crypto Fraud", 45.0, "Investment Scam", "Promises impossible, guaranteed financial returns through automated trading algorithms."),
    (r"\b(?:giving\s+away\s+\d+\s+ethereum|send\s+0\.\d+\s+eth\s+to\s+receive|deposit\s+minimum\s+\$\d+\s+bitcoin)\b", "Cryptocurrency Doubling Bait", 45.0, "Investment Scam", "Impersonates celebrities or projects with promises to double deposited cryptocurrency."),
]

# 13. Indian Cybercrime & Social Engineering Scenarios (UPI, KYC, Digital Arrest, India Post)
INDIAN_CYBER_PATTERNS = [
    (r"\b(?:enter|share|type)\s+(?:your\s+)?(?:upi\s+pin|google\s*pay\s+pin|phonepe\s+pin|paytm\s+pin)\s+(?:to\s+(?:receive|claim|credit|accept)|for\s+receiving)\b", "Fraudulent UPI PIN Solicitation", 50.0, "UPI Fraud", "Fraudulent instruction demanding victim enter their secret UPI PIN to receive money. UPI PIN is only needed to SEND money, never to receive."),
    (r"\b(?:upi\s+collect\s+request|accept\s+collect\s+request|scan\s+qr\s+code\s+to\s+receive\s+(?:money|cashback|payment))\b", "Deceptive UPI Collect / QR Bait", 45.0, "UPI Fraud", "Exploits UPI collect requests or deceptive QR codes to debit funds from the victim's account."),
    (r"\b(?:sbi|hdfc|icici|axis\s+bank|pnb|bank\s+of\s+baroda|yono(?:\s+sbi)?)\b.*?\b(?:kyc\s+(?:update|pending|suspended|blocked|deactivated)|pan\s+card|aadhaar\s+card)\b", "Indian Banking KYC Suspension Scam", 48.0, "Bank Impersonation", "Phishing campaign impersonating Indian banks threatening account deactivation over fake KYC/PAN/Aadhaar deadlines."),
    (r"\b(?:digital\s+arrest|cyber\s+crime\s+cell|cbi|narcotics\s+control\s+bureau|ncb|mumbai\s+police|enforcement\s+directorate)\b.*?\b(?:drugs|narcotics|illegal\s+parcel|fake\s+passport|video\s+call\s+investigation|clearance\s+account|arrest\s+warrant)\b", "Digital Arrest Cyber Extortion", 50.0, "Government Impersonation", "Digital Arrest extortion scheme where cybercriminals pose as CBI/Police claiming an illegal parcel was intercepted in your name."),
    (r"\b(?:india\s+post|blue\s+dart|dtdc|delhivery)\b.*?\b(?:redelivery|address\s+update|unpaid\s+(?:fee|surcharge|charge)\s+of\s+rs\.?\s*\d+)\b", "Indian Postal & Courier Delivery Phishing", 38.0, "Package Phishing", "Impersonates India Post or domestic courier services demanding nominal re-delivery fees via spoofed portals."),
    (r"\b(?:pm\s+kisan|pm\s+awas|beti\s+bachao|dbt\s+subsidy|modi\s+government\s+scheme)\b.*?\b(?:eligible|approved|claim\s+subsidy|link\s+bank\s+account|dbt\s+subsidy)\b", "Indian Government DBT Welfare Fraud", 42.0, "Government Impersonation", "Deceptively lures citizens with fabricated direct bank transfer (DBT) welfare schemes to harvest banking credentials."),
]


class MessageScanner:
    """
    Advanced Message Analysis Engine.
    Detects contextual phrases across 12 primary threat vectors,
    integrates psychological social engineering tactics, extracts URLs,
    and isolates legitimate transactional/benign communications.
    """

    @classmethod
    def scan(cls, message: str, source_type: str = "auto") -> Tuple[List[ThreatIndicator], List[SocialEngineeringTactic], List[str], List[UrlAnalysisItem], Dict[str, Any]]:
        indicators: List[ThreatIndicator] = []
        suspicious_phrases: List[str] = []
        url_analyses: List[UrlAnalysisItem] = []
        metadata: Dict[str, Any] = {
            "char_count": len(message) if message else 0,
            "source_type": source_type,
            "embedded_url_count": 0,
            "is_legitimate_bank_alert": False,
        }

        if not message or not message.strip():
            return indicators, [], suspicious_phrases, url_analyses, metadata

        clean_text = message.strip()
        lower_text = clean_text.lower()

        # Contextual Safeguard: Detect Legitimate Bank Transaction Alerts
        # Hallmark of genuine alerts:
        # 1. Mentions "charged $X" or "direct deposit" or "balance is"
        # 2. Includes "If this was you, no response is needed" or "no action needed"
        # 3. Contains NO hyperlinks or requests for passwords/PIN/OTP
        has_benign_bank_phrase = bool(
            re.search(r"\b(?:if\s+this\s+was\s+you,\s+no\s+(?:response|action)\s+is\s+needed|no\s+response\s+is\s+needed)\b", lower_text)
            or re.search(r"\b(?:your\s+direct\s+deposit\s+from\s+.*?has\s+been\s+credited)\b", lower_text)
            or re.search(r"\b(?:debited\s+by\s+rs\.?\s*\d+.*?avail\s+bal.*?sms\s+block)\b", lower_text)
        )
        has_embedded_hyperlink = bool(re.search(r"https?://|www\.", lower_text))
        has_credential_request = bool(re.search(r"\b(?:password|pin|otp|login\s+at)\b", lower_text))

        if has_benign_bank_phrase and not has_embedded_hyperlink and not has_credential_request:
            metadata["is_legitimate_bank_alert"] = True
            # Legitimate alert recognized; do not flag impersonation
            return indicators, [], suspicious_phrases, url_analyses, metadata

        # Execute 12 Contextual Scanners
        pattern_groups = [
            OTP_HARVEST_PATTERNS,
            CREDENTIAL_THEFT_PATTERNS,
            BANK_IMPERSONATION_PATTERNS,
            GOVERNMENT_IMPERSONATION_PATTERNS,
            FAKE_JOB_PATTERNS,
            LOTTERY_PRIZE_PATTERNS,
            FINANCIAL_FRAUD_PATTERNS,
            FAKE_PAYMENT_PATTERNS,
            ACCOUNT_VERIFICATION_PATTERNS,
            LINK_INVITATION_PATTERNS,
            CUSTOMER_SUPPORT_PATTERNS,
            INVESTMENT_SCAM_PATTERNS,
            INDIAN_CYBER_PATTERNS,
        ]

        for group in pattern_groups:
            for pattern, name, score_impact, category, description in group:
                matches = re.findall(pattern, lower_text)
                if matches:
                    unique_hits = list(dict.fromkeys(matches))
                    match_summary = ", ".join(f"'{m}'" for m in unique_hits[:3])
                    indicators.append(
                        ThreatIndicator(
                            name=name,
                            category=category,
                            severity="critical" if score_impact >= 40 else "high" if score_impact >= 30 else "warning",
                            score_impact=score_impact,
                            description=f"{description} (Matched: {match_summary})",
                        )
                    )
                    suspicious_phrases.extend(unique_hits)

        # Execute Social Engineering Intelligence (Module 2)
        se_indicators, se_tactics, se_phrases = SocialEngineeringAnalyzer.analyze(clean_text)
        indicators.extend(se_indicators)
        suspicious_phrases.extend(se_phrases)

        # Embedded URL Extraction & Safe Offline Inspection (Module 3)
        url_regex = r"(?:https?://[^\s<>\"'{}|\\^`]+|www\.[^\s<>\"'{}|\\^`]+|[a-zA-Z0-9-]+\.(?:com|org|net|xyz|top|club|ru|cn|tk|club|site|online|live)[^\s<>\"'{}|\\^`]*)"
        found_raw_urls = re.findall(url_regex, clean_text)
        unique_urls = list(dict.fromkeys(found_raw_urls))
        metadata["embedded_url_count"] = len(unique_urls)
        metadata["embedded_urls"] = unique_urls

        if unique_urls:
            indicators.append(
                ThreatIndicator(
                    name="Embedded External Hyperlink",
                    category="URL Deception",
                    severity="warning",
                    score_impact=15.0,
                    description=f"Message embeds {len(unique_urls)} external link(s). Threat actors use external links to direct victims to credential-harvesting portals.",
                )
            )
            for raw_u in unique_urls[:4]:  # Deep inspect up to 4 URLs
                url_indicators, url_phrases, _, analysis_item = UrlScanner.scan(raw_u)
                indicators.extend(url_indicators)
                suspicious_phrases.extend(url_phrases)
                url_analyses.append(analysis_item)

        return indicators, se_tactics, list(set(suspicious_phrases)), url_analyses, metadata
