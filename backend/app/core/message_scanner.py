import re
from typing import List, Dict, Any, Tuple
from app.schemas.scan import ThreatIndicator, SocialEngineeringTactic, UrlAnalysisItem
from app.core.social_engineering import SocialEngineeringAnalyzer
from app.core.url_scanner import UrlScanner

# ---------------------------------------------------------------------------
# 1. OTP Harvesting Patterns
# ---------------------------------------------------------------------------
OTP_HARVEST_PATTERNS = [
    (
        r"\b(?:reply\s+with|forward|send|share|enter)\s+(?:(?:your|the)\s+)?(?:[\w-]+\s+){0,3}(?:otp|verification\s+code|sms\s+code|passcode|token)\b",
        "OTP Harvesting Request", 45.0, "Credential Theft",
        "Message explicitly solicits a one-time verification passcode, which legitimate identity systems instruct users never to share.",
    ),
    (
        r"\b(?:whatsapp|google|uber|telegram)\s+(?:security\s+)?code\s+was\s+requested\b",
        "Unsolicited 2FA Request Baiting", 35.0, "Credential Theft",
        "Alerts about an unsolicited security code to induce the recipient into forwarding it.",
    ),
    (
        r"\b(?:accidentally|by\s+mistake)\s+sent\s+(?:my\s+)?(?:\d+[- ]digit\s+)?(?:code|otp)\b",
        "Accidental Code Forwarding Trick", 45.0, "Credential Theft",
        "Classic social engineering trick claiming a verification code was sent by mistake to steal the victim's account registration.",
    ),
]

# ---------------------------------------------------------------------------
# 2. Password & Credential Theft
# ---------------------------------------------------------------------------
CREDENTIAL_THEFT_PATTERNS = [
    (
        r"\b(?:enter|provide|confirm|verify)\s+(?:your\s+)?(?:[\w\s,]+)?(?:password|cvv|security\s+code|ssn|social\s+security)\b",
        "Direct Sensitive Credential Request", 48.0, "Credential Theft",
        "Explicitly demands passwords, CVV, or SSN — which legitimate entities never request over unauthenticated messaging channels.",
    ),
    (
        r"\b(?:email\s+password\s+expires\s+today|keep\s+your\s+current\s+password)\b",
        "Credential Expiration Phish", 40.0, "Credential Theft",
        "Phishing pretext claiming credentials will expire to harvest authentication logins.",
    ),
    (
        r"\b(?:upload\s+(?:your\s+)?(?:driver\s+license|credit\s+card\s+photos?))\b",
        "Identity Document Exfiltration", 42.0, "Credential Theft",
        "Demands photographic copies of government ID or payment cards.",
    ),
]

# ---------------------------------------------------------------------------
# 3. Bank Impersonation
# ---------------------------------------------------------------------------
BANK_IMPERSONATION_PATTERNS = [
    (
        r"\b(?:chase|wells\s+fargo|bank\s+of\s+america|citibank|paypal)\s+(?:alert|notice|security|fraud)?[:\- ]+(?:your\s+)?(?:account|card|profile|online\s+access)\b",
        "Financial Institution Impersonation", 40.0, "Impersonation",
        "Impersonates a major banking institution to simulate an authoritative security alert.",
    ),
    (
        r"\b(?:debit\s+card|bank\s+account)\s+(?:has\s+been\s+)?(?:locked|suspended|blocked|on\s+hold|terminated)\b",
        "Account Suspension Panic Hook", 35.0, "Impersonation",
        "Claims financial access has been terminated to trigger panic.",
    ),
]

# ---------------------------------------------------------------------------
# 4. Government & Law Enforcement Impersonation
# ---------------------------------------------------------------------------
GOVERNMENT_IMPERSONATION_PATTERNS = [
    (
        r"\b(?:internal\s+revenue(?:\s+service)?|irs|social\s+security\s+administration|ssa|homeland\s+security|immigration\s+officer|state\s+police|local\s+sheriff)\b",
        "Government Agency Impersonation", 45.0, "Impersonation",
        "Impersonates federal or state law enforcement agencies.",
    ),
    (
        r"\b(?:arrest\s+warrant|federal\s+felony|unpaid\s+federal\s+taxes|customs\s+package\s+contains\s+illegal)\b",
        "Fabricated Legal Coercion", 42.0, "Government Impersonation",
        "Fabricates legal liability or arrest warrants to force financial settlement.",
    ),
]

# ---------------------------------------------------------------------------
# 5. Fake Job Offers
# ---------------------------------------------------------------------------
FAKE_JOB_PATTERNS = [
    (
        r"\b(?:work\s+from\s+home(?:\s+internship)?|internship\s+at|remote\s+(?:assistant|job|product\s+reviewers?|internship))\b.*?\b(?:(?:rs\.?|inr|\$)\s*\d+[\d,]*\s*(?:daily|per\s+day|an\s+hour)?|earn\s+(?:rs\.?|inr|\$)?\s*\d+)\b",
        "High-Yield Work-From-Home Scam", 38.0, "Employment Fraud",
        "Offers unrealistic compensation for minimal work with no formal interview process.",
    ),
    (
        r"\b(?:equipment\s+registration\s+fee|paid\s+via\s+usdt|contact\s+(?:hr|recruiter)\s+on\s+telegram|refundable\s+equipment\s+fee)\b",
        "Unorthodox Recruitment Funnel", 35.0, "Employment Fraud",
        "Directs job applicants to unverified chat apps (Telegram/WhatsApp) or demands advance equipment fees.",
    ),
    (
        r"\b(?:earn\s+\$\d+\s+every\s+\d+\s+minutes\s+by\s+liking\s+youtube\s+videos)\b",
        "Task-Based Phishing Scam", 38.0, "Employment Fraud",
        "Promotes fraudulent task-based click-farming with promised instant payouts.",
    ),
]

# ---------------------------------------------------------------------------
# 6. Lottery & Prize Scams
# ---------------------------------------------------------------------------
LOTTERY_PRIZE_PATTERNS = [
    (
        r"\b(?:congratulations|selected\s+as\s+(?:the\s+)?winner)\b.*?\b(?:won\s+[£$€]\d+|international\s+lottery|sweepstakes|mega\s+millions)\b",
        "Unsolicited Lottery / Sweepstakes Claim", 42.0, "Lottery / Prize",
        "Claims recipient won a large cash lottery or sweepstakes they never entered.",
    ),
    (
        r"\b(?:free\s+\$?\d+[\d,]*\s+(?:walmart|amazon|apple|target)?\s*gift\s+card)\b",
        "Bait Gift Card Voucher", 32.0, "Lottery / Prize",
        "Offers free high-value gift cards to entice victims into surveys or credential entry.",
    ),
]

# ---------------------------------------------------------------------------
# 7. Financial Fraud & Wire Requests
# ---------------------------------------------------------------------------
FINANCIAL_FRAUD_PATTERNS = [
    (
        r"\b(?:wire\s+transfer|western\s+union|greendot\s+moneypak|transfer\s+\d+\s+btc)\b",
        "Irreversible Payment Mechanism", 38.0, "Financial Fraud",
        "Requests payment through irreversible, non-traceable settlement networks.",
    ),
    (
        r"\b(?:deceased\s+client\s+with\s+\$\d+m|barrister\s+\w+\s+representing|unclaimed\s+funds)\b",
        "Inheritance / Advance-Fee Phish", 40.0, "Financial Fraud",
        "Promotes classic 419 advance-fee inheritance fraud.",
    ),
]

# ---------------------------------------------------------------------------
# 8. Fake Payment Demands
# ---------------------------------------------------------------------------
FAKE_PAYMENT_PATTERNS = [
    (
        r"\b(?:unpaid\s+shipping\s+tax\s+of\s+\$\d+|redelivery\s+(?:fee|surcharge)\s+of\s+\$\d+)\b",
        "Micro-Fee Package Phishing", 35.0, "Payment Phish",
        "Lures victims with nominal shipping fees ($1-$5) to capture full credit card details on fake postal gateways.",
    ),
    (
        r"\b(?:power\s+service\s+will\s+be\s+disconnected\s+in\s+\d+\s+minutes|pay\s+fine\s+today\s+via\s+bitcoin)\b",
        "Utility Disconnection Extortion", 40.0, "Payment Phish",
        "Threatens immediate utility disconnection unless settled through unorthodox channels.",
    ),
]

# ---------------------------------------------------------------------------
# 9. Suspicious Account Verification
# ---------------------------------------------------------------------------
ACCOUNT_VERIFICATION_PATTERNS = [
    (
        r"\b(?:verify\s+immediately\s+at\s+https?://|confirm\s+your\s+account\s+details\s+immediately)\b",
        "Urgent Phishing Redirection Link", 36.0, "Suspicious Verification",
        "Pressures recipient to verify account details via external embedded web link.",
    ),
    (
        r"\b(?:placed\s+on\s+hold\s+due\s+to\s+unusual|account\s+will\s+be\s+deleted\s+within\s+\d+\s+hours)\b",
        "Account Deletion / Hold Bait", 34.0, "Suspicious Verification",
        "Uses artificial countdowns to force authentication on spoofed portals.",
    ),
]

# ---------------------------------------------------------------------------
# 10. Malicious Link Invitations
# ---------------------------------------------------------------------------
LINK_INVITATION_PATTERNS = [
    (
        r"\b(?:click\s+(?:here|link|below)\s+(?:to|and)\s+(?:cancel|dispute|view|restore|unlock|verify|reactivate|update|confirm))\b",
        "Deceptive Call-To-Action Link", 30.0, "Link Bait",
        "Urges immediate hyperlink clicks to resolve a fabricated problem.",
    ),
]

# ---------------------------------------------------------------------------
# 11. Fake Customer Support
# ---------------------------------------------------------------------------
CUSTOMER_SUPPORT_PATTERNS = [
    (
        r"\b(?:geek\s+squad|norton\s+lifelock|mcafee\s+security|paypal\s+dispute\s+line)\b.*?\b(?:renewed\s+automatically|annual\s+subscription|call\s+(?:billing\s+support|cancellation\s+desk))\b",
        "Tech Support Renewal Scam", 40.0, "Fake Support",
        "Impersonates antivirus or tech support with fabricated invoices and fake call center numbers.",
    ),
    (
        r"\b(?:call\s+(?:our\s+)?(?:fraud\s+line|agent\s+now|billing\s+support)\s+(?:at\s+)?1?-?8\d{2}[- ]\d{3}[- ]\d{4})\b",
        "Inbound Call-Center Lure", 32.0, "Fake Support",
        "Provides fraudulent toll-free phone number designed to connect victims to offshore call-center scammers.",
    ),
]

# ---------------------------------------------------------------------------
# 12. Investment & Crypto Scams
# ---------------------------------------------------------------------------
INVESTMENT_SCAM_PATTERNS = [
    (
        r"\b(?:guaranteed\s+\d+%\s+(?:profit|return)|crypto\s+ai\s+arbitrage|1000x\s+gem)\b",
        "Guaranteed Yield Crypto Fraud", 45.0, "Investment Scam",
        "Promises impossible, guaranteed financial returns through automated trading algorithms.",
    ),
    (
        r"\b(?:giving\s+away\s+\d+\s+ethereum|send\s+0\.\d+\s+eth\s+to\s+receive|deposit\s+minimum\s+\$\d+\s+bitcoin)\b",
        "Cryptocurrency Doubling Bait", 45.0, "Investment Scam",
        "Impersonates celebrities or projects with promises to double deposited cryptocurrency.",
    ),
]

# ---------------------------------------------------------------------------
# 13. Indian UPI / KYC / Digital Arrest / Courier / Subsidy Patterns
#     (Expanded for full contextual coverage)
# ---------------------------------------------------------------------------
INDIAN_CYBER_PATTERNS = [

    # --- UPI PIN harvesting (multiple phrasings) ---
    (
        r"\b(?:enter|share|type|provide)\s+(?:your\s+)?(?:upi\s+pin|google\s*pay\s+pin|phonepe\s+pin|paytm\s+pin)\s+(?:to\s+(?:receive|claim|credit|accept|reactivate|verify|activate)|for\s+(?:receiving|verification))\b",
        "Fraudulent UPI PIN Solicitation", 50.0, "UPI Fraud",
        "Instruction demanding the victim enter their secret UPI PIN to 'receive' money or reactivate an account. UPI PIN is only required to SEND money — entering it on request always debits the account.",
    ),
    (
        r"\b(?:upi\s+pin|google\s*pay\s+pin|phonepe\s+pin|paytm\s+pin)\b.{0,60}\b(?:blocked|expired|reactivate|reactivation|verify|verification|suspended)\b",
        "UPI PIN Combined with Account Threat", 48.0, "UPI Fraud",
        "Combines mention of a UPI PIN with an account blocking or expiry threat — a hallmark phishing pattern used to extract payment credentials under false urgency.",
    ),
    (
        r"\bupi\s+pin\b.{0,40}\b(?:click|link|visit|go\s+to|open)\b",
        "UPI PIN Redirect Bait", 45.0, "UPI Fraud",
        "Instructs the victim to click a link and then enter their UPI PIN — a clear credential-harvesting redirect attack.",
    ),

    # --- UPI Collect / QR code abuse ---
    (
        r"\b(?:upi\s+collect\s+request|accept\s+collect\s+request|scan\s+qr\s+code\s+to\s+receive\s+(?:money|cashback|payment))\b",
        "Deceptive UPI Collect / QR Bait", 45.0, "UPI Fraud",
        "Exploits UPI collect requests or deceptive QR codes to debit funds from the victim's account without their awareness.",
    ),
    (
        r"\bscan\s+(?:this\s+)?qr\s+(?:code\s+)?to\s+(?:get|receive|claim|collect|accept)\b",
        "QR Code Payment Manipulation", 42.0, "UPI Fraud",
        "Instructs victim to scan a QR code to 'receive' money — scanning a fraudulent QR always initiates a payment FROM the victim.",
    ),

    # --- PhonePe / Google Pay / Paytm impersonation ---
    (
        r"\b(?:phonepe|phone\s+pe)\b.{0,80}\b(?:blocked|suspended|deactivated|expired|kyc|verify|reactivate|account\s+will\s+be)\b",
        "PhonePe Account Threat Impersonation", 45.0, "UPI Fraud",
        "Impersonates PhonePe with an account blocking or KYC threat — PhonePe never requests UPI PIN or KYC via SMS.",
    ),
    (
        r"\b(?:google\s*pay|gpay)\b.{0,80}\b(?:blocked|suspended|deactivated|expired|kyc|verify|reactivate|account\s+will\s+be)\b",
        "Google Pay Account Threat Impersonation", 45.0, "UPI Fraud",
        "Impersonates Google Pay with an account blocking or KYC threat — Google Pay never asks for PIN or KYC via SMS.",
    ),
    (
        r"\b(?:paytm)\b.{0,80}\b(?:blocked|suspended|deactivated|expired|kyc|verify|reactivate|reward|cashback\s+credited)\b",
        "Paytm Account Threat / Fake Reward", 42.0, "UPI Fraud",
        "Impersonates Paytm with account threats or fake cashback rewards to harvest credentials or extract UPI PIN.",
    ),

    # --- Indian bank KYC expiry / suspension ---
    (
        r"\b(?:sbi|hdfc|icici|axis\s+bank|pnb|bank\s+of\s+baroda|yono(?:\s+sbi)?|kotak|yes\s+bank|idfc|rbl\s+bank)\b.{0,120}\b(?:kyc\s+(?:update|pending|suspended|blocked|deactivated|expired|expir)|pan\s+card|aadhaar\s+(?:card|link|verification)|re-?kyc)\b",
        "Indian Banking KYC Suspension Scam", 48.0, "Bank Impersonation",
        "Phishing campaign impersonating Indian banks threatening account deactivation over fake KYC/PAN/Aadhaar deadlines.",
    ),
    (
        r"\b(?:kyc\s+(?:verification|update)\s+(?:has\s+)?(?:expired?|pending|failed|not\s+completed?)|kyc\s+expir(?:ed?|y))\b",
        "KYC Expiry Threat", 44.0, "Bank Impersonation",
        "False claim that a KYC verification has expired to create urgency around clicking a phishing link. Banks communicate KYC renewals through official apps, not unsolicited SMS.",
    ),
    (
        r"\b(?:your\s+)?(?:account|card)\s+(?:will\s+be\s+(?:blocked|suspended|deactivated)|(?:has\s+been\s+)?(?:blocked|suspended))\s+(?:today|immediately|within|due\s+to)\b",
        "Account Blocking Threat", 38.0, "Bank Impersonation",
        "Threatens immediate account blocking to induce panic and force quick compliance with a phishing link.",
    ),

    # --- Aadhaar / PAN verification scams ---
    (
        r"\b(?:link|update|verify|submit)\s+(?:your\s+)?(?:aadhaar|aadhar|pan\s+card|pan\s+number)\b.{0,60}\b(?:immediately|today|within|urgent|click|link|sms|portal)\b",
        "Aadhaar / PAN Credential Harvesting", 46.0, "Credential Theft",
        "Demands Aadhaar or PAN details via SMS link — the Government of India's official services only update these through registered portals, never via unsolicited SMS.",
    ),

    # --- Digital arrest threats ---
    (
        r"\b(?:digital\s+arrest|cyber\s+crime\s+cell|cbi|narcotics\s+control\s+bureau|ncb|mumbai\s+police|enforcement\s+directorate|customs\s+department)\b.{0,150}\b(?:drugs|narcotics|illegal\s+parcel|fake\s+passport|video\s+call\s+investigation|clearance\s+account|arrest\s+warrant|money\s+laundering|ncb\s+officer)\b",
        "Digital Arrest Cyber Extortion", 50.0, "Government Impersonation",
        "Digital Arrest extortion scheme where criminals pose as CBI/Police claiming an illegal parcel or activity is linked to the victim's name to extort money.",
    ),

    # --- Indian Courier / Delivery phishing ---
    (
        r"\b(?:india\s+post|blue\s+dart|dtdc|delhivery|ekart|amazon\s+delivery)\b.{0,120}\b(?:redelivery|address\s+update|unpaid\s+(?:fee|surcharge|charge)\s+of\s+(?:rs\.?\s*)?\d+|delivery\s+failed|incorrect\s+(?:pin\s+code|address))\b",
        "Indian Courier Delivery Phishing", 38.0, "Package Phishing",
        "Impersonates Indian courier services demanding nominal re-delivery fees via spoofed portals — official couriers never collect redelivery fees via SMS links.",
    ),

    # --- Government subsidy / DBT scams ---
    (
        r"\b(?:pm\s+kisan|pm\s+awas|beti\s+bachao|dbt\s+subsidy|modi\s+government\s+scheme|ayushman\s+bharat|ujjwala\s+yojana)\b.{0,150}\b(?:eligible|approved|claim\s+subsidy|link\s+bank\s+account|dbt\s+subsidy|verify\s+aadhaar|bank\s+details)\b",
        "Indian Government DBT Welfare Fraud", 42.0, "Government Impersonation",
        "Deceptively lures citizens with fabricated direct bank transfer (DBT) welfare schemes to harvest banking credentials — genuine DBT payments require no link-clicking.",
    ),
]

# ---------------------------------------------------------------------------
# Benign UPI / bank transaction phrases (false-positive suppression)
# These appear in REAL bank debit/credit alerts — should NOT be flagged
# ---------------------------------------------------------------------------
BENIGN_UPI_TRANSACTION_PATTERNS = [
    # Real UPI payment receipts from banks
    r"\b(?:credited\s+to\s+your\s+(?:a/?c|account)|debited\s+from\s+your\s+(?:a/?c|account))\b",
    r"\b(?:upi\s+ref(?:erence)?\s+(?:no\.?\s*)?\d+|upi\s+txn\s+id|upi\s+transaction\s+id)\b",
    r"\b(?:avail(?:able)?\s+bal(?:ance)?|available\s+balance\s+rs\.?\s*\d+)\b",
]


class MessageScanner:
    """
    Advanced Message Analysis Engine.
    Detects contextual phrases across 13 primary threat vectors,
    integrates psychological social engineering tactics, extracts URLs,
    and isolates legitimate transactional/benign communications.

    Detection modules:
    1.  OTP Harvesting
    2.  Password & Credential Theft
    3.  Bank Impersonation (Global)
    4.  Government & Law Enforcement Impersonation (Global)
    5.  Fake Job Offers
    6.  Lottery & Prize Scams
    7.  Financial Fraud & Wire Requests
    8.  Fake Payment Demands
    9.  Suspicious Account Verification
    10. Malicious Link Invitations
    11. Fake Customer Support
    12. Investment & Crypto Scams
    13. Indian Cybercrime (UPI / KYC / Digital Arrest / Courier / Subsidy)
    """

    @classmethod
    def scan(
        cls,
        message: str,
        source_type: str = "auto",
    ) -> Tuple[List[ThreatIndicator], List[SocialEngineeringTactic], List[str], List[UrlAnalysisItem], Dict[str, Any]]:
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

        # ------------------------------------------------------------------- #
        # Contextual Safeguard — Legitimate Bank Transaction Alerts
        # Hallmarks of genuine alerts:
        #   1. "If this was you, no response is needed" or "SMS BLOCK to …"
        #   2. "Your A/C debited by Rs … Avail Bal … SMS BLOCK"
        #   3. "Your direct deposit from … has been credited"
        # AND: no embedded hyperlinks, no credential/PIN requests
        # ------------------------------------------------------------------- #
        has_benign_bank_phrase = bool(
            re.search(r"\b(?:if\s+this\s+was\s+you,?\s+no\s+(?:response|action)\s+is\s+needed|no\s+response\s+is\s+needed)\b", lower_text)
            or re.search(r"\b(?:your\s+direct\s+deposit\s+from\s+.*?has\s+been\s+credited)\b", lower_text)
            or re.search(r"\b(?:debited\s+by\s+rs\.?\s*\d+.*?avail\s+bal.*?sms\s+block)\b", lower_text)
        )

        # Benign UPI payment receipt signals (real txn notifications)
        has_benign_upi_receipt = any(
            re.search(pat, lower_text) for pat in BENIGN_UPI_TRANSACTION_PATTERNS
        )

        has_embedded_hyperlink = bool(re.search(r"https?://|www\.", lower_text))
        has_credential_request = bool(re.search(r"\b(?:password|pin|otp|login\s+at)\b", lower_text))

        if has_benign_bank_phrase and not has_embedded_hyperlink and not has_credential_request:
            metadata["is_legitimate_bank_alert"] = True
            return indicators, [], suspicious_phrases, url_analyses, metadata

        # ------------------------------------------------------------------- #
        # Execute all 13 Contextual Scanner Groups
        # ------------------------------------------------------------------- #
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

        # Track already-named indicators to avoid exact duplicates
        seen_indicator_keys: set = set()

        for group in pattern_groups:
            for pattern, name, score_impact, category, description in group:
                # Suppress CREDENTIAL_THEFT "pin" matches on genuine UPI receipts
                if category == "Credential Theft" and has_benign_upi_receipt and "pin" in pattern.lower():
                    continue

                matches = re.findall(pattern, lower_text, re.IGNORECASE | re.DOTALL)
                if matches:
                    dedup_key = f"{category}::{name}"
                    if dedup_key in seen_indicator_keys:
                        continue
                    seen_indicator_keys.add(dedup_key)

                    unique_hits = list(dict.fromkeys(str(m) for m in matches))
                    match_summary = ", ".join("'%s'" % m for m in unique_hits[:3])
                    indicators.append(
                        ThreatIndicator(
                            name=name,
                            category=category,
                            severity=(
                                "critical" if score_impact >= 40
                                else "high" if score_impact >= 30
                                else "warning"
                            ),
                            score_impact=score_impact,
                            description="%s (Evidence: %s)" % (description, match_summary),
                        )
                    )
                    suspicious_phrases.extend(unique_hits)

        # ------------------------------------------------------------------- #
        # Social Engineering Intelligence (Module 2)
        # ------------------------------------------------------------------- #
        se_indicators, se_tactics, se_phrases = SocialEngineeringAnalyzer.analyze(clean_text)

        # Only add SE indicators whose category is not already represented by a
        # rule-based indicator at higher confidence (avoids double-counting urgency)
        existing_categories = {ind.category for ind in indicators}
        for se_ind in se_indicators:
            if se_ind.category not in existing_categories:
                indicators.append(se_ind)
                existing_categories.add(se_ind.category)
            # If same category already flagged with higher score, skip the SE duplicate
            else:
                existing_max = max(
                    (i.score_impact for i in indicators if i.category == se_ind.category),
                    default=0,
                )
                if se_ind.score_impact > existing_max:
                    indicators.append(se_ind)

        suspicious_phrases.extend(se_phrases)

        # ------------------------------------------------------------------- #
        # Embedded URL Extraction & Safe Offline Inspection (Module 3)
        # ------------------------------------------------------------------- #
        url_regex = r"(?:https?://[^\s<>\"'{}|\\^`]+|www\.[^\s<>\"'{}|\\^`]+|[a-zA-Z0-9-]+\.(?:com|org|net|xyz|top|club|ru|cn|tk|site|online|live)[^\s<>\"'{}|\\^`]*)"
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
                    description="Message embeds %d external link(s). Threat actors use external links to direct victims to credential-harvesting portals." % len(unique_urls),
                )
            )
            for raw_u in unique_urls[:4]:  # Deep inspect up to 4 URLs
                url_indicators, url_phrases, _, analysis_item = UrlScanner.scan(raw_u)
                indicators.extend(url_indicators)
                suspicious_phrases.extend(url_phrases)
                url_analyses.append(analysis_item)

        return indicators, se_tactics, list(set(suspicious_phrases)), url_analyses, metadata
