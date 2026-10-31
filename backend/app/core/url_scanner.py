import re
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple
from app.schemas.scan import ThreatIndicator

# Common URL shorteners used to mask destinations
COMMON_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "goo.gl", "tiny.cc", "rb.gy", "rebrand.ly", "shorturl.at"
}

# Suspicious Top-Level Domains frequently abused in phishing campaigns
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".cam", ".zip", ".mov", ".tk", ".ml", ".ga", ".cf", ".gq", ".country", ".kim"
}

# Target high-profile brands frequently impersonated
TARGETED_BRANDS = [
    "paypal", "apple", "microsoft", "netflix", "amazon", "google", "bankofamerica",
    "wellsfargo", "chase", "dhl", "fedex", "usps", "whatsapp", "facebook", "instagram"
]


class UrlScanner:
    """
    Offline structural URL analysis engine.
    Detects IP addresses in hostnames, misleading subdomains, unusual ports,
    homoglyphs/suspicious characters, known URL shorteners, and deceptive brand tokens.
    NEVER makes outbound network calls or visits the target URL.
    """

    @classmethod
    def scan(cls, raw_url: str) -> Tuple[List[ThreatIndicator], List[str], Dict[str, Any]]:
        indicators: List[ThreatIndicator] = []
        suspicious_phrases: List[str] = []
        metadata: Dict[str, Any] = {}

        url = raw_url.strip()
        if not re.match(r"^[a-zA-Z]+://", url):
            url = "http://" + url

        try:
            parsed = urlparse(url)
        except Exception as e:
            indicators.append(
                ThreatIndicator(
                    name="Malformed URL",
                    category="URL Deception",
                    severity="high",
                    score_impact=45.0,
                    description=f"The supplied URL syntax is malformed or invalid: {str(e)}",
                )
            )
            return indicators, suspicious_phrases, metadata

        hostname = (parsed.hostname or "").lower()
        port = parsed.port
        path = parsed.path
        query = parsed.query

        metadata["hostname"] = hostname
        metadata["port"] = port
        metadata["scheme"] = parsed.scheme
        metadata["path_length"] = len(path)

        # 1. IP address in Hostname
        ip_v4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if re.match(ip_v4_pattern, hostname):
            indicators.append(
                ThreatIndicator(
                    name="IP Address Hostname",
                    category="URL Deception",
                    severity="critical",
                    score_impact=60.0,
                    description=f"URL points directly to an IP address ({hostname}) rather than a verified domain name.",
                )
            )
            suspicious_phrases.append(hostname)

        # 2. Known URL Shortener
        if hostname in COMMON_SHORTENERS:
            indicators.append(
                ThreatIndicator(
                    name="URL Shortening Service",
                    category="Shortener",
                    severity="warning",
                    score_impact=25.0,
                    description=f"Uses known URL shortening service ({hostname}) that obscures the ultimate destination.",
                )
            )
            suspicious_phrases.append(hostname)

        # 3. Suspicious or high-risk TLD
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                indicators.append(
                    ThreatIndicator(
                        name="High-Risk Top-Level Domain",
                        category="URL Deception",
                        severity="warning",
                        score_impact=20.0,
                        description=f"Domain ends with '{tld}', a TLD statistically prone to abusive disposable registrations.",
                    )
                )
                suspicious_phrases.append(tld)
                break

        # 4. Unusual / Non-standard Ports
        if port and port not in (80, 443, 8080):
            indicators.append(
                ThreatIndicator(
                    name="Non-Standard Port",
                    category="URL Deception",
                    severity="warning",
                    score_impact=25.0,
                    description=f"Web service communicates over non-standard port {port}, commonly used in phishing relays.",
                )
            )
            suspicious_phrases.append(f":{port}")

        # 5. Excessive Subdomains (Deep subdomain nesting)
        subdomain_parts = hostname.split(".")
        if len(subdomain_parts) >= 4:
            indicators.append(
                ThreatIndicator(
                    name="Excessive Subdomain Stacking",
                    category="URL Deception",
                    severity="warning",
                    score_impact=25.0,
                    description=f"Host possesses {len(subdomain_parts)} domain segments, often designed to mimic legitimate domain structures.",
                )
            )
            suspicious_phrases.append(hostname)

        # 6. Brand Impersonation / Lookalike in Subdomain or Path
        for brand in TARGETED_BRANDS:
            # If brand appears in subdomain or path, but domain is not brand.com
            if brand in hostname:
                # Check if it's the genuine domain
                genuine_suffixes = (f"{brand}.com", f"{brand}.org", f"{brand}.net", f"{brand}.co.uk")
                if not any(hostname == suffix or hostname.endswith("." + suffix) for suffix in genuine_suffixes):
                    indicators.append(
                        ThreatIndicator(
                            name=f"Brand Lookalike ({brand.capitalize()})",
                            category="Impersonation",
                            severity="critical",
                            score_impact=50.0,
                            description=f"Brand identifier '{brand}' appears in host '{hostname}' without official domain authorization.",
                        )
                    )
                    suspicious_phrases.append(brand)

        # 7. Suspicious characters / Homoglyphs (@ symbol, multiple hyphens)
        if "@" in raw_url:
            indicators.append(
                ThreatIndicator(
                    name="Embedded Credentials / @ Character",
                    category="URL Deception",
                    severity="high",
                    score_impact=45.0,
                    description="Contains '@' character in URL authority, which modern browsers may use to obscure real host destinations.",
                )
            )
            suspicious_phrases.append("@")

        if hostname.count("-") >= 3:
            indicators.append(
                ThreatIndicator(
                    name="Excessive Hyphens in Hostname",
                    category="URL Deception",
                    severity="warning",
                    score_impact=20.0,
                    description=f"Hostname contains {hostname.count('-')} hyphens, a signature tactic of spoofed domains.",
                )
            )
            suspicious_phrases.append(hostname)

        return indicators, list(set(suspicious_phrases)), metadata
