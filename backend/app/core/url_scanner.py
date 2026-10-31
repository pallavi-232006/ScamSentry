import re
import urllib.parse
from typing import List, Dict, Any, Tuple, Optional
from app.schemas.scan import ThreatIndicator, UrlAnalysisItem

# Known URL Shorteners that obscure real destinations
COMMON_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "goo.gl", "tiny.cc", "rb.gy", "rebrand.ly", "shorturl.at",
    "t.me", "v.gd", "clck.ru", "bc.vc"
}

# Suspicious Top-Level Domains frequently abused in phishing campaigns
HIGH_RISK_TLDS = {
    ".xyz", ".top", ".club", ".work", ".cam", ".zip", ".mov", ".tk",
    ".ml", ".ga", ".cf", ".gq", ".country", ".kim", ".su", ".click",
    ".link", ".surf", ".rest"
}

# High-profile brands frequently impersonated
TARGETED_BRANDS = [
    "paypal", "apple", "microsoft", "netflix", "amazon", "google", "chase",
    "wellsfargo", "bankofamerica", "boa", "citibank", "citi", "dhl", "fedex", "usps",
    "whatsapp", "facebook", "instagram", "binance", "coinbase", "dropbox"
]

# Common lookalike typosquat substitutions
TYPOSQUAT_PATTERNS = [
    (r"paypa[l1i]", "paypal"),
    (r"micros[o0]ft", "microsoft"),
    (r"app[l1i]e", "apple"),
    (r"arnazon|amaz[o0]n", "amazon"),
    (r"g[o0]{2}g[l1i]e", "google"),
    (r"we[l1]{2}sfargo", "wellsfargo"),
    (r"c[o0]inbase", "coinbase"),
    (r"b[i1]nance", "binance"),
]

# Sensitive path keywords that necessitate HTTPS
SENSITIVE_PATH_KEYWORDS = {
    "login", "signin", "auth", "verify", "verification", "account",
    "security", "password", "credential", "banking", "checkout", "portal"
}

# Query parameter keys frequently used in open redirection or phishing
SUSPICIOUS_QUERY_KEYS = {
    "redirect", "url", "dest", "destination", "return_to", "next",
    "target", "r", "token", "session", "auth_key", "cmd", "download"
}


def extract_registered_domain(hostname: str) -> str:
    """Extracts registrable domain handling common two-part TLDs (e.g. .co.uk)."""
    parts = hostname.lower().split(".")
    if len(parts) <= 2:
        return hostname

    two_part_tlds = {"co.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.in", "com.br", "co.jp"}
    joined_last_two = f"{parts[-2]}.{parts[-1]}"

    if joined_last_two in two_part_tlds and len(parts) >= 3:
        return f"{parts[-3]}.{joined_last_two}"
    return f"{parts[-2]}.{parts[-1]}"


class UrlScanner:
    """
    Offline Structural URL Analysis Engine.
    Examines URLs for deceptive structures, homoglyphs, IP hosts, abnormal ports,
    and lookalike patterns without visiting, downloading, or resolving the target.
    """

    @classmethod
    def scan(cls, raw_url: str) -> Tuple[List[ThreatIndicator], List[str], Dict[str, Any], UrlAnalysisItem]:
        indicators: List[ThreatIndicator] = []
        suspicious_phrases: List[str] = []
        metadata: Dict[str, Any] = {}

        cleaned_url = raw_url.strip() if raw_url else ""

        # Handle empty input
        if not cleaned_url:
            empty_item = UrlAnalysisItem(
                raw_url="",
                scheme="",
                hostname="",
                domain="",
                path="",
                has_https=False,
            )
            return indicators, suspicious_phrases, metadata, empty_item

        # Check for malformed protocol scheme
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned_url):
            # Auto-prepend http for parsing inspection if missing
            url_to_parse = "http://" + cleaned_url
            has_explicit_scheme = False
        else:
            url_to_parse = cleaned_url
            has_explicit_scheme = True

        try:
            parsed = urllib.parse.urlparse(url_to_parse)
        except Exception as e:
            indicators.append(
                ThreatIndicator(
                    name="Malformed URL Structure",
                    category="URL Deception",
                    severity="high",
                    score_impact=35.0,
                    description=f"The provided URL syntax could not be parsed: {str(e)}",
                )
            )
            malformed_item = UrlAnalysisItem(
                raw_url=cleaned_url,
                scheme="",
                hostname="",
                domain="",
                path="",
                has_https=False,
                suspicious_indicators=indicators,
            )
            return indicators, suspicious_phrases, metadata, malformed_item

        scheme = (parsed.scheme or "http").lower()
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
        path = parsed.path or "/"
        query = parsed.query or ""

        # Parse query parameters into key-value pairs
        parsed_query: Dict[str, Any] = {}
        if query:
            try:
                raw_qs = urllib.parse.parse_qs(query, keep_blank_values=True)
                # Flatten single-item lists for clean reporting
                parsed_query = {k: v[0] if len(v) == 1 else v for k, v in raw_qs.items()}
            except Exception:
                pass

        registered_domain = extract_registered_domain(hostname) if hostname else ""

        is_ip_address = False
        is_shortener = False
        has_homoglyphs = False
        has_brand_lookalike = False

        metadata["scheme"] = scheme
        metadata["hostname"] = hostname
        metadata["domain"] = registered_domain
        metadata["port"] = port
        metadata["path"] = path
        metadata["path_length"] = len(path)
        metadata["query_param_count"] = len(parsed_query)

        # 1. IP Address Hostname Detection (IPv4, Hex/Octal, IPv6)
        ipv4_regex = r"^(?:\d{1,3}\.){3}\d{1,3}$"
        hex_ip_regex = r"^0x[0-9a-fA-F]+$"
        if re.match(ipv4_regex, hostname) or re.match(hex_ip_regex, hostname) or (parsed.hostname and parsed.hostname.startswith("[")):
            is_ip_address = True
            indicators.append(
                ThreatIndicator(
                    name="IP Address Hostname",
                    category="URL Deception",
                    severity="critical",
                    score_impact=50.0,
                    description=f"URL targets a raw IP address ({hostname}) rather than an authenticated domain name, bypassing domain validation standards.",
                )
            )
            suspicious_phrases.append(hostname)

        # 2. Known URL Shortener
        if hostname in COMMON_SHORTENERS:
            is_shortener = True
            indicators.append(
                ThreatIndicator(
                    name="URL Shortening Service",
                    category="Shortener",
                    severity="warning",
                    score_impact=20.0,
                    description=f"Uses a public URL shortener ({hostname}) that obscures the true destination address.",
                )
            )
            suspicious_phrases.append(hostname)

        # 3. High-Risk / Disposable Top-Level Domain (TLD)
        for tld in HIGH_RISK_TLDS:
            if hostname.endswith(tld):
                indicators.append(
                    ThreatIndicator(
                        name="High-Risk Top-Level Domain",
                        category="URL Deception",
                        severity="warning",
                        score_impact=18.0,
                        description=f"Host uses '{tld}', a top-level domain statistically associated with disposable phishing infrastructure.",
                    )
                )
                suspicious_phrases.append(tld)
                break

        # 4. Unusual or Non-Standard Port
        if port and port not in (80, 443, 8080):
            indicators.append(
                ThreatIndicator(
                    name="Non-Standard Port",
                    category="URL Deception",
                    severity="warning",
                    score_impact=22.0,
                    description=f"Service communicates over non-standard port {port}, commonly observed in evasion relays.",
                )
            )
            suspicious_phrases.append(f":{port}")

        # 5. Excessive Subdomain Stacking
        subdomain_parts = hostname.split(".")
        if len(subdomain_parts) >= 4 and not is_ip_address:
            indicators.append(
                ThreatIndicator(
                    name="Excessive Subdomain Stacking",
                    category="URL Deception",
                    severity="warning",
                    score_impact=20.0,
                    description=f"Host contains {len(subdomain_parts)} domain segments ('{hostname}'), often configured to confuse mobile browser address bars.",
                )
            )
            suspicious_phrases.append(hostname)

        # 6. Misleading Brand in Subdomain (Brand spoofing via DNS hierarchy)
        for brand in TARGETED_BRANDS:
            # Check if brand appears in a subdomain segment while registered domain is NOT the brand's official domain
            official_suffixes = (f"{brand}.com", f"{brand}.org", f"{brand}.net", f"{brand}.co.uk")
            if brand in hostname:
                is_official = any(registered_domain == s or registered_domain.endswith("." + s) for s in official_suffixes)
                if not is_official:
                    has_brand_lookalike = True
                    # Check if brand is specifically in subdomain
                    if hostname != registered_domain and brand in hostname.replace(registered_domain, ""):
                        indicators.append(
                            ThreatIndicator(
                                name=f"Misleading Brand Subdomain ({brand.capitalize()})",
                                category="Impersonation",
                                severity="critical",
                                score_impact=45.0,
                                description=f"Brand '{brand}' appears in subdomain of unauthorized domain '{registered_domain}'.",
                            )
                        )
                        suspicious_phrases.append(brand)
                    else:
                        indicators.append(
                            ThreatIndicator(
                                name=f"Brand Lookalike Domain ({brand.capitalize()})",
                                category="Impersonation",
                                severity="critical",
                                score_impact=40.0,
                                description=f"Host '{hostname}' incorporates brand token '{brand}' on an unofficial root domain.",
                            )
                        )
                        suspicious_phrases.append(brand)

        # 7. Typosquatting / Character Substitution
        for pattern, brand_name in TYPOSQUAT_PATTERNS:
            if re.search(pattern, hostname):
                if brand_name not in hostname:  # e.g., paypa1 or micros0ft
                    has_brand_lookalike = True
                    indicators.append(
                        ThreatIndicator(
                            name=f"Typosquatting Lookalike ({brand_name.capitalize()})",
                            category="Impersonation",
                            severity="critical",
                            score_impact=45.0,
                            description=f"Hostname contains deceptive character substitution targeting '{brand_name}'.",
                        )
                    )
                    suspicious_phrases.append(hostname)

        # 8. Homograph & Punycode (IDN) Attack Detection
        if hostname.startswith("xn--") or ".xn--" in hostname:
            has_homoglyphs = True
            indicators.append(
                ThreatIndicator(
                    name="Internationalized Domain (Punycode)",
                    category="URL Deception",
                    severity="high",
                    score_impact=35.0,
                    description=f"Host uses Punycode encoding ('{hostname}'), commonly deployed in visual homograph spoofing.",
                )
            )
            suspicious_phrases.append("xn--")

        # Check for non-ASCII or mixed-script homoglyphs in raw url
        cyrillic_homoglyphs = set("асеорхуіј")  # Cyrillic lookalikes to Latin a, c, e, o, p, x, y, i, j
        found_homoglyphs = [c for c in cleaned_url if c in cyrillic_homoglyphs]
        if found_homoglyphs:
            has_homoglyphs = True
            indicators.append(
                ThreatIndicator(
                    name="Cyrillic/Latin Homoglyph Characters",
                    category="URL Deception",
                    severity="critical",
                    score_impact=45.0,
                    description=f"URL contains non-Latin visual homoglyph character(s) ({', '.join(set(found_homoglyphs))}) designed to deceive human eyes.",
                )
            )
            suspicious_phrases.extend(found_homoglyphs)

        # 9. Authority Confusion (@ Symbol)
        if "@" in cleaned_url:
            indicators.append(
                ThreatIndicator(
                    name="Authority Confusion (@ Symbol)",
                    category="URL Deception",
                    severity="critical",
                    score_impact=45.0,
                    description="Contains '@' delimiter in URL authority, which causes web clients to ignore the preceding text and connect to the following host.",
                )
            )
            suspicious_phrases.append("@")

        # 10. Excessive Hyphens in Hostname
        if hostname.count("-") >= 3:
            indicators.append(
                ThreatIndicator(
                    name="Excessive Hyphenation in Hostname",
                    category="URL Deception",
                    severity="warning",
                    score_impact=18.0,
                    description=f"Hostname contains {hostname.count('-')} hyphens, a characteristic hallmark of machine-generated spoof domains.",
                )
            )
            suspicious_phrases.append(hostname)

        # 11. Suspicious Query Parameters (Open redirect / payload injection)
        for q_key in parsed_query.keys():
            if q_key.lower() in SUSPICIOUS_QUERY_KEYS:
                val = str(parsed_query[q_key])
                if "http://" in val or "https://" in val or ".xyz" in val or ".top" in val:
                    indicators.append(
                        ThreatIndicator(
                            name="Suspicious Open Redirect Parameter",
                            category="URL Deception",
                            severity="high",
                            score_impact=25.0,
                            description=f"Query parameter '{q_key}' points to secondary target URL ('{val[:40]}...').",
                        )
                    )
                    suspicious_phrases.append(f"{q_key}={val[:30]}")

        # 12. URL Encoding Tricks (Double encoding or hex obfuscation)
        if "%25" in cleaned_url or re.search(r"%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}", cleaned_url):
            indicators.append(
                ThreatIndicator(
                    name="Double URL Encoding Evasion",
                    category="URL Deception",
                    severity="high",
                    score_impact=25.0,
                    description="Contains double-percent encoding ('%25'), a technique used by attackers to evade web security filters.",
                )
            )
            suspicious_phrases.append("%25")

        # 13. HTTPS Absence on Credential / Banking Targets
        has_https = (scheme == "https")
        sensitive_match = any(term in (path + query).lower() for term in SENSITIVE_PATH_KEYWORDS)
        if not has_https and (sensitive_match or has_brand_lookalike):
            indicators.append(
                ThreatIndicator(
                    name="Insecure HTTP on Sensitive Target",
                    category="Transport Security",
                    severity="warning",
                    score_impact=15.0,
                    description=f"Authentication or sensitive path served over insecure plain HTTP rather than encrypted HTTPS.",
                )
            )
            suspicious_phrases.append("http://")

        # Construct UrlAnalysisItem object
        analysis_item = UrlAnalysisItem(
            raw_url=cleaned_url,
            scheme=scheme,
            hostname=hostname,
            domain=registered_domain,
            port=port,
            path=path,
            query_params=parsed_query,
            is_ip_address=is_ip_address,
            is_shortener=is_shortener,
            has_https=has_https,
            has_homoglyphs=has_homoglyphs,
            has_brand_lookalike=has_brand_lookalike,
            suspicious_indicators=indicators,
        )

        return indicators, list(set(suspicious_phrases)), metadata, analysis_item
