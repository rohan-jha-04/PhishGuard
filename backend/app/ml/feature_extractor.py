import re
import math
from urllib.parse import urlparse
from typing import Dict, Any, List

# List of known URL shortening domains used frequently in phishing redirection
SHORTENING_SERVICES = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "tiny.cc", "rebrand.ly", "cutt.ly",
    "shorte.st", "bc.vc", "snipurl.com", "bl.ink", "lnkd.in", "rb.gy"
}

# High-frequency keywords utilized by phishing campaigns for social engineering
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "banking",
    "secure", "security", "update", "wallet", "paypal", "appleid",
    "support", "confirm", "recovery", "password", "auth", "credential",
    "billing", "invoice", "validate", "suspended", "urgent"
]

COMMON_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "io", "co", "ai",
    "uk", "ca", "de", "fr", "in", "au", "app", "dev"
}

# High-reputation, verified apex authority domains
TOP_LEGITIMATE_DOMAINS = {
    "google.com", "google.co.in", "google.co.uk", "google.ca", "google.de", "google.fr",
    "youtube.com", "wikipedia.org", "github.com", "microsoft.com", "apple.com",
    "amazon.com", "cloudflare.com", "nature.com", "arxiv.org", "nih.gov",
    "cdc.gov", "who.int", "harvard.edu", "mit.edu", "stanford.edu",
    "ox.ac.uk", "cam.ac.uk", "berkeley.edu", "reuters.com", "bloomberg.com",
    "bbc.com", "cnn.com", "nytimes.com", "linkedin.com", "twitter.com",
    "x.com", "reddit.com", "stackoverflow.com", "w3.org", "gnu.org",
    "apache.org", "python.org", "scikit-learn.org", "fastapi.tiangolo.com",
    "react.dev", "mozilla.org", "kernel.org", "docker.com", "gitlab.com",
    "zoom.us", "slack.com", "dropbox.com", "netflix.com", "spotify.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "paypal.com",
    "stripe.com", "adobe.com", "salesforce.com", "ubuntu.com"
}

def extract_apex_domain(domain: str) -> str:
    """Extracts the registered apex domain (e.g. 'google.com' from 'www.google.com' or 'maps.google.co.uk')."""
    if not domain:
        return ""
    clean = domain.lower().split(":")[0].strip()
    parts = clean.split(".")
    if len(parts) >= 2:
        if len(parts) >= 3 and parts[-2] in ("co", "ac", "gov", "org", "edu", "net", "com"):
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return clean

def is_verified_apex_domain(domain: str) -> bool:
    """Returns True if the domain's apex is in the high-reputation top domains whitelist."""
    apex = extract_apex_domain(domain)
    return apex in TOP_LEGITIMATE_DOMAINS

FEATURE_ORDER = [
    "url_length",
    "having_ip_address",
    "num_subdomains",
    "is_https",
    "having_at_symbol",
    "double_slash_redirect",
    "prefix_suffix_hyphen",
    "is_shortened",
    "count_dots",
    "count_hyphens",
    "count_at",
    "count_question",
    "count_percent",
    "count_digits",
    "digit_ratio",
    "suspicious_words_count",
    "shannon_entropy",
    "path_length",
    "num_query_params",
    "tld_in_subdomain"
]

def calculate_shannon_entropy(text: str) -> float:
    """
    Computes Shannon Character Entropy of a string.
    High entropy (> 4.2) often indicates algorithmic domain generation (DGA) or obfuscated tokens.
    H(X) = - sum(p(x) * log2(p(x)))
    """
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = -sum([p * math.log2(p) for p in prob])
    return round(entropy, 4)

def check_ip_address(domain: str) -> int:
    """
    Checks if domain uses an explicit IPv4 or IPv6 address instead of legitimate FQDN.
    IPv4: 4 octets (0-255)
    IPv6: Hexadecimal representation
    Returns 1 if IP address is used, 0 otherwise.
    """
    # IPv4 regex
    ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    # IPv6 regex
    ipv6_pattern = r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
    
    clean_domain = domain.split(":")[0]  # remove port if present
    if re.match(ipv4_pattern, clean_domain) or re.match(ipv6_pattern, clean_domain):
        return 1
    return 0

def extract_features_from_url(url: str) -> Dict[str, Any]:
    """
    Extracts 20 academic lexical, syntactic, and structural features from a raw URL.
    Normalizes scheme-less inputs (e.g. 'www.google.com') according to modern browser standards.
    Returns dictionary with all computed features ready for vectorization and XAI analysis.
    """
    raw_url = url.strip()
    # Normalize for parsing: if no explicit scheme is present (e.g. www.google.com),
    # treat as standard modern web input (defaulting to https as browsers do)
    has_explicit_scheme = raw_url.startswith("http://") or raw_url.startswith("https://")
    if not has_explicit_scheme:
        effective_url = "https://" + raw_url
        is_https = 1
    else:
        effective_url = raw_url
        is_https = 1 if raw_url.lower().startswith("https://") else 0

    parsed = urlparse(effective_url)
    domain = parsed.netloc.lower() if parsed.netloc else parsed.path.split("/")[0].lower()
    path = parsed.path
    query = parsed.query

    # Clean domain (remove port)
    clean_domain = domain.split(":")[0]
    parts = clean_domain.split(".")
    if parts and parts[0] == "www":
        parts = parts[1:]
    num_subdomains = max(0, len(parts) - 2) if len(parts) > 2 else 0

    # 1. Overall URL length
    url_length = len(effective_url)

    # 2. IP Address presence
    having_ip = check_ip_address(domain)

    # 4. HTTPS usage (evaluated above)

    # 5. Having '@' symbol (ignores everything before @ in browsers, classic trick)
    having_at = 1 if "@" in effective_url else 0

    # 6. Double slash redirect (check if // appears anywhere after the scheme separator)
    after_scheme = effective_url.split("://", 1)[-1]
    double_slash = 1 if "//" in after_scheme else 0

    # 7. Prefix/Suffix hyphen in domain (phishers use paypal-update.com)
    prefix_suffix = 1 if "-" in clean_domain else 0

    # 8. Shortening service
    is_shortened = 1 if any(short_service in clean_domain for short_service in SHORTENING_SERVICES) else 0

    # 9-13. Lexical character counts
    count_dots = effective_url.count(".")
    count_hyphens = effective_url.count("-")
    count_at = effective_url.count("@")
    count_question = effective_url.count("?")
    count_percent = effective_url.count("%")

    # 14-15. Digits analysis
    digit_chars = sum(c.isdigit() for c in effective_url)
    digit_ratio = round(digit_chars / max(1, url_length), 4)

    # 16. Suspicious phishing keywords count
    url_lower = effective_url.lower()
    suspicious_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    # 17. Shannon character entropy
    entropy = calculate_shannon_entropy(clean_domain if clean_domain else effective_url)

    # 18. Path length
    path_len = len(path)

    # 19. Query parameters count
    query_params_count = len(query.split("&")) if query else 0

    # 20. TLD inside subdomain spoofing (e.g. secure.bank.com-login.net)
    tld_spoofing = 0
    if len(parts) > 2:
        for sub in parts[:-2]:
            if sub in COMMON_TLDS:
                tld_spoofing = 1
                break

    # Authority domain verification
    is_top_domain = 1 if is_verified_apex_domain(clean_domain) else 0
    apex = extract_apex_domain(clean_domain)

    features = {
        "url_length": url_length,
        "having_ip_address": having_ip,
        "num_subdomains": num_subdomains,
        "is_https": is_https,
        "having_at_symbol": having_at,
        "double_slash_redirect": double_slash,
        "prefix_suffix_hyphen": prefix_suffix,
        "is_shortened": is_shortened,
        "count_dots": count_dots,
        "count_hyphens": count_hyphens,
        "count_at": count_at,
        "count_question": count_question,
        "count_percent": count_percent,
        "count_digits": digit_chars,
        "digit_ratio": digit_ratio,
        "suspicious_words_count": suspicious_count,
        "shannon_entropy": entropy,
        "path_length": path_len,
        "num_query_params": query_params_count,
        "tld_in_subdomain": tld_spoofing,
        "domain": clean_domain,
        "is_top_domain": is_top_domain,
        "apex_domain": apex,
        "effective_url": effective_url
    }

    return features

    return features

def vectorize_features(features: Dict[str, Any]) -> List[float]:
    """Converts feature dict to ordered numerical vector for ML model input."""
    return [float(features[key]) for key in FEATURE_ORDER]

