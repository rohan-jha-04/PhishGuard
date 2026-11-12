"""
Real-Time Domain & Threat Verification Engine
Performs zero-page-execution live verification without fetching or rendering untrusted HTML:
1. Typosquatting & Visual Homoglyph Detection (Levenshtein + confusables + Punycode)
2. Live DNS Resolution Check (A/AAAA existence vs NXDOMAIN)
3. Live RDAP Registry Lookup (Real-time registration status, domain age, registrar)
4. Live TLS/SSL Handshake Verification (Certificate validity, issuer, age)
"""

import socket
import ssl
import concurrent.futures
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urlparse
import httpx

from app.ml.feature_extractor import TOP_LEGITIMATE_DOMAINS, extract_apex_domain, check_ip_address

# Major targets commonly impersonated by typosquatting and homoglyph campaigns
PROTECTED_BRAND_DOMAINS = TOP_LEGITIMATE_DOMAINS | {
    "facebook.com", "instagram.com", "whatsapp.com", "tiktok.com",
    "binance.com", "coinbase.com", "metamask.io", "blockchain.com",
    "yahoo.com", "outlook.com", "live.com", "icloud.com",
    "ebay.com", "walmart.com", "target.com", "bestbuy.com",
    "americanexpress.com", "citibank.com", "hsbc.com", "barclays.co.uk",
    "steam.com", "steampowered.com", "discord.com", "twitch.tv",
    "fedex.com", "ups.com", "dhl.com", "usps.com",
    "hdfcbank.com", "icicibank.com", "sbi.co.in", "onlinesbi.sbi"
}

# Precompute (brand_apex, brand_sld) pairs; prioritize .com/.org/.edu/.gov over regional ccTLDs
_PROTECTED_SLD_MAP: List[Tuple[str, str]] = [
    (brand, brand.split(".")[0])
    for brand in sorted(
        PROTECTED_BRAND_DOMAINS,
        key=lambda b: (0 if b.endswith(".com") else 1, b)
    )
    if len(brand.split(".")[0]) >= 4
]

# Confusable character pairs commonly used in visual typosquatting (e.g. paypaI.com, g00gle.com)
_HOMOGLYPH_CHAR_MAP = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "@": "a",
    "$": "s",
})


def _levenshtein(s1: str, s2: str) -> int:
    """Computes standard Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def _normalize_confusables(raw_label: str) -> List[str]:
    """
    Generates normalized candidate variants of a domain label by replacing
    common visual homoglyphs (e.g. 'I'->'l', 'i'->'l', '0'->'o', 'rn'->'m', 'vv'->'w').
    """
    lower = raw_label.lower().translate(_HOMOGLYPH_CHAR_MAP)
    variants = {lower}

    # Multi-character visual substitutions
    for v in list(variants):
        if "rn" in v:
            variants.add(v.replace("rn", "m"))
        if "vv" in v:
            variants.add(v.replace("vv", "w"))
        if "cl" in v:
            variants.add(v.replace("cl", "d"))

    # Capital 'I' inside lowercase text (e.g., paypaI) or 'i' replacing 'l'
    if "I" in raw_label:
        variants.add(raw_label.replace("I", "l").lower().translate(_HOMOGLYPH_CHAR_MAP))
    if "i" in lower:
        variants.add(lower.replace("i", "l"))
    if "l" in lower:
        variants.add(lower.replace("l", "i"))

    return list(variants)


def detect_typosquatting(raw_url: str, clean_domain: str, apex_domain: str) -> Dict[str, Any]:
    """
    Detects IDN Punycode homograph attacks, visual homoglyph substitutions (e.g. paypaI.com),
    and 1-to-2 character typosquatting against protected global brands.
    """
    result = {
        "typosquatting_detected": False,
        "typosquatting_target": None,
        "typosquatting_type": None,
        "punycode_detected": "xn--" in clean_domain
    }

    if result["punycode_detected"]:
        result["typosquatting_detected"] = True
        result["typosquatting_type"] = "IDN Punycode Homograph"

    if not apex_domain or check_ip_address(clean_domain) == 1:
        return result

    # If exact apex matches a protected brand, it's authentic (unless mixed-case homoglyph tricks)
    if apex_domain in PROTECTED_BRAND_DOMAINS:
        return result

    # Extract raw host before lowercasing to catch tricks like capital 'I' in paypaI.com
    raw_stripped = raw_url.strip()
    if not (raw_stripped.startswith("http://") or raw_stripped.startswith("https://")):
        raw_stripped = "https://" + raw_stripped
    raw_host = (urlparse(raw_stripped).netloc or "").split(":")[0]
    raw_apex_parts = raw_host.split(".")
    raw_sld = raw_apex_parts[-2] if len(raw_apex_parts) >= 2 else raw_host

    apex_sld = apex_domain.split(".")[0]
    if len(apex_sld) < 4:
        return result

    confusable_variants = _normalize_confusables(raw_sld)

    for brand_apex, brand_sld in _PROTECTED_SLD_MAP:
        # Skip if same SLD under a different legitimate ccTLD (e.g., google.in vs google.com)
        if apex_sld == brand_sld:
            continue

        # 1. Direct visual homoglyph match (e.g., paypaI -> paypal, g00gle -> google, arnazon -> amazon)
        if any(v == brand_sld for v in confusable_variants):
            result["typosquatting_detected"] = True
            result["typosquatting_target"] = brand_apex
            result["typosquatting_type"] = "Visual Homoglyph Spoofing"
            return result

        # 2. Edit-distance typosquatting (1 edit for >=5 char brands, 2 edits for >=8 char brands)
        dist = _levenshtein(apex_sld, brand_sld)
        max_allowed = 2 if len(brand_sld) >= 8 else (1 if len(brand_sld) >= 5 else 0)
        if 1 <= dist <= max_allowed:
            # Check if it involves a visual confusable character swap (i/l/1, o/0, m/n)
            has_mixed_i = "I" in raw_sld and any(c.islower() for c in raw_sld)
            has_digit_swap = any(ch in apex_sld for ch in ("0", "1", "3", "5"))
            if has_mixed_i or has_digit_swap or dist == 1:
                result["typosquatting_detected"] = True
                result["typosquatting_target"] = brand_apex
                result["typosquatting_type"] = f"Brand Typosquatting (Edit Distance {dist})"
                return result

    return result


def _check_dns_and_tls(clean_domain: str) -> Dict[str, Any]:
    """
    Resolves DNS records and, if live, performs a TLS/SSL handshake on port 443.
    Never downloads HTTP response body or executes remote page content.
    """
    dns_info = {
        "dns_resolved": False,
        "resolved_ip": None,
        "dns_error": None,
        "tls_checked": False,
        "tls_valid": None,
        "tls_issuer": None,
        "tls_age_days": None,
        "tls_error": None,
    }

    try:
        addr_info = socket.getaddrinfo(clean_domain, None)
        ips = [item[4][0] for item in addr_info if item[4]]
        if ips:
            dns_info["dns_resolved"] = True
            dns_info["resolved_ip"] = ips[0]
    except socket.gaierror as e:
        dns_info["dns_error"] = str(e)
        return dns_info
    except Exception as e:
        dns_info["dns_error"] = str(e)
        return dns_info

    # If DNS resolved, perform zero-content TLS handshake on port 443
    dns_info["tls_checked"] = True
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((clean_domain, 443), timeout=2.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                cert = ssock.getpeercert()
                dns_info["tls_valid"] = True
                if cert:
                    issuer_tuples = cert.get("issuer", ())
                    issuer_dict = dict(x[0] for x in issuer_tuples if x)
                    dns_info["tls_issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Verified CA"
                    not_before = cert.get("notBefore")
                    if not_before:
                        try:
                            nb_dt = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            dns_info["tls_age_days"] = max(0, (datetime.now(timezone.utc) - nb_dt).days)
                        except Exception:
                            pass
    except ssl.SSLCertVerificationError as e:
        dns_info["tls_valid"] = False
        dns_info["tls_error"] = f"Certificate verification failed: {e.verify_message}"
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        dns_info["tls_valid"] = False
        dns_info["tls_error"] = f"TLS port 443 unreachable ({type(e).__name__})"
    except Exception as e:
        dns_info["tls_valid"] = False
        dns_info["tls_error"] = str(e)

    return dns_info


def _check_rdap(apex_domain: str) -> Dict[str, Any]:
    """
    Queries public RDAP registry (rdap.org) for domain registration status,
    creation date, age in days, and registrar name.
    """
    rdap_info = {
        "rdap_status": None,
        "domain_registered": None,
        "registration_date": None,
        "domain_age_days": None,
        "registrar": None,
        "rdap_error": None,
    }

    if not apex_domain or "." not in apex_domain:
        return rdap_info

    try:
        with httpx.Client(timeout=3.0, follow_redirects=True) as client:
            resp = client.get(f"https://rdap.org/domain/{apex_domain}")
            rdap_info["rdap_status"] = resp.status_code

            if resp.status_code == 200:
                rdap_info["domain_registered"] = True
                data = resp.json()

                # Extract registration timestamp
                for ev in data.get("events", []):
                    if ev.get("eventAction") == "registration" and ev.get("eventDate"):
                        reg_str = ev["eventDate"]
                        rdap_info["registration_date"] = reg_str
                        try:
                            reg_dt = datetime.fromisoformat(reg_str.replace("Z", "+00:00"))
                            if reg_dt.tzinfo is None:
                                reg_dt = reg_dt.replace(tzinfo=timezone.utc)
                            rdap_info["domain_age_days"] = max(0, (datetime.now(timezone.utc) - reg_dt).days)
                        except Exception:
                            pass
                        break

                # Extract registrar name if available
                for ent in data.get("entities", []):
                    if "registrar" in ent.get("roles", []):
                        vcard = ent.get("vcardArray")
                        if isinstance(vcard, list) and len(vcard) > 1:
                            for item in vcard[1]:
                                if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                                    rdap_info["registrar"] = str(item[3])
                                    break
                        if rdap_info["registrar"]:
                            break
            elif resp.status_code == 404:
                rdap_info["domain_registered"] = False
    except Exception as e:
        rdap_info["rdap_error"] = str(e)

    return rdap_info


def verify_url_realtime(raw_url: str, clean_domain: str, apex_domain: str, is_ip: bool = False) -> Dict[str, Any]:
    """
    Executes typosquatting analysis + parallel real-time DNS, TLS, and RDAP checks.
    Bounded by strict timeouts so API latency stays low (~0.3s - 3.0s).
    """
    typo_result = detect_typosquatting(raw_url, clean_domain, apex_domain)

    # Skip network resolution for explicit IP addresses or local hostnames
    if is_ip or not clean_domain or clean_domain in ("localhost", "127.0.0.1") or clean_domain.endswith(".local"):
        return {
            **typo_result,
            "live_check_performed": False,
            "dns_resolved": None,
            "resolved_ip": None,
            "rdap_status": None,
            "domain_registered": None,
            "registration_date": None,
            "domain_age_days": None,
            "registrar": None,
            "tls_checked": False,
            "tls_valid": None,
            "tls_issuer": None,
            "tls_age_days": None,
            "tls_error": None,
            "domain_non_existent": False,
        }

    dns_tls_res: Dict[str, Any] = {
        "dns_resolved": None, "resolved_ip": None, "dns_error": None,
        "tls_checked": False, "tls_valid": None, "tls_issuer": None,
        "tls_age_days": None, "tls_error": None,
    }
    rdap_res: Dict[str, Any] = {
        "rdap_status": None, "domain_registered": None, "registration_date": None,
        "domain_age_days": None, "registrar": None, "rdap_error": None,
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        dns_future = executor.submit(_check_dns_and_tls, clean_domain)
        rdap_future = executor.submit(_check_rdap, apex_domain)

        try:
            dns_tls_res = dns_future.result(timeout=4.0)
        except Exception as e:
            dns_tls_res["dns_error"] = f"Timeout/Error: {e}"
            dns_tls_res["dns_resolved"] = False

        try:
            rdap_res = rdap_future.result(timeout=4.0)
        except Exception as e:
            rdap_res["rdap_error"] = f"Timeout/Error: {e}"

    # Determine if domain truly does not exist:
    # DNS failed AND RDAP returned 404 (rules out offline local environments and non-RDAP TLDs like .edu)
    dns_resolved = dns_tls_res.get("dns_resolved")
    rdap_status = rdap_res.get("rdap_status")
    domain_non_existent = (dns_resolved is False and rdap_status == 404)

    return {
        **typo_result,
        "live_check_performed": True,
        **dns_tls_res,
        **rdap_res,
        "domain_non_existent": domain_non_existent,
    }
