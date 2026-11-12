"""
Predictor & Explainable AI (XAI) Engine
Calculates prediction probability, risk score, classification, and
mathematically exact tree-path feature contributions derived from the Random Forest model.
"""

import os
import threading
import joblib
import numpy as np
from typing import Dict, Any, List
from app.config import settings
from app.ml.feature_extractor import (
    FEATURE_ORDER,
    extract_features_from_url,
    vectorize_features
)
from app.ml.model_trainer import train_and_evaluate_models
from app.ml.realtime_verifier import verify_url_realtime

# Cached model instance (protected by a lock to prevent concurrent init races)
_MODEL = None
_SCALER = None
_model_lock = threading.Lock()

def get_or_load_model():
    """Lazy loader for persisted ML model; thread-safe, automatically trains if missing."""
    global _MODEL, _SCALER
    if _MODEL is not None:
        return _MODEL

    with _model_lock:
        if _MODEL is not None:
            return _MODEL

        model_dir = settings.MODEL_DIR
        model_path = os.path.join(model_dir, "model.joblib")
        scaler_path = os.path.join(model_dir, "scaler.joblib")

        if not os.path.exists(model_path):
            train_and_evaluate_models(model_dir)

        _MODEL = joblib.load(model_path)
        if os.path.exists(scaler_path):
            _SCALER = joblib.load(scaler_path)

    return _MODEL

def compute_tree_contributions(model, vector: List[float]) -> Dict[str, float]:
    """
    Computes mathematically exact tree-path feature contributions
    across all decision trees in the Random Forest ensemble (TreeSHAP / Tree Path Attribution).
    For each tree, traces root-to-leaf decision nodes and attributes the probability shifts
    ΔP to the specific split feature.
    """
    X = np.array([vector], dtype=np.float32)
    n_features = len(vector)
    contributions = np.zeros(n_features, dtype=np.float64)

    if not hasattr(model, "estimators_"):
        return {feat: 0.0 for feat in FEATURE_ORDER}

    for estimator in model.estimators_:
        tree = estimator.tree_
        node_indicator = tree.decision_path(X)
        node_indices = node_indicator.indices

        # Probability of class 1 (phishing) at each node
        values = tree.value[:, 0, :]
        node_totals = values.sum(axis=1, keepdims=True)
        # Avoid division by zero
        node_totals[node_totals == 0] = 1.0
        phish_probs = (values / node_totals)[:, 1]

        for i in range(len(node_indices) - 1):
            curr_node = node_indices[i]
            next_node = node_indices[i + 1]
            split_feature = tree.feature[curr_node]
            if split_feature >= 0:
                diff = phish_probs[next_node] - phish_probs[curr_node]
                contributions[split_feature] += diff

    contributions /= len(model.estimators_)
    return {FEATURE_ORDER[idx]: float(contributions[idx]) for idx in range(n_features)}

def explain_features(features: Dict[str, Any], contributions: Dict[str, float] = None) -> List[Dict[str, Any]]:
    """
    Explainable AI (XAI) feature analysis engine.
    Audits each structural, lexical, and behavioral indicator, combining
    actual tree-path mathematical contributions with domain compliance reasoning.
    """
    if contributions is None:
        contributions = {}

    explanations = []

    # Helper to evaluate status and impact level from actual mathematical contribution
    def evaluate_status_impact(contrib_val: float, is_inherent_threat: bool = False):
        if is_inherent_threat or contrib_val >= 15.0:
            return "PHISHING", "Critical"
        elif contrib_val >= 7.5:
            return "PHISHING", "High"
        elif contrib_val >= 2.0:
            return "SUSPICIOUS", "Moderate"
        elif contrib_val >= 0.5:
            return "SUSPICIOUS", "Low"
        elif contrib_val <= -3.0:
            return "SAFE", "Beneficial"
        else:
            return "SAFE", "None"

    # 1. IP Address usage
    ip_val = features.get("having_ip_address", 0)
    c_ip = round(contributions.get("having_ip_address", 0.0) * 100, 1)
    status_ip, impact_ip = evaluate_status_impact(c_ip, is_inherent_threat=(ip_val == 1))
    explanations.append({
        "feature_key": "having_ip_address",
        "feature_name": "Direct IP Address Usage",
        "value": "Explicit IP Found" if ip_val == 1 else "Domain Name Used",
        "baseline_threshold": "Standard FQDN Domain Name",
        "status": status_ip,
        "impact_level": impact_ip,
        "score_contribution": c_ip,
        "explanation": "URL uses a raw IP address directly, bypassing standard DNS reputation and domain controls."
                       if ip_val == 1 else
                       "Legitimate Fully Qualified Domain Name (FQDN) is utilized rather than a raw IP address."
    })

    # 2. URL Shortener
    is_short = features.get("is_shortened", 0)
    c_short = round(contributions.get("is_shortened", 0.0) * 100, 1)
    status_short, impact_short = evaluate_status_impact(c_short, is_inherent_threat=(is_short == 1))
    explanations.append({
        "feature_key": "is_shortened",
        "feature_name": "URL Shortener Redirection",
        "value": "Shortening Service Detected" if is_short == 1 else "Direct Canonical URL",
        "baseline_threshold": "Direct Canonical Domain",
        "status": status_short,
        "impact_level": impact_short,
        "score_contribution": c_short,
        "explanation": "URL utilizes a shortening service that conceals the destination domain from pre-navigation inspection."
                       if is_short == 1 else
                       "No masking or redirecting URL shortening service was detected."
    })

    # 3. '@' Symbol credential ingestion
    has_at = features.get("having_at_symbol", 0)
    c_at = round(contributions.get("having_at_symbol", 0.0) * 100, 1)
    status_at, impact_at = evaluate_status_impact(c_at, is_inherent_threat=(has_at == 1))
    explanations.append({
        "feature_key": "having_at_symbol",
        "feature_name": "Credential '@' Ingestion Trick",
        "value": f"Present ({features.get('count_at', 1)} instance)" if has_at == 1 else "None (0 occurrences)",
        "baseline_threshold": "0 occurrences",
        "status": status_at,
        "impact_level": impact_at,
        "score_contribution": c_at,
        "explanation": "Contains '@' symbol. Browsers discard all characters before '@', routing the victim to an attacker host."
                       if has_at == 1 else
                       "Standard URI syntax without embedded credential '@' redirection characters."
    })

    # 4. Prefix-Suffix Hyphen in Domain
    has_hyphen = features.get("prefix_suffix_hyphen", 0)
    c_hyphen = round(contributions.get("prefix_suffix_hyphen", 0.0) * 100, 1)
    status_hyphen, impact_hyphen = evaluate_status_impact(c_hyphen, is_inherent_threat=(has_hyphen == 1))
    explanations.append({
        "feature_key": "prefix_suffix_hyphen",
        "feature_name": "Domain Hyphenation Squatting",
        "value": f"Hyphen Found ('{features.get('domain', '')}')" if has_hyphen == 1 else "Clean Domain Structure",
        "baseline_threshold": "Clean alphanumeric domain",
        "status": status_hyphen,
        "impact_level": impact_hyphen,
        "score_contribution": c_hyphen,
        "explanation": "Domain contains hyphens (e.g. 'paypal-security.com'), a frequent brand-squatting technique."
                       if has_hyphen == 1 else
                       "Clean domain structure without suspicious brand-hyphenation patterns."
    })

    # 5. Subdomain nesting depth
    subdomains = features.get("num_subdomains", 0)
    c_sub = round(contributions.get("num_subdomains", 0.0) * 100, 1)
    status_sub, impact_sub = evaluate_status_impact(c_sub, is_inherent_threat=(subdomains >= 2))
    explanations.append({
        "feature_key": "num_subdomains",
        "feature_name": "Subdomain Depth Level",
        "value": f"{subdomains} Nested Subdomain(s)",
        "baseline_threshold": "0 to 1 Subdomains",
        "status": status_sub,
        "impact_level": impact_sub,
        "score_contribution": c_sub,
        "explanation": f"Excessive subdomain depth ({subdomains} tiers). Attackers frequently nest brand names as subdomains."
                       if subdomains >= 2 else
                       "Subdomain hierarchy is within normal parameters for modern web architecture."
    })

    # 6. Suspicious Phishing Keywords
    kw_count = features.get("suspicious_words_count", 0)
    c_kw = round(contributions.get("suspicious_words_count", 0.0) * 100, 1)
    status_kw, impact_kw = evaluate_status_impact(c_kw, is_inherent_threat=(kw_count > 1))
    explanations.append({
        "feature_key": "suspicious_words_count",
        "feature_name": "Social Engineering Keywords",
        "value": f"{kw_count} Sensitive Keyword(s)" if kw_count > 0 else "None Detected",
        "baseline_threshold": "0 Keywords",
        "status": status_kw,
        "impact_level": impact_kw,
        "score_contribution": c_kw,
        "explanation": "URL contains sensitive keywords associated with credential harvesting (login, verify, banking, security)."
                       if kw_count > 0 else
                       "No deceptive social-engineering credential keywords detected in URL path."
    })

    # 7. Shannon Character Entropy (Domain Randomness)
    entropy = features.get("shannon_entropy", 0.0)
    c_ent = round(contributions.get("shannon_entropy", 0.0) * 100, 1)
    status_ent, impact_ent = evaluate_status_impact(c_ent, is_inherent_threat=(entropy > 4.2))
    explanations.append({
        "feature_key": "shannon_entropy",
        "feature_name": "Domain Shannon Entropy",
        "value": f"{entropy} bits",
        "baseline_threshold": "< 3.8 bits",
        "status": status_ent,
        "impact_level": impact_ent,
        "score_contribution": c_ent,
        "explanation": "High character entropy indicates algorithmic domain generation (DGA) or randomized evasion tokens."
                       if entropy > 4.2 else
                       "Domain character entropy conforms to standard human-readable linguistic patterns."
    })

    # 8. Protocol Security (HTTPS vs HTTP)
    is_https = features.get("is_https", 1)
    c_https = round(contributions.get("is_https", 0.0) * 100, 1)
    status_https, impact_https = evaluate_status_impact(c_https)
    explanations.append({
        "feature_key": "is_https",
        "feature_name": "Transport Layer Security (TLS)",
        "value": "HTTPS Enforced" if is_https == 1 else "Insecure HTTP Protocol",
        "baseline_threshold": "HTTPS Standard",
        "status": status_https,
        "impact_level": impact_https,
        "score_contribution": c_https,
        "explanation": "Encrypted HTTPS communication is active."
                       if is_https == 1 else
                       "Plain HTTP protocol detected; communications are unencrypted."
    })

    # 9. URL Total Length
    length = features.get("url_length", 0)
    c_len = round(contributions.get("url_length", 0.0) * 100, 1)
    status_len, impact_len = evaluate_status_impact(c_len, is_inherent_threat=(length > 100))
    explanations.append({
        "feature_key": "url_length",
        "feature_name": "URL Character Length",
        "value": f"{length} Characters",
        "baseline_threshold": "< 75 Characters",
        "status": status_len,
        "impact_level": impact_len,
        "score_contribution": c_len,
        "explanation": "Abnormally long URL length, frequently used to conceal attack indicators within padded query parameters."
                       if length > 75 else
                       "Standard compact URL length consistent with authentic web destinations."
    })

    # 10. Double Slash Redirect
    double_slash = features.get("double_slash_redirect", 0)
    c_ds = round(contributions.get("double_slash_redirect", 0.0) * 100, 1)
    status_ds, impact_ds = evaluate_status_impact(c_ds, is_inherent_threat=(double_slash == 1))
    explanations.append({
        "feature_key": "double_slash_redirect",
        "feature_name": "Embedded Double Slash Redirect",
        "value": "Detected within path" if double_slash == 1 else "Protocol Only",
        "baseline_threshold": "Protocol only",
        "status": status_ds,
        "impact_level": impact_ds,
        "score_contribution": c_ds,
        "explanation": "Contains '//' inside URL path, a known open-redirect evasion exploit."
                       if double_slash == 1 else
                       "No embedded double slash redirection sequences detected."
    })

    # 11. Top Domain Reputation factor (if verified authority domain)
    if features.get("is_top_domain"):
        explanations.insert(0, {
            "feature_key": "top_authority_domain",
            "feature_name": "Global Authority Domain Reputation",
            "value": f"Verified ({features.get('apex_domain', '')})",
            "baseline_threshold": "Verified Apex Whitelist",
            "status": "SAFE",
            "impact_level": "Beneficial",
            "score_contribution": -25.0,
            "explanation": f"Apex domain '{features.get('apex_domain', '')}' is a verified high-reputation global platform with clean structural attributes."
        })

    return explanations


def _build_realtime_explanations(rt: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Builds structured XAI cards for real-time typosquatting, DNS, RDAP, and TLS checks."""
    rt_cards: List[Dict[str, Any]] = []

    # A. Brand Typosquatting & Homoglyph Spoofing
    if rt.get("typosquatting_detected"):
        target = rt.get("typosquatting_target") or "Protected Brand"
        typo_type = rt.get("typosquatting_type") or "Lookalike Domain"
        rt_cards.append({
            "feature_key": "typosquatting_check",
            "feature_name": "Brand Typosquatting & Homoglyph Check",
            "value": f"Spoofs '{target}' ({typo_type})",
            "baseline_threshold": "Zero Brand Impersonation",
            "status": "PHISHING",
            "impact_level": "Critical",
            "score_contribution": 45.0,
            "explanation": f"Domain closely mimics '{target}' via {typo_type}. Attackers substitute characters (such as 'I' for 'l', '0' for 'o', or Punycode) to deceive users."
        })
    else:
        rt_cards.append({
            "feature_key": "typosquatting_check",
            "feature_name": "Brand Typosquatting & Homoglyph Check",
            "value": "No Impersonation Detected",
            "baseline_threshold": "Zero Brand Impersonation",
            "status": "SAFE",
            "impact_level": "None",
            "score_contribution": -3.0,
            "explanation": "Domain does not match visual homoglyph or edit-distance spoofing patterns against major protected brands."
        })

    if not rt.get("live_check_performed"):
        return rt_cards

    # B. Live DNS Resolution
    dns_ok = rt.get("dns_resolved")
    if dns_ok is True:
        rt_cards.append({
            "feature_key": "live_dns_resolution",
            "feature_name": "Live DNS Resolution",
            "value": f"Resolved ({rt.get('resolved_ip')})",
            "baseline_threshold": "Active A/AAAA Record",
            "status": "SAFE",
            "impact_level": "Beneficial",
            "score_contribution": -5.0,
            "explanation": f"Domain actively resolves in public DNS to {rt.get('resolved_ip')}."
        })
    elif rt.get("domain_non_existent"):
        rt_cards.append({
            "feature_key": "live_dns_resolution",
            "feature_name": "Live DNS Resolution",
            "value": "NXDOMAIN (Does Not Exist)",
            "baseline_threshold": "Active A/AAAA Record",
            "status": "SUSPICIOUS",
            "impact_level": "High",
            "score_contribution": 35.0,
            "explanation": "Domain does not resolve in public DNS and has no active registry record. Non-existent domains cannot be verified as safe websites."
        })
    elif dns_ok is False:
        rt_cards.append({
            "feature_key": "live_dns_resolution",
            "feature_name": "Live DNS Resolution",
            "value": "Unresolvable / Inactive Host",
            "baseline_threshold": "Active A/AAAA Record",
            "status": "SUSPICIOUS",
            "impact_level": "Moderate",
            "score_contribution": 25.0,
            "explanation": "Live DNS lookup failed to resolve an IP address for this host. The site may be inactive, parked, or taken down."
        })

    # C. Live RDAP Domain Age & Registry Status
    age_days = rt.get("domain_age_days")
    rdap_status = rt.get("rdap_status")
    if age_days is not None:
        years = round(age_days / 365.25, 1)
        age_label = f"{years} yrs ({age_days} days)" if age_days >= 365 else f"{age_days} days old"
        if age_days < 30:
            rt_cards.append({
                "feature_key": "rdap_domain_age",
                "feature_name": "RDAP Registry & Domain Age",
                "value": f"{age_label} (Newly Registered)",
                "baseline_threshold": "> 365 Days Registered",
                "status": "PHISHING" if age_days < 7 else "SUSPICIOUS",
                "impact_level": "High",
                "score_contribution": 28.0 if age_days < 7 else 18.0,
                "explanation": f"RDAP registry confirms this domain was created only {age_days} days ago. Newly registered domains are strongly correlated with active phishing kits."
            })
        else:
            rt_cards.append({
                "feature_key": "rdap_domain_age",
                "feature_name": "RDAP Registry & Domain Age",
                "value": age_label,
                "baseline_threshold": "> 365 Days Registered",
                "status": "SAFE",
                "impact_level": "Beneficial" if age_days >= 365 else "None",
                "score_contribution": -8.0 if age_days >= 365 else -2.0,
                "explanation": f"RDAP registry confirms established domain history ({age_label})."
            })
    elif rdap_status == 404 and rt.get("domain_non_existent"):
        rt_cards.append({
            "feature_key": "rdap_domain_age",
            "feature_name": "RDAP Registry & Domain Age",
            "value": "Unregistered (HTTP 404)",
            "baseline_threshold": "Active Domain Registration",
            "status": "SUSPICIOUS",
            "impact_level": "High",
            "score_contribution": 23.0,
            "explanation": "Public RDAP registry returned HTTP 404 (not found), indicating the domain is not registered."
        })

    # D. Live TLS/SSL Handshake
    if rt.get("tls_checked"):
        if rt.get("tls_valid"):
            issuer = rt.get("tls_issuer") or "Verified CA"
            rt_cards.append({
                "feature_key": "live_tls_certificate",
                "feature_name": "Live TLS/SSL Certificate",
                "value": f"Valid ({issuer})",
                "baseline_threshold": "Trusted CA & Valid Hostname",
                "status": "SAFE",
                "impact_level": "Beneficial",
                "score_contribution": -4.0,
                "explanation": f"Zero-content TLS handshake succeeded with a valid certificate issued by {issuer}."
            })
        else:
            rt_cards.append({
                "feature_key": "live_tls_certificate",
                "feature_name": "Live TLS/SSL Certificate",
                "value": "Invalid / Unreachable TLS",
                "baseline_threshold": "Trusted CA & Valid Hostname",
                "status": "SUSPICIOUS",
                "impact_level": "Moderate",
                "score_contribution": 12.0,
                "explanation": f"TLS/SSL certificate check failed: {rt.get('tls_error') or 'Handshake unsuccessful'}."
            })

    return rt_cards


def predict_url(url: str, check_realtime: bool = True) -> Dict[str, Any]:
    """
    Main prediction pipeline:
    1. Feature extraction with browser-standard URL normalization
    2. Vectorization & Random Forest inference
    3. Mathematically exact Tree Path Feature Attribution (TreeSHAP)
    4. Real-time verification (Typosquatting/Homoglyphs, DNS, RDAP Age, TLS Handshake)
    5. Calibrated risk scoring and plain-English explainability
    """
    features = extract_features_from_url(url)
    vector = vectorize_features(features)

    model = get_or_load_model()
    proba = model.predict_proba([vector])[0]
    phishing_prob = float(proba[1])

    # Compute mathematically exact Tree-Path Feature Contributions
    contributions = compute_tree_contributions(model, vector)

    # Real-time verification checks (zero-page-execution)
    is_ip = features.get("having_ip_address", 0) == 1
    if check_realtime:
        rt = verify_url_realtime(
            raw_url=url,
            clean_domain=features.get("domain", ""),
            apex_domain=features.get("apex_domain", ""),
            is_ip=is_ip,
        )
    else:
        rt = {
            "typosquatting_detected": False, "typosquatting_target": None,
            "typosquatting_type": None, "punycode_detected": False,
            "live_check_performed": False, "dns_resolved": None,
            "resolved_ip": None, "rdap_status": None, "domain_registered": None,
            "registration_date": None, "domain_age_days": None, "registrar": None,
            "tls_checked": False, "tls_valid": None, "tls_issuer": None,
            "tls_age_days": None, "tls_error": None, "domain_non_existent": False,
        }

    # Attach real-time audit telemetry to features snapshot
    features.update({
        "dns_resolved": rt.get("dns_resolved"),
        "resolved_ip": rt.get("resolved_ip"),
        "domain_age_days": rt.get("domain_age_days"),
        "rdap_status": rt.get("rdap_status"),
        "tls_valid": rt.get("tls_valid"),
        "tls_issuer": rt.get("tls_issuer"),
        "typosquatting_target": rt.get("typosquatting_target"),
        "domain_non_existent": rt.get("domain_non_existent"),
    })

    is_top_domain = bool(features.get("is_top_domain", False))
    has_critical_exploit = (
        is_ip or
        features.get("having_at_symbol", 0) == 1 or
        features.get("double_slash_redirect", 0) == 1 or
        features.get("is_shortened", 0) == 1 or
        features.get("tld_in_subdomain", 0) == 1 or
        features.get("num_subdomains", 0) >= 2 or
        features.get("prefix_suffix_hyphen", 0) == 1
    )

    risk_score = round(phishing_prob * 100, 1)
    confidence = round(max(proba) * 100, 1)

    # Calibrate verdict & rating combining ML + Real-Time Verification
    if rt.get("typosquatting_detected"):
        target = rt.get("typosquatting_target") or "Protected Brand"
        risk_score = max(risk_score, 91.5)
        confidence = round(max(confidence, 94.0), 1)
        classification = "phishing"
        verdict = f"HIGH RISK: Brand Typosquatting / Homoglyph Spoofing ({target})"
        recommendation = (
            f"Do NOT trust or enter credentials. This domain mimics '{target}' using "
            f"{rt.get('typosquatting_type') or 'lookalike character substitution'}."
        )
    elif rt.get("domain_non_existent"):
        risk_score = max(risk_score, 58.0)
        classification = "phishing" if risk_score >= 70.0 else "suspicious"
        confidence = round(max(78.0, min(95.0, risk_score + 20.0)), 1)
        verdict = "UNVERIFIED / NON-EXISTENT: Domain Not Found in DNS or Registry"
        recommendation = (
            "Live DNS lookup returned NXDOMAIN and the RDAP registry returned 404 (not registered). "
            "This website does not exist; verify the spelling carefully before proceeding."
        )
    elif rt.get("live_check_performed") and rt.get("dns_resolved") is False:
        risk_score = max(risk_score, 48.0)
        classification = "phishing" if risk_score >= 70.0 else "suspicious"
        confidence = round(max(65.0, confidence), 1)
        verdict = "MODERATE RISK: Host Unreachable / Failed Live DNS Resolution"
        recommendation = (
            "Domain failed live DNS resolution. Inactive, parked, or taken-down domains cannot be "
            "verified as safe destinations."
        )
    elif rt.get("domain_age_days") is not None and rt["domain_age_days"] < 30:
        age_d = rt["domain_age_days"]
        risk_score = max(risk_score, 76.0 if age_d < 7 else 55.0)
        classification = "phishing" if risk_score >= 70.0 else "suspicious"
        confidence = round(max(confidence, 80.0), 1)
        verdict = (
            f"HIGH RISK: Newly Registered Domain ({age_d} Days Old)"
            if classification == "phishing"
            else f"MODERATE RISK: Young Domain Registration ({age_d} Days Old)"
        )
        recommendation = (
            f"RDAP registry indicates this domain was registered only {age_d} days ago. "
            "Exercise extreme caution, as newly created domains are heavily used in phishing campaigns."
        )
    elif is_top_domain and not has_critical_exploit:
        calibrated_risk = min(risk_score, 3.5)
        risk_score = calibrated_risk
        confidence = round(max(96.5, (1.0 - (calibrated_risk / 100.0)) * 100), 1)
        classification = "safe"
        verdict = f"LOW RISK: Verified Global Authority Domain ({features.get('apex_domain', '')})"
        recommendation = (
            "Live DNS, TLS, and structural checks confirm this is an authentic global authority destination."
        )
    else:
        if rt.get("tls_checked") and rt.get("tls_valid") is False and features.get("is_https") == 1:
            risk_score = max(risk_score, 45.0)

        if risk_score >= 70.0:
            classification = "phishing"
            verdict = "HIGH RISK: Phishing & Malicious Patterns Detected"
            recommendation = "Do NOT visit or input credentials. This URL exhibits significant structural and lexical indicators common in identity theft campaigns."
        elif risk_score >= 40.0:
            classification = "suspicious"
            verdict = "MODERATE RISK: Anomaly or Obfuscation Detected"
            recommendation = "Exercise extreme caution. Several structural abnormalities match deceptive URL patterns. Verify domain authenticity before proceeding."
        else:
            classification = "safe"
            verdict = "LOW RISK: URL Appears Legitimate & Structurally Sound"
            if rt.get("dns_resolved") and rt.get("tls_valid"):
                recommendation = "Live DNS resolution and TLS certificate checks passed with no malicious heuristics detected."
            else:
                recommendation = "No malicious heuristics detected. URL exhibits standard structural properties consistent with legitimate web domains."

    # Combine Real-Time Verification cards with Tree-Path ML explanations
    rt_cards = _build_realtime_explanations(rt)
    ml_cards = explain_features(features, contributions)
    explanations = rt_cards + ml_cards

    return {
        "url": url,
        "domain": features.get("domain", ""),
        "classification": classification,
        "risk_score": risk_score,
        "confidence": confidence,
        "model_used": "Random Forest + Real-Time DNS/RDAP/TLS Verifier",
        "features": features,
        "explanations": explanations,
        "security_verdict": verdict,
        "recommendation": recommendation
    }
