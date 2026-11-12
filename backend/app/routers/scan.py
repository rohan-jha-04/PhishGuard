import json
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.database import get_db
from app.models.user import User
from app.models.scan import Scan
from app.schemas.scan import (
    ScanRequest,
    ScanResponse,
    ScanHistoryResponse,
    ScanHistoryItem,
    UserScanStats
)
from app.security import (
    defang_url,
    get_current_user_optional,
    get_current_user
)
from app.ml.predictor import predict_url

router = APIRouter(prefix="/api/scan", tags=["URL Scanner & Explainability"])
limiter = Limiter(key_func=get_remote_address)

@router.post("/analyze", response_model=ScanResponse)
@limiter.limit("30/minute")
def analyze_url(
    payload: ScanRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """
    Performs full explainable machine learning detection on the submitted URL.
    Persists scan results, defangs the URL for safe storage, and returns structured XAI report.
    """
    url = payload.url.strip()
    prediction_result = predict_url(url)
    defanged = defang_url(url)

    # Client IP for security audit trail
    client_ip = request.client.host if request.client else "127.0.0.1"

    new_scan = Scan(
        user_id=current_user.id if current_user else None,
        url=url,
        defanged_url=defanged,
        domain=prediction_result["domain"],
        classification=prediction_result["classification"],
        risk_score=prediction_result["risk_score"],
        confidence=prediction_result["confidence"],
        model_used=prediction_result["model_used"],
        features_snapshot=json.dumps(prediction_result["features"]),
        explanation=json.dumps(prediction_result["explanations"]),
        client_ip=client_ip,
        created_at=datetime.now(timezone.utc)
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    return {
        "id": new_scan.id,
        "url": url,
        "defanged_url": defanged,
        "domain": prediction_result["domain"],
        "classification": prediction_result["classification"],
        "risk_score": prediction_result["risk_score"],
        "confidence": prediction_result["confidence"],
        "model_used": prediction_result["model_used"],
        "created_at": new_scan.created_at,
        "features": prediction_result["features"],
        "explanations": prediction_result["explanations"],
        "security_verdict": prediction_result["security_verdict"],
        "recommendation": prediction_result["recommendation"]
    }

@router.get("/history", response_model=ScanHistoryResponse)
def get_scan_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(15, ge=1, le=100),
    classification: Optional[str] = Query(None, description="Filter: 'safe', 'suspicious', 'phishing'"),
    search: Optional[str] = Query(None, description="Search domain or URL"),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Returns paginated, searchable scan history."""
    query = db.query(Scan)

    if current_user and current_user.role != "admin":
        query = query.filter(Scan.user_id == current_user.id)

    if classification and classification.lower() != "all":
        query = query.filter(Scan.classification == classification.lower())

    if search:
        search_filter = f"%{search.strip()}%"
        query = query.filter(
            (Scan.url.ilike(search_filter)) |
            (Scan.domain.ilike(search_filter)) |
            (Scan.defanged_url.ilike(search_filter))
        )

    total = query.count()
    items = query.order_by(desc(Scan.created_at)).offset((page - 1) * page_size).limit(page_size).all()

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size
    }

@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan_detail(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Retrieves full XAI explanation breakdown of a specific historical scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")

    # Access check: user can see own scans, admin can see all
    if current_user and current_user.role != "admin" and scan.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Unauthorized access to this scan record")

    features = json.loads(scan.features_snapshot) if scan.features_snapshot else {}
    explanations = json.loads(scan.explanation) if scan.explanation else []

    if scan.classification == "phishing":
        verdict = "HIGH RISK: Phishing & Malicious Patterns Detected"
        rec = "Do NOT visit or input credentials. High risk of identity theft."
    elif scan.classification == "suspicious":
        verdict = "MODERATE RISK: Structural Obfuscation Detected"
        rec = "Exercise caution. Check domain authenticity before interaction."
    else:
        verdict = "LOW RISK: URL Appears Legitimate & Structurally Sound"
        rec = "No malicious heuristics detected."

    return {
        "id": scan.id,
        "url": scan.url,
        "defanged_url": scan.defanged_url,
        "domain": scan.domain or "",
        "classification": scan.classification,
        "risk_score": scan.risk_score,
        "confidence": scan.confidence,
        "model_used": scan.model_used,
        "created_at": scan.created_at,
        "features": features,
        "explanations": explanations,
        "security_verdict": verdict,
        "recommendation": rec
    }

@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Removes a scan record from the database."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")
    if current_user.role != "admin" and scan.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Unauthorized deletion request")
    db.delete(scan)
    db.commit()
    return None

@router.get("/stats/summary", response_model=UserScanStats)
def get_user_scan_stats(
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Computes aggregated analytics, threat distribution, and timeline charts for User Dashboard."""
    query = db.query(Scan)
    if current_user and current_user.role != "admin":
        query = query.filter(Scan.user_id == current_user.id)

    total_scans = query.count()
    safe_scans = query.filter(Scan.classification == "safe").count()
    suspicious_scans = query.filter(Scan.classification == "suspicious").count()
    phishing_scans = query.filter(Scan.classification == "phishing").count()

    avg_score_res = query.with_entities(func.avg(Scan.risk_score)).scalar()
    avg_score = round(float(avg_score_res), 1) if avg_score_res is not None else 0.0

    threat_ratio = round(((phishing_scans + suspicious_scans) / max(1, total_scans)) * 100, 1)

    # 7-day daily activity
    now = datetime.now(timezone.utc)
    daily_activity = []
    for i in range(6, -1, -1):
        day_date = (now - timedelta(days=i)).date()
        day_str = day_date.strftime("%b %d")
        day_scans = query.filter(func.date(Scan.created_at) == day_date).count()
        phish_in_day = query.filter(func.date(Scan.created_at) == day_date, Scan.classification != "safe").count()
        daily_activity.append({
            "date": day_str,
            "total_scans": day_scans,
            "threats_detected": phish_in_day
        })

    # Distribution for donut chart
    threat_distribution = [
        {"name": "Safe URLs", "value": safe_scans, "color": "#27D17F"},
        {"name": "Suspicious", "value": suspicious_scans, "color": "#F59E0B"},
        {"name": "Phishing", "value": phishing_scans, "color": "#EF4444"}
    ]

    # Top threat indicators — counted from actual features_snapshot JSON stored per scan
    indicator_keys = {
        "having_ip_address":    "Direct IP Address Usage",
        "suspicious_words_count": "Social Engineering Keywords",
        "num_subdomains":       "Excessive Subdomain Depth",
        "is_https":             "Insecure HTTP Protocol",
        "is_shortened":         "URL Shortener Redirection",
        "prefix_suffix_hyphen": "Hyphenated Brand Squatting",
    }
    indicator_counts: dict = {label: 0 for label in indicator_keys.values()}

    # Only inspect non-safe scans (threat indicator context)
    threat_scans = query.filter(Scan.classification != "safe").all()
    for s in threat_scans:
        try:
            feat = json.loads(s.features_snapshot)
        except (TypeError, json.JSONDecodeError):
            continue
        for key, label in indicator_keys.items():
            val = feat.get(key, 0)
            # having_ip_address, is_shortened, prefix_suffix_hyphen: flag=1 means active
            # is_https: flag=0 means insecure (threat)
            # num_subdomains: >1 is threat
            # suspicious_words_count: >0 is threat
            if key == "is_https":
                if val == 0:
                    indicator_counts[label] += 1
            elif key == "num_subdomains":
                if val >= 2:
                    indicator_counts[label] += 1
            elif key == "suspicious_words_count":
                if val > 0:
                    indicator_counts[label] += 1
            else:
                if val == 1:
                    indicator_counts[label] += 1

    top_threat_indicators = sorted(
        [{"indicator": label, "count": count} for label, count in indicator_counts.items()],
        key=lambda x: x["count"],
        reverse=True
    )

    return {
        "total_scans": total_scans,
        "safe_scans": safe_scans,
        "suspicious_scans": suspicious_scans,
        "phishing_scans": phishing_scans,
        "avg_risk_score": avg_score,
        "threat_ratio_percent": threat_ratio,
        "daily_activity": daily_activity,
        "threat_distribution": threat_distribution,
        "top_threat_indicators": top_threat_indicators
    }

