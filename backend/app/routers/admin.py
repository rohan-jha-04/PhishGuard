import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from app.database import get_db
from app.models.user import User
from app.models.scan import Scan
from app.schemas.scan import AdminOverviewStats
from app.schemas.auth import UserResponse
from app.security import get_current_admin_user
from app.config import settings
from app.ml.model_trainer import train_and_evaluate_models

router = APIRouter(prefix="/api/admin", tags=["Admin Portal & Model Management"])

@router.get("/overview", response_model=AdminOverviewStats)
def get_admin_overview(
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """Provides high-level system-wide telemetry, model accuracy, and threat rates."""
    total_users = db.query(User).count()
    total_scans = db.query(Scan).count()
    safe_count = db.query(Scan).filter(Scan.classification == "safe").count()
    suspicious_count = db.query(Scan).filter(Scan.classification == "suspicious").count()
    phishing_count = db.query(Scan).filter(Scan.classification == "phishing").count()

    threat_rate = round(((suspicious_count + phishing_count) / max(1, total_scans)) * 100, 2)

    # Load current model accuracy
    metrics_path = os.path.join(settings.MODEL_DIR, "metrics.json")
    model_acc = 0.965
    active_model_name = "Random Forest Classifier (Ensemble)"
    if os.path.exists(metrics_path):
        try:
            with open(metrics_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                model_acc = data["models"]["random_forest"]["metrics"]["accuracy"]
                active_model_name = data["models"]["random_forest"]["name"]
        except Exception:
            pass

    # Recent system scans
    recent = db.query(Scan).order_by(desc(Scan.created_at)).limit(5).all()
    recent_activity = [
        {
            "id": s.id,
            "url": s.defanged_url,
            "classification": s.classification,
            "risk_score": s.risk_score,
            "time": s.created_at.strftime("%H:%M:%S - %b %d")
        }
        for s in recent
    ]

    return {
        "total_users": total_users,
        "total_scans": total_scans,
        "threat_detection_rate": threat_rate,
        "safe_count": safe_count,
        "suspicious_count": suspicious_count,
        "phishing_count": phishing_count,
        "active_model": active_model_name,
        "model_accuracy": round(model_acc * 100, 2),
        "recent_system_activity": recent_activity
    }

@router.get("/users")
def get_all_users(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Results per page"),
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    Lists registered users with their scan volumes.
    Uses a single JOIN query (no N+1) and supports pagination.
    """
    # Single query: users + aggregated scan count via left outer join
    rows = (
        db.query(User, func.count(Scan.id).label("scan_count"))
        .outerjoin(Scan, Scan.user_id == User.id)
        .group_by(User.id)
        .order_by(desc(User.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    total = db.query(User).count()

    result = []
    for u, scan_count in rows:
        result.append({
            "id": u.id,
            "email": u.email,
            "full_name": u.full_name,
            "role": u.role,
            "is_active": u.is_active,
            "total_scans": scan_count,
            "created_at": u.created_at
        })

    return {
        "items": result,
        "total": total,
        "page": page,
        "page_size": page_size
    }

# Track training status to avoid duplicate runs
_retraining_in_progress = False

def _run_retrain():
    """Background task that resets the in-progress flag when done."""
    global _retraining_in_progress
    try:
        train_and_evaluate_models(settings.MODEL_DIR)
    finally:
        _retraining_in_progress = False

@router.post("/retrain")
def trigger_retraining(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    Queues a background retraining of the Random Forest and Logistic Regression
    models on the benchmark dataset. Returns immediately — does NOT block the
    event loop or other API requests.
    """
    global _retraining_in_progress
    if _retraining_in_progress:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A retraining job is already in progress. Please wait."
        )
    _retraining_in_progress = True
    background_tasks.add_task(_run_retrain)
    return {
        "status": "training_queued",
        "message": "Model retraining has been queued in the background. "
                   "Check /api/ml/metrics in a few minutes for updated results."
    }
