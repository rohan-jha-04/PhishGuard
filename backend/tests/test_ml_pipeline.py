import pytest
from app.ml.model_trainer import train_and_evaluate_models
from app.ml.predictor import predict_url

def test_model_training_and_metrics():
    report = train_and_evaluate_models()
    assert "models" in report
    rf = report["models"]["random_forest"]["metrics"]
    lr = report["models"]["logistic_regression"]["metrics"]
    
    # Both models should exhibit strong academic accuracy on benchmark
    assert rf["accuracy"] >= 0.85
    assert lr["accuracy"] >= 0.80
    assert "confusion_matrix" in rf
    assert len(report["feature_importances"]) > 0

def test_prediction_output():
    phish_url = "http://192.168.1.100/paypal/login.php?update=1"
    res = predict_url(phish_url)
    
    assert res["classification"] in ["suspicious", "phishing"]
    assert res["risk_score"] > 50.0
    assert len(res["explanations"]) > 0
    assert any(item["feature_key"] == "having_ip_address" for item in res["explanations"])

def test_legitimate_prediction_output():
    safe_urls = [
        "https://www.nature.com/articles/nature14539",
        "www.google.com",
        "http://www.google.com",
        "https://www.google.com"
    ]
    for safe_url in safe_urls:
        res = predict_url(safe_url)
        assert res["classification"] == "safe", f"Expected safe for {safe_url}, got {res['classification']}"
        assert res["risk_score"] < 10.0, f"Expected risk < 10 for {safe_url}, got {res['risk_score']}"

def test_typosquatting_and_nonexistent_domains():
    typo_res = predict_url("paypaI.com")
    assert typo_res["classification"] == "phishing"
    assert typo_res["risk_score"] >= 85.0
    assert typo_res["features"].get("typosquatting_target") == "paypal.com"

    nx_res = predict_url("rohanjhabihar.com")
    assert nx_res["classification"] in ["suspicious", "phishing"]
    assert nx_res["risk_score"] >= 40.0
    assert nx_res["features"].get("domain_non_existent") is True


