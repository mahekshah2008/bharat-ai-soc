import os
import re
import joblib

# Load serialized model
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "sms_classifier.joblib")

model = None
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)

# High-risk urgency / scam trigger keywords common in Indian cyber threats
SUSPICIOUS_KEYWORDS = [
    "kyc", "suspended", "blocked", "immediately", "urgent", 
    "lottery", "prize", "aadhaar", "pan", "electricity", "challan"
]

def extract_threat_evidence(sms_text: str) -> dict:
    """
    Extracts heuristic signals and ML prediction to return structured evidence.
    """
    text_lower = sms_text.lower()
    
    # 1. Check for web links (http, https, bit.ly, etc.)
    has_link = bool(re.search(r'(https?://\S+|www\.\S+|bit\.ly/\S+)', sms_text, re.IGNORECASE))
    
    # 2. Check for flagged keywords
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text_lower]
    
    # 3. Model inference
    ml_prob = 0.0
    if model is not None:
        try:
            # Predict probability of scam (class 1)
            probs = model.predict_proba([sms_text])[0]
            ml_prob = round(float(probs[1]), 2)
        except Exception:
            pred = model.predict([sms_text])[0]
            ml_prob = 1.0 if pred == 1 else 0.0

    # 4. Composite Risk Score calculation
    # Base risk from ML probability
    risk_score = ml_prob
    if has_link and found_keywords:
        risk_score = min(1.0, risk_score + 0.3)
    elif has_link or found_keywords:
        risk_score = min(1.0, risk_score + 0.15)
        
    risk_score = round(risk_score, 2)
    is_scam = bool(risk_score >= 0.50)
    
    return {
        "is_scam": is_scam,
        "risk_score": risk_score,
        "ml_probability": ml_prob,
        "has_link": has_link,
        "flagged_keywords": found_keywords
    }