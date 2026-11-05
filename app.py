import os
import re
import json
import joblib

# Find the exact path of the directory this script is in
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(BASE_DIR, "sms_classifier.joblib")

# Load the saved model
model = joblib.load(model_path)

def scan_sms(text):
    # Rule heuristics
    has_link = bool(re.search(r'(https?://\S+|www\.\S+|bit\.ly/\S+)', text, re.IGNORECASE))
    
    # Extract urgent trigger words
    urgent_keywords = ["urgent", "blocked", "kyc", "suspended", "immediately", "lottery", "unpaid", "deactivated"]
    flagged_words = [w for w in urgent_keywords if w in text.lower()]
    
    # ML Prediction
    ml_probability = model.predict_proba([text])[0][1]
    
    # Risk fusion score
    final_score = ml_probability
    if has_link:
        final_score = min(1.0, final_score + 0.35)
    if flagged_words:
        final_score = min(1.0, final_score + 0.15)
        
    is_scam = bool(final_score >= 0.5)
    
    evidence = {
        "is_scam": is_scam,
        "risk_score": round(float(final_score), 2),
        "ml_probability": round(float(ml_probability), 2),
        "has_link": bool(has_link),
        "flagged_keywords": flagged_words
    }
    
    return evidence

if __name__ == "__main__":
    incoming_sms = input("\nEnter an SMS to test (or press Enter for default scam test): ").strip()
    if not incoming_sms:
        incoming_sms = "URGENT: Your bank account is suspended. Verify KYC immediately: http://bank-verify.in"
        
    print(f"\nAnalyzing: \"{incoming_sms}\"")
    evidence = scan_sms(incoming_sms)
    
    print("\n--- STAGE 1: DETECTOR EVIDENCE OUTPUT ---")
    print(json.dumps(evidence, indent=2))
    
    if evidence["is_scam"]:
        print("\n[DECISION]: Triggering Stage 2 (Llama Reasoning Prompt)...")
        print(">> Prompt Payload Prepared for ExecuTorch:")
        print(f"   Context: User received scam message with keywords {evidence['flagged_keywords']}.")
        print("   Task: Generate 2-sentence plain-language safety advice.")
    else:
        print("\n[DECISION]: Message is SAFE. LLM kept offline to preserve device battery.")