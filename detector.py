import re
import json

def detect_scam(sms_text):
    # 1. Guard rules: check links aur scam keywords
    has_link = bool(re.search(r'(https?://\S+|www\.\S+|bit\.ly/\S+)', sms_text, re.IGNORECASE))
    scam_keywords = [
        "blocked", "urgent", "kyc", "lottery", "prize", 
        "account suspended", "electricity", "cut off", "immediately", "verify"
    ]
    
    found_keywords = [word for word in scam_keywords if word in sms_text.lower()]
            
    # 2. Risk scoring (0.0 to 1.0)
    risk_score = 0.0
    if has_link:
        risk_score += 0.5
    if len(found_keywords) > 0:
        risk_score += 0.2 * len(found_keywords)
        
    risk_score = min(risk_score, 1.0)
    is_scam = risk_score >= 0.5
    
    return {
        "is_scam": is_scam,
        "risk_score": round(risk_score, 2),
        "has_link": has_link,
        "indicators": found_keywords
    }

def llama_generate_explanation(sms_text, evidence):
    """
    Yeh function wahi kaam karega jo aage chalke Llama on-device karega:
    Evidence ko dekh kar aasan bhasha mein warning aur next steps dena.
    """
    reasons = []
    if evidence["has_link"]:
        reasons.append("unverified suspicious link")
    if evidence["indicators"]:
        reasons.append(f"urgent pressure tactics (words used: {', '.join(evidence['indicators'])})")
    
    explanation = f"This message appears to be a fraudulent attempt using {' and '.join(reasons)}."
    
    remediation = [
        "1. Do not tap on the link or download any attachments.",
        "2. Do not share OTPs, bank credentials, or personal identity details.",
        "3. Verify independently by contacting the official service provider via their legitimate helpline or website."
    ]
    
    return explanation, remediation

def process_message(sms_text):
    print("\n" + "="*55)
    print(f"📩 INCOMING SMS: \"{sms_text}\"")
    print("="*55)
    
    # Stage 1: Guard ka kaam (Fast check)
    evidence = detect_scam(sms_text)
    
    if not evidence["is_scam"]:
        print("\n✅ [STATUS: SAFE]")
        print("Guard Verdict: No threats or suspicious patterns detected.")
        print("Battery Saver: Llama model was NOT awakened.")
        return
    
    # Stage 2: Officer ka kaam (Jab khatra mile)
    print("\n🚨 [STATUS: THREAT DETECTED]")
    print(f"Risk Score: {evidence['risk_score']} / 1.0")
    print(f"Flags Triggered: {evidence['indicators']} | Link Found: {evidence['has_link']}")
    
    print("\n🧠 [STAGE 2: LLAMA ON-DEVICE ADVISORY]:")
    explanation, actions = llama_generate_explanation(sms_text, evidence)
    
    print(f"Explanation: {explanation}")
    print("\nRecommended Next Steps:")
    for act in actions:
        print(f"  {act}")

# --- Test Runs ---
if __name__ == "__main__":
    test_1 = "Hi beta, lunch pack karke le gaye ya hostel mess mein khaoge?"
    test_2 = "URGENT: Your electricity connection will be disconnected tonight. Update bill immediately: http://bit.ly/power-pay"

    process_message(test_1)
    process_message(test_2)