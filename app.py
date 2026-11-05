import sys
from detector import extract_threat_evidence
from llm_engine import Stage2ReasoningEngine

def run_pipeline(sms_text: str):
    print(f"\nAnalyzing: \"{sms_text}\"")
    
    # --- STAGE 1: Fast Heuristic & ML Filter ---
    evidence = extract_threat_evidence(sms_text)
    
    print("\n--- STAGE 1: DETECTOR EVIDENCE OUTPUT ---")
    import json
    print(json.dumps(evidence, indent=2))
    
    # --- GATING LOGIC ---
    if evidence["is_scam"]:
        print("\n[DECISION]: Threat detected (Risk Score >= 0.5). Triggering Stage 2 Reasoning...")
        
        # Instantiate Stage 2 LLM Reasoning Engine
        reasoning_engine = Stage2ReasoningEngine()
        advice = reasoning_engine.generate_advice(sms_text, evidence)
        
        print("\n--- STAGE 2: ACTIONABLE SAFETY ADVICE ---")
        print(f">> {advice}\n")
    else:
        print("\n[DECISION]: Message is SAFE. LLM kept offline to preserve device battery.\n")

if __name__ == "__main__":
    # Test SMS can be passed via command line argument, prompt, or default
    if len(sys.argv) > 1:
        test_msg = " ".join(sys.argv[1:])
    else:
        test_msg = input("\nEnter an SMS to test (or press Enter for default scam test): ").strip()
        if not test_msg:
            test_msg = "URGENT: Your SBI account has been locked due to incomplete KYC verification. Click here to verify your identity immediately: http://bit.ly/sbi-kyc-verify"
            
    run_pipeline(test_msg)