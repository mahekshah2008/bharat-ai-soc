import sys
import json
import time
from detector import BharatThreatDetector, extract_threat_evidence
from llm_engine import Stage2ReasoningEngine

def run_pipeline(sms_text: str):
    print(f"\nAnalyzing SMS: \"{sms_text}\"")
    
    detector = BharatThreatDetector()
    t0 = time.perf_counter_ns()
    evidence = extract_threat_evidence(sms_text, detector=detector)
    s1_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
    
    print(f"\n--- STAGE 1: DETECTOR TELEMETRY ({s1_ms:.3f} ms) ---")
    print(json.dumps(evidence, indent=2))
    
    if evidence["is_threat"]:
        print("\n[GATING DECISION]: Threat Flagged -> Escalating to Stage 2 Coprocessor...")
        reasoning_engine = Stage2ReasoningEngine()
        t1 = time.perf_counter_ns()
        advice = reasoning_engine.generate_advice(sms_text, evidence)
        s2_ms = (time.perf_counter_ns() - t1) / 1_000_000.0
        
        print(f"\n--- STAGE 2: STRUCTURED SAFETY CONTRACT ({s2_ms:.3f} ms) ---")
        print(json.dumps(advice, indent=2))
    else:
        print("\n[GATING DECISION]: Benign Message -> Stage 2 Kept Offline (0 mW LLM Power Draw).\n")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        test_msg = " ".join(sys.argv[1:])
    else:
        test_msg = "URGENT: SВI асcount blосked! Updаte PAN immediately at https://sbi-secure982a.xyz/kyc"
            
    run_pipeline(test_msg)
