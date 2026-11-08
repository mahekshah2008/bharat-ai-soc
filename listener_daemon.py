import sys
import json
import time
from detector import extract_threat_evidence
from llm_engine import Stage2ReasoningEngine

class BharatSOCDaemon:
    def __init__(self):
        self.stage2 = Stage2ReasoningEngine()

    def process_sms(self, sender: str, body: str):
        print(f"\n[{time.strftime('%H:%M:%S')}] INCOMING SMS from [{sender}]:")
        print(f"  Content: \"{body}\"")

        # Stage 1: Feature Extraction + Lightweight ML
        t0 = time.perf_counter_ns()
        evidence = extract_threat_evidence(body)
        s1_latency_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

        print(f"  [STAGE 1] Threat Score: {evidence['threat_score']:.4f} | Latency: {s1_latency_ms:.3f} ms")

        # Stage 2 Gating
        if evidence["is_scam"]:
            print("  [ALERT] 🚨 Threat detected (Threshold >= 0.40). Waking Stage 2 Reasoning...")
            advice = self.stage2.generate_advice(body, evidence)
            print(f"  [STAGE 2 OUTPUT]:")
            print(f"    Category : {advice.get('threat_category')}")
            print(f"    Action   : {advice.get('actionable_guidance')}")
            print(f"    Helpline : {advice.get('reporting_helpline')}")
        else:
            print("  [SAFE] Benign message. Stage 2 LLM kept offline to preserve device battery.")

    def run_live(self):
        print("=" * 60)
        print("      BHARAT AI-SOC: ON-DEVICE TELECOM LISTENER       ")
        print("=" * 60)
        print("Listening for incoming messages. Type 'exit' to stop.\n")

        try:
            while True:
                sender = input("\nEnter Sender ID / Number (or Enter for default): ").strip()
                if sender.lower() == "exit":
                    break
                if not sender:
                    sender = "+919876543210"

                body = input("Enter SMS Text: ").strip()
                if body.lower() == "exit":
                    break
                if not body:
                    print("Empty text skipped.")
                    continue

                self.process_sms(sender, body)
        except KeyboardInterrupt:
            print("\n[DAEMON] Terminated cleanly.")

if __name__ == "__main__":
    daemon = BharatSOCDaemon()
    daemon.run_live()