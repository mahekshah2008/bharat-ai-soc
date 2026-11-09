import sys
import json
import time
import os
import argparse
from typing import Optional
from detector import BharatThreatDetector, extract_threat_evidence
from llm_engine import Stage2ReasoningEngine

class BharatSOCDaemon:
    """
    On-Device Real-Time Telecom Security Daemon
    Performs in-memory zero-latency Stage 1 filtering and conditionally
    wakes Stage 2 ExecuTorch LLM for actionable threat mitigation.
    """
    def __init__(self):
        print("[DAEMON] Initializing in-memory engines...")
        t0 = time.perf_counter_ns()
        self.detector = BharatThreatDetector()
        self.stage2 = Stage2ReasoningEngine()
        init_time = (time.perf_counter_ns() - t0) / 1_000_000.0
        print(f"[DAEMON] Engines loaded in {init_time:.2f} ms. System armed.\n")

    def process_sms(self, sender: str, body: str) -> dict:
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        print("=" * 64)
        print(f"[{timestamp}] INCOMING SMS INTERCEPT")
        print(f"  Sender  : {sender}")
        print(f"  Payload : \"{body}\"")
        print("-" * 64)

        # Stage 1: In-Memory Heuristic + Statistical ML Filter
        t0 = time.perf_counter_ns()
        evidence = extract_threat_evidence(body, detector=self.detector)
        s1_latency_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

        is_threat = evidence["is_threat"]
        print(f"  [STAGE 1 ML] Threat Score: {evidence['threat_score']:.4f} | Latency: {s1_latency_ms:.3f} ms")
        if evidence["shannon_entropy"] > 0:
            print(f"  [FORENSICS] Max Domain Shannon Entropy: {evidence['shannon_entropy']} bits")
        if evidence["detected_urls"]:
            print(f"  [FORENSICS] Extracted URLs: {evidence['detected_urls']}")

        # Stage 2 Gating Logic
        response_event = {
            "timestamp": timestamp,
            "sender": sender,
            "sms": body,
            "stage1": evidence,
            "stage2": None
        }

        if is_threat:
            print("\n  [ALERT] Threat Vector Confirmed -> Activating Stage 2 Coprocessor...")
            t1 = time.perf_counter_ns()
            advice = self.stage2.generate_advice(body, evidence)
            s2_latency_ms = (time.perf_counter_ns() - t1) / 1_000_000.0
            response_event["stage2"] = advice

            print(f"  [STAGE 2 TELEMETRY ({s2_latency_ms:.3f} ms)]:")
            print(f"    Threat Category : {advice.get('threat_category')}")
            print(f"    Threat Level    : {advice.get('threat_level')}")
            print(f"    Forensic Summary: {advice.get('forensic_summary')}")
            print(f"    Action Guidance : {advice.get('actionable_guidance')}")
            print(f"    Helpline Target : {advice.get('reporting_helpline')}")
        else:
            print("\n  [VERDICT] Clean / Benign Message.")
            print("  [ENERGY] Stage 2 LLM kept in low-power idle (0 mW LLM draw).")

        print("=" * 64 + "\n")
        return response_event

    def poll_inbox_file(self, file_path: str, interval_sec: float = 1.0):
        """
        Polls an incoming SMS buffer file (useful for ADB logcat or Termux dump redirection).
        """
        print(f"[DAEMON] Polling incoming SMS spool: {file_path}")
        last_pos = 0
        if os.path.exists(file_path):
            last_pos = os.path.getsize(file_path)

        try:
            while True:
                if os.path.exists(file_path):
                    current_size = os.path.getsize(file_path)
                    if current_size > last_pos:
                        with open(file_path, "r", encoding="utf-8") as f:
                            f.seek(last_pos)
                            new_lines = f.readlines()
                            last_pos = f.tell()

                        for line in new_lines:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                msg_data = json.loads(line)
                                self.process_sms(msg_data.get("sender", "UNKNOWN"), msg_data.get("body", ""))
                            except json.JSONDecodeError:
                                self.process_sms("SPOOL", line)

                time.sleep(interval_sec)
        except KeyboardInterrupt:
            print("\n[DAEMON] Spool polling terminated.")

    def run_interactive(self):
        print("=" * 64)
        print("         BHARAT AI-SOC: INTERACTIVE SECURITY RUNNER")
        print("=" * 64)
        print("Enter messages to test real-time pipeline. Type 'exit' to quit.\n")

        try:
            while True:
                sender = input("Sender ID / Number [Default: +919876543210]: ").strip()
                if sender.lower() == "exit":
                    break
                if not sender:
                    sender = "+919876543210"

                body = input("SMS Body Text: ").strip()
                if body.lower() == "exit":
                    break
                if not body:
                    print("Empty text skipped.\n")
                    continue

                self.process_sms(sender, body)
        except KeyboardInterrupt:
            print("\n[DAEMON] Interactive session stopped.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bharat AI-SOC Real-Time Edge Daemon")
    parser.add_argument("--sender", type=str, default=None, help="Sender ID for direct execution")
    parser.add_argument("--message", type=str, default=None, help="SMS text body for direct execution")
    parser.add_argument("--spool", type=str, default=None, help="Path to SMS JSON spool file to poll")
    args = parser.parse_args()

    daemon = BharatSOCDaemon()

    if args.message:
        sender_id = args.sender or "CLI_DISPATCH"
        daemon.process_sms(sender_id, args.message)
    elif args.spool:
        daemon.poll_inbox_file(args.spool)
    else:
        daemon.run_interactive()
