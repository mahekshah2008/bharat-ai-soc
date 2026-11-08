import os
import sys
import json
import subprocess
import shutil

class Stage2ReasoningEngine:
    def __init__(self, model_path=None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.model_path = model_path or os.path.join(base_dir, "llama3_2_1b_int4.pte")
        self.is_pte_available = os.path.exists(self.model_path)
        
        # Check for compiled ExecuTorch binary on path or local directory
        self.runner_bin = shutil.which("executor_runner") or shutil.which("./executor_runner")
        
        if self.is_pte_available:
            print(f"[STAGE 2] ExecuTorch model artifact found: {self.model_path}")
            if self.runner_bin:
                print(f"[STAGE 2] Active native runner bound: {self.runner_bin}")
            else:
                print("[STAGE 2] Native runner binary not linked; running deterministic on-device parser.")
        else:
            print(f"[STAGE 2] '{os.path.basename(self.model_path)}' not found. Stage 2 in deterministic mode.")

    def format_prompt(self, message: str, evidence: dict) -> str:
        """
        Creates a constrained instruction prompt instructing Llama 3.2 1B
        to return strictly parseable JSON adhering to our mobile defense schema.
        """
        threat_factors = []
        if evidence.get("apk_threat"):
            threat_factors.append("MALICIOUS_APK_DOWNLOAD")
        if evidence.get("url_detected"):
            threat_factors.append(f"EXTERNAL_URL(entropy={evidence.get('url_shannon_entropy', 0)})")
        if evidence.get("utility_threat"):
            threat_factors.append("UTILITY_BILL_DISCONNECTION")
        if evidence.get("kyc_pan_markers"):
            threat_factors.append("BANKING_KYC_VERIFICATION")
        if evidence.get("suspicious_phone"):
            threat_factors.append("UNOFFICIAL_10_DIGIT_SENDER")

        prompt = (
            "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n"
            "You are an on-device telecom security coprocessor. Analyze the SMS and detector flags. "
            "Output ONLY a raw JSON object with keys: 'threat_category', 'threat_level' (CRITICAL/HIGH/MEDIUM), "
            "'actionable_guidance' (max 2 concise sentences), and 'reporting_helpline'. Do not include markdown codeblocks.<|eot_id|>\n"
            "<|start_header_id|>user<|end_header_id|>\n"
            f"SMS: \"{message}\"\n"
            f"Stage 1 Threat Score: {evidence.get('threat_score', 0.0)}\n"
            f"Evidence Vector: {', '.join(threat_factors) if threat_factors else 'SUSPICIOUS_CONTENT'}\n"
            "<|start_header_id|>assistant<|end_header_id|>\n"
        )
        return prompt

    def _infer_deterministic_response(self, message: str, evidence: dict) -> dict:
        """
        Zero-dependency, low-latency fallback delivering guaranteed JSON schema
        aligned directly with empirical evidence from Stage 1.
        """
        if evidence.get("apk_threat"):
            return {
                "threat_category": "MALICIOUS_PAYLOAD_DROP",
                "threat_level": "CRITICAL",
                "actionable_guidance": "Do not download or install any .apk file from this message. Never bypass Google Play Protect or Android unknown source warnings.",
                "reporting_helpline": "1930 / cybercrime.gov.in"
            }
        elif evidence.get("utility_threat"):
            return {
                "threat_category": "UTILITY_DISCONNECTION_FRAUD",
                "threat_level": "HIGH",
                "actionable_guidance": "Do not call the 10-digit number or pay through unauthorized links. Power distribution companies never issue immediate disconnection threats over unofficial numbers.",
                "reporting_helpline": "1930 / State Electricity Customer Care"
            }
        elif evidence.get("kyc_pan_markers"):
            return {
                "threat_category": "FINANCIAL_KYC_PHISHING",
                "threat_level": "CRITICAL",
                "actionable_guidance": "Never enter banking passwords, PAN, or OTPs on unverified external links. Banks never request emergency account verification via SMS links.",
                "reporting_helpline": "1930 / Official Bank Customer Support"
            }
        elif evidence.get("high_entropy_url") or evidence.get("url_detected"):
            return {
                "threat_category": "DECEPTIVE_URL_HARVESTING",
                "threat_level": "HIGH",
                "actionable_guidance": "Do not click on shortened or high-entropy web domains. These domains are routinely used to harvest credentials or install tracking payloads.",
                "reporting_helpline": "1930 / cybercrime.gov.in"
            }
        else:
            return {
                "threat_category": "SOCIAL_ENGINEERING_SUSPECT",
                "threat_level": "MEDIUM",
                "actionable_guidance": "Exercise caution. Do not disclose personal or financial credentials, and verify sender authenticity directly through official channels.",
                "reporting_helpline": "1930 / National Cyber Crime Portal"
            }

    def generate_advice(self, message: str, evidence: dict) -> dict:
        """
        Executes Stage 2 inference. If native executor_runner exists and .pte is present,
        spawns runtime; otherwise executes deterministic schema generator.
        """
        prompt = self.format_prompt(message, evidence)

        if self.is_pte_available and self.runner_bin:
            try:
                cmd = [self.runner_bin, "--model_path", self.model_path, "--prompt", prompt]
                proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
                raw_out = proc.stdout.strip()
                # Clean markdown formatting if model wrapped response
                if raw_out.startswith("```"):
                    raw_out = raw_out.strip("`").replace("json", "").strip()
                return json.loads(raw_out)
            except Exception:
                # Safe degradation to schema on binary or parse exception
                return self._infer_deterministic_response(message, evidence)
        else:
            return self._infer_deterministic_response(message, evidence)

if __name__ == "__main__":
    engine = Stage2ReasoningEngine()
    sample_evidence = {
        "is_scam": True,
        "threat_score": 0.4893,
        "utility_threat": True,
        "urgency_markers": True,
        "suspicious_phone": True,
        "url_detected": False
    }
    result = engine.generate_advice("Electricity power will be cut off tonight. Call 9876543210", sample_evidence)
    print("\n--- STAGE 2 STRUCTURED OUTPUT ---")
    print(json.dumps(result, indent=2))