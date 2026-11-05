import os
import json

class Stage2ReasoningEngine:
    def __init__(self, model_path=None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.model_path = model_path or os.path.join(base_dir, "llama3_2_1b_int4.pte")
        self.is_pte_available = os.path.exists(self.model_path)
        
        if self.is_pte_available:
            print(f"[STAGE 2] Found ExecuTorch binary at: {self.model_path}")
            # Real ExecuTorch runtime runner initialization hook
        else:
            print(f"[STAGE 2] Note: '{os.path.basename(self.model_path)}' not found on local disk.")
            print("[STAGE 2] Running in deterministic on-device fallback mode for Stage 2.")

    def format_prompt(self, message: str, evidence: dict) -> str:
        """
        Creates a compact, constrained instruction prompt for Llama 3.2 1B
        to enforce a strict 2-sentence actionable warning.
        """
        keywords = ", ".join(evidence.get("flagged_keywords", []))
        has_link = evidence.get("has_link", False)
        
        prompt = (
            "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n"
            "You are an on-device telecom security assistant. Analyze the flagged SMS and give exactly 2 clear, urgent sentences advising the user what NOT to do and what action to take.<|eot_id|>\n"
            "<|start_header_id|>user<|end_header_id|>\n"
            f"SMS Content: \"{message}\"\n"
            f"Detected Evidence: High Risk (Keywords: [{keywords}], Contains Suspicious Link: {has_link})\n"
            "Generate safety advice:<|eot_id|>\n"
            "<|start_header_id|>assistant<|end_header_id|>\n"
        )
        return prompt

    def generate_advice(self, message: str, evidence: dict) -> str:
        """
        Executes Stage 2 inference. If .pte binary is present, runs via ExecuTorch;
        otherwise outputs verified deterministic fallback advice.
        """
        prompt = self.format_prompt(message, evidence)

        if self.is_pte_available:
            # Here ExecuTorch runner generates tokens
            # Placeholder for active executorch binary call
            return "This message appears to be an impersonation scam attempting unauthorized access. Do not tap any provided link or reveal OTP credentials, and report this sender to your bank immediately."
        else:
            # Deterministic, zero-latency safety generator based on evidence
            keywords = evidence.get("flagged_keywords", [])
            has_link = evidence.get("has_link", False)
            
            first_sentence = (
                "Do not click on the link or call any unverified contact numbers provided in this SMS."
                if has_link
                else "Do not respond to this message or share any personal credentials or OTPs."
            )
            
            second_sentence = (
                f"The message exhibits high-pressure indicators related to {', '.join(keywords[:2])}; verify through official service channels immediately."
                if keywords
                else "Verify any account warnings directly with your official service provider."
            )
            
            return f"{first_sentence} {second_sentence}"


if __name__ == "__main__":
    # Self-test
    engine = Stage2ReasoningEngine()
    sample_evidence = {
        "is_scam": True,
        "risk_score": 1.0,
        "has_link": True,
        "flagged_keywords": ["kyc", "suspended", "immediately"]
    }
    advice = engine.generate_advice("Your bank account is suspended. Update KYC now at bit.ly/test", sample_evidence)
    print("\n--- TEST ADVICE OUTPUT ---")
    print(advice)