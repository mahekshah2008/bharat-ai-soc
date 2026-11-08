import re
import math
import json
from collections import Counter

class SMSThreatDetector:
    def __init__(self, params_path="model_params.json"):
        with open(params_path, "r", encoding="utf-8") as f:
            params = json.load(f)
            
        self.vocab = params["vocabulary"]
        self.idf = params["idf"]
        self.feature_log_prob = params["feature_log_prob"]  # shape: [2, vocab_size]
        self.class_log_prior = params["class_log_prior"]    # shape: [2]
        self.classes = params.get("classes", [0, 1])

        # Domain knowledge regex patterns tailored for Indian threat vectors
        self.url_pattern = re.compile(r'https?://[^\s]+|bit\.ly/[^\s]+|tinyurl\.com/[^\s]+', re.IGNORECASE)
        self.apk_pattern = re.compile(r'\.apk\b|download\s+app', re.IGNORECASE)
        self.utility_pattern = re.compile(r'(electricity|power|bill|disconnection|challan|traffic|fine)', re.IGNORECASE)
        self.urgency_pattern = re.compile(r'(urgent|immediately|blocked|suspended|tonight|24\s*hours|penalty|deactivated)', re.IGNORECASE)
        self.kyc_pattern = re.compile(r'(kyc|pan|aadhaar|account\s*blocked|update\s*details)', re.IGNORECASE)
        self.lottery_pattern = re.compile(r'(lottery|won\b|winner|prize|crorepati|kbc|reward\s*points)', re.IGNORECASE)
        self.advance_fee_pattern = re.compile(r'(processing\s*fee|registration\s*fee|claim\b|send\s*(?:rs\.?|inr|\d+)|to\s*upi|@upi\b)', re.IGNORECASE)
        self.phone_pattern = re.compile(r'(?:\+91|0)?[6-9]\d{9}')

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Computes Shannon entropy to catch algorithmic/obfuscated URLs."""
        if not text:
            return 0.0
        counts = Counter(text)
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    def _normalize_text(self, text: str) -> str:
        """Normalizes character obfuscation often used to evade keyword filters."""
        text = text.lower()
        # Collapse repeated delimiters used for evasion (e.g., s.b.i -> sbi)
        text = re.sub(r'(\b[a-z])\.(?=[a-z]\b)', r'\1', text)
        return text

    def _predict_naive_bayes_proba(self, tokens) -> float:
        """Pure-Python TF-IDF vectorization and MultinomialNB log-prob evaluation."""
        tf = Counter(tokens)
        doc_len = len(tokens)
        if doc_len == 0:
            return 0.0

        tfidf = {}
        norm_sq = 0.0
        for word, count in tf.items():
            if word in self.vocab:
                idx = self.vocab[word]
                score = (count / doc_len) * self.idf[idx]
                tfidf[idx] = score
                norm_sq += score * score

        if norm_sq == 0.0:
            return 0.0

        inv_norm = 1.0 / math.sqrt(norm_sq)
        for idx in tfidf:
            tfidf[idx] *= inv_norm

        log_probs = list(self.class_log_prior)
        for c in range(2):
            for idx, val in tfidf.items():
                log_probs[c] += val * self.feature_log_prob[c][idx]

        max_log = max(log_probs)
        prob_safe = math.exp(log_probs[0] - max_log)
        prob_scam = math.exp(log_probs[1] - max_log)
        
        return prob_scam / (prob_safe + prob_scam)

    def extract_evidence(self, text: str) -> dict:
        normalized = self._normalize_text(text)
        urls = self.url_pattern.findall(text)
        
        max_entropy = 0.0
        for url in urls:
            domain_part = url.split('/')[2] if len(url.split('/')) > 2 else url
            entropy = self.calculate_entropy(domain_part)
            if entropy > max_entropy:
                max_entropy = round(entropy, 3)

        has_apk = bool(self.apk_pattern.search(normalized))
        utility_threat = bool(self.utility_pattern.search(normalized))
        urgency_markers = bool(self.urgency_pattern.search(normalized))
        kyc_markers = bool(self.kyc_pattern.search(normalized))
        lottery_markers = bool(self.lottery_pattern.search(normalized))
        fee_claim_markers = bool(self.advance_fee_pattern.search(normalized))
        suspicious_phone = bool(self.phone_pattern.search(normalized))

        tokens = re.findall(r'\b\w+\b', normalized)
        nb_scam_prob = self._predict_naive_bayes_proba(tokens)

        # Ensemble scoring: Statistical ML Prior (45%) + Edge Domain Heuristics
        threat_score = nb_scam_prob * 0.45

        if len(urls) > 0:
            threat_score += 0.25
        if max_entropy > 3.8:
            threat_score += 0.15
        if has_apk:
            threat_score += 0.35
        if urgency_markers and (kyc_markers or utility_threat):
            threat_score += 0.25
        if suspicious_phone and (utility_threat or kyc_markers):
            threat_score += 0.20
        if lottery_markers and fee_claim_markers:
            threat_score += 0.30

        threat_score = min(max(threat_score, 0.0), 1.0)
        
        # Decision boundary: >= 0.40 triggers Stage 2 LLM reasoning
        is_scam = threat_score >= 0.40

        return {
            "threat_score": round(threat_score, 4),
            "is_scam": is_scam,
            "nb_prob": round(nb_scam_prob, 4),
            "url_detected": len(urls) > 0,
            "url_shannon_entropy": max_entropy,
            "high_entropy_url": max_entropy > 3.8,
            "apk_threat": has_apk,
            "utility_threat": utility_threat,
            "urgency_markers": urgency_markers,
            "kyc_pan_markers": kyc_markers,
            "lottery_markers": lottery_markers,
            "fee_claim_markers": fee_claim_markers,
            "suspicious_phone": suspicious_phone
        }

# Global cached instance to avoid reloading params JSON on multiple calls
_DETECTOR_INSTANCE = None

def extract_threat_evidence(sms_text: str) -> dict:
    """Entry point matching app.py expectations."""
    global _DETECTOR_INSTANCE
    if _DETECTOR_INSTANCE is None:
        _DETECTOR_INSTANCE = SMSThreatDetector()
    return _DETECTOR_INSTANCE.extract_evidence(sms_text)