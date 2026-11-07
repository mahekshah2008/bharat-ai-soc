import json
import math
import os
import re
from typing import List, Dict, Any

class SMSDetector:
    def __init__(self, params_path: str = "model_params.json"):
        # Resolve path relative to this script file
        if not os.path.isabs(params_path):
            base_dir = os.path.dirname(os.path.abspath(__file__))
            params_path = os.path.join(base_dir, params_path)

        with open(params_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.classes = data["classes"]
        self.class_log_prior = data["class_log_prior"]
        self.feature_log_prob = data["feature_log_prob"]
        self.vocabulary = data["vocabulary"]
        self.idf = data["idf"]
        self.stop_words = set(data.get("stop_words", []))
        self.min_n, self.max_n = data.get("ngram_range", [1, 2])

    def _tokenize(self, text: str) -> List[str]:
        words = re.findall(r"(?u)\b\w\w+\b", text.lower())
        tokens = [w for w in words if w not in self.stop_words]
        if self.max_n >= 2:
            for i in range(len(words) - 1):
                tokens.append(f"{words[i]} {words[i+1]}")
        return tokens

    def predict_proba(self, text: str) -> float:
        tokens = self._tokenize(text)
        term_counts: Dict[int, int] = {}
        for t in tokens:
            if t in self.vocabulary:
                idx = self.vocabulary[t]
                term_counts[idx] = term_counts.get(idx, 0) + 1

        if not term_counts:
            exps = [math.exp(p) for p in self.class_log_prior]
            return float(exps[1] / sum(exps))

        tf_idf_vec = {}
        squared_sum = 0.0
        for idx, count in term_counts.items():
            val = float(count) * self.idf[idx]
            tf_idf_vec[idx] = val
            squared_sum += val * val

        norm = math.sqrt(squared_sum) if squared_sum > 0 else 1.0
        for idx in tf_idf_vec:
            tf_idf_vec[idx] /= norm

        log_probs = []
        for c_idx in range(len(self.classes)):
            lp = self.class_log_prior[c_idx]
            for idx, tfidf_val in tf_idf_vec.items():
                lp += tfidf_val * self.feature_log_prob[c_idx][idx]
            log_probs.append(lp)

        max_lp = max(log_probs)
        exps = [math.exp(lp - max_lp) for lp in log_probs]
        sum_exps = sum(exps)
        probs = [e / sum_exps for e in exps]

        threat_idx = self.classes.index(1) if 1 in self.classes else 1
        return float(probs[threat_idx])


# Initialize global detector instance
_detector = None

def get_detector() -> SMSDetector:
    global _detector
    if _detector is None:
        _detector = SMSDetector()
    return _detector


def extract_threat_evidence(text: str) -> Dict[str, Any]:
    evidence = {
        "urls": re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text, flags=re.IGNORECASE),
        "phones": re.findall(r'(?:\+?91[\-\s]?)?[6-9]\d{9}\b|\b\d{4,6}\b', text),
        "urgency_triggers": [],
        "financial_triggers": [],
        "ml_probability": 0.0,
        "threat_score": 0.0,
        "is_scam": False
    }

    urgency_keywords = [
        "urgent", "immediately", "blocked", "suspended", "expire", "expires",
        "penalty", "warning", "action required", "within 24 hours", "deactivated",
        "disconnected", "tonight", "cutoff", "last date"
    ]
    financial_keywords = [
        "sbi", "hdfc", "icici", "pan", "kyc", "otp", "debit", "credit", 
        "account", "lottery", "cash", "reward", "refund", "tax", "bill",
        "electricity", "power", "payment", "due"
    ]

    lower_text = text.lower()
    evidence["urgency_triggers"] = [kw for kw in urgency_keywords if kw in lower_text]
    evidence["financial_triggers"] = [kw for kw in financial_keywords if kw in lower_text]

    # Run ML prediction on the extracted vocabulary
    try:
        clf = get_detector()
        evidence["ml_probability"] = round(clf.predict_proba(text), 4)
    except Exception:
        evidence["ml_probability"] = 0.5  # Neutral fallback

    # Heuristic scoring
    heuristic_score = 0.0
    if evidence["urls"]:
        heuristic_score += 0.35
    if evidence["phones"]:
        heuristic_score += 0.20
    heuristic_score += min(0.30, len(evidence["urgency_triggers"]) * 0.15)
    heuristic_score += min(0.30, len(evidence["financial_triggers"]) * 0.15)

    # Ensemble: 50% ML Model + 50% Heuristics
    final_score = round(min(1.0, (evidence["ml_probability"] * 0.50) + (heuristic_score * 0.50)), 2)
    evidence["threat_score"] = final_score

    # Trigger threshold
    evidence["is_scam"] = bool(
        final_score >= 0.40 
        or (evidence["urls"] and (evidence["urgency_triggers"] or evidence["financial_triggers"]))
        or (evidence["phones"] and evidence["urgency_triggers"] and evidence["financial_triggers"])
    )

    return evidence