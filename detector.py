import json
import re
import math
import unicodedata
from typing import Dict, List, Any, Optional

class BharatThreatDetector:
    """
    Stage 1 Zero-Dependency Threat & SMS Phishing Detector
    Ensemble: Multinomial Naive Bayes + Heuristic Indicators + Shannon URL Entropy
    Target Architecture: Physical ARM64 / Edge SoC
    """
    def __init__(self, params_path: str = "model_params.json"):
        with open(params_path, "r", encoding="utf-8") as f:
            self.params = json.load(f)
            
        self.vocab: Dict[str, int] = self.params["vocabulary"]
        self.idf: List[float] = self.params["idf"]
        self.feature_log_prob: List[List[float]] = self.params["feature_log_prob"]
        self.class_log_prior: List[float] = self.params["class_log_prior"]
        self.classes: List[str] = self.params["classes"]
        self.spam_index: int = self.classes.index("spam") if "spam" in self.classes else 1

        # Cyrillic/Greek to Latin homoglyph mapping table
        self.homoglyph_map = str.maketrans({
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
            'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
            'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
            'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'Ү': 'Y'
        })

    def normalize_text(self, text: str) -> str:
        """Strip zero-width characters, normalize unicode forms, and resolve homoglyphs."""
        text = re.sub(r'[\u200B-\u200D\uFEFF\u00A0]', '', text)
        text = unicodedata.normalize('NFKD', text)
        text = text.translate(self.homoglyph_map)
        return text

    def calculate_shannon_entropy(self, string: str) -> float:
        """Calculate Shannon entropy to flag high-randomness DGA domains."""
        if not string:
            return 0.0
        entropy = 0.0
        length = len(string)
        char_counts: Dict[str, int] = {}
        for char in string:
            char_counts[char] = char_counts.get(char, 0) + 1
        for count in char_counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 3)

    def extract_heuristics(self, text: str) -> Dict[str, Any]:
        """Inspect Indian telecom specific fraud vectors, links, UPI handles, and urgency indicators."""
        clean_text = self.normalize_text(text)
        lower_text = clean_text.lower()

        url_pattern = r'(https?://[^\s]+|bit\.ly/[^\s]+|tinyurl\.com/[^\s]+|t\.me/[^\s]+|wa\.me/[^\s]+|[a-zA-Z0-9.-]+\.(?:top|xyz|club|online|site|live|apk|link|icu|vip)/[^\s]*)'
        urls = re.findall(url_pattern, clean_text)
        
        has_apk = bool(re.search(r'(\.apk\b|install.*app|download.*apk)', lower_text))
        has_suspicious_tld = bool(re.search(r'\.(top|xyz|club|online|site|apk|cc|vip|icu|click)\b', lower_text))
        has_shortener = bool(re.search(r'(bit\.ly|tinyurl\.com|t\.me|wa\.me|cutt\.ly|rb\.gy)', lower_text))
        has_upi_handle = bool(re.search(r'\b[a-zA-Z0-9.\-_]+@(upi|ybl|paytm|okaxis|oksbi|okhdfcbank|okicici|ibl|axl)\b', lower_text))
        
        max_entropy = 0.0
        for u in urls:
            domain_match = re.search(r'https?://([^/:]+)', u)
            domain = domain_match.group(1) if domain_match else u.split('/')[0]
            ent = self.calculate_shannon_entropy(domain)
            if ent > max_entropy:
                max_entropy = ent

        kyc_pan = bool(re.search(r'\b(kyc|pan|aadhaar|aadhar|sim|deactivated|deactivation|blocked|expire|suspend)\b', lower_text))
        utility_cutoff = bool(re.search(r'\b(electricity|power|bill|disconnected|disconnection|light bill)\b', lower_text))
        traffic_challan = bool(re.search(r'\b(echallan|e-challan|parivahan|traffic fine|rto|court)\b', lower_text))
        digital_arrest = bool(re.search(r'\b(cbi|customs|trai|arrest|narcotics|dcp|police)\b', lower_text))
        financial_urgency = bool(re.search(r'\b(lottery|winner|won|reward|cashback|credited|gift card|upi pin|instant credit|loan|0% interest|processing fee|crorepati|claim)\b', lower_text))
        job_scam = bool(re.search(r'\b(part time|work from home|job offer|daily income|liking youtube|telegram channel|earn \d+)\b', lower_text))
        vishing_call = bool(re.search(r'\b(contact officer|call customer care|contact care|call officer|officer at \d+)\b', lower_text))
        urgency_terms = bool(re.search(r'\b(immediately|immediate|urgent|urgently|tonight|within \d+ hours|24 hours|tonight at \d+)\b', lower_text))

        heuristic_score = 0.0

        if urls or has_shortener:
            heuristic_score += 0.25
        if has_suspicious_tld or has_apk:
            heuristic_score += 0.35
        if max_entropy >= 3.75:
            heuristic_score += 0.20

        if utility_cutoff and (urgency_terms or vishing_call):
            heuristic_score += 0.50
        elif kyc_pan and (urgency_terms or vishing_call):
            heuristic_score += 0.50
        elif job_scam and (has_shortener or urls):
            heuristic_score += 0.50
        elif financial_urgency and (has_apk or urls or has_shortener or has_upi_handle):
            heuristic_score += 0.55
        elif traffic_challan or digital_arrest:
            heuristic_score += 0.45
        elif urgency_terms and vishing_call:
            heuristic_score += 0.30
        elif financial_urgency:
            heuristic_score += 0.25

        return {
            "urls": urls,
            "max_entropy": max_entropy,
            "has_apk": has_apk,
            "has_upi_handle": has_upi_handle,
            "threat_factors": {
                "kyc_pan": kyc_pan,
                "utility_cutoff": utility_cutoff,
                "traffic_challan": traffic_challan,
                "digital_arrest": digital_arrest,
                "financial_urgency": financial_urgency,
                "job_scam": job_scam,
                "vishing_call": vishing_call
            },
            "heuristic_score": min(round(heuristic_score, 4), 1.0)
        }

    def predict_stage1(self, text: str) -> Dict[str, Any]:
        """Compute ensemble score using Naive Bayes log probabilities and heuristics."""
        normalized = self.normalize_text(text)
        tokens = re.findall(r'\b\w\w+\b', normalized.lower())
        
        tf_dict: Dict[int, int] = {}
        for token in tokens:
            if token in self.vocab:
                idx = self.vocab[token]
                tf_dict[idx] = tf_dict.get(idx, 0) + 1

        vector: Dict[int, float] = {}
        sum_sq = 0.0
        for idx, count in tf_dict.items():
            val = float(count) * self.idf[idx]
            vector[idx] = val
            sum_sq += val * val

        norm = math.sqrt(sum_sq) if sum_sq > 0 else 1.0
        for idx in vector:
            vector[idx] /= norm

        log_prob_ham = self.class_log_prior[0]
        log_prob_spam = self.class_log_prior[self.spam_index]

        for idx, val in vector.items():
            log_prob_ham += val * self.feature_log_prob[0][idx]
            log_prob_spam += val * self.feature_log_prob[self.spam_index][idx]

        diff = log_prob_spam - log_prob_ham
        diff = max(min(diff, 20.0), -20.0)
        nb_spam_prob = 1.0 / (1.0 + math.exp(-diff))

        heuristics = self.extract_heuristics(text)
        h_score = heuristics["heuristic_score"]

        combined_threat_score = round((0.50 * nb_spam_prob) + (0.50 * h_score), 4)
        is_threat = (combined_threat_score >= 0.38) or (h_score >= 0.50)

        return {
            "threat_score": combined_threat_score,
            "nb_prob": round(nb_spam_prob, 4),
            "heuristic_score": h_score,
            "shannon_entropy": heuristics["max_entropy"],
            "detected_urls": heuristics["urls"],
            "is_threat": is_threat,
            "threat_factors": heuristics["threat_factors"]
        }


def extract_threat_evidence(text: str, detector: Optional[BharatThreatDetector] = None) -> Dict[str, Any]:
    """
    Extract forensic indicators and heuristics for benchmark logging and LLM prompt grounding.
    """
    if detector is None:
        detector = BharatThreatDetector()
    
    heuristics = detector.extract_heuristics(text)
    prediction = detector.predict_stage1(text)
    
    return {
        "text": text,
        "is_threat": prediction["is_threat"],
        "is_scam": prediction["is_threat"],
        "threat_score": prediction["threat_score"],
        "scam_score": prediction["threat_score"],
        "nb_prob": prediction["nb_prob"],
        "heuristic_score": prediction["heuristic_score"],
        "shannon_entropy": prediction["shannon_entropy"],
        "detected_urls": heuristics["urls"],
        "has_apk": heuristics["has_apk"],
        "has_upi_handle": heuristics["has_upi_handle"],
        "threat_factors": heuristics["threat_factors"]
    }
