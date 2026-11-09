import unittest
from detector import BharatThreatDetector, extract_threat_evidence
from llm_engine import Stage2ReasoningEngine

class TestBharatThreatPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.detector = BharatThreatDetector()
        cls.stage2 = Stage2ReasoningEngine()

    def test_benign_traffic_bypass(self):
        sms = "Your Swiggy order #91823 has been picked up and will arrive in 15 mins."
        ev = extract_threat_evidence(sms, detector=self.detector)
        self.assertFalse(ev["is_threat"])
        self.assertLess(ev["threat_score"], 0.38)

    def test_adversarial_homoglyph_detection(self):
        sms = "URGENT: SВI асcount blосked! Updаte PAN immediately at https://sbi-secure982a.xyz/kyc"
        ev = extract_threat_evidence(sms, detector=self.detector)
        self.assertTrue(ev["is_threat"])
        self.assertGreaterEqual(ev["shannon_entropy"], 3.75)

    def test_upi_lottery_vector(self):
        sms = "Congratulation! You have won lottery of Rs. 25,00,000 from Kaun Banega Crorepati. To claim, send processing fee of Rs. 500 to UPI kbc@upi"
        ev = extract_threat_evidence(sms, detector=self.detector)
        self.assertTrue(ev["is_threat"])
        self.assertTrue(ev["has_upi_handle"])

    def test_stage2_schema_contract(self):
        sms = "CBI & Customs Alert: A parcel in your name contains illegal narcotics. Digital arrest warrant issued. Contact DCP officer immediately at https://cbi-verify-case.top"
        ev = extract_threat_evidence(sms, detector=self.detector)
        self.assertTrue(ev["is_threat"])
        
        advice = self.stage2.generate_advice(sms, ev)
        self.assertIsInstance(advice, dict)
        for key in Stage2ReasoningEngine.REQUIRED_KEYS:
            self.assertIn(key, advice)
        self.assertEqual(advice["threat_category"], "DIGITAL_ARREST_EXTORTION")
        self.assertEqual(advice["threat_level"], "CRITICAL")

if __name__ == "__main__":
    unittest.main(verbosity=2)
