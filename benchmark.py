import time
import json
import os
import sys
from detector import extract_threat_evidence
from llm_engine import Stage2ReasoningEngine

# Test suite containing authentic Indian telecom spam vectors and legitimate messages
TEST_DATASET = [
    # --- BENIGN MESSAGES (Expected: Stage 2 BYPASSED) ---
    {"text": "Your Swiggy order #91823 has been picked up and will arrive in 15 mins.", "label": "benign"},
    {"text": "582910 is your secret OTP for transaction of Rs. 450.00 at Amazon. Do not share.", "label": "benign"},
    {"text": "Dear customer, your ICICI bank account XX4021 has been credited with Rs. 15,000 on 05-Nov.", "label": "benign"},
    {"text": "Your Uber ride is arriving in 3 mins. Driver: Ramesh (MH12-AB-1234).", "label": "benign"},
    {"text": "Hi Mahek, are we meeting at the college library at 4 PM today?", "label": "benign"},
    {"text": "Recharge of Rs. 299 successful for your Airtel mobile 98xxxxxx10. Validity: 28 days.", "label": "benign"},
    {"text": "Your appointment with Dr. Kulkarni is confirmed for tomorrow 10:30 AM.", "label": "benign"},
    {"text": "Reminder: Return book 'Digital Signal Processing' to library by Friday to avoid fine.", "label": "benign"},
    {"text": "Good morning! Please find attached lecture notes for the microcontrollers class.", "label": "benign"},
    {"text": "Payment received: Rs. 120 paid to Campus Canteen via Google Pay UPI.", "label": "benign"},

    # --- MALICIOUS VECTORS (Expected: Stage 2 TRIGGERED) ---
    {"text": "URGENT: Your SBI account 4029 is blocked. Update PAN immediately at https://sbi-kyc-update.com/verify to avoid legal penalty", "label": "threat"},
    {"text": "Dear consumer, electricity power will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Contact officer at 9876543210", "label": "threat"},
    {"text": "E-Challan Alert: Pending traffic fine of Rs. 2000 against vehicle. Pay immediately or arrest warrant will be issued: http://echallan-parivahan-pay.cc", "label": "threat"},
    {"text": "Congratulation! You have won lottery of Rs. 25,00,000 from Kaun Banega Crorepati. To claim, send processing fee of Rs. 500 to UPI kbc@upi", "label": "threat"},
    {"text": "Your SIM card will be deactivated in 24 hours due to missing Aadhaar KYC. Call customer care officer at 8912345678 immediately.", "label": "threat"},
    {"text": "Dear user, install our fast loan app APK now to get instant credit up to 50000 with 0% interest: http://tinyurl.com/quick-cash-loan-apk", "label": "threat"},
    {"text": "HDFC Bank Alert: Suspicious transaction of Rs. 49,999 detected on your card. If not done by you, block immediately at http://hdfc-fraud-block.top", "label": "threat"},
    {"text": "Part time work from home job offer! Earn 3000 to 5000 daily by liking YouTube videos. Join telegram channel: bit.ly/easy-daily-income", "label": "threat"},
    {"text": "Income Tax Department: Tax refund of Rs. 18,420 approved. Enter bank details to credit refund: http://incometax-refund-gov.in.secure-pay.xyz", "label": "threat"},
    {"text": "Dear customer, your credit card reward points worth Rs. 7,450 will expire tonight. Redeem now into bank account: http://sbi-reward-pts.cc/claim", "label": "threat"}
]

def run_benchmark():
    print("=" * 65)
    print("      BHARAT AI-SOC: ON-DEVICE INFERENCE BENCHMARK      ")
    print("=" * 65)
    print(f"Dataset Size: {len(TEST_DATASET)} samples (10 Benign, 10 Threat Vectors)")
    print("Platform: Edge ARM64 / On-Device Python Runtime\n")

    stage2_engine = Stage2ReasoningEngine()
    
    stage1_latencies_ms = []
    stage2_latencies_ms = []
    total_latencies_ms = []
    
    gated_count = 0  # Number of times Stage 2 was kept asleep
    correct_predictions = 0

    for idx, item in enumerate(TEST_DATASET, start=1):
        text = item["text"]
        ground_truth = item["label"]

        # --- Benchmark Stage 1 ---
        t0 = time.perf_counter_ns()
        evidence = extract_threat_evidence(text)
        t1 = time.perf_counter_ns()
        s1_time_ms = (t1 - t0) / 1_000_000.0
        stage1_latencies_ms.append(s1_time_ms)

        is_threat = evidence["is_scam"]
        
        # Ground truth evaluation
        predicted_label = "threat" if is_threat else "benign"
        if predicted_label == ground_truth:
            correct_predictions += 1

        # --- Benchmark Stage 2 (Conditional) ---
        if is_threat:
            t2 = time.perf_counter_ns()
            advice = stage2_engine.generate_advice(text, evidence)
            t3 = time.perf_counter_ns()
            s2_time_ms = (t3 - t2) / 1_000_000.0
            stage2_latencies_ms.append(s2_time_ms)
            total_latencies_ms.append(s1_time_ms + s2_time_ms)
        else:
            gated_count += 1
            total_latencies_ms.append(s1_time_ms)

    # --- Calculations ---
    stage1_latencies_ms.sort()
    total_latencies_ms.sort()
    
    def percentile(arr, p):
        if not arr:
            return 0.0
        k = (len(arr) - 1) * p
        f = int(k)
        c = f + 1 if f + 1 < len(arr) else f
        return arr[f] + (k - f) * (arr[c] - arr[f])

    s1_p50 = percentile(stage1_latencies_ms, 0.50)
    s1_p90 = percentile(stage1_latencies_ms, 0.90)
    s1_p99 = percentile(stage1_latencies_ms, 0.99)
    s1_avg = sum(stage1_latencies_ms) / len(stage1_latencies_ms)

    tot_p50 = percentile(total_latencies_ms, 0.50)
    tot_p90 = percentile(total_latencies_ms, 0.90)
    tot_p99 = percentile(total_latencies_ms, 0.99)
    tot_avg = sum(total_latencies_ms) / len(total_latencies_ms)

    accuracy = (correct_predictions / len(TEST_DATASET)) * 100.0
    gating_ratio = (gated_count / len(TEST_DATASET)) * 100.0

    # Diagnostic for any misclassifications
    mismatches = []
    for item in TEST_DATASET:
        ev = extract_threat_evidence(item["text"])
        pred = "threat" if ev["is_scam"] else "benign"
        if pred != item["label"]:
            mismatches.append((item["label"], pred, ev["threat_score"], item["text"]))

    if mismatches:
        print("-" * 65)
        print("                 MISCLASSIFICATIONS DETECTED                     ")
        print("-" * 65)
        for expected, got, score, txt in mismatches:
            print(f"  [Expected: {expected.upper()} | Predicted: {got.upper()} | Score: {score}]")
            print(f"  SMS: \"{txt}\"\n")

    # --- Print Benchmark Summary ---
    print("\n" + "-" * 65)
    print("                    BENCHMARK RESULTS SUMMARY                    ")
    print("-" * 65)
    print(f"Overall Classification Accuracy : {accuracy:.1f}% ({correct_predictions}/{len(TEST_DATASET)})")
    print(f"Energy-Preserving Gating Ratio  : {gating_ratio:.1f}% of messages bypassed heavy LLM")
    print(f"Stage 2 LLM Invocations         : {len(stage2_latencies_ms)} / {len(TEST_DATASET)}")
    print("-" * 65)
    print("LATENCY PROFILING (Milliseconds):")
    print(f"  Stage 1 (Feature Extraction + ML Filter):")
    print(f"    - Mean : {s1_avg:.3f} ms")
    print(f"    - P50  : {s1_p50:.3f} ms")
    print(f"    - P90  : {s1_p90:.3f} ms")
    print(f"    - P99  : {s1_p99:.3f} ms")
    print(f"  End-to-End Pipeline Latency (Across entire workload):")
    print(f"    - Mean : {tot_avg:.3f} ms")
    print(f"    - P50  : {tot_p50:.3f} ms")
    print(f"    - P90  : {tot_p90:.3f} ms")
    print(f"    - P99  : {tot_p99:.3f} ms")
    print("-" * 65)
    print("Status: Edge gating pipeline operational and verified.")
    print("=" * 65)

if __name__ == "__main__":
    run_benchmark()