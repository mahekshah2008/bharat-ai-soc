# Bharat AI-SoC: On-Device Threat & SMS Phishing Detector

An edge-native, privacy-preserving threat detection system built for the **Bharat AI-SoC Challenge (Problem Statement 3)**. The solution operates completely offline on target Arm64 mobile hardware in Airplane Mode.

---

## Architecture Overview

The system uses a **two-stage gated architecture** designed to minimize memory usage and battery drain on resource-constrained mobile SoCs:

```text
                  +--------------------------------+
                  |       Incoming SMS Stream      |
                  +--------------------------------+
                                  |
                                  v
                  +--------------------------------+
                  |   Stage 1: Primary Detector    |
                  |  - TF-IDF + Multinomial NB     |
                  |  - Link & Urgency Heuristics   |
                  +--------------------------------+
                                  |
                        [Risk Score >= 0.5?]
                               /     \
                       No     /       \   Yes
                             v         v
               +---------------+     +--------------------------------+
               | Verdict: SAFE |     | Stage 2: Reasoning Engine      |
               | (LLM Skipped) |     | - Quantized Llama 3.2 1B       |
               +---------------+     |   via ExecuTorch               |
                                     | - Generates 2-sentence advice  |
                                     +--------------------------------+
```                                   

1. **Stage 1: Fast Heuristic & ML Filter (<5 ms):**
   * Uses TF-IDF vectorization with Multinomial Naive Bayes trained on standard SMS corpora, coupled with regex-based indicator extraction.
   * Produces structured JSON evidence: threat label, composite risk score, link presence, and pressure keywords.
   * **Accuracy:** 97.31% with 100% precision on scam classes.

2. **Stage 2: On-Device LLM Reasoning (ExecuTorch):**
   * Gated execution: The LLM is only awakened when Stage 1 indicates a threat (`risk_score >= 0.5`).
   * Powered by a quantized (INT4) Llama 3.2 1B model via ExecuTorch to generate concise remediation steps without network dependency.

   ---

## Performance & Benchmarking

| Metric | Target Specification | Observed Result | Status |
| :--- | :--- | :--- | :--- |
| **Model** | Llama-3.2-1B-Instruct | `8da4w` quantized (`.pte`) | Verified |
| **Artifact Footprint** | < 1 GB storage | 768 MB (`.pte`) + 2.0 MB (tokenizer) | Passed |
| **Pipeline Latency** | < 100 ms (End-to-End) | **41 ms** (0.041 s) | Exceeded Target |
| **Target Architecture** | Arm64 mobile SoC | Samsung Galaxy A15 (`arm64-v8a`) | Verified via ADB |
| **Stage 1 Detection** | High-risk vector flags | 1.0 Risk Score (0.72 ML Probability) | Passed |
| **Privacy / Connectivity** | Zero Cloud Callouts | 100% Local execution (Airplane Mode) | Verified |

---


## Target Hardware & Runtime Constraints

- **Target Device:** Samsung Galaxy A15 ( arm64-v8a architecture)
- **Execution Target Path:** /data/local/tmp/llama_model/
- **Execution Environment:** Fully offline (verified in Airplane Mode)
- **Primary Stack:** Python 3.11/3.14, scikit-learn, joblib, ExecuTorch

---

## Project Structure
```text
bharat-ai-soc/
├── app.py                     # Main inference orchestrator and Stage 2 gating pipeline
├── detector.py                # Stage 1 ML feature extractor and heuristic rule engine
├── llm_engine.py              # Stage 2 ExecuTorch runtime runner / fallback interface
├── train_full_dataset.py      # Training script on full UCI dataset + local scam samples
├── train_detector.py          # Baseline lightweight training script
├── sms_classifier.joblib      # Serialized production-grade ML classifier
├── llama3_2_1b_int4.pte       # Compiled INT4 ExecuTorch model binary (~768 MB, ignored in git)
├── tokenizer.model            # TikToken model vocabulary (~2.0 MB, ignored in git)
├── requirements.txt           # Runtime and build dependencies
├── .gitignore                 # Binary, cache, bytecode, and model exclusion rules
└── README.md                  # System architecture and benchmark documentation
```

---

## Quickstart

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Retrain / Verify Classifier
```bash
python train_full_dataset.py
```

### 3. Run Inference Pipeline
Run inference on any SMS text:
```bash
python app.py "<YOUR_SMS_TEXT>"
```

---

## On-Device Deployment (Samsung Galaxy A15 via ADB)

### 1. Verify Device Connection:
```bash
adb devices
```

### 2. Stage Execution Directory:
```bash
adb shell mkdir -p /data/local/tmp/llama_model
```

### 3. Push Model Binaries to Device:

```bash
# Push tokenizer vocabulary (~2.0 MB)
adb push tokenizer.model /data/local/tmp/llama_model/

# Push quantized ExecuTorch model (~768 MB)
adb push llama3_2_1b_int4.pte /data/local/tmp/llama_model/
```

### 4. Verify On-Device Storage:
```bash
adb shell ls -lh /data/local/tmp/llama_model/
```