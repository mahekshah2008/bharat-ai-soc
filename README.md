# Bharat AI-SoC: On-Device Threat & SMS Phishing Detector

An edge-native, privacy-preserving threat detection system built for the **Bharat AI-SoC Challenge (Problem Statement 3)**. The solution operates completely offline on target Arm64 mobile hardware in Airplane Mode.

---

## Architecture Overview

The system uses a **two-stage gated architecture** designed to minimize memory usage and battery drain on resource-constrained mobile SoCs:
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

 1. **Stage 1: Fast Heuristic & ML Filter (<5 ms):**
   * Uses TF-IDF vectorization with Multinomial Naive Bayes trained on standard SMS corpora, coupled with regex-based indicator extraction.
   * Produces structured JSON evidence: threat label, composite risk score, link presence, and pressure keywords.
   * **Accuracy:** 97.31% with 100% precision on scam classes.

2. **Stage 2: On-Device LLM Reasoning (ExecuTorch):**
   * Gated execution: The LLM is only awakened when Stage 1 indicates a threat (`risk_score >= 0.5`).
   * Powered by a quantized (INT4) Llama 3.2 1B model via ExecuTorch to generate concise remediation steps without network dependency.

---

## Target Hardware & Runtime Constraints

* **Target Device:** Samsung Galaxy A15 (Arm64 architecture)
* **Execution Environment:** Fully offline (verified in Airplane Mode)
* **Primary Stack:** Python 3.11, scikit-learn, joblib, ExecuTorch

---

## Project Structure
bharat-ai-soc/
├── app.py                   # Main inference runner and Stage 2 gating pipeline
├── train_full_dataset.py    # Training script on full UCI dataset + local scam samples
├── train_detector.py        # Baseline lightweight training script
├── sms_classifier.joblib    # Serialized production-grade ML classifier
├── requirements.txt         # Runtime and build dependencies
├── .gitignore               # Ignored cache, bytecode, and environment files
└── README.md                # System documentation

---

## Quickstart

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Train / Verify Detector
```bash
python train_full_dataset.py
```

### 3. Run Inference Engine
```bash
python app.py
```