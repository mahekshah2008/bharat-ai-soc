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

1. **Stage 1: Ultra-Fast Heuristic & Statistical Ensemble (<5 ms):**
   * Zero Runtime Overhead: Implemented in pure Python without heavy C++ dependencies(scikit-learn or scipy),parsing math        priors directly from model_params.json (375 KB).
   * Blends Multinomial Naive Bayes class log-odds with heuristic regex indicator extraction (phishing URLs, Indian phone/shortcode tokens, urgency words, and financial cues).
   * **Accuracy**: 97.31% with zero external runtime footprint on mobile silicon.

2. **Stage 2: On-Device LLM Reasoning (ExecuTorch):**
   * Gated Execution: The LLM stays dormant and consumes 0% CPU/RAM for routine traffic, awakening only when Stage 1 indicates a threat (threat_score >= 0.40).
   * Powered by a quantized (INT4) Llama 3.2 1B model via ExecuTorch to generate immediate, human-readable safety advice locally.

   ---

## Performance & Benchmarking

## Performance & Benchmarking

| Metric / Parameter | Target Requirement | On-Device Measured Value | Validation Status |
| :--- | :--- | :--- | :--- |
| **Stage 2 Foundation Model** | Edge LLM ($\le 3\text{B}$) | Meta Llama 3.2 1B Instruct | **Verified** |
| **Quantization Format** | Sub-byte / INT4 quantization | `8da4w` INT4 (`.pte` format) | **Verified** |
| **Storage Footprint** | $< 1.0\text{ GB}$ total model storage | **$771.5\text{ MB}$** ($769\text{ MB}$ `.pte` + $2.1\text{ MB}$ tokenizer + $375\text{ KB}$ JSON) | **Passed** (Well under limit) |
| **Stage 1 Gating Latency** | $< 20\text{ ms}$ | **$3.8\text{ ms} - 4.5\text{ ms}$** | **Exceeded Target** |
| **End-to-End Threat Latency** | $< 2.0\text{ s}$ (Stage 1 + Stage 2 Advice) | **$\sim 1.3\text{ s} - 1.4\text{ s}$** | **Passed** |
| **Target Hardware Architecture** | Physical ARM64 / Linux edge SoC | Samsung Galaxy A15 (`arm64-v8a`, MediaTek Helio G99) | **Verified On-Device** |
| **Safe Traffic Gating Rate** | Bypass Stage 2 on benign SMS | Threat score $< 0.40 \rightarrow$ Stage 2 dormant (0% CPU/RAM) | **Verified** |
| **Network Air-Gap / Privacy** | Zero cloud/network callouts | 100% offline edge inference (Airplane Mode active) | **Verified** |
| **Stage 1 Classification Accuracy**| $> 90\%$ detection rate | **$97.31\%$** test accuracy ($100\%$ precision on test scam vectors) | **Passed** |
---

### Benchmark Analysis & Optimization Notes
* **Zero scikit-learn Runtime Bloat:** Exporting TF-IDF and Naive Bayes parameters to JSON (`model_params.json`) allowed Stage 1 to execute in pure Python in under $5\text{ ms}$, entirely circumventing Android C++ build toolchain incompatibilities.
* **Battery Preservation via Gating:** More than 90% of user SMS traffic is safe. Gating the INT4 Llama model behind Stage 1 keeps the heavy 769 MB model dormant, eliminating thermal throttling and battery drain during routine use.
* **100% Data Sovereignty:** Evaluated strictly under hardware Airplane Mode; no SMS content, extracted URLs, or phone numbers ever exit device memory.

## Hardware & Runtime Environment

| Component / Layer | Specification & Configuration |
| :--- | :--- |
| **Target Device** | Samsung Galaxy A15 (MediaTek Helio G99 / 2× ARM Cortex-A76 + 6× Cortex-A55) |
| **Architecture** | ARM64 (`arm64-v8a` / `aarch64`) |
| **Host Runtime** | Termux native Linux user-space environment |
| **Execution Path** | `~/bharat_soc/` (Internal local storage) |
| **Connectivity & Privacy** | 100% Offline / Air-Gapped (Hardware Airplane Mode verified; zero cloud telemetry) |
| **Software Stack** | Python 3.11+, ExecuTorch ARM runtime, pure-Python zero-dependency vectorizer |
| **Memory Constraint** | Peak RAM $< 850\text{ MB}$ (INT4 quantized execution); Idle/Stage 1 RAM $< 25\text{ MB}$ |

### Environment Setup Notes
* **Pure Python Vectorization:** Standalone mathematical evaluation eliminates compilation toolchain dependencies (e.g., `scikit-learn`, `scipy`, or heavy GCC build wheels on Android).
* **On-Chip Inference:** Binary model weights and tokenizer run entirely within local flash memory and RAM inside the user-space sandbox.

---

## Repository & Project Structure

```text
bharat-ai-soc/
├── app.py                 # Main inference orchestrator and Stage 2 gating controller
├── detector.py            # Stage 1 zero-dependency feature extractor and ensemble classifier
├── llm_engine.py          # Stage 2 ExecuTorch runtime runner / fallback interface
├── model_params.json      # Exported TF-IDF vocabulary, IDFs, and Naive Bayes priors (375 KB)
├── export_params.py       # Script used on host PC to serialize scikit-learn model into JSON
├── bharat_soc_run.sh      # Shell launcher script for Termux / ARM64
├── .gitignore             # Binary, cache, and heavy weight exclusion rules
└── README.md              # System architecture and deployment documentation
```

---

## Quickstart (Testing Locally on Host PC)

### 1. Prerequisites
- Python 3.10+ (No external ML dependencies like `scikit-learn` or `scipy` required for inference)

### 2. Run Inference Directly
The pipeline uses pure Python with pre-computed mathematical weights from `model_params.json`. Run inference on any SMS text directly:

```bash
# Test a phishing attack vector (Triggers Stage 1 & Stage 2)
python app.py "URGENT: Your SBI account 4029 is blocked. Update PAN immediately at [https://sbi-kyc-update.com/verify](https://sbi-kyc-update.com/verify) to avoid legal penalty"

# Test a benign transaction SMS (Stage 1 bypasses LLM, saving compute)
python app.py "582910 is your secret OTP for transaction of Rs. 450.00 at Swiggy. Do not share this with anyone."
```

---

## On-Device Deployment & Execution (Termux on Samsung Galaxy A15)

### 1. Stage Directory & Push Files (from PC via ADB)
Run these commands in PowerShell on your host PC to push the scripts, zero-dependency parameters, and quantized models to the device:

```powershell
# 1. Verify ADB device connection
adb devices

# 2. Create the staging directory on the device
adb shell mkdir -p /data/local/tmp/llama_model

# 3. Push source code and model parameters
adb push detector.py app.py llm_engine.py model_params.json bharat_soc_run.sh /data/local/tmp/llama_model/

# 4. Push ExecuTorch INT4 model and tokenizer
adb push llama3_2_1b_int4.pte tokenizer_model /data/local/tmp/llama_model/

# 5. Verify staged files on the device
adb shell ls -lh /data/local/tmp/llama_model/
```

### 2. Copy into Termux Execution Environment
Open **Termux** on your Samsung Galaxy A15 and sync the files from the temporary staging directory into your local project folder:

```bash
# Set up the Termux workspace
mkdir -p ~/bharat_soc
cp -r /data/local/tmp/llama_model/* ~/bharat_soc/
cd ~/bharat_soc

# Ensure execute permissions
chmod +x bharat_soc_run.sh
```
### 3. Run Inference Pipeline (Offline / Airplane Mode)
Enable **Airplane Mode** on your device to ensure an air-gapped test, then run the pipeline natively:

```bash
# Threat Case: Phishing attack vector (Triggers Stage 1 & Stage 2 reasoning)
python app.py "URGENT: Your SBI account 4029 is blocked. Update PAN immediately at https://sbi-kyc-update.com/verify to avoid legal penalty"

# Benign Case: Legitimate transaction OTP (Stage 1 suppresses Stage 2, preserving battery)
python app.py "582910 is your secret OTP for transaction of Rs. 450.00 at Swiggy. Do not share this with anyone."
```