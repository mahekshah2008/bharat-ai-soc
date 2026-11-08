# Bharat AI-SoC: On-Device Threat & SMS Phishing Detector

An edge-native, privacy-preserving threat detection system built for the **Bharat AI-SoC Challenge (Problem Statement 3)**. The solution operates completely offline on target ARM64 mobile hardware in Airplane Mode.

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
                        [Threat Score >= 0.40?]
                               /     \
                       No     /       \   Yes
                             v         v
               +---------------+     +--------------------------------+
               | Verdict: SAFE |     | Stage 2: Reasoning Engine      |
               | (LLM Skipped) |     | - Quantized Llama 3.2 1B       |
               +---------------+     |   via ExecuTorch               |
                                     | - Generates structured advice  |
                                     +--------------------------------+
```
---

1. **Stage 1: Ultra-Fast Heuristic & Statistical Ensemble (<1.5 ms Mean):**
   * Zero Runtime Overhead: Implemented in pure Python without heavy C++ dependencies(scikit-learn or scipy),parsing mathematical priors directly from model_params.json (375 KB).
   * Blends Multinomial Naive Bayes class log-odds with Shannon string entropy analysis on URLs and heuristic regex indicator extraction (phishing URLs, Indian phone/shortcode tokens, urgency words, utility threats, and financial cues).
   * **Accuracy**: 100.0% detection rate on Indian telecom vectors with zero external runtime footprint on mobile silicon.

2. **Stage 2: On-Device LLM Reasoning (ExecuTorch):**
   * Gated Execution: The LLM stays dormant and consumes 0% CPU/RAM for routine traffic, awakening only when Stage 1 indicates a threat (threat_score >= 0.40).
   * Powered by a quantized (INT4) Llama 3.2 1B model via ExecuTorch to generate immediate, structured safety advice and national reporting helplines (1930) locally.

---

## 📊 Performance & Physical Silicon Benchmarking

Evaluated directly on native ARM64 silicon (Samsung Galaxy A15 / MediaTek Helio G99 / Termux runtime) across a balanced validation suite covering authentic Indian telecom fraud vectors (KYC/PAN phishing, electricity disconnection extortion, fake traffic e-challans, malicious APKs, and lottery/advance-fee scams):

| Metric / Parameter | Target Requirement | On-Device Measured Value | Validation Status |
| :--- | :--- | :--- | :--- |
| **Stage 2 Foundation Model** | Edge LLM ($\le 3\text{B}$) | Meta Llama 3.2 1B Instruct | **Verified** |
| **Quantization Format** | Sub-byte / INT4 quantization | `8da4w` INT4 (`.pte` format) | **Verified** |
| **Storage Footprint** | $< 1.0\text{ GB}$ total model storage | **$771.5\text{ MB}$** ($769\text{ MB}$ `.pte` + $2.1\text{ MB}$ tokenizer + $375\text{ KB}$ JSON) | **Passed** (Well under limit) |
| **Stage 1 Mean Latency** | $< 20\text{ ms}$ | **$1.273\text{ ms}$** | **Exceeded Target** |
| **Stage 1 P50 / P90 Latency** | Edge Sub-millisecond | **$0.170\text{ ms}$ / $0.225\text{ ms}$** | **Exceeded Target** |
| **Stage 1 P99 Latency** | Real-time bound | **$18.115\text{ ms}$** | **Passed** |
| **End-to-End Pipeline Latency** | Real-time stream processing | **$1.278\text{ ms}$** Mean (Stage 1 + Gated Dispatch) | **Passed** |
| **Safe Traffic Gating Ratio** | Bypass Stage 2 on benign SMS | **$50.0\%$** bypassed (Threat score $< 0.40 \rightarrow$ 0% LLM compute) | **Verified** |
| **Detection Accuracy** | $> 90\%$ detection rate | **$100.0\%$** ($20/20$ validation set, zero false negatives) | **Passed** |
| **Target Hardware Architecture** | Physical ARM64 / Linux edge SoC | Samsung Galaxy A15 (`arm64-v8a`, MediaTek Helio G99) | **Verified On-Device** |
| **Network Air-Gap / Privacy** | Zero cloud/network callouts | 100% offline edge inference (Hardware Airplane Mode active) | **Verified** |

---

### ⚙️ Benchmark Analysis & Optimization Notes

* **Zero `scikit-learn` Runtime Bloat:** Exporting TF-IDF and Naive Bayes parameters to JSON (`model_params.json`) allows Stage 1 to execute in pure Python in under $1.5\text{ ms}$, entirely circumventing Android C++ build toolchain incompatibilities.
* **Battery Preservation via Gating:** Benign everyday messages bypass the heavy LLM entirely, keeping the 769 MB model dormant to eliminate thermal throttling and battery drain.
* **100% Data Sovereignty:** Evaluated strictly under hardware Airplane Mode; no SMS content, extracted URLs, or phone numbers ever leave device memory.

---

## 📱 Hardware & Runtime Environment

| Component / Layer | Specification & Configuration |
| :--- | :--- |
| **Target Device** | Samsung Galaxy A15 (MediaTek Helio G99 / 2× ARM Cortex-A76 + 6× Cortex-A55) |
| **Architecture** | ARM64 (`arm64-v8a` / `aarch64`) |
| **Host Runtime** | Termux native Linux user-space environment |
| **Execution Path** | `~/bharat_soc/` (Internal local storage) |
| **Connectivity & Privacy** | 100% Offline / Air-Gapped (Hardware Airplane Mode verified; zero cloud telemetry) |
| **Software Stack** | Python 3.11+, ExecuTorch ARM runtime, pure-Python zero-dependency vectorizer |
| **Memory Footprint** | Peak RAM $< 850\text{ MB}$ (INT4 quantized execution); Idle/Stage 1 RAM $< 25\text{ MB}$ |

---

## 📂 Repository & Project Structure

```text
bharat-ai-soc/
├── app.py                 # Interactive single-sample testing CLI
├── benchmark.py           # On-device latency profiling suite & 20-sample validation test
├── listener_daemon.py     # Real-time telecom ingest listener & alert dispatcher
├── detector.py            # Stage 1 zero-dependency feature extractor & ensemble classifier
├── llm_engine.py          # Stage 2 ExecuTorch runtime runner / deterministic fallback
├── model_params.json      # Serialized TF-IDF vocabulary, IDFs, and Naive Bayes priors (375 KB)
├── export_params.py       # Host script to serialize trained model into model_params.json
├── bharat_soc_run.sh      # Shell launcher script for Termux / ARM64
├── .gitignore             # Binary, cache, and heavy weight exclusion rules
└── README.md              # System architecture and deployment documentation
```

---

## ⚡ Quickstart (Testing Locally on Host PC)

### 1. Prerequisites
* Python 3.10+ (No external ML dependencies like `scikit-learn` or `scipy` required for inference)

### 2. Run Inference Directly
```bash
# Test a phishing attack vector (Triggers Stage 1 & Stage 2)
python app.py

# Run full evaluation benchmark
python benchmark.py
```

## 📲 On-Device Deployment & Execution (Termux on Samsung Galaxy A15)

### 1. Stage Directory & Push Files (from PC via ADB)
Run these commands in PowerShell on your host PC to push the scripts and model parameters to the device:

```powershell
# 1. Verify ADB device connection
adb devices

# 2. Push updated source code and parameters
adb push detector.py app.py llm_engine.py benchmark.py listener_daemon.py model_params.json /data/local/tmp/
```
### 2. Sync inside Termux

Open **Termux** on your device and copy the staged files into your active workspace:

```bash
mkdir -p ~/bharat_soc
cp /data/local/tmp/detector.py /data/local/tmp/app.py /data/local/tmp/llm_engine.py /data/local/tmp/benchmark.py /data/local/tmp/listener_daemon.py /data/local/tmp/model_params.json ~/bharat_soc/
cd ~/bharat_soc
```

---

### 3. Run on Device (Offline / Airplane Mode)

Enable **Airplane Mode** on your device to ensure an air-gapped test, then execute:

* **Run Full Silicon Latency Benchmark:**
  ```bash
  python benchmark.py
  ```

* **Run Live Telecom Listener Daemon:**
  ```bash
  python listener_daemon.py
  ```
* **Run Single-Sample Interactive CLI:**
  ```bash
  python app.py
  ```

---  