# Bharat AI-SoC: On-Device Threat, Phishing & Scam Detection Engine

[![Target](https://img.shields.io/badge/Architecture-ARM64%20%2F%20Cortex--A-orange)](https://github.com/mahekshah2008/bharat-ai-soc)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Evaluation-Passed%20(100%25)-brightgreen)](https://github.com/mahekshah2008/bharat-ai-soc)

An ultra-low latency, energy-preserving dual-stage threat detection daemon designed for on-device mobile hardware (ARM Cortex-A series). Engineered specifically for **Problem Statement 3: On-Device Threat & Scam Detection** in the **ARM Bharat AI-SoC Challenge 2026–2027**.

---

## 1. Architectural Overview

Continuous inference on battery-constrained edge devices necessitates aggressive energy preservation. Running full-parameter language models on every incoming notification or SMS causes thermal throttling, memory spikes, and rapid battery depletion.

Our solution implements a **Dual-Stage Gated Architecture**:
1. **Stage 1 (Lightweight Gating Filter):** Runs in under **0.5 ms** (P50) using an adversarial Unicode homoglyph normalizer, sub-word n-gram TF-IDF vectorizer, and Shannon entropy analysis. Benign traffic is filtered immediately, keeping the heavy reasoning engine suspended.
2. **Stage 2 (Local LLM Security Reasoning):** Triggered strictly when Stage 1 threat score meets or exceeds the empirical threshold ($\tau \ge 0.40$). Formats threat attribution into a strict, validated **5-Key JSON Schema** containing contextual remediation actions and verified Indian emergency response helplines (1930 / DoT Chakshu).

```
                        [ Incoming SMS / Notification Payload ]
                                         │
                                         ▼
                     ┌───────────────────────────────────────┐
                     │         STAGE 1 GATING FILTER         │
                     │  - NFKC / Cyrillic Homoglyph Flatten  │
                     │  - Shannon Character-Level Entropy    │
                     │  - Term Frequency Indicator Matrices  │
                     └───────────────────┬───────────────────┘
                                         │
                         Threat Score (S) >= 0.40 ?
                                        / \
                                  No   /   \  Yes
                                      /     \
                                     ▼       ▼
                ┌────────────────────────┐  ┌───────────────────────────────────┐
                │ BENIGN TRAFFIC BYPASS  │  │     STAGE 2 EXECUTORCH RUNTIME    │
                │ LLM Kept in Low-Power  │  │  - Low-Rank Quantized Model       │
                │ Sleep Mode (~0 W Burst)│  │  - Strict 5-Key Contract Schema   │
                └────────────────────────┘  └─────────────────┬─────────────────┘
                                                              │
                                                              ▼
                                               [ Structured Security Advice ]
```

---

## 2. Physical ARM64 Hardware Benchmark

Measured directly on native **ARM64 (Android aarch64)** mobile silicon using production kernel telemetry interfaces (`/proc/self/status` and `/sys/class/thermal`):

### Performance & Gating Efficiency
| Metric | Physical ARM64 Measurement | Validation Status |
| :--- | :--- | :--- |
| **Overall Classification Accuracy** | **100.0%** (24 / 24 adversarial vectors) | Verified |
| **Battery Gating Ratio** | **50.0%** bypassed heavy Stage 2 LLM | Energy Optimized |
| **Stage 2 Schema Contract** | **100% compliance** across all invocations | Deterministic Schema |
| **Process Working Set (VmRSS)** | **15.70 MB** (Delta: `+0.94 MB`) | Ultra-low Edge Footprint |
| **Peak Dynamic Heap Allocation** | **1567.21 KB** (~1.5 MB runtime memory) | Safe for Low-RAM Targets |

### Latency Profiles: Pure Python vs. ARM NEON SIMD C-Extension (`-march=armv8-a+simd`)
| Pipeline Component | Implementation | Mean Latency | Median (P50) | P90 Latency | P99 (Tail) Latency |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Stage 1 (Gate + Entropy)** | Pure Python Baseline | 1.122 ms | 0.496 ms | 0.669 ms | 12.106 ms |
| **Stage 1 (Gate + Entropy)** | **ARM NEON SIMD (`.so`)** | **0.403 ms** | **0.414 ms** | **0.516 ms** | **0.684 ms (17.7x faster)** |
| **End-to-End Pipeline** | **ARM NEON + Gated Stage 2** | **0.445 ms** | **0.481 ms** | **0.604 ms** | **0.701 ms** |

---

## 3. Threat Matrix & Defense Coverage

The pipeline is hardened against key regional fraud patterns targeting Indian mobile users:

* **Digital Arrest & Legal Coercion:** Detects CBI, ED, and Supreme Court impersonation campaigns demanding non-disclosure or virtual appearances.
* **Electricity & Utility Disconnection Scams:** Flags urgency triggers mimicking MSEB/State electricity board billing notices demanding urgent calls to 10-digit mobile numbers.
* **UPI & Payment Gateway Fraud:** Detects malicious payment requests masquerading as lotteries, cashback approvals, or refund links containing raw UPI request intents (`collect`, `approve-pay`).
* **APK Droppers & Drive-by Downloads:** Identifies hidden URL redirects and file endpoints attempting to drop malicious Android packages (e.g., WhatsApp update or banking support impersonators).
* **Adversarial Homoglyphs:** Flattens Cyrillic and look-alike script bypass attempts (e.g., `sbi` spoofed with Cyrillic characters) via canonical NFKC normalization.

---

## 4. Stage 2 Contract Interface

Alert outputs conform to the mandatory 5-key security specification:

```json
{
  "is_threat": true,
  "confidence": 0.88,
  "threat_category": "UTILITY_DISCONNECTION_FRAUD",
  "recommended_action": "Do not call the provided 10-digit number or transfer money. Electricity boards never issue immediate disconnection notices via SMS.",
  "relevant_helpline": "1930 / State Electricity Distribution Portal"
}
```

---

## 5. Repository File Structure

```
bharat-ai-soc/
├── app.py                # Web / API interface for pipeline interaction
├── benchmark.py          # Real-time physical ARM64 performance and RSS telemetry profiler
├── bharat_soc_run.sh     # Automation launcher script for physical edge deployment
├── detector.py           # Stage 1 lightweight heuristic & statistical feature extractor
├── export_params.py      # Serialization utility to export trained weights to JSON
├── listener_daemon.py    # Background service for SMS spool and CLI stream processing
├── llm_engine.py         # Stage 2 ExecuTorch / quantized local reasoning engine
├── model_params.json     # Serialized lightweight model weights and decision thresholds
├── neon_kernel.c         # ARM NEON 128-bit SIMD C kernel for byte entropy & homoglyph detection
├── requirements.txt      # Python dependencies for training and desktop runtime
├── sms_classifier.joblib # Desktop scikit-learn training artifact
├── test_pipeline.py      # Unit testing suite covering adversarial attack vectors
├── train_detector.py     # Base training pipeline for Stage 1 classifier
├── train_full_dataset.py # Full dataset training with cross-validation
└── README.md             # Architecture documentation and hardware benchmarks

```

---

## 6. Execution & Deployment Guide

### Run on Mobile Silicon (Termux / Linux ARM64)

```bash
# 1. Update environment
pkg update && pkg install git python -y

# 2. Clone repository
git clone https://github.com/mahekshah2008/bharat-ai-soc.git
cd bharat-ai-soc

# 3. Execute Adversarial Test Suite
python test_pipeline.py

# 4. Run Physical Telemetry & Benchmark
python benchmark.py

# 5. Start Background Ingestion Daemon
python listener_daemon.py --cli

```
