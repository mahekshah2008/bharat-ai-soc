# Bharat AI-SOC (v3.0): Dual-Stage Air-Gapped Edge SMS Threat Defense

[![Bharat AI-SOC Edge CI & Release Builder](https://github.com/mahekshah2008/bharat-ai-soc/actions/workflows/ci.yml/badge.svg)](https://github.com/mahekshah2008/bharat-ai-soc/actions/workflows/ci.yml)
[![Release v3.0.0](https://img.shields.io/github/v/release/mahekshah2008/bharat-ai-soc?label=Compiled%20Binaries&color=brightgreen)](https://github.com/mahekshah2008/bharat-ai-soc/releases/tag/v3.0.0)
[![Target Silicon](https://img.shields.io/badge/Hardware-ARMv8--A%20aarch64%20NEON%20SIMD-blue)](#empirical-hardware-benchmarks-samsung-galaxy-a15-sm-a156e)
[![Memory Footprint](https://img.shields.io/badge/RAM%20Footprint-18.11%20MB%20RSS-orange)](#empirical-hardware-benchmarks-samsung-galaxy-a15-sm-a156e)

**Bharat AI-SOC** is a zero-cloud, hardware-accelerated on-device security operations engine engineered to detect and neutralize Indian telecom threats—including **Digital Arrest extortion**, **Cyrillic/Unicode homoglyph banking phishing**, **malicious `.apk` sideloading lures**, **adversarial LLM prompt injections**, and **regional Marathi/Hindi Devanagari utility scams**—entirely offline on physical **ARM64 (`aarch64`)** silicon.

---

## Hackathon Deliverables Mapping

| Deliverable Requirement | Repository Artifact / Location | Status |
| :--- | :--- | :--- |
| **1. Source Code on GitHub** | Complete C-SIMD (`neon_kernel.c`), Stage-2 Runner (`executor_runner.c`), and Python Co-Design Pipeline | Verified (`main`) |
| **2. Compiled Working Application** | Pre-compiled static **ARM64 (`aarch64`)** & **Linux (`x86_64`)** executables in [**GitHub Releases (`v3.0.0`)**](https://github.com/mahekshah2008/bharat-ai-soc/releases/tag/v3.0.0) and `/bin` | Ready to Run |
| **3. Offline Hardware Video Demo** | Executed on physical **Samsung Galaxy A15 (`SM-A156E`)** in Airplane Mode | Verified |
| **4. Technical Report** | Full hardware architecture, model configuration, and P50/P90/P99 telemetry in [**`whitepaper.md`**](./whitepaper.md) | Complete |

---

## System Architecture: Energy-Preserving Dual-Stage Co-Design

Running a 1-billion-parameter LLM on every incoming SMS drains mobile batteries and introduces multi-second latency. Bharat AI-SOC solves this via a **Hardware-Gated Dual-Stage Pipeline**:

1. **Stage 1: Native ARM NEON SIMD C-Kernel + Statistical Gate (`neon_kernel.c` & `detector.py`)**
   * Compiles directly to `neon_kernel.so` (`-O3 -march=armv8-a+simd`) utilizing 128-bit ARM NEON vector intrinsics (`<arm_neon.h>`).
   * Performs vectorized UTF-8 multibyte scanning for Cyrillic/Greek homoglyph spoofing, UTF-8 Devanagari (Marathi/Hindi) scam markers, URL Shannon entropy calculation, and calibrated character n-gram scoring in **0.0527 ms (P50)**.
   * **Energy-Preserving Gate:** Legitimate transactional traffic (UPI debits, IRCTC PNR alerts, OTPs, conversational SMS) is cleared in **< 1.0 ms**, keeping Stage 2 in deep sleep (`0.0 mW` LLM wakeup).

2. **Stage 2: Gated INT4 Quantized ExecuTorch Co-Processor (`executor_runner.c` & `llm_engine.py`)**
   * Woken **exclusively** when Stage 1 flags a statistical or structural anomaly (`threat_score >= 0.38`).
   * Sanitizes untrusted SMS payloads against control-token breakout (`<|begin_of_text|>`, role spoofing) and binds to the native `executor_runner` binary (`llama3_2_1b_int4.pte`) to emit a deterministic 5-key **1930 NCRP / Chakshu Portal** forensic JSON packet.

---

## Empirical Hardware Benchmarks: Samsung Galaxy A15 (`SM-A156E`)

All benchmarks were executed offline on physical mobile silicon (**Samsung Galaxy A15 `SM-A156E`**, Octa-Core **ARMv8-A `aarch64`**: 2x Cortex-A76 @ 2.20 GHz + 6x Cortex-A55 @ 2.00 GHz, Android 14 / Linux 6.1, Termux Python 3.14.10).

### 1. 100-Vector Evaluation Benchmark (`python benchmark.py`)
* **Dataset:** 100 balanced samples (`dataset_eval.json` — 50 Benign Indian transactional/conversational SMS, 50 Malicious/Adversarial SMS).

| Metric / Subsystem | Measured Value (`SM-A156E` ARM64) | Measured Value (`x86_64` Host) | Target / SLA |
| :--- | :--- | :--- | :--- |
| **Classification Accuracy** | **100.0% (100 / 100)** | **100.0% (100 / 100)** | > 95.0% |
| **Precision / Recall / F1-Score** | **100.0% / 100.0% / 100.0%** | **100.0% / 100.0% / 100.0%** | > 95.0% |
| **False Positive Rate (FPR)** | **0.0% (FP = 0, TN = 50)** | **0.0% (FP = 0, TN = 50)** | 0.0% |
| **Energy-Preserving Gate Ratio** | **50.0% bypassed Stage-2 wakeup** | **50.0% bypassed Stage-2 wakeup** | Dynamic |
| **Stage 1 Native C-SIMD Latency** | **0.0527 ms (P50)** / `0.0722 ms` (Mean) | **0.0439 ms (P50)** / `0.0420 ms` (Mean) | < 1.0 ms |
| **Stage 1 Full Pipeline Latency** | **0.663 ms (P50)** / `1.007 ms` (Mean) | **0.509 ms (P50)** / `0.572 ms` (Mean) | < 5.0 ms |
| **End-to-End Gated Latency** | **6.457 ms (P50)** / `8.570 ms` (Mean) | **14.065 ms (P50)** / `23.907 ms` (Mean) | < 50.0 ms |
| **Process Memory Footprint (RSS)** | **18.11 MB** (`+0.75 MB` delta) | **23.94 MB** (`+1.71 MB` delta) | < 25.0 MB |
| **Peak Dynamic Heap (`tracemalloc`)** | **2598.15 KB (~2.54 MB)** | **2404.09 KB (~2.35 MB)** | < 5.0 MB |
| **Stage 2 JSON Contract Compliance** | **100.0% (50 / 50 Verified)** | **100.0% (50 / 50 Verified)** | 100.0% |

### 2. 26-Vector Multi-Lingual Adversarial Fuzzer (`python fuzzer.py`)
* **Coverage:** Cyrillic homoglyphs, Digital Arrest coercion, LLM prompt injection, Marathi (`महावितरण`) & Hindi (`बिजली विभाग`) Devanagari lures, `.apk` droppers, and benign regional controls.
* **Result:** `TP = 20 | TN = 6 | FP = 0 | FN = 0` (**100.0% F1-Score**, **0.309 ms** mean latency on `SM-A156E`).

---

## Judge Quickstart: Running the Compiled Application (Zero Setup)

### Option A: Run Pre-Compiled Native Binaries (No Compiler Required)
Download the pre-compiled executables directly from [**GitHub Releases (`v3.0.0`)**](https://github.com/mahekshah2008/bharat-ai-soc/releases/tag/v3.0.0):

**On ARM64 Devices (Android Termux / Raspberry Pi 5 / ARM Linux):**
```bash
chmod +x bharat-ai-soc-linux-arm64
./bharat-ai-soc-linux-arm64
# Test custom SMS payload directly via CLI:
./bharat-ai-soc-linux-arm64 "URGENT: Your SBI KYC is suspended! Click http://sbi-update99.xyz/login.apk"
```

### Option B: Installable Android APK (bharat-ai-soc.apk)
1. **Target:** Standard Android smartphones (such as my Samsung Galaxy A15 test device).
2. **How to Download:** Download bharat-ai-soc.apk directly from GitHub Releases (v3.0.0) onto any Android phone, tap to install, and launch the offline C-SIMD threat defense UI directly from your home screen.

## Run Full Telemetry & Interactive Judge Suite from Source
git clone https://github.com/mahekshah2008/bharat-ai-soc.git
cd bharat-ai-soc

# 1. Compile Stage-1 NEON C-Kernel & Stage-2 Native Runner (ARM64 example)
gcc -O3 -fPIC -shared -march=armv8-a+simd -o neon_kernel.so neon_kernel.c -lm
gcc -O3 -march=armv8-a+simd -o executor_runner executor_runner.c
gcc -O3 -march=armv8-a+simd -o bharat-ai-soc-arm64 bharat_soc_app.c neon_kernel.c -lm

# 2. Run 100-Vector Hardware Benchmark & P50/P90/P99 Profiler
python benchmark.py

# 3. Run 26-Vector Multi-Lingual Adversarial Fuzzer
python fuzzer.py

# 4. Launch Interactive Live Judge Telemetry Dashboard
python demo.py

## Repository Structure

```text
bharat-ai-soc/
├── .github/workflows/     # Automated ARM64 cross-compilation, CI test verification & Release publisher
├── .gitignore             # Git ignore specification for compiled objects and local artifacts
├── README.md              # Project overview, deliverables, and quickstart documentation
├── whitepaper.md          # Technical report & hardware co-design specification (Deliverable #4)
├── requirements.txt       # Dependency specification (rich, psutil, pytest, google-genai)
├── app.py                 # Core application entrypoint / FastAPI or orchestration wrapper
├── dashboard.py           # Real-time monitoring and analytics visual dashboard
├── demo.py                # Interactive Rich TUI judge verification suite
├── test_pipeline.py       # End-to-end integration and security test suite
├── neon_kernel.c          # Stage 1 128-bit ARM NEON SIMD C-kernel (homoglyphs, entropy, UTF-8 Devanagari)
├── neon_loader.py         # Cross-platform ctypes FFI bridge binding neon_kernel.so / .dll
├── detector.py            # Stage 1 calibrated ensemble (C-SIMD + character n-gram TF-IDF + entropy)
├── executor_runner.c      # Stage 2 Native INT4 quantized co-processor binary & schema guard
├── llm_engine.py          # Stage 2 gated reasoning engine + prompt-injection sanitizer + 1930 JSON schema
├── bharat_soc_app.c       # Standalone native C CLI application wrapper (Deliverable #2 executable)
├── bharat_soc_run.sh      # Bash execution script for automated daemon/runner startup on ARM64/Termux
├── daemon_mock.py         # Simulated background SMS listener daemon for testing alerts
├── listener_daemon.py     # Real-time background SMS interception and threat-dispatch daemon
├── benchmark.py           # 100-vector hardware latency (P50/P90/P99) & tracemalloc memory profiler
├── fuzzer.py              # 26-vector multi-lingual adversarial red-team fuzzer (Marathi/Hindi/Cyrillic)
├── dataset_eval.json      # 100-sample balanced evaluation corpus (50 Malicious, 50 Benign)
├── benchmark_report.json  # Exported empirical latency and memory metrics artifact
├── fuzz_report.json       # Automated fuzzer confusion matrix telemetry artifact
├── train_detector.py      # Offline training script for Stage 1 threat classification models
├── train_full_dataset.py  # Full training corpus compilation script
├── export_params.py       # Model parameter extraction and export utility
├── sms_classifier.joblib  # Serialized machine learning weights for classification ensemble
└── model_params.json      # Exported structural parameters for offline edge parsing
```

---

## License & Ethics

Distributed under the **MIT License**. See `LICENSE` for more information. 

**Privacy Commitment:** Bharat AI-SOC operates 100% locally on-device. No SMS content, telemetry, or forensic metadata is ever transmitted to cloud servers, fully preserving user data sovereignty.

## Author

* **Mahek Shah** — *First-Year B.Tech Electronics & Telecommunication (ENTC) Student* — [GitHub Profile](https://github.com/mahekshah2008)