#!/system/bin/sh
# Native Arm64 execution runner for Bharat AI-SoC SMS Threat Detector

BASE_DIR="/data/local/tmp/llama_model"
cd "$BASE_DIR" || exit 1

INPUT_SMS="$1"

if [ -z "$INPUT_SMS" ]; then
  echo "Usage: ./bharat_soc_run.sh \"<SMS_BODY>\""
  exit 1
fi

python3 app.py "$INPUT_SMS"