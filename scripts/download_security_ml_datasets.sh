#!/bin/bash
# ════════════════════════════════════════════════════════════
# Download Specialized Security ML Datasets
#  1. PyCode_Vul (Python Code Vulnerabilities - 17.8K functions)
#  2. XSS-dataset (Large scale XSS payloads & features - 138K records)
# ════════════════════════════════════════════════════════════

set -e
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIR="$BASE_DIR/data"
mkdir -p "$DATA_DIR"

echo "=========================================="
echo " Downloading Specialized Security ML Datasets"
echo "=========================================="

# 1. PyCode_Vul (GitHub)
echo "[1/2] Cloning PyCode_Vul repository..."
if [ ! -d "$DATA_DIR/PyCode_Vul" ]; then
  git clone --depth 1 https://github.com/TasminKarim-19/PyCode_Vul.git "$DATA_DIR/PyCode_Vul"
  echo "  ✅ PyCode_Vul downloaded!"
else
  echo "  ✅ PyCode_Vul already present!"
fi

# 2. XSS-dataset (GitHub)
echo "[2/2] Cloning XSS-dataset repository..."
if [ ! -d "$DATA_DIR/XSS-dataset" ]; then
  git clone --depth 1 https://github.com/fawaz2015/XSS-dataset.git "$DATA_DIR/XSS-dataset"
  echo "  ✅ XSS-dataset downloaded!"
else
  echo "  ✅ XSS-dataset already present!"
fi

echo "=========================================="
echo "  ✅ All Security Datasets Downloaded!"
echo "=========================================="
