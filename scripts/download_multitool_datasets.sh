#!/bin/bash
# ════════════════════════════════════════════════════════════
# Multi-Tool Security Datasets Downloader
# Downloads real-world datasets from GitHub for:
#   - Nuclei Templates (4,000+ templates with tags & CVEs)
#   - SQLmap Tamper Scripts & Payload lists
#   - SecLists (Fuzzing & Directory discovery statistics)
#   - PayloadsAllTheThings (XSS, SQLi, SSTI, RCE patterns)
# ════════════════════════════════════════════════════════════

set -e
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIR="$BASE_DIR/data"
mkdir -p "$DATA_DIR"

echo "=========================================="
echo " Downloading Multi-Tool Security Datasets"
echo "=========================================="

# 1. Nuclei Templates (Real vulnerability scanner patterns)
echo "[1/4] Cloning Nuclei Templates Repository..."
if [ ! -d "$DATA_DIR/nuclei-templates" ]; then
  git clone --depth 1 --quiet https://github.com/projectdiscovery/nuclei-templates.git "$DATA_DIR/nuclei-templates"
  echo "  ✅ Nuclei Templates cloned!"
else
  echo "  ✅ Nuclei Templates already present!"
fi

# 2. PayloadsAllTheThings (Exploit & vulnerability patterns)
echo "[2/4] Cloning PayloadsAllTheThings..."
if [ ! -d "$DATA_DIR/payloads" ]; then
  git clone --depth 1 --quiet https://github.com/swisskyrepo/PayloadsAllTheThings.git "$DATA_DIR/payloads"
  echo "  ✅ PayloadsAllTheThings cloned!"
else
  echo "  ✅ PayloadsAllTheThings already present!"
fi

# 3. SecLists (Top Fuzzing & Discovery Wordlists statistics)
echo "[3/4] Cloning SecLists Fuzzing Statistics..."
if [ ! -d "$DATA_DIR/seclists" ]; then
  git clone --depth 1 --quiet https://github.com/danielmiessler/SecLists.git "$DATA_DIR/seclists"
  echo "  ✅ SecLists cloned!"
else
  echo "  ✅ SecLists already present!"
fi

# 4. SQLmap Tamper Scripts Repository
echo "[4/4] Cloning SQLmap Tamper Database..."
if [ ! -d "$DATA_DIR/sqlmap_db" ]; then
  git clone --depth 1 --quiet https://github.com/sqlmapproject/sqlmap.git "$DATA_DIR/sqlmap_db"
  echo "  ✅ SQLmap Database cloned!"
else
  echo "  ✅ SQLmap Database already present!"
fi

echo "=========================================="
echo "  ✅ All Multi-Tool Datasets Downloaded!"
echo "=========================================="
