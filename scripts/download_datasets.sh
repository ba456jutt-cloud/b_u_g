#!/bin/bash
# ════════════════════════════════════════════════════════════
# ML Scan Engine — Dataset Download Script
# Run: bash scripts/download_datasets.sh
# ════════════════════════════════════════════════════════════

set -e
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIR="$BASE_DIR/data"
mkdir -p "$DATA_DIR" "$DATA_DIR/nvd"

echo "════════════════════════════════════════════"
echo "  ML Scan Engine Dataset Downloader"
echo "  Target: $DATA_DIR"
echo "════════════════════════════════════════════"
echo ""

# ── 1. Nmap Official Databases (already local) ─────────────
echo "[1/7] Copying Nmap databases from /usr/share/nmap/ ..."
cp -f /usr/share/nmap/nmap-service-probes "$DATA_DIR/nmap-service-probes.txt" 2>/dev/null && echo "  ✅ nmap-service-probes (2.5MB)" || echo "  ⚠️  Not found, skip"
cp -f /usr/share/nmap/nmap-services "$DATA_DIR/nmap-services.txt" 2>/dev/null && echo "  ✅ nmap-services (975KB)" || echo "  ⚠️  Not found, skip"
cp -f /usr/share/nmap/nmap-os-db "$DATA_DIR/nmap-os-db.txt" 2>/dev/null && echo "  ✅ nmap-os-db (5.2MB)" || echo "  ⚠️  Not found, skip"
echo ""

# ── 2. NSL-KDD (Probe/Scan traffic detection) ─────────────
echo "[2/7] Downloading NSL-KDD (~20MB) ..."
if [ ! -f "$DATA_DIR/nsl_kdd_train.csv" ]; then
  wget -q --show-progress \
    "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt" \
    -O "$DATA_DIR/nsl_kdd_train.csv" && echo "  ✅ KDDTrain+ downloaded" || echo "  ❌ Failed"
  wget -q --show-progress \
    "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt" \
    -O "$DATA_DIR/nsl_kdd_test.csv" && echo "  ✅ KDDTest+ downloaded" || echo "  ❌ Failed"
else
  echo "  ✅ NSL-KDD already exists, skipping"
fi
echo ""

# ── 3. EPSS Scores (VulnScorer training labels) ────────────
echo "[3/7] Downloading EPSS scores (~12MB) ..."
if [ ! -f "$DATA_DIR/epss_scores.csv" ]; then
  wget -q --show-progress \
    "https://epss.cyentia.com/epss_scores-current.csv.gz" \
    -O "$DATA_DIR/epss_scores.csv.gz" && \
    gunzip -f "$DATA_DIR/epss_scores.csv.gz" && \
    echo "  ✅ EPSS scores downloaded and extracted" || echo "  ❌ Failed"
else
  echo "  ✅ EPSS already exists, skipping"
fi
echo ""

# ── 4. Rapid7 Recog (Banner fingerprinting signatures) ─────
echo "[4/7] Cloning Rapid7 Recog (~28MB) ..."
if [ ! -d "$DATA_DIR/recog" ]; then
  git clone --depth 1 --quiet \
    https://github.com/rapid7/recog.git \
    "$DATA_DIR/recog" && echo "  ✅ Recog cloned (28MB)" || echo "  ❌ Failed"
else
  echo "  ✅ Recog already exists, skipping"
fi
echo ""

# ── 5. nmap-harvester (Nmap XML output dataset) ────────────
echo "[5/7] Cloning nmap-harvester (~120MB) ..."
if [ ! -d "$DATA_DIR/nmap-harvester" ]; then
  git clone --depth 1 --quiet \
    https://github.com/Virgula0/nmap-harvester.git \
    "$DATA_DIR/nmap-harvester" && echo "  ✅ nmap-harvester cloned (120MB)" || echo "  ❌ Failed"
else
  echo "  ✅ nmap-harvester already exists, skipping"
fi
echo ""

# ── 6. CISA KEV (Already fetched live, but cache locally) ──
echo "[6/7] Downloading CISA KEV catalog ..."
if [ ! -f "$DATA_DIR/cisa_kev.json" ]; then
  wget -q --show-progress \
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
    -O "$DATA_DIR/cisa_kev.json" && echo "  ✅ CISA KEV downloaded (2.8MB)" || echo "  ❌ Failed (will use live API)"
else
  echo "  ✅ CISA KEV already exists, skipping"
fi
echo ""

# ── 7. NVD CVE List (2020-2024 from GitHub mirror) ─────────
echo "[7/7] Cloning NVD CVEList (2020-2024, ~600MB) ..."
if [ ! -d "$DATA_DIR/nvd/cvelistV5" ]; then
  git clone --depth 1 --filter=blob:none --sparse --quiet \
    https://github.com/CVEProject/cvelistV5.git \
    "$DATA_DIR/nvd/cvelistV5"
  cd "$DATA_DIR/nvd/cvelistV5"
  git sparse-checkout set cves/2020 cves/2021 cves/2022 cves/2023 cves/2024
  git checkout 2>/dev/null
  cd "$BASE_DIR"
  echo "  ✅ NVD CVEList (2020-2024) downloaded"
else
  echo "  ✅ NVD CVEList already exists, skipping"
fi
echo ""

echo "════════════════════════════════════════════"
echo "  ✅ All datasets ready! Now run:"
echo "  python scripts/generate_synthetic.py"
echo "  python scripts/train_all_models.py"
echo "════════════════════════════════════════════"
