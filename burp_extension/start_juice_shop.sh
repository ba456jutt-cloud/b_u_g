#!/bin/bash
# Juice Shop Startup Script
# Starts OWASP Juice Shop on port 3001

JUICE_DIR="$HOME/juice-shop"

if [ ! -d "$JUICE_DIR" ]; then
    echo "[!] Juice Shop not found at $JUICE_DIR"
    echo "    Run: git clone https://github.com/juice-shop/juice-shop.git ~/juice-shop && cd ~/juice-shop && npm install --omit=dev"
    exit 1
fi

echo "════════════════════════════════════════════"
echo "  OWASP Juice Shop — Starting on port 3001"
echo "════════════════════════════════════════════"
echo ""
echo "  URL: http://localhost:3001"
echo "  Admin: admin@juice-sh.op / admin123"
echo ""
echo "  Use Burp proxy: http://127.0.0.1:8080"
echo "  Intercept and right-click → Bug Bounty Agent"
echo ""
echo "════════════════════════════════════════════"
echo ""

cd "$JUICE_DIR"
PORT=3001 node app
