#!/bin/bash
# Bug Bounty Copilot Tool Dependency Installer

echo "[+] Updating Python security packages in virtual environment..."
cd /home/ahmad/Documents/Agent
source venv/bin/activate
pip install arjun sublist3r assetfinder dirsearch requests beautifulsoup4 urllib3 pyopenssl

echo "[+] Installing Go security tools into ~/go/bin..."
export PATH=$PATH:~/go/bin
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/hahwul/dalfox/v2@latest

echo "[+] Updating Nuclei vulnerability templates..."
nuclei -update-templates || true

echo "[+] Tool installation script completed successfully!"
