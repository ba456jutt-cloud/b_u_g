"""
Multi-Tool ML Scan Engine — Synthetic Dataset Generator (20,000 rows per tool)
================================================================================
Generates 20,000 training records for EVERY security tool ML model:
 1. Firewall & Port Scan (Nmap / Masscan / Rustscan) - 20,000 rows
 2. WAF & Tech Predictor (Wafw00f / WhatWeb / Headers) - 20,000 rows
 3. Web Fuzzing Optimizer (Gobuster / FFUF / Feroxbuster) - 20,000 rows
 4. Nuclei Tag Predictor (Nuclei Template Tags & CVEs) - 20,000 rows
 5. SQLmap Tamper & Risk Scorer (SQLmap Tamper Scripts & Risks) - 20,000 rows
 6. Service Classifier (Banners & Protocols) - 20,000 rows
 7. Vulnerability Scorer (EPSS & CVE Ratings) - 20,000 rows

Total Synthetic Records Generated: 140,000 rows
"""
import os
import json
import random
import numpy as np
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

np.random.seed(42)
random.seed(42)

ROW_COUNT = 20000

# ── 1. Firewall & Port Scan (Nmap / Masscan / Rustscan) ─────────────
FIREWALL_TYPES = ["none", "iptables", "pf_bsd", "cisco_acl", "cloudflare", "aws_waf", "ids_ips"]
FLAGS = ["connect_scan", "stealth_syn", "null_scan", "fin_scan", "xmas_scan", "ack_scan", "fragment", "dns_source_port", "http_source_port", "https_source_port", "slow_scan", "decoy_scan", "combo_advanced"]

def gen_firewall_data(n=ROW_COUNT):
    records = []
    for _ in range(n):
        fw_type = random.choice(FIREWALL_TYPES)
        fw_present = 0 if fw_type == "none" else 1
        filtered_ratio = random.uniform(0.5, 0.95) if fw_present else random.uniform(0.0, 0.1)
        rtt_ms = round(random.uniform(5, 500), 2)
        ttl = random.choice([64, 128, 255]) - random.randint(1, 15)
        
        # Best flag heuristic
        if fw_type == "iptables": flag = random.choice(["null_scan", "fin_scan", "xmas_scan"])
        elif fw_type == "cisco_acl": flag = random.choice(["dns_source_port", "http_source_port"])
        elif fw_type == "cloudflare": flag = random.choice(["dns_source_port", "stealth_syn", "fragment"])
        elif fw_type == "aws_waf": flag = random.choice(["fragment", "slow_scan", "decoy_scan"])
        else: flag = "connect_scan"

        records.append({
            "port": random.choice([21, 22, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 5432, 6379, 8080, 8443, 27017]),
            "port_state": "filtered" if fw_present and random.random() < filtered_ratio else ("open" if random.random() > 0.1 else "closed"),
            "protocol": "tcp",
            "rtt_ms": rtt_ms,
            "ttl": ttl,
            "os_fingerprint": random.choice(["Linux 4.x/5.x", "Windows 10", "Cisco IOS", "Unknown"]),
            "banner_text": random.choice(["Apache/2.4.41", "OpenSSH_8.2p1", "ProFTPD 1.3.5", "MariaDB 10.6", "nginx/1.18.0", ""]),
            "icmp_blocked": 1 if fw_present and random.random() < 0.7 else 0,
            "rst_received": 1 if not fw_present and random.random() < 0.2 else 0,
            "filtered_port_count": int(filtered_ratio * 100),
            "open_port_count": random.randint(1, 10),
            "total_ports_scanned": 100,
            "firewall_present": fw_present,
            "firewall_type": fw_type,
            "best_bypass_flag": flag,
        })
    return pd.DataFrame(records)


# ── 2. WAF & Web Tech Predictor (Wafw00f / WhatWeb) ─────────────────
WAF_TYPES = ["None", "Cloudflare", "ModSecurity", "Imperva", "Sucuri", "AWS_WAF", "F5_BIG_IP"]
WEB_FRAMEWORKS = ["WordPress", "Laravel", "Django", "Node.js", "Spring_Boot", "ASP.NET", "Express", "React", "Vue", "Unknown"]

SERVER_HEADERS = {
    "Cloudflare": ["cloudflare", "cloudflare-nginx"],
    "ModSecurity": ["Apache/2.4.41 (Ubuntu)", "nginx/1.18.0"],
    "Imperva": ["Incapsula"],
    "Sucuri": ["Sucuri/Cloudproxy"],
    "AWS_WAF": ["AWS", "AmazonS3", "CloudFront"],
    "F5_BIG_IP": ["BIG-IP", "BigIP"],
    "None": ["Apache/2.4.41", "nginx/1.18.0", "LiteSpeed", "Microsoft-IIS/10.0"]
}

def gen_waf_data(n=ROW_COUNT):
    records = []
    for _ in range(n):
        waf = random.choice(WAF_TYPES)
        fw = random.choice(WEB_FRAMEWORKS)
        server = random.choice(SERVER_HEADERS[waf])
        has_cookie = 1 if waf != "None" or random.random() < 0.3 else 0
        status_code = 403 if waf != "None" and random.random() < 0.4 else random.choice([200, 301, 302, 404, 500])

        records.append({
            "server_header": server,
            "status_code": status_code,
            "has_waf_cookie": has_cookie,
            "content_length": random.randint(100, 50000),
            "waf_detected": waf,
            "predicted_framework": fw
        })
    return pd.DataFrame(records)


# ── 3. Web Fuzzing Optimizer (Gobuster / FFUF / Feroxbuster) ────────
def gen_web_fuzz_data(n=ROW_COUNT):
    records = []
    for _ in range(n):
        fw = random.choice(WEB_FRAMEWORKS)
        waf = random.choice(WAF_TYPES)

        if waf in ["Cloudflare", "Imperva", "AWS_WAF"]:
            tool = "ffuf"
            threads = random.randint(5, 15)
            delay_ms = random.randint(200, 1000)
        else:
            tool = random.choice(["gobuster", "feroxbuster"])
            threads = random.randint(20, 50)
            delay_ms = 0

        if fw == "WordPress":
            wordlist = "cms-wordpress.txt"
            ext = ".php"
        elif fw in ["Laravel", "Django", "Node.js"]:
            wordlist = "api-endpoints.txt"
            ext = ".json"
        else:
            wordlist = random.choice(["common.txt", "directory-list-2.3-medium.txt"])
            ext = random.choice([".php", ".html", ".bak,.old,.swp", "none"])

        records.append({
            "framework": fw,
            "waf_type": waf,
            "recommended_tool": tool,
            "recommended_wordlist": wordlist,
            "recommended_extensions": ext,
            "recommended_threads": threads,
            "recommended_delay_ms": delay_ms
        })
    return pd.DataFrame(records)


# ── 4. Nuclei Template Tag Selector ─────────────────────────────────
def gen_nuclei_tag_data(n=ROW_COUNT):
    records = []
    for _ in range(n):
        port = random.choice([21, 22, 80, 443, 3306, 5432, 6379, 8080, 27017])
        service = "http" if port in [80, 443, 8080] else ("ftp" if port == 21 else ("ssh" if port == 22 else "db"))
        fw = random.choice(WEB_FRAMEWORKS)

        if service == "http":
            if fw == "WordPress": tags = "wordpress,plugin"
            elif random.random() < 0.4: tags = "cve,rce"
            else: tags = "panel,misconfig"
        elif service == "db": tags = "cve,sqli"
        elif service in ["ftp", "ssh"]: tags = "network,default-login"
        else: tags = "tech,fingerprint"

        records.append({
            "port": port,
            "service": service,
            "framework": fw,
            "recommended_nuclei_tags": tags
        })
    return pd.DataFrame(records)


# ── 5. SQLmap Tamper & Risk Scorer ──────────────────────────────────
def gen_sqlmap_data(n=ROW_COUNT):
    records = []
    for _ in range(n):
        db_type = random.choice(["MySQL", "PostgreSQL", "MSSQL", "Oracle", "SQLite"])
        waf = random.choice(WAF_TYPES)

        if waf == "Cloudflare": tamper, risk, level = "space2comment", 3, 5
        elif waf == "ModSecurity": tamper, risk, level = "charencode", 2, 3
        elif waf != "None": tamper, risk, level = random.choice(["between", "randomcase", "space2plus"]), 2, 3
        else: tamper, risk, level = "none", 1, 1

        records.append({
            "db_type": db_type,
            "waf_type": waf,
            "recommended_tamper": tamper,
            "recommended_risk": risk,
            "recommended_level": level
        })
    return pd.DataFrame(records)


# ── 6. Service Classifier Data ──────────────────────────────────────
def gen_service_data(n=ROW_COUNT):
    records = []
    TOP_SERVICES = ["http", "ssh", "ftp", "smtp", "dns", "pop3", "imap", "https", "smb", "rdp", "mysql", "postgresql", "redis", "mongodb"]
    BANNERS = {
        "http": ["Apache/2.4.41", "nginx/1.18.0", "LiteSpeed httpd", "Microsoft-IIS/10.0"],
        "ssh": ["OpenSSH_8.2p1", "OpenSSH_7.4p1", "Dropbear SSH"],
        "ftp": ["ProFTPD 1.3.5", "vsftpd 3.0.3", "Pure-FTPd"],
        "mysql": ["MariaDB 10.6", "MySQL 8.0.28", "MySQL 5.7.38"],
        "redis": ["Redis server v=7.0.4", "+OK"],
        "mongodb": ["MongoDB 6.0", "ismaster"]
    }
    for _ in range(n):
        svc = random.choice(TOP_SERVICES)
        banners = BANNERS.get(svc, [f"{svc} service ready"])
        banner = random.choice(banners)
        port = 80 if svc in ["http", "https"] else (21 if svc == "ftp" else (22 if svc == "ssh" else 3306))
        records.append({
            "port": port,
            "protocol": "tcp",
            "banner_text": banner,
            "service_label": svc
        })
    return pd.DataFrame(records)


# ── 7. Vulnerability Scorer Data ────────────────────────────────────
def gen_vuln_score_data(n=ROW_COUNT):
    records = []
    SERVICES = ["ProFTPD", "vsftpd", "OpenSSH", "Apache", "nginx", "LiteSpeed", "MariaDB", "MySQL", "PostgreSQL", "Redis", "MongoDB", "SMB", "RDP"]
    for _ in range(n):
        svc = random.choice(SERVICES)
        port = 21 if "ftp" in svc.lower() else (22 if "ssh" in svc.lower() else (80 if svc in ["Apache", "nginx", "LiteSpeed"] else 3306))
        banner = f"{svc} version {random.randint(1,9)}.{random.randint(0,9)}"
        score = float(np.clip(np.random.normal(6.5 if svc in ["ProFTPD", "SMB", "RDP"] else 4.5, 1.5), 0.0, 10.0))
        records.append({
            "port": port,
            "service_name": svc,
            "banner_text": banner,
            "os_fingerprint": random.choice(["Linux", "Windows", "Unix"]),
            "vuln_score": round(score, 2)
        })
    return pd.DataFrame(records)


def main():
    print("=" * 65)
    print("  MULTI-TOOL SYNTHETIC DATASET GENERATOR (20,000 rows per tool)")
    print("=" * 65)

    # 1. Firewall & Port scan
    df_fw = gen_firewall_data(ROW_COUNT)
    df_fw.to_csv(os.path.join(DATA_DIR, "synthetic_firewall_scans.csv"), index=False)
    print(f"  ✅ [1/7] Firewall & Port Scan: {len(df_fw):,} rows")

    # 2. WAF & Tech
    df_waf = gen_waf_data(ROW_COUNT)
    df_waf.to_csv(os.path.join(DATA_DIR, "synthetic_waf_tech.csv"), index=False)
    print(f"  ✅ [2/7] WAF & Tech Stack: {len(df_waf):,} rows")

    # 3. Web Fuzzing
    df_fuzz = gen_web_fuzz_data(ROW_COUNT)
    df_fuzz.to_csv(os.path.join(DATA_DIR, "synthetic_web_fuzz.csv"), index=False)
    print(f"  ✅ [3/7] Web Directory Fuzzing: {len(df_fuzz):,} rows")

    # 4. Nuclei Tags
    df_nuclei = gen_nuclei_tag_data(ROW_COUNT)
    df_nuclei.to_csv(os.path.join(DATA_DIR, "synthetic_nuclei_tags.csv"), index=False)
    print(f"  ✅ [4/7] Nuclei Tag Selector: {len(df_nuclei):,} rows")

    # 5. SQLmap Tamper
    df_sql = gen_sqlmap_data(ROW_COUNT)
    df_sql.to_csv(os.path.join(DATA_DIR, "synthetic_sqlmap.csv"), index=False)
    print(f"  ✅ [5/7] SQLmap Tamper & Risk: {len(df_sql):,} rows")

    # 6. Service Data
    df_svc = gen_service_data(ROW_COUNT)
    df_svc.to_csv(os.path.join(DATA_DIR, "synthetic_service_data.csv"), index=False)
    print(f"  ✅ [6/7] Service Classifier: {len(df_svc):,} rows")

    # 7. Vuln Scores
    df_vuln = gen_vuln_score_data(ROW_COUNT)
    df_vuln.to_csv(os.path.join(DATA_DIR, "synthetic_vuln_scores.csv"), index=False)
    print(f"  ✅ [7/7] Vulnerability Scorer: {len(df_vuln):,} rows")

    print("\n" + "=" * 65)
    print(f"  🎉 TOTAL SYNTHETIC RECORDS GENERATED: {ROW_COUNT * 7:,} ROWS across 7 security tools!")
    print("=" * 65)

if __name__ == "__main__":
    main()
