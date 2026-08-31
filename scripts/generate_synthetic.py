"""
ML Scan Engine — Synthetic Firewall Evasion Data Generator
============================================================
Generates 60,000 synthetic nmap scan scenarios for training
the FirewallDetector and FlagOptimizer models.

Scenarios cover:
 - All firewall types (none, iptables, cisco, cloudflare, aws_waf, ids_ips)
 - All bypass flag strategies
 - Realistic TTL values, RTT distributions, port state patterns
 - Known-good flag→firewall_type mappings from OSCP/pentest knowledge

Run: python scripts/generate_synthetic.py
"""
import numpy as np
import pandas as pd
import random
import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

# ── Seed for reproducibility ─────────────────────────────────
np.random.seed(42)
random.seed(42)

# ── Ground truth: which flags work against which firewall ────
FIREWALL_FLAG_MATRIX = {
    "none": {
        "bypass_flags": ["connect_scan"],
        "detection_confidence": 0.95,
        "ttl_range": (60, 70),
        "rtt_range": (1, 80),
        "filtered_ratio": 0.0,
        "icmp_blocked": 0.0,
        "rst_probability": 0.1,
    },
    "iptables": {
        "bypass_flags": ["null_scan", "fin_scan", "xmas_scan"],
        "detection_confidence": 0.88,
        "ttl_range": (55, 64),
        "rtt_range": (5, 150),
        "filtered_ratio": 0.6,
        "icmp_blocked": 0.4,
        "rst_probability": 0.05,
    },
    "pf_bsd": {
        "bypass_flags": ["ack_scan", "null_scan"],
        "detection_confidence": 0.82,
        "ttl_range": (55, 64),
        "rtt_range": (10, 200),
        "filtered_ratio": 0.7,
        "icmp_blocked": 0.6,
        "rst_probability": 0.02,
    },
    "cisco_acl": {
        "bypass_flags": ["dns_source_port", "http_source_port", "https_source_port"],
        "detection_confidence": 0.85,
        "ttl_range": (250, 255),
        "rtt_range": (20, 300),
        "filtered_ratio": 0.75,
        "icmp_blocked": 0.8,
        "rst_probability": 0.01,
    },
    "cloudflare": {
        "bypass_flags": ["stealth_syn", "dns_source_port", "fragment"],
        "detection_confidence": 0.78,
        "ttl_range": (50, 64),
        "rtt_range": (15, 120),
        "filtered_ratio": 0.85,
        "icmp_blocked": 0.9,
        "rst_probability": 0.03,
    },
    "aws_waf": {
        "bypass_flags": ["fragment", "slow_scan", "decoy_scan"],
        "detection_confidence": 0.75,
        "ttl_range": (45, 64),
        "rtt_range": (10, 100),
        "filtered_ratio": 0.80,
        "icmp_blocked": 0.85,
        "rst_probability": 0.03,
    },
    "ids_ips": {
        "bypass_flags": ["slow_scan", "decoy_scan", "combo_advanced"],
        "detection_confidence": 0.70,
        "ttl_range": (55, 64),
        "rtt_range": (5, 50),
        "filtered_ratio": 0.90,
        "icmp_blocked": 0.7,
        "rst_probability": 0.08,
    },
}

# Service banners (port → typical banner)
SERVICE_BANNERS = {
    21:   ["ProFTPD 1.3.5", "vsftpd 3.0.3", "Pure-FTPd", "FileZilla FTP"],
    22:   ["OpenSSH_8.2p1", "OpenSSH_7.4p1", "SSH-2.0-OpenSSH_9.0", "Dropbear SSH"],
    25:   ["Postfix ESMTP", "Exim 4.95", "Sendmail 8.15", "Microsoft ESMTP"],
    53:   ["", "", "", ""],  # DNS usually no banner
    80:   ["Apache/2.4.41", "nginx/1.18.0", "LiteSpeed", "Microsoft-IIS/10.0", ""],
    110:  ["Dovecot ready", "+OK Dovecot", "+OK POP3 ready"],
    139:  ["", "Samba"],
    143:  ["Dovecot IMAP", "* OK [CAPABILITY IMAP4rev1]"],
    443:  ["Apache/2.4.41", "nginx/1.18.0", "LiteSpeed", ""],
    445:  ["", "Samba", "Windows SMB"],
    1433: ["Microsoft SQL Server 2019", ""],
    1521: ["Oracle TNS Listener"],
    3306: ["MariaDB 10.6", "MySQL 8.0.28", "MySQL 5.7.38"],
    3389: ["", "Microsoft Terminal Services"],
    5432: ["PostgreSQL 14.2"],
    5900: ["RFB 003.008", "RealVNC"],
    6379: ["Redis server v=7.0.4", "+OK"],
    8080: ["Apache/2.4.41", "nginx/1.18.0", "Tomcat/9.0", "Jetty"],
    8443: ["Apache/2.4.41", "nginx/1.18.0", ""],
    27017:["MongoDB 6.0", "ismaster"],
}

# Common ports to simulate
COMMON_PORTS = list(SERVICE_BANNERS.keys())
EXTRA_PORTS = [23, 69, 111, 512, 513, 514, 873, 2049, 4444, 8888]
ALL_PORTS = COMMON_PORTS + EXTRA_PORTS

# OS fingerprints → TTL mapping
OS_SIGNATURES = {
    "Linux 4.x/5.x": {"ttl": 64, "window": 29200},
    "Linux 3.x": {"ttl": 64, "window": 65535},
    "Windows 10": {"ttl": 128, "window": 65535},
    "Windows Server 2019": {"ttl": 128, "window": 65535},
    "macOS 12": {"ttl": 64, "window": 65535},
    "FreeBSD 13": {"ttl": 64, "window": 65535},
    "Cisco IOS": {"ttl": 255, "window": 4128},
    "Unknown": {"ttl": 64, "window": 8192},
}

FLAG_CLASSES = [
    "connect_scan",      # -sT (no root, universal)
    "stealth_syn",       # -sS (root, stealth)
    "null_scan",         # -sN
    "fin_scan",          # -sF
    "xmas_scan",         # -sX
    "ack_scan",          # -sA
    "fragment",          # -f --mtu 8
    "dns_source_port",   # -g 53
    "http_source_port",  # --source-port 80
    "https_source_port", # --source-port 443
    "slow_scan",         # -T1
    "decoy_scan",        # -D RND:10
    "combo_advanced",    # -f -D RND:5 --source-port 53 -T2
]

FIREWALL_TYPES = list(FIREWALL_FLAG_MATRIX.keys())


def gen_banner(port: int, state: str) -> str:
    if state != "open":
        return ""
    if port in SERVICE_BANNERS:
        banners = SERVICE_BANNERS[port]
        return random.choice(banners) if banners else ""
    return ""


def gen_os_fingerprint(fw_type: str) -> str:
    if fw_type == "cisco_acl":
        return random.choice(["Cisco IOS", "Unknown"])
    if fw_type in ("cloudflare", "aws_waf"):
        return random.choice(["Linux 4.x/5.x", "Linux 5.x", "Unknown"])
    return random.choice(list(OS_SIGNATURES.keys()))


def gen_scan_record(fw_type: str) -> dict:
    """Generate one synthetic scan record for a single port."""
    fw = FIREWALL_FLAG_MATRIX[fw_type]

    # TTL with realistic noise
    ttl_base = random.randint(*fw["ttl_range"])
    # Add hop count noise (each router decrements by 1)
    hops = random.randint(1, 15)
    ttl = max(1, ttl_base - hops)

    # RTT with lognormal distribution (realistic network latency)
    rtt_base = random.uniform(*fw["rtt_range"])
    rtt_ms = round(abs(np.random.lognormal(np.log(rtt_base + 1), 0.5)), 2)

    # Port state
    if random.random() < fw["filtered_ratio"]:
        state = "filtered"
    elif random.random() < 0.1:
        state = "closed"
    else:
        state = "open"

    # Port selection (bias toward common ports)
    port = random.choice(COMMON_PORTS if random.random() < 0.8 else ALL_PORTS)

    # OS fingerprint
    os_fp = gen_os_fingerprint(fw_type)

    # Banner
    banner = gen_banner(port, state)

    # ICMP blocked
    icmp_blocked = 1 if random.random() < fw["icmp_blocked"] else 0

    # RST received
    rst_received = 1 if state == "closed" and random.random() < fw["rst_probability"] else 0

    # Best bypass flag for this firewall (label for FlagOptimizer)
    best_flag = random.choice(fw["bypass_flags"])

    # Firewall present (label for FirewallDetector)
    fw_present = 0 if fw_type == "none" else 1

    # Filtered port count (simulated from same-host scan of 100 ports)
    total_ports_scanned = random.randint(50, 1000)
    filtered_count = int(total_ports_scanned * fw["filtered_ratio"] * random.uniform(0.8, 1.1))
    open_count = int((1 - fw["filtered_ratio"]) * total_ports_scanned * 0.05)

    return {
        # Input features
        "port": port,
        "port_state": state,
        "protocol": "tcp",
        "rtt_ms": min(rtt_ms, 5000),
        "ttl": ttl,
        "os_fingerprint": os_fp,
        "banner_text": banner,
        "icmp_blocked": icmp_blocked,
        "rst_received": rst_received,
        "filtered_port_count": min(filtered_count, total_ports_scanned),
        "open_port_count": max(0, open_count),
        "total_ports_scanned": total_ports_scanned,
        # Labels
        "firewall_present": fw_present,
        "firewall_type": fw_type,
        "best_bypass_flag": best_flag,
    }


def generate_service_training_data(n: int = 10000) -> pd.DataFrame:
    """Generate port+banner → service classification training data from nmap-services."""
    nmap_services_path = os.path.join(DATA_DIR, "nmap-services.txt")
    records = []

    # Use nmap-services as ground truth
    service_map = {}
    if os.path.exists(nmap_services_path):
        with open(nmap_services_path, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                parts = line.split("\t")
                if len(parts) >= 2:
                    svc_name = parts[0]
                    port_proto = parts[1]  # e.g. "80/tcp"
                    if "/" in port_proto:
                        port_str, proto = port_proto.split("/")
                        if port_str.isdigit():
                            service_map[int(port_str)] = svc_name

    # Service label set (top 50 most common)
    TOP_SERVICES = [
        "http", "ssh", "ftp", "smtp", "dns", "pop3", "imap", "https",
        "smb", "rdp", "mysql", "mssql", "postgresql", "oracle", "redis",
        "mongodb", "vnc", "telnet", "snmp", "ldap", "nfs", "tftp",
        "http-proxy", "unknown"
    ]

    for _ in range(n):
        port = random.choice(ALL_PORTS)
        svc = service_map.get(port, "unknown")
        # Normalize to top services
        svc_clean = svc.split("-")[0].lower() if svc else "unknown"
        if svc_clean not in TOP_SERVICES:
            svc_clean = "unknown"
        banner = gen_banner(port, "open")
        records.append({
            "port": port,
            "protocol": "tcp",
            "banner_text": banner,
            "service_label": svc_clean,
        })

    return pd.DataFrame(records)


def generate_vuln_score_data(n: int = 10000) -> pd.DataFrame:
    """
    Generate service → vulnerability score training data.
    Uses known CVE counts and CVSS distributions from EPSS research.
    """
    # Service → avg vuln score (based on real CVE frequency data)
    SERVICE_VULN_SCORES = {
        "ProFTPD": (8.5, 1.2),      # many critical CVEs
        "vsftpd": (5.0, 1.5),
        "OpenSSH": (5.0, 2.0),       # occasional highs
        "Dropbear": (4.0, 1.5),
        "Apache": (6.5, 2.0),        # frequent medium-high
        "nginx": (5.5, 1.8),
        "LiteSpeed": (4.5, 1.5),
        "IIS": (6.0, 2.0),
        "Tomcat": (7.0, 2.0),
        "MariaDB": (6.0, 1.5),
        "MySQL": (5.5, 1.8),
        "PostgreSQL": (4.0, 1.2),
        "Redis": (8.0, 1.5),         # often unauthenticated exposure
        "MongoDB": (7.5, 1.8),       # often unauthenticated
        "SMB": (9.0, 1.0),           # EternalBlue etc.
        "RDP": (8.5, 1.5),           # BlueKeep etc.
        "Telnet": (9.5, 0.5),        # cleartext always critical
        "VNC": (7.5, 1.5),
        "SNMP": (7.0, 1.5),
        "Postfix": (4.5, 1.2),
        "Exim": (8.0, 1.5),          # many critical CVEs
        "Unknown": (3.0, 2.0),
    }

    records = []
    for _ in range(n):
        port = random.choice(ALL_PORTS)
        banner = gen_banner(port, "open")

        # Map port to service name for scoring
        port_to_service = {
            21: random.choice(["ProFTPD", "vsftpd"]),
            22: random.choice(["OpenSSH", "Dropbear"]),
            25: random.choice(["Postfix", "Exim"]),
            80: random.choice(["Apache", "nginx", "LiteSpeed", "IIS"]),
            443: random.choice(["Apache", "nginx", "LiteSpeed"]),
            139: "SMB", 445: "SMB",
            3306: random.choice(["MySQL", "MariaDB"]),
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
            3389: "RDP",
            5900: "VNC",
            161: "SNMP",
            23: "Telnet",
            8080: random.choice(["Apache", "Tomcat", "nginx"]),
        }
        service = port_to_service.get(port, "Unknown")
        mean_score, std_score = SERVICE_VULN_SCORES.get(service, (3.0, 2.0))
        vuln_score = float(np.clip(np.random.normal(mean_score, std_score), 0.0, 10.0))

        records.append({
            "port": port,
            "service_name": service,
            "banner_text": banner,
            "os_fingerprint": random.choice(list(OS_SIGNATURES.keys())),
            "vuln_score": round(vuln_score, 2),
        })

    return pd.DataFrame(records)


def main():
    print("=" * 56)
    print("  Synthetic Data Generator for ML Scan Engine")
    print("=" * 56)

    # ── 1. Firewall + FlagOptimizer data ──────────────────
    print("\n[1/3] Generating firewall detection + flag data (60,000 records)...")
    records = []
    per_class = 60000 // len(FIREWALL_TYPES)
    for fw_type in FIREWALL_TYPES:
        for _ in range(per_class):
            records.append(gen_scan_record(fw_type))
    df_fw = pd.DataFrame(records)
    df_fw = df_fw.sample(frac=1, random_state=42).reset_index(drop=True)

    out_path = os.path.join(DATA_DIR, "synthetic_firewall_scans.csv")
    df_fw.to_csv(out_path, index=False)
    print(f"  ✅ Saved: {out_path} ({len(df_fw):,} rows, {os.path.getsize(out_path)//1024}KB)")
    print(f"  Class distribution:\n{df_fw['firewall_type'].value_counts().to_string()}")

    # ── 2. Service classifier data ────────────────────────
    print("\n[2/3] Generating service classification data (10,000 records)...")
    df_svc = generate_service_training_data(10000)
    svc_path = os.path.join(DATA_DIR, "synthetic_service_data.csv")
    df_svc.to_csv(svc_path, index=False)
    print(f"  ✅ Saved: {svc_path} ({len(df_svc):,} rows)")
    print(f"  Top services:\n{df_svc['service_label'].value_counts().head(10).to_string()}")

    # ── 3. Vulnerability scorer data ─────────────────────
    print("\n[3/3] Generating vulnerability score data (10,000 records)...")
    df_vuln = generate_vuln_score_data(10000)
    vuln_path = os.path.join(DATA_DIR, "synthetic_vuln_scores.csv")
    df_vuln.to_csv(vuln_path, index=False)
    print(f"  ✅ Saved: {vuln_path} ({len(df_vuln):,} rows)")

    print("\n" + "=" * 56)
    print("  ✅ All synthetic datasets generated!")
    print("  Next: python scripts/train_all_models.py")
    print("=" * 56)


if __name__ == "__main__":
    main()
