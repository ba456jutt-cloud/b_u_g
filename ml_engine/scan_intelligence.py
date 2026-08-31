"""
ML Scan Engine — Core Intelligence Module
==========================================
Main entry point for intelligent network scanning.

This module replaces the dumb Stage 1 PreReconEngine with a
machine-learning-powered scanner that:
  1. Probes target and detects firewall type (Model 1)
  2. Selects optimal nmap flags to bypass firewall (Model 2)
  3. Classifies services from banners (Model 3)
  4. Scores vulnerability likelihood per port/service (Model 4)
  5. Returns structured JSON results to MasterAgent

Usage:
    from ml_engine.scan_intelligence import MLScanEngine
    engine = MLScanEngine()
    results = engine.scan("scholarhub.online", task_id="scan-001")
"""
import os
import re
import sys
import json
import time
import socket
import logging
import subprocess
import threading
import hashlib
from typing import Optional
from datetime import datetime

import numpy as np

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "ml_engine", "models")

# ── Flag class → actual nmap command flags ───────────────────
FLAG_MAP = {
    "connect_scan":      ["-sT", "-T4"],
    "stealth_syn":       ["-sS", "-T3"],
    "null_scan":         ["-sN", "-T3"],
    "fin_scan":          ["-sF", "-T3"],
    "xmas_scan":         ["-sX", "-T3"],
    "ack_scan":          ["-sA", "-T3"],
    "fragment":          ["-sT", "-f", "--mtu", "8", "-T3"],
    "dns_source_port":   ["-sT", "-g", "53", "-T3"],
    "http_source_port":  ["-sT", "--source-port", "80", "-T3"],
    "https_source_port": ["-sT", "--source-port", "443", "-T3"],
    "slow_scan":         ["-sT", "-T1"],
    "decoy_scan":        ["-sT", "-D", "RND:5", "-T2"],
    "combo_advanced":    ["-sT", "-f", "-D", "RND:5", "--source-port", "53", "-T2"],
}

# ── Default service vulnerability scores (fallback if model unavailable) ──
KNOWN_VULN_SCORES = {
    "telnet": 9.5, "rsh": 9.5, "rlogin": 9.5,
    "smb": 9.0, "netbios": 8.8,
    "rdp": 8.5, "proftp": 8.5,
    "redis": 8.0, "exim": 8.0,
    "mongodb": 7.5, "vnc": 7.5,
    "ftp": 7.0, "tomcat": 7.0,
    "snmp": 7.0,
    "http": 6.0, "apache": 6.5, "nginx": 5.5, "iis": 6.0,
    "ssh": 5.0, "openssl": 6.0,
    "mysql": 5.5, "mariadb": 5.5, "postgresql": 4.0,
    "smtp": 4.5, "pop3": 4.0, "imap": 4.0,
    "dns": 5.0, "ldap": 6.0, "oracle": 6.0, "mssql": 6.5,
    "default": 3.5,
}

# ── Known port → service fallback ────────────────────────────
PORT_SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    69: "tftp", 80: "http", 110: "pop3", 111: "rpc", 123: "ntp",
    135: "msrpc", 137: "netbios", 139: "netbios", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    512: "rsh", 513: "rlogin", 514: "rsh",
    587: "smtp", 636: "ldaps", 873: "rsync",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 3306: "mysql", 3389: "rdp", 4444: "unknown",
    5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http-proxy", 8443: "https-proxy", 8888: "http",
    27017: "mongodb",
}


class MLScanEngine:
    """
    Intelligence network scanner powered by 4 ML models.

    Pipeline:
      Quick Probe → Firewall Detection → Flag Selection →
      Smart Scan → Service Classification → Vuln Scoring →
      Structured JSON Output

    Falls back gracefully to rule-based logic if models not yet trained.
    """

    def __init__(self):
        self._models_loaded = False
        self._fw_detector = None
        self._fw_cols = None
        self._flag_optimizer = None
        self._flag_le = None
        self._svc_classifier = None
        self._svc_tfidf = None
        self._svc_le = None
        self._vuln_regressor = None
        self._vuln_tfidf = None
        self._vuln_le = None
        self._load_models()

    def _load_models(self):
        """Load pre-trained models from disk. Silent fallback if not found."""
        try:
            import joblib
            fw_path = os.path.join(MODELS_DIR, "firewall_detector.pkl")
            if os.path.exists(fw_path):
                data = joblib.load(fw_path)
                self._fw_detector = data["pipeline"]
                self._fw_cols = data["feature_cols"]
                logger.info("[MLScanEngine] ✅ FirewallDetector loaded")

            flag_path = os.path.join(MODELS_DIR, "flag_optimizer.pkl")
            if os.path.exists(flag_path):
                data = joblib.load(flag_path)
                self._flag_optimizer = data["pipeline"]
                self._flag_le = data["label_encoder"]
                logger.info("[MLScanEngine] ✅ FlagOptimizer loaded")

            svc_path = os.path.join(MODELS_DIR, "service_classifier.pkl")
            if os.path.exists(svc_path):
                data = joblib.load(svc_path)
                self._svc_classifier = data["classifier"]
                self._svc_tfidf = data["tfidf"]
                self._svc_le = data["label_encoder"]
                logger.info("[MLScanEngine] ✅ ServiceClassifier loaded")

            vuln_path = os.path.join(MODELS_DIR, "vuln_scorer.pkl")
            if os.path.exists(vuln_path):
                data = joblib.load(vuln_path)
                self._vuln_regressor = data["regressor"]
                self._vuln_tfidf = data["tfidf"]
                self._vuln_le = data["label_encoder"]
                logger.info("[MLScanEngine] ✅ VulnScorer loaded")

            waf_path = os.path.join(MODELS_DIR, "waf_predictor.pkl")
            if os.path.exists(waf_path):
                data = joblib.load(waf_path)
                self._waf_predictor = data["classifier"]
                self._waf_tfidf = data["tfidf"]
                self._waf_le = data["label_encoder"]
                logger.info("[MLScanEngine] ✅ WafPredictor loaded")

            fuzz_path = os.path.join(MODELS_DIR, "web_fuzz_optimizer.pkl")
            if os.path.exists(fuzz_path):
                data = joblib.load(fuzz_path)
                self._fuzz_optimizer = data["classifier"]
                self._fuzz_tfidf_fw = data["tfidf_fw"]
                self._fuzz_tfidf_waf = data["tfidf_waf"]
                self._fuzz_le = data["label_encoder"]
                logger.info("[MLScanEngine] ✅ WebFuzzOptimizer loaded")

            nuclei_path = os.path.join(MODELS_DIR, "nuclei_tag_selector.pkl")
            if os.path.exists(nuclei_path):
                data = joblib.load(nuclei_path)
                self._nuclei_tag_selector = data["classifier"]
                self._nuclei_tfidf_svc = data["tfidf_svc"]
                self._nuclei_le = data["label_encoder"]
                logger.info("[MLScanEngine] ✅ NucleiTagSelector loaded")

            sql_path = os.path.join(MODELS_DIR, "sqli_tamper_scorer.pkl")
            if os.path.exists(sql_path):
                data = joblib.load(sql_path)
                self._sqli_tamper_scorer = data["classifier"]
                self._sqli_tfidf_db = data["tfidf_db"]
                self._sqli_tfidf_waf = data["tfidf_waf"]
                self._sqli_le = data["label_encoder"]
                logger.info("[MLScanEngine] ✅ SqliTamperScorer loaded")

            self._models_loaded = all([
                self._fw_detector, self._flag_optimizer,
                self._svc_classifier, self._vuln_regressor
            ])

            if self._models_loaded:
                logger.info("[MLScanEngine] All 4 ML models loaded — ML mode ACTIVE")
            else:
                logger.info("[MLScanEngine] Partial/no models — Rule-based fallback mode")

        except Exception as e:
            logger.warning(f"[MLScanEngine] Model load error: {e} — using rule-based mode")

    # ═══════════════════════════════════════════════════════════
    # PUBLIC: Main scan method
    # ═══════════════════════════════════════════════════════════
    def scan(self, target: str, task_id: str = "scan-001") -> dict:
        """
        Intelligently scan a target using ML-driven decision making.
        Returns structured JSON results for MasterAgent consumption.
        """
        clean_target = self._clean_target(target)
        logger.info(f"[MLScanEngine] Starting intelligent scan: {clean_target} (task_id={task_id})")
        print(f"\n[MLScanEngine] 🧠 Starting intelligent scan: {clean_target}")
        scan_start = time.time()

        results = {
            "task_id": task_id,
            "target": target,
            "domain": clean_target,
            "scan_timestamp": datetime.utcnow().isoformat() + "Z",
            "ml_mode": self._models_loaded,
            "ip_address": "",
            "os_fingerprint": "Unknown",
            "firewall_detected": False,
            "firewall_type": "none",
            "bypass_flags_used": [],
            "open_ports": [],
            "services": {},
            "raw_nmap_output": "",
            "scan_duration_seconds": 0,
            "ml_predictions": {},
        }

        try:
            # ── PHASE 1: DNS Resolution ────────────────────
            print(f"[MLScanEngine] Phase 1/5: DNS resolution...")
            ip = self._resolve_ip(clean_target)
            results["ip_address"] = ip
            print(f"[MLScanEngine]   → IP: {ip or 'N/A'}")

            # ── PHASE 2: Quick Probe + Firewall Detection ──
            print(f"[MLScanEngine] Phase 2/5: Quick probe + firewall detection...")
            probe_data = self._quick_probe(clean_target, ip)
            fw_prediction = self._detect_firewall(probe_data)
            results["firewall_detected"] = fw_prediction["firewall_present"]
            results["firewall_type"] = fw_prediction["firewall_type"]
            results["ml_predictions"]["firewall"] = fw_prediction
            print(f"[MLScanEngine]   → Firewall: {fw_prediction['firewall_type']} "
                  f"(confidence: {fw_prediction.get('confidence', 'N/A')})")

            # ── PHASE 3: Smart Flag Selection + Scanning ──
            print(f"[MLScanEngine] Phase 3/5: Intelligent port scanning...")
            flags, flag_class = self._select_scan_flags(probe_data, fw_prediction)
            results["bypass_flags_used"] = flags
            results["ml_predictions"]["flag_class"] = flag_class
            print(f"[MLScanEngine]   → Strategy: {flag_class} → flags: {' '.join(flags)}")

            open_ports, services, os_fp, raw_nmap = self._adaptive_scan(
                clean_target, ip, flags, flag_class
            )
            results["open_ports"] = open_ports
            results["os_fingerprint"] = os_fp
            results["raw_nmap_output"] = raw_nmap
            print(f"[MLScanEngine]   → Open ports: {open_ports}")

            # ── PHASE 4: Service Classification ──────────
            print(f"[MLScanEngine] Phase 4/5: Service classification...")
            enriched_services = {}
            for port_num, svc_info in services.items():
                banner = svc_info.get("banner", "")
                predicted_svc = self._classify_service(int(port_num), banner)
                svc_info["ml_service"] = predicted_svc
                enriched_services[port_num] = svc_info
                print(f"[MLScanEngine]   → Port {port_num}: {predicted_svc} (banner: {banner[:40]}...)")
            results["services"] = enriched_services

            # ── PHASE 5: Vulnerability Scoring ───────────
            print(f"[MLScanEngine] Phase 5/5: Vulnerability scoring...")
            vuln_scores = []
            for port_num, svc_info in enriched_services.items():
                service_name = svc_info.get("ml_service", svc_info.get("service", "unknown"))
                banner = svc_info.get("banner", "")
                score = self._score_vulnerability(int(port_num), service_name, banner)
                svc_info["vuln_score"] = score
                vuln_scores.append({"port": port_num, "service": service_name, "score": score})
                print(f"[MLScanEngine]   → Port {port_num} ({service_name}): vuln_score={score}/10")

            results["ml_predictions"]["vuln_scores"] = sorted(
                vuln_scores, key=lambda x: x["score"], reverse=True
            )

            # ── PHASE 6: Multi-Tool Intelligence Predictions ──
            print(f"[MLScanEngine] Multi-Tool Intelligence Predictions (Gobuster/FFUF, Nuclei, SQLmap, XSS)...")
            results["ml_predictions"]["waf_tech"] = self._predict_waf_tech(results)
            results["ml_predictions"]["web_fuzz"] = self._predict_web_fuzz(results)
            results["ml_predictions"]["nuclei_tags"] = self._predict_nuclei_tags(results)
            results["ml_predictions"]["sqli_tamper"] = self._predict_sqli_tamper(results)

            # Security ML Integration (Real-time XSS & Target Vuln Prediction)
            try:
                from security_ml import SecurityMLModel
                sec_ml = SecurityMLModel()
                target_url = f"https://{clean_target}"
                results["ml_predictions"]["target_risk_analysis"] = sec_ml.predict_target_vuln(target_url)
                print(f"[MLScanEngine]   → Target Risk Rating: {results['ml_predictions']['target_risk_analysis'].get('overall_risk_level')}")
            except Exception as e:
                logger.warning(f"[MLScanEngine] SecurityMLModel prediction skipped: {e}")

            # ── PHASE 7: Overall ML Confidence & Escalation Evaluation ──
            fw_conf = float(fw_prediction.get("confidence", 0.8)) if isinstance(fw_prediction.get("confidence"), (int, float)) else 0.85
            results["overall_ml_confidence"] = round(fw_conf, 2)
            results["requires_agent_escalation"] = results["overall_ml_confidence"] < 0.75

            print(f"\n[MLScanEngine] 📊 Overall ML Confidence Score: {results['overall_ml_confidence'] * 100:.1f}%")
            if results["requires_agent_escalation"]:
                print(f"[MLScanEngine] ⚠️  Confidence < 75% — ESCALATING to Cognitive AI Agents for deep analysis!")
            else:
                print(f"[MLScanEngine] ⚡ Confidence >= 75% — Fast ML Autonomous Scan Mode active!")

        except Exception as e:
            logger.error(f"[MLScanEngine] Scan error: {e}", exc_info=True)
            results["error"] = str(e)

        results["scan_duration_seconds"] = round(time.time() - scan_start, 1)

        # ── Save to task-scoped cache ─────────────────────
        self._write_cache(results, task_id)

        print(f"\n[MLScanEngine] ✅ Scan complete in {results['scan_duration_seconds']}s")
        print(f"[MLScanEngine] Found {len(results['open_ports'])} open ports")
        return results

    # ═══════════════════════════════════════════════════════════
    # PHASE 1: DNS Resolution
    # ═══════════════════════════════════════════════════════════
    def _resolve_ip(self, domain: str) -> str:
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return ""

    # ═══════════════════════════════════════════════════════════
    # PHASE 2: Quick Probe + Firewall Detection
    # ═══════════════════════════════════════════════════════════
    def _quick_probe(self, domain: str, ip: str = "") -> dict:
        """Fast initial probe to gather features for firewall detection."""
        probe = {
            "domain": domain,
            "ip": ip,
            "icmp_blocked": 1,
            "filtered_port_count": 0,
            "open_port_count": 0,
            "total_ports_scanned": 20,
            "avg_rtt_ms": 100.0,
            "ttl": 64,
            "rst_received": 0,
        }

        # TCP connect to quick ports for state analysis
        quick_ports = [80, 443, 22, 21, 8080, 3306, 25, 53]
        open_c, filtered_c, closed_c = 0, 0, 0
        rtts = []

        target = ip or domain
        for port in quick_ports:
            t_start = time.time()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                result = sock.connect_ex((target, port))
                rtt = (time.time() - t_start) * 1000
                rtts.append(rtt)
                if result == 0:
                    open_c += 1
                else:
                    # Connection refused = closed (no firewall), timeout = filtered
                    if rtt >= 1900:
                        filtered_c += 1
                    else:
                        closed_c += 1
                        # RST received if quick response
                        if rtt < 50:
                            probe["rst_received"] = 1
                sock.close()
            except socket.timeout:
                filtered_c += 1
                rtts.append(2000)
            except Exception:
                filtered_c += 1

        probe["open_port_count"] = open_c
        probe["filtered_port_count"] = filtered_c
        probe["total_ports_scanned"] = len(quick_ports)
        if rtts:
            probe["avg_rtt_ms"] = round(sum(rtts) / len(rtts), 1)

        # ICMP ping test
        try:
            ping_result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", target],
                capture_output=True, text=True, timeout=5
            )
            if ping_result.returncode == 0:
                probe["icmp_blocked"] = 0
                # Extract TTL from ping output
                ttl_match = re.search(r'ttl=(\d+)', ping_result.stdout, re.IGNORECASE)
                if ttl_match:
                    probe["ttl"] = int(ttl_match.group(1))
        except Exception:
            pass

        return probe

    def _detect_firewall(self, probe_data: dict) -> dict:
        """Use ML model or rule-based heuristics to detect firewall type."""
        if self._fw_detector is not None:
            try:
                import pandas as pd
                df = pd.DataFrame([{
                    "port": 80,
                    "rtt_ms": probe_data.get("avg_rtt_ms", 100),
                    "ttl": probe_data.get("ttl", 64),
                    "icmp_blocked": probe_data.get("icmp_blocked", 1),
                    "rst_received": probe_data.get("rst_received", 0),
                    "filtered_port_count": probe_data.get("filtered_port_count", 0),
                    "open_port_count": probe_data.get("open_port_count", 0),
                    "total_ports_scanned": probe_data.get("total_ports_scanned", 20),
                }])
                avail_cols = [c for c in self._fw_cols if c in df.columns]
                pred = self._fw_detector.predict(df[avail_cols])[0]
                proba = self._fw_detector.predict_proba(df[avail_cols])[0]
                confidence = round(float(max(proba)), 3)
                return {
                    "firewall_present": bool(pred),
                    "firewall_type": "detected" if pred else "none",
                    "confidence": confidence,
                    "method": "ml_model",
                }
            except Exception as e:
                logger.debug(f"[FWDetector] ML prediction failed: {e}")

        # Rule-based fallback
        total = probe_data.get("total_ports_scanned", 1)
        filtered = probe_data.get("filtered_port_count", 0)
        filtered_ratio = filtered / max(total, 1)
        icmp_blocked = probe_data.get("icmp_blocked", 0)
        ttl = probe_data.get("ttl", 64)

        fw_present = filtered_ratio > 0.4 or icmp_blocked == 1
        fw_type = "none"

        if fw_present:
            if ttl >= 240:
                fw_type = "cisco_acl"
            elif filtered_ratio > 0.8 and icmp_blocked:
                fw_type = "cloudflare"
            elif filtered_ratio > 0.5:
                fw_type = "iptables"
            else:
                fw_type = "iptables"

        return {
            "firewall_present": fw_present,
            "firewall_type": fw_type,
            "filtered_ratio": round(filtered_ratio, 3),
            "confidence": "rule_based",
            "method": "rule_based",
        }

    # ═══════════════════════════════════════════════════════════
    # PHASE 3: Smart Flag Selection + Adaptive Scanning
    # ═══════════════════════════════════════════════════════════
    def _select_scan_flags(self, probe_data: dict, fw_prediction: dict) -> tuple:
        """Select optimal nmap flags based on firewall detection."""
        fw_present = fw_prediction.get("firewall_present", False)
        fw_type = fw_prediction.get("firewall_type", "none")

        if not fw_present:
            # No firewall — fast connect scan
            flag_class = "connect_scan"
            return FLAG_MAP["connect_scan"], flag_class

        # Try ML model for flag selection
        if self._flag_optimizer is not None:
            try:
                import pandas as pd
                df = pd.DataFrame([{
                    "port": 80,
                    "rtt_ms": probe_data.get("avg_rtt_ms", 100),
                    "ttl": probe_data.get("ttl", 64),
                    "icmp_blocked": probe_data.get("icmp_blocked", 1),
                    "rst_received": probe_data.get("rst_received", 0),
                    "filtered_port_count": probe_data.get("filtered_port_count", 0),
                    "open_port_count": probe_data.get("open_port_count", 0),
                    "total_ports_scanned": probe_data.get("total_ports_scanned", 20),
                }])
                avail_cols = [c for c in self._fw_cols if c in df.columns]
                pred_class_idx = self._flag_optimizer.predict(df[avail_cols])[0]
                flag_class = self._flag_le.inverse_transform([pred_class_idx])[0]
                return FLAG_MAP.get(flag_class, FLAG_MAP["connect_scan"]), flag_class
            except Exception as e:
                logger.debug(f"[FlagOptimizer] ML prediction failed: {e}")

        # Rule-based flag selection by firewall type
        FW_FLAG_RULES = {
            "iptables": "null_scan",
            "pf_bsd": "null_scan",
            "cisco_acl": "dns_source_port",
            "cloudflare": "dns_source_port",
            "aws_waf": "fragment",
            "ids_ips": "slow_scan",
            "detected": "null_scan",
        }
        flag_class = FW_FLAG_RULES.get(fw_type, "connect_scan")
        return FLAG_MAP.get(flag_class, FLAG_MAP["connect_scan"]), flag_class

    def _adaptive_scan(self, domain: str, ip: str, flags: list, flag_class: str) -> tuple:
        """
        Run nmap with selected flags. If scan returns no open ports,
        automatically tries fallback strategies.
        """
        target = ip or domain

        # Strategy rotation: try primary flags, then fallbacks
        strategies_to_try = [
            (flags, flag_class),
            (FLAG_MAP["connect_scan"], "connect_scan"),    # Always works
            (FLAG_MAP["null_scan"], "null_scan"),           # Stateless bypass
            (FLAG_MAP["dns_source_port"], "dns_source_port"),  # DNS bypass
        ]

        # Privilege check — remove flags that need root
        uid = os.getuid()
        is_root = (uid == 0)

        for attempt_flags, attempt_class in strategies_to_try:
            # Remove root-only flags if not root
            if not is_root:
                attempt_flags = [f for f in attempt_flags
                                 if f not in ["-sS", "-sN", "-sF", "-sX", "-sA"]]
                if not attempt_flags:
                    attempt_flags = ["-sT", "-T4"]

            open_ports, services, os_fp, raw = self._run_nmap_scan(
                domain, target, attempt_flags
            )
            if open_ports:
                logger.info(f"[MLScanEngine] Strategy '{attempt_class}' found {len(open_ports)} open ports")
                return open_ports, services, os_fp, raw

            logger.info(f"[MLScanEngine] Strategy '{attempt_class}' found no open ports, trying fallback...")

        # Last resort: socket-based scan of critical ports
        logger.warning("[MLScanEngine] All nmap strategies exhausted — using socket fallback")
        return self._socket_scan_fallback(target)

    def _run_nmap_scan(self, domain: str, target: str, flags: list) -> tuple:
        """Execute a single nmap scan and parse results."""
        # Build nmap command
        cmd = ["nmap", "-Pn"] + flags + [
            "--top-ports", "1000",
            "-sV",          # Service version detection
            "--open",       # Only show open ports
            "-oX", "-",     # XML output to stdout
            target
        ]

        logger.debug(f"[Nmap] Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=180
            )
            stdout = result.stdout or ""
            return self._parse_nmap_xml(stdout, domain)
        except subprocess.TimeoutExpired:
            logger.warning("[Nmap] Scan timed out (180s)")
            return [], {}, "Unknown", ""
        except Exception as e:
            logger.warning(f"[Nmap] Error: {e}")
            return [], {}, "Unknown", ""

    def _parse_nmap_xml(self, xml_output: str, domain: str) -> tuple:
        """Parse nmap XML output into structured data."""
        import xml.etree.ElementTree as ET

        open_ports = []
        services = {}
        os_fingerprint = "Unknown"
        raw = xml_output

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            # Fall back to text parsing if XML malformed
            return self._parse_nmap_text(xml_output)

        for host in root.findall("host"):
            # OS detection
            for os_match in host.findall(".//osmatch"):
                name = os_match.get("name", "")
                accuracy = int(os_match.get("accuracy", "0"))
                if accuracy > 70:
                    os_fingerprint = name
                    break

            # Ports
            for port_elem in host.findall(".//port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue

                port_num = int(port_elem.get("portid", 0))
                protocol = port_elem.get("protocol", "tcp")
                open_ports.append(port_num)

                svc_elem = port_elem.find("service")
                service_name = ""
                product = ""
                version = ""
                banner = ""

                if svc_elem is not None:
                    service_name = svc_elem.get("name", "")
                    product = svc_elem.get("product", "")
                    version = svc_elem.get("version", "")
                    extra = svc_elem.get("extrainfo", "")
                    banner = f"{product} {version} {extra}".strip()

                # Script output for banners
                for script in port_elem.findall(".//script[@id='banner']"):
                    output = script.get("output", "")
                    if output:
                        banner = output[:200]

                services[str(port_num)] = {
                    "service": service_name or PORT_SERVICE_MAP.get(port_num, "unknown"),
                    "product": product,
                    "version": version,
                    "banner": banner,
                    "protocol": protocol,
                }

        return open_ports, services, os_fingerprint, raw

    def _parse_nmap_text(self, text_output: str) -> tuple:
        """Fallback: parse nmap text output (non-XML)."""
        open_ports = []
        services = {}

        for line in text_output.split("\n"):
            match = re.search(
                r'^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', line.strip()
            )
            if match:
                port_num = int(match.group(1))
                protocol = match.group(2)
                svc = match.group(3)
                banner = match.group(4).strip()
                open_ports.append(port_num)
                services[str(port_num)] = {
                    "service": svc,
                    "product": "",
                    "version": banner[:100],
                    "banner": banner[:200],
                    "protocol": protocol,
                }

        # OS detection
        os_fp = "Unknown"
        os_match = re.search(r'OS(?: details|:)\s*(.+)', text_output)
        if os_match:
            os_fp = os_match.group(1).strip()

        return open_ports, services, os_fp, text_output

    def _socket_scan_fallback(self, target: str) -> tuple:
        """Pure Python socket scan for when nmap fails entirely."""
        critical_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443,
                          445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
        open_ports = []
        services = {}

        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                result = sock.connect_ex((target, port))
                banner = ""
                if result == 0:
                    try:
                        sock.send(b"\r\n")
                        banner = sock.recv(512).decode("utf-8", errors="ignore").strip()[:200]
                    except Exception:
                        pass
                    return port, banner
                sock.close()
            except Exception:
                pass
            return None, None

        with __import__("concurrent.futures", fromlist=["ThreadPoolExecutor"]).ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(check_port, p): p for p in critical_ports}
            for fut in futures:
                port, banner = fut.result()
                if port:
                    open_ports.append(port)
                    services[str(port)] = {
                        "service": PORT_SERVICE_MAP.get(port, "unknown"),
                        "product": "",
                        "version": "",
                        "banner": banner or "",
                        "protocol": "tcp",
                    }

        return open_ports, services, "Unknown", "[socket fallback scan]"

    # ═══════════════════════════════════════════════════════════
    # PHASE 4: Service Classification
    # ═══════════════════════════════════════════════════════════
    def _classify_service(self, port: int, banner: str) -> str:
        """Classify service from banner text using ML model or rules."""
        if self._svc_classifier is not None and self._svc_tfidf is not None:
            try:
                from scipy.sparse import hstack, csr_matrix
                import numpy as np

                banner_feat = self._svc_tfidf.transform([banner or ""])
                port_feat = csr_matrix([[port]])
                X = hstack([banner_feat, port_feat])
                pred_idx = self._svc_classifier.predict(X)[0]
                return self._svc_le.inverse_transform([pred_idx])[0]
            except Exception as e:
                logger.debug(f"[ServiceClassifier] ML failed: {e}")

        # Rule-based: banner keyword matching
        banner_lower = (banner or "").lower()
        if "apache" in banner_lower:
            return "http"
        elif "nginx" in banner_lower:
            return "http"
        elif "litespeed" in banner_lower:
            return "http"
        elif "ssh" in banner_lower or "openssh" in banner_lower:
            return "ssh"
        elif "ftp" in banner_lower or "proftp" in banner_lower or "vsftpd" in banner_lower:
            return "ftp"
        elif "smtp" in banner_lower or "postfix" in banner_lower or "exim" in banner_lower:
            return "smtp"
        elif "mariadb" in banner_lower or "mysql" in banner_lower:
            return "mysql"
        elif "postgres" in banner_lower:
            return "postgresql"
        elif "redis" in banner_lower:
            return "redis"
        elif "mongodb" in banner_lower:
            return "mongodb"
        elif "rdp" in banner_lower or "terminal" in banner_lower:
            return "rdp"
        elif "vnc" in banner_lower or "rfb" in banner_lower:
            return "vnc"
        elif "smb" in banner_lower or "samba" in banner_lower:
            return "smb"

        # Port-based fallback
        return PORT_SERVICE_MAP.get(port, "unknown")

    # ═══════════════════════════════════════════════════════════
    # PHASE 5: Vulnerability Scoring
    # ═══════════════════════════════════════════════════════════
    def _score_vulnerability(self, port: int, service: str, banner: str) -> float:
        """Score vulnerability likelihood (0–10) using ML or known scores."""
        if self._vuln_regressor is not None and self._vuln_tfidf is not None:
            try:
                from scipy.sparse import hstack, csr_matrix
                import numpy as np

                banner_feat = self._vuln_tfidf.transform([banner or ""])
                # Service encode
                try:
                    svc_encoded = self._vuln_le.transform([service])[0]
                except ValueError:
                    svc_encoded = 0
                port_feat = csr_matrix([[port, svc_encoded]])
                X = hstack([banner_feat, port_feat])
                score = float(self._vuln_regressor.predict(X)[0])
                return round(float(np.clip(score, 0, 10)), 2)
            except Exception as e:
                logger.debug(f"[VulnScorer] ML failed: {e}")

        # Rule-based: service name lookup
        service_lower = (service or "").lower()
        for key, score in KNOWN_VULN_SCORES.items():
            if key in service_lower:
                return score

        # Banner keyword-based adjustments
        banner_lower = (banner or "").lower()
        if any(x in banner_lower for x in ["proftp", "proftpd"]):
            return KNOWN_VULN_SCORES["proftp"]
        if "exim" in banner_lower:
            return KNOWN_VULN_SCORES["exim"]

        return KNOWN_VULN_SCORES["default"]

    # ═══════════════════════════════════════════════════════════
    # UTILS
    # ═══════════════════════════════════════════════════════════
    def _clean_target(self, target: str) -> str:
        """Strip protocol/path from target to get clean domain or IP."""
        target = target.strip()
        for proto in ["https://", "http://"]:
            if target.startswith(proto):
                target = target[len(proto):]
        return target.split("/")[0].split(":")[0]

    def _write_cache(self, data: dict, task_id: str = "global"):
        """Write scan results to task-scoped cache file."""
        safe_task_id = re.sub(r'[^a-zA-Z0-9_-]', '_', str(task_id))[:40]
        cache_path = f"/tmp/ml_scan_cache_{safe_task_id}.json"
        legacy_path = "/tmp/discovery_cache.json"

        # Prepare cache payload (compatible with existing tools)
        payload = {
            "task_id": task_id,
            "ip": data.get("ip_address"),
            "domain": data.get("domain"),
            "url": f"https://{data.get('domain')}",
            "open_ports": data.get("open_ports"),
            "services": data.get("services"),
            "os_fingerprint": data.get("os_fingerprint"),
            "firewall_detected": data.get("firewall_detected"),
            "firewall_type": data.get("firewall_type"),
            "bypass_flags_used": data.get("bypass_flags_used"),
            "ml_predictions": data.get("ml_predictions"),
            "ml_mode": data.get("ml_mode"),
            "stage1_complete": True,
            "ml_scan_complete": True,
        }

        for path in [cache_path, legacy_path]:
            try:
                with open(path, "w") as f:
                    json.dump(payload, f, indent=2)
            except Exception as e:
                logger.warning(f"[MLScanEngine] Cache write error {path}: {e}")

    @property
    def models_ready(self) -> bool:
        return self._models_loaded

    def __repr__(self):
        mode = "ML_ACTIVE" if self._models_loaded else "RULE_BASED_FALLBACK"
        return f"<MLScanEngine mode={mode}>"
