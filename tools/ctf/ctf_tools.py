"""
CTF Solver & Flag Finder Tools Package
=======================================
Specialized tools for CTF (Capture The Flag) competitions:
1. FlagScannerTool: Detects and extracts flag patterns (flag{...}, CTF{...}, picoCTF{...}, etc.)
2. CryptoDecoderTool: Decodes Base64, Hex, ROT13, XOR, JWT, URL, Binary, and Reverse strings.
3. StegoForensicsTool: Inspects file headers, EXIF metadata, embedded strings, and hidden payload markers.
4. WebCTFSolverTool: Automates common Web CTF challenges (cookie tampering, header injections, hidden HTML comments, SQLi auth bypass).
"""

import re
import base64
import json
import urllib.parse
import binascii
from typing import Optional, Dict, Any
from tools.base import Tool, StandardSecurityTool

# Common CTF flag regex patterns
FLAG_PATTERNS = [
    r"(flag\{[^\}\s]+\})",
    r"(ctf\{[^\}\s]+\})",
    r"(picoCTF\{[^\}\s]+\})",
    r"(HTB\{[^\}\s]+\})",
    r"(THM\{[^\}\s]+\})",
    r"(FLAG-[A-Za-z0-9_\-]+)",
    r"([a-zA-Z0-9_\-]{4,63}\{[\x20-\x7E]+\})",  # Generic prefix{flag}
]


# ─────────────────────────────────────────────────────────────────────────────
# 1. Flag Scanner Tool
# ─────────────────────────────────────────────────────────────────────────────

class FlagScannerTool(Tool):
    name = "flag_scanner"
    description = (
        "Scans raw text, HTTP responses, file contents, or source code for CTF flags "
        "using regex patterns (flag{...}, CTF{...}, picoCTF{...}, HTB{...}, custom format)."
    )
    parameters = {
        "text": "The raw string, response body, or source code to scan for flags",
        "custom_pattern": "Optional custom regex pattern (e.g., 'MYCTF\\{[^\\}]+\\}')"
    }

    def execute(self, text: str = "", custom_pattern: str = "", **kwargs) -> str:
        text = str(text)
        found_flags = []

        patterns = list(FLAG_PATTERNS)
        if custom_pattern:
            patterns.insert(0, custom_pattern)

        for pat in patterns:
            try:
                matches = re.findall(pat, text, re.IGNORECASE)
                for m in matches:
                    flag_str = m if isinstance(m, str) else m[0]
                    if flag_str not in found_flags:
                        found_flags.append(flag_str)
            except Exception:
                pass

        if found_flags:
            return (
                f"🚩 CTF FLAG(S) DISCOVERED! ({len(found_flags)} flag(s) found):\n"
                + "\n".join([f"  - {f}" for f in found_flags])
            )
        return "No standard CTF flag patterns detected in the provided text."


# ─────────────────────────────────────────────────────────────────────────────
# 2. Crypto & Encoding Decoder Tool
# ─────────────────────────────────────────────────────────────────────────────

class CryptoDecoderTool(Tool):
    name = "crypto_decoder"
    description = (
        "Decodes common CTF ciphers and encodings: Base64, Base32, Hex, ROT13, URL, "
        "Binary, Reverse, JWT tokens, and single-byte XOR brute-force."
    )
    parameters = {
        "ciphertext": "The encoded string or ciphertext to decode",
        "operation": "Operation: auto | base64 | hex | rot13 | url | binary | reverse | jwt | xor_brute"
    }

    def execute(self, ciphertext: str = "", operation: str = "auto", **kwargs) -> str:
        ciphertext = str(ciphertext).strip()
        if not ciphertext:
            return "Error: No ciphertext provided."

        results = []

        # Auto mode tries multiple common decoders
        ops_to_try = [operation] if operation != "auto" else ["base64", "hex", "rot13", "url", "jwt", "reverse"]

        for op in ops_to_try:
            try:
                if op == "base64":
                    decoded = base64.b64decode(ciphertext).decode("utf-8", errors="ignore")
                    if decoded and any(c.isalnum() for c in decoded):
                        results.append(f"[Base64] -> {decoded}")
                elif op == "hex":
                    clean_hex = ciphertext.replace("0x", "").replace(" ", "")
                    decoded = binascii.unhexlify(clean_hex).decode("utf-8", errors="ignore")
                    if decoded:
                        results.append(f"[Hex] -> {decoded}")
                elif op == "rot13":
                    decoded = ciphertext.translate(
                        str.maketrans(
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
                        )
                    )
                    results.append(f"[ROT13] -> {decoded}")
                elif op == "url":
                    decoded = urllib.parse.unquote(ciphertext)
                    if decoded != ciphertext:
                        results.append(f"[URL Decoded] -> {decoded}")
                elif op == "reverse":
                    results.append(f"[Reversed] -> {ciphertext[::-1]}")
                elif op == "jwt":
                    parts = ciphertext.split(".")
                    if len(parts) >= 2:
                        header = base64.b64decode(parts[0] + "==").decode("utf-8", errors="ignore")
                        payload = base64.b64decode(parts[1] + "==").decode("utf-8", errors="ignore")
                        results.append(f"[JWT Header]  -> {header}")
                        results.append(f"[JWT Payload] -> {payload}")
                elif op == "xor_brute":
                    xor_matches = []
                    raw_bytes = ciphertext.encode()
                    for key in range(1, 256):
                        try:
                            dec = "".join(chr(b ^ key) for b in raw_bytes)
                            if "flag" in dec.lower() or "ctf" in dec.lower() or any(k in dec for k in ["{", "}", "secret"]):
                                xor_matches.append(f"Key {key:#04x} ({key:3d}): {dec}")
                        except Exception:
                            pass
                    if xor_matches:
                        results.append("[XOR Brute-Force Matches]:\n" + "\n".join(xor_matches[:10]))
            except Exception:
                pass

        # Check if any decoded result contains a flag
        scanner = FlagScannerTool()
        all_results_str = "\n".join(results)
        flag_check = scanner.execute(text=all_results_str + "\n" + ciphertext)

        output = []
        output.append("=== CTF Crypto/Encoding Decoder Results ===")
        output.append(f"Input: {ciphertext[:80]}...")
        output.append("")

        if "🚩" in flag_check:
            output.append(flag_check)
            output.append("")

        if results:
            output.append("Decoded Candidates:")
            output.extend([f"  {r}" for r in results])
        else:
            output.append("No clean text decodings produced by selected operations.")

        return "\n".join(output)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Stego & Forensics Tool
# ─────────────────────────────────────────────────────────────────────────────

class StegoForensicsTool(StandardSecurityTool):
    name = "stego_forensics"
    description = (
        "Inspects files, images, or raw binary data for hidden CTF strings, EXIF metadata, "
        "magic bytes, and embedded payloads."
    )
    parameters = {
        "file_path": "Absolute path to local file OR base64 data string",
        "min_string_len": "Minimum string length for string extraction (default: 4)"
    }

    def execute(self, file_path: str = "", min_string_len: int = 4, **kwargs) -> str:
        import os
        import subprocess

        output_lines = ["=== CTF Stego & Forensics Analysis ==="]

        if not os.path.exists(file_path):
            return f"Error: File '{file_path}' not found."

        output_lines.append(f"Target File: {file_path}")
        output_lines.append(f"File Size  : {os.path.getsize(file_path)} bytes")

        # 1. Check Magic Bytes / File Command
        try:
            res = subprocess.run(["file", file_path], capture_output=True, text=True, timeout=5)
            output_lines.append(f"File Type  : {res.stdout.strip()}")
        except Exception:
            pass

        # 2. Extract Printable Strings
        try:
            res = subprocess.run(
                ["strings", "-n", str(min_string_len), file_path],
                capture_output=True, text=True, timeout=10
            )
            raw_strings = res.stdout
            
            # Scan strings for flags!
            scanner = FlagScannerTool()
            flag_check = scanner.execute(text=raw_strings)
            
            if "🚩" in flag_check:
                output_lines.append("")
                output_lines.append(flag_check)
            
            # Filter interesting strings (keys, flags, tokens, passwords)
            interesting = []
            for line in raw_strings.splitlines():
                line_str = line.strip()
                if any(kw in line_str.lower() for kw in ["flag", "ctf", "pass", "secret", "user", "admin", "key", "token", "http"]):
                    interesting.append(line_str)

            if interesting:
                output_lines.append("")
                output_lines.append("Interesting Strings Found in File:")
                for s in interesting[:15]:
                    output_lines.append(f"  - {s[:100]}")
        except Exception as e:
            output_lines.append(f"Strings extraction error: {e}")

        # 3. EXIF Metadata Check (if exiftool installed)
        try:
            res = subprocess.run(["exiftool", file_path], capture_output=True, text=True, timeout=5)
            if res.returncode == 0 and res.stdout:
                output_lines.append("")
                output_lines.append("EXIF Metadata Highlights:")
                for line in res.stdout.splitlines()[:10]:
                    output_lines.append(f"  {line}")
        except Exception:
            pass

        return "\n".join(output_lines)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Web CTF Solver Tool
# ─────────────────────────────────────────────────────────────────────────────

class WebCTFSolverTool(StandardSecurityTool):
    name = "web_ctf_solver"
    description = (
        "Automates common Web CTF challenge inspections: checks hidden HTML comments, "
        "robots.txt, .git directory exposure, cookie tampering hints, HTTP header injections, "
        "and basic SQLi auth bypass probes."
    )
    parameters = {
        "target_url": "Target CTF web challenge URL (e.g. http://challenge.ctf:8080/login)",
        "check_git": "Check for .git exposure (default: true)",
        "check_comments": "Check for hidden HTML comments (default: true)"
    }

    def execute(self, target_url: str, check_git: bool = True, check_comments: bool = True, **kwargs) -> str:
        import requests
        from urllib.parse import urljoin

        url = self.normalize_url(target_url)
        output_lines = [
            f"=== Web CTF Automated Challenge Inspector ===",
            f"Target: {url}",
            ""
        ]

        scanner = FlagScannerTool()
        decoder = CryptoDecoderTool()

        # 1. Fetch Main Page
        resp, err = self.safe_request(url, timeout=10)
        if err or not resp:
            return f"Error connecting to target URL: {err}"

        output_lines.append(f"HTTP Status  : {resp.status_code}")
        output_lines.append(f"Server Header: {resp.headers.get('Server', 'Not disclosed')}")

        # Check response body & headers for flags
        combined_text = f"{resp.headers}\n{resp.text}"
        flag_check = scanner.execute(text=combined_text)
        if "🚩" in flag_check:
            output_lines.append("")
            output_lines.append(flag_check)

        # 2. Check Hidden HTML Comments
        if check_comments:
            comments = re.findall(r"<!--(.*?)-->", resp.text, re.DOTALL)
            if comments:
                output_lines.append("")
                output_lines.append(f"Discovered HTML Comments ({len(comments)} found):")
                for c in comments[:8]:
                    clean_c = c.strip()
                    output_lines.append(f"  <!-- {clean_c[:120]} -->")
                    # Check comment for flags or base64
                    c_flag = scanner.execute(text=clean_c)
                    if "🚩" in c_flag:
                        output_lines.append(f"    {c_flag}")

        # 3. Check Sensitive Web CTF Endpoints (robots.txt, .git, .env)
        ctf_paths = ["/robots.txt", "/.git/HEAD", "/.env", "/sitemap.xml", "/secret", "/admin", "/flag", "/api/flag"]
        found_paths = []

        for path in ctf_paths:
            test_path_url = urljoin(url, path)
            r, _ = self.safe_request(test_path_url, timeout=5)
            if r and r.status_code == 200 and len(r.text) > 0:
                found_paths.append((path, len(r.text)))
                p_flag = scanner.execute(text=f"{r.headers}\n{r.text}")
                if "🚩" in p_flag:
                    output_lines.append("")
                    output_lines.append(f"🚩 FLAG FOUND IN {path}:")
                    output_lines.append(f"   {p_flag}")

        if found_paths:
            output_lines.append("")
            output_lines.append("Exposed CTF Endpoints Discovered:")
            for p, size in found_paths:
                output_lines.append(f"  - {p} (HTTP 200, {size} bytes)")

        # 4. Check Cookies & Authorization Headers
        cookies = resp.cookies.get_dict()
        if cookies:
            output_lines.append("")
            output_lines.append(f"Cookies Set: {cookies}")
            for k, v in cookies.items():
                dec_val = decoder.execute(ciphertext=v, operation="auto")
                if "Decoded Candidates" in dec_val:
                    output_lines.append(f"  Cookie '{k}' Decoded -> {dec_val}")

        return "\n".join(output_lines)

class AdvancedDecoderTool(Tool):
    name = "advanced_decoder"
    description = "Advanced CTF decoder: Base32/58/85, Morse, multi-byte XOR, hash ID, JWT"
    parameters = {"input": "Encoded data", "operation": "base32/base58/base85/morse/xor/hash_id/jwt/auto"}
    
    def execute(self, input: str = None, data: str = None, operation: str = "auto", **kwargs):
        text = input or data or kwargs.get('text', '') or kwargs.get('target', '')
        if not text: return "Error: No input data"
        results = []
        
        ops = [operation] if operation != 'auto' else ['base64', 'base32', 'hex', 'base85', 'url', 'rot13', 'morse', 'binary', 'jwt', 'hash_id']
        
        for op in ops:
            try:
                if op == 'base32':
                    import base64
                    decoded = base64.b32decode(text.strip()).decode('utf-8', errors='replace')
                    results.append(f"Base32: {decoded}")
                elif op == 'base64':
                    import base64
                    decoded = base64.b64decode(text.strip() + '==').decode('utf-8', errors='replace')
                    results.append(f"Base64: {decoded}")
                elif op == 'base85':
                    import base64
                    decoded = base64.b85decode(text.strip()).decode('utf-8', errors='replace')
                    results.append(f"Base85: {decoded}")
                elif op == 'hex':
                    decoded = bytes.fromhex(text.strip().replace('0x','').replace(' ','')).decode('utf-8', errors='replace')
                    results.append(f"Hex: {decoded}")
                elif op == 'url':
                    from urllib.parse import unquote
                    results.append(f"URL decode: {unquote(text)}")
                elif op == 'rot13':
                    import codecs
                    results.append(f"ROT13: {codecs.decode(text, 'rot_13')}")
                elif op == 'morse':
                    morse_map = {'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5','-....':'6','--...':'7','---..':'8','----.':'9','-----':'0'}
                    words = text.strip().split('  ' if '  ' in text else '/')
                    decoded = ' '.join(''.join(morse_map.get(c, '?') for c in word.split()) for word in words)
                    results.append(f"Morse: {decoded}")
                elif op == 'binary':
                    bits = text.strip().replace(' ', '')
                    if all(c in '01' for c in bits) and len(bits) % 8 == 0:
                        decoded = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
                        results.append(f"Binary: {decoded}")
                elif op == 'jwt':
                    parts = text.strip().split('.')
                    if len(parts) >= 2:
                        import base64, json
                        for i, label in enumerate(['Header', 'Payload']):
                            padded = parts[i] + '=' * (4 - len(parts[i]) % 4)
                            decoded = json.loads(base64.urlsafe_b64decode(padded))
                            results.append(f"JWT {label}: {json.dumps(decoded, indent=2)}")
                elif op == 'hash_id':
                    h = text.strip()
                    hash_types = []
                    if len(h) == 32: hash_types.append('MD5')
                    if len(h) == 40: hash_types.append('SHA-1')
                    if len(h) == 64: hash_types.append('SHA-256')
                    if len(h) == 128: hash_types.append('SHA-512')
                    if h.startswith('$2'): hash_types.append('bcrypt')
                    if h.startswith('$6$'): hash_types.append('SHA-512crypt')
                    results.append(f"Hash type: {', '.join(hash_types) if hash_types else 'Unknown'}")
            except Exception:
                pass
        
        # Check for flags in decoded output
        import re
        for r_text in results:
            flags = re.findall(r'(flag\{[^}]+\}|CTF\{[^}]+\}|picoCTF\{[^}]+\})', r_text, re.I)
            if flags:
                results.append(f"🚩 FLAG FOUND: {flags}")
        
        return '\n'.join(results) if results else f"Could not decode input with {operation}"
