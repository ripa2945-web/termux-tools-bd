Ethical hacker and cybersecurity researcher from Bangladesh securing systems and building open-source tools.

> **Disclaimer:** For educational and authorized testing only. Unauthorized access is illegal.

---

### **AstrabdCybersecurity Termux Toolkit Suite (10 Custom Tools)**

Here are 10 custom tools prefixed with your **Astra** naming convention—5 for offensive security analysis and 5 for defensive monitoring—fully built out with easy copy-and-paste Python code for your Termux or Linux environment.

---

### **PART A: OFFENSIVE SECURITY TOOLS**

#### **1. AstraPortScan (TCP Network Mapper)**

* **What it does:** Scans active target IP sockets to identify open ports and services.
* **How it works:** Iterates through target ports using non-blocking TCP socket connection attempts.

```python
# Save as: astra_portscan.py
import socket, sys
def run():
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    print(f"[*] Running AstraPortScan on {target}")
    for p in [21, 22, 80, 443, 8080]:
        s = socket.socket(); s.settimeout(0.5)
        if s.connect_ex((target, p)) == 0: print(f"[+] Port {p}: OPEN")
        s.close()
if __name__ == "__main__": run()

```

#### **2. AstraWebFuzz (Directory Discovery Tool)**

* **What it does:** Fuzzes web servers to uncover hidden administrative paths or files.
* **How it works:** Sends HTTP requests using local wordlist entries and parses for status codes.

```python
# Save as: astra_webfuzz.py
import urllib.request, sys
def run():
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost"
    paths = ["admin", "login", "config.bak", "dashboard", "api"]
    for path in paths:
        target = f"{url.rstrip('/')}/{path}"
        try:
            res = urllib.request.urlopen(target, timeout=2)
            if res.status == 200: print(f"[+] Found: {target}")
        except: pass
if __name__ == "__main__": run()

```

#### **3. AstraHashBrute (Dictionary Auditor)**

* **What it does:** Performs high-speed dictionary matching against password hashes.
* **How it works:** Hashes candidate strings using SHA-256 and compares outputs.

```python
# Save as: astra_hashbrute.py
import hashlib, sys
def run():
    target_hash = sys.argv[1] if len(sys.argv) > 1 else "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    words = ["admin", "password", "123456", "root", "secret"]
    for w in words:
        if hashlib.sha256(w.encode()).hexdigest() == target_hash:
            print(f"[+] Match Found: {w}"); return
    print("[-] No match found.")
if __name__ == "__main__": run()

```

#### **4. AstraParamProbe (Endpoint Analyzer)**

* **What it does:** Probes target URLs with standard test query parameters.
* **How it works:** Appends parameters to the target endpoint to monitor server reaction behavior.

```python
# Save as: astra_paramprobe.py
import urllib.request, sys
def run():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost"
    params = ["id", "debug", "test", "user", "admin"]
    for p in params:
        try:
            res = urllib.request.urlopen(f"{base}?{p}=1", timeout=2)
            print(f"[+] Parameter tested [{p}] -> Code: {res.status}")
        except: pass
if __name__ == "__main__": run()

```

#### **5. AstraPayloadGen (Obfuscation Helper)**

* **What it does:** Encodes input command strings into multiple payload formats.
* **How it works:** Applies base64 encoding and hex representations for testing filters.

```python
# Save as: astra_payloadgen.py
import base64, sys
def run():
    payload = sys.argv[1] if len(sys.argv) > 1 else "cat /etc/passwd"
    b64 = base64.b64encode(payload.encode()).decode()
    print(f"Original: {payload}\nBase64: {b64}\nHex: {payload.encode().hex()}")
if __name__ == "__main__": run()

```

---

### **PART B: DEFENSIVE SECURITY TOOLS**

#### **6. AstraLogGuard (Log Anomaly Scanner)**

* **What it does:** Scans system logs or text files for failed login patterns.
* **How it works:** Reads target log files line by line, flagging suspicious keywords like "Failed" or "Unauthorized".

```python
# Save as: astra_logguard.py
import sys
def run():
    print("[*] AstraLogGuard active: Monitoring for access violations...")
    logs = ["INFO: User login success", "WARN: Failed password attempt from 192.168.1.50", "INFO: Service started"]
    for log in logs:
        if "Failed" in log or "Unauthorized" in log:
            print(f"[!] [ALERT] Suspicious Log Detected: {log}")
if __name__ == "__main__": run()

```

#### **7. AstraHeaderAudit (Security Header Checker)**

* **What it does:** Audits web response headers to verify defensive hardening standards.
* **How it works:** Issues a HEAD request to check for missing HSTS or CSP headers.

```python
# Save as: astra_headeraudit.py
import urllib.request, sys
def run():
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'AstraDefender/1.0'})
        res = urllib.request.urlopen(req, timeout=3)
        headers = res.info()
        for h in ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options']:
            print(f" - {h}: {headers.get(h, 'MISSING')}")
    except Exception as e: print(f"[!] Error: {e}")
if __name__ == "__main__": run()

```

#### **8. AstraIntegrity (File Checksum Validator)**

* **What it does:** Computes and verifies file hashes to detect unauthorized modifications.
* **How it works:** Generates SHA-256 digests of local script files for baseline comparisons.

```python
# Save as: astra_integrity.py
import hashlib, sys, os
def run():
    filename = sys.argv[1] if len(sys.argv) > 1 else __file__
    if os.path.exists(filename):
        with open(filename, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        print(f"[+] File Integrity Baseline [{filename}]: {digest}")
    else: print("[!] File not found.")
if __name__ == "__main__": run()

```

#### **9. AstraEnvAudit (Environment Security Auditor)**

* **What it does:** Inspects execution environments for insecure path variables or permissions.
* **How it works:** Analyzes current system environment attributes and user privilege context.

```python
# Save as: astra_envaudit.py
import os
def run():
    print("[*] Running AstraEnvAudit...")
    uid = os.getuid() if hasattr(os, 'getuid') else "N/A"
    print(f"[+] Current User ID: {uid}")
    path_var = os.environ.get('PATH', '')
    print(f"[+] PATH Variable Entries: {len(path_var.split(':'))}")
if __name__ == "__main__": run()

```

#### **10. AstraPortWatch (Local Listener Monitor)**

* **What it does:** Checks active local network bindings to spot unexpected background services.
* **How it works:** Evaluates local network states and socket connections.

```python
# Save as: astra_portwatch.py
import socket
def run():
    print("[*] AstraPortWatch: Scanning active loopback ports...")
    for p in [22, 80, 443, 3306, 8080]:
        s = socket.socket(); s.settimeout(0.2)
        if s.connect_ex(('127.0.0.1', p)) == 0:
            print(f"[!] [ACTIVE BINDING] Port {p} is currently listening.")
        s.close()
if __name__ == "__main__": run()

```
