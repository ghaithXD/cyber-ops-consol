from flask import Flask, render_template, request, url_for, Response, jsonify
import os
import html
import re
import socket
import time
import subprocess
import urllib.request
import urllib.parse
import base64
import hashlib
import platform
import sqlite3
import json
import csv
import io
import requests
import concurrent.futures
from collections import Counter
from datetime import datetime
from urllib.error import URLError, HTTPError
from jinja2 import DictLoader

app = Flask(__name__)
TEMPLATES = {}
DB_NAME = "cyberops.db"

app.jinja_loader = DictLoader(TEMPLATES)

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scan_history
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  scan_type TEXT,
                  target TEXT,
                  result TEXT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

def save_scan(scan_type, target, result):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    if isinstance(result, (dict, list)):
        result = json.dumps(result, indent=2)
    c.execute("INSERT INTO scan_history (scan_type, target, result) VALUES (?, ?, ?)", 
              (scan_type, target, str(result)))
    conn.commit()
    conn.close()

def get_nmap_path():
    if platform.system() == "Windows":
        paths = [r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"]
        for path in paths:
            if os.path.exists(path): return path
    return "nmap"

NMAP_EXE = get_nmap_path()

# =================================================================
# 2. LOGIC FUNCTIONS
# =================================================================
# ضيف هذا المتغير فوق مع الإعدادات
XSSTRIKE_PATH = "xsstrike.py" 

@app.route("/xsstrike", methods=["GET", "POST"])
def xsstrike_scan():
    url, output = "", ""
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        crawl = request.form.get("crawl")
        if url:
            try:
                cmd = ["python", XSSTRIKE_PATH, "-u", url]
                if crawl:
                    cmd.append("--crawl")
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                output = html.escape(result.stdout)
                if result.stderr:
                    output += "\n\n[ERRORS]\n" + html.escape(result.stderr)
                    
                save_scan("XSStrike XSS Scan", url, result.stdout)
            except subprocess.TimeoutExpired:
                output = "Error: XSStrike scan timed out."
            except Exception as e: 
                output = f"Error: {e}"
                
    return render_template("xsstrike_template", url=url, output=output)
def parse_hosts(nmap_text: str):
    hosts = []
    pattern = re.compile(r'(?:(?:Nmap scan report for )?(\d+\.\d+\.\d+\.\d+)).*?Host is (\w+)(?: \(([\d\.]+s latency)\))?(?:\.?\s*MAC Address:\s*([0-9A-Fa-f:]+)(?: \((.*?)\))?)?', re.S)
    for m in pattern.finditer(nmap_text):
        hosts.append({"host": m.group(1), "up": m.group(2).lower() == "up", "latency": m.group(3), "mac": m.group(4), "vendor": m.group(5)})
    return hosts

def ports_info(text, host):
    port_re = re.compile(r'^(\d+)\/tcp\s+(\S+)\s+(\S+)(?:\s+(.*))?$', re.MULTILINE)
    service_info_re = re.compile(r'^Service Info:\s*(.+)$', re.MULTILINE)
    os_guess_re = re.compile(r'^Aggressive OS guesses:\s*(.+)$', re.MULTILINE)
    results = [{'port': m.group(1), 'state': m.group(2), 'service': m.group(3), 'version': (m.group(4) or '').strip()} for m in port_re.finditer(text)]
    svc_info, os_guess = service_info_re.search(text), os_guess_re.search(text)
    return {'ports': results, 'service_info': svc_info.group(1).strip() if svc_info else None, 'os': os_guess.group(1).strip() if os_guess else None}

def resolve_domain(subdomain):
    """دالة فرعية للتحقق مما إذا كان النطاق الفرعي نشطاً وجلب الـ IP الخاص به"""
    try:
        ip = socket.gethostbyname(subdomain)
        return f"{subdomain} - <span style='color: #00e676;'>[{ip}]</span>"
    except socket.gaierror:
        # إذا لم يتمكن من حله، نعيده كنطاق غير نشط
        return f"{subdomain} - <span style='color: #ef4444;'>[Dead/Unresolved]</span>"

def fetch_subdomains(domain):
    subs = set()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberOps/2.0"}
    
    # 1. جلب البيانات من crt.sh
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", headers=headers, timeout=10)
        if r.status_code == 200:
            for entry in r.json():
                name = entry.get('name_value', '')
                if '*' not in name:
                    subs.update(name.split('\n'))
    except: pass

    # 2. جلب البيانات من HackerTarget
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", headers=headers, timeout=10)
        if r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.split('\n'):
                if line:
                    sub = line.split(',')[0]
                    if sub.endswith(domain): subs.add(sub)
    except: pass

    # 3. جلب البيانات من AlienVault OTX
    try:
        r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            for entry in data.get('passive_dns', []):
                hostname = entry.get('hostname', '')
                if hostname.endswith(domain) and '*' not in hostname:
                    subs.add(hostname)
    except: pass

    # تنظيف وتصفية النطاقات
    clean_subs = {s.strip().lower() for s in subs if s.strip().lower().endswith(domain)}

    if not clean_subs:
        return ["No subdomains found or APIs rate-limited."]

    # 4. فحص النطاقات المستخرجة بسرعة باستخدام Multithreading لمعرفة الـ IPs
    resolved_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        results = executor.map(resolve_domain, clean_subs)
        for res in results:
            if res:
                resolved_results.append(res)

    return sorted(resolved_results)
def normalize_target_url(url: str):
    url = (url or "").strip()
    if not url:
        return "", "Invalid URL format."
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urllib.parse.urlparse(url)
    if not parsed.netloc:
        return "", "Invalid URL format."
    return url, None

def build_test_url(parsed, params):
    return urllib.parse.urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        urllib.parse.urlencode(params, doseq=True),
        parsed.fragment
    ))

def snippet_around(text, marker, size=90):
    idx = text.find(marker)
    if idx == -1:
        return None
    start = max(0, idx - size)
    end = min(len(text), idx + len(marker) + size)
    return text[start:end].replace("\n", " ").replace("\r", " ")

def classify_xss_context(text, marker):
    idx = text.find(marker)
    if idx == -1:
        return "html"
    prefix = text[max(0, idx - 140):idx].lower()
    if "<script" in prefix and "</script>" not in prefix:
        return "javascript"
    if re.search(r'[\w:-]+\s*=\s*["\'][^"\']*$', prefix):
        return "attribute"
    return "html"

def xss_fix_for_context(context):
    examples = {
        "html": "from markupsafe import escape\nrendered = escape(user_input)",
        "attribute": "from markupsafe import escape\nvalue = escape(user_input)  # never concatenate into event handlers",
        "javascript": "const safeData = JSON.stringify(userInput); // inject only serialized data"
    }
    mappings = {
        "html": {
            "remediation": [
                "HTML-encode untrusted data before rendering it into the page.",
                "Validate expected input format with allowlists where possible.",
                "Add a Content-Security-Policy to reduce impact if escaping is missed."
            ],
            "code_example": examples["html"]
        },
        "attribute": {
            "remediation": [
                "Attribute-encode untrusted values before inserting them into HTML attributes.",
                "Do not place user input inside inline event handlers like onclick.",
                "Prefer safe template bindings or DOM APIs instead of manual concatenation."
            ],
            "code_example": examples["attribute"]
        },
        "javascript": {
            "remediation": [
                "Do not concatenate raw user input into JavaScript blocks.",
                "Serialize untrusted values as JSON instead of injecting raw strings.",
                "Enforce a strict CSP and remove inline scripts where possible."
            ],
            "code_example": examples["javascript"]
        }
    }
    return mappings.get(context, mappings["html"])

def detect_reflected_xss(url, headers, timeout):
    findings = []
    marker = "CYOPSXSSMARK123"
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        params = {"q": ["test"]}
    baseline_url = build_test_url(parsed, params)
    try:
        baseline_text = requests.get(baseline_url, headers=headers, timeout=timeout, allow_redirects=True).text
    except Exception:
        baseline_text = ""
    for param, values in list(params.items()):
        new_params = {k: list(v) for k, v in params.items()}
        new_params[param] = [marker]
        test_url = build_test_url(parsed, new_params)
        try:
            resp = requests.get(test_url, headers=headers, timeout=timeout, allow_redirects=True)
        except Exception:
            continue
        body = resp.text
        if marker in body and marker not in baseline_text:
            context = classify_xss_context(body, marker)
            fix = xss_fix_for_context(context)
            sev = "High" if context in ("javascript", "attribute") else "Medium"
            findings.append({
                "type": f"Reflected XSS ({param})",
                "risk": sev,
                "desc": f"Input marker was reflected back in the {context} context without clear output encoding.",
                "evidence": html.escape(snippet_around(body, marker) or f"Marker '{marker}' was reflected in the response."),
                "confidence": "Likely",
                "affected_param": param,
                "safe_check": f"Marker reflection observed on parameter '{param}' during a safe probe.",
                "mitigation": "\n".join(f"{i+1}. {item}" for i, item in enumerate(fix["remediation"])),
                "code_example": fix["code_example"],
                "color": "#ffb020" if sev == "Medium" else "#ff1744"
            })
    return findings

def detect_sqli_indicators(url, headers, timeout):
    findings = []
    sql_errors = [
        "sql syntax", "warning: mysql", "unclosed quotation mark", "quoted string not properly terminated",
        "sqlite error", "postgresql", "psql:", "ora-", "syntax error near", "odbc", "jdbc"
    ]
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        params = {"id": ["1"]}
    try:
        baseline_resp = requests.get(build_test_url(parsed, params), headers=headers, timeout=timeout, allow_redirects=True)
        baseline_text = baseline_resp.text.lower()
        baseline_len = len(baseline_resp.text)
        baseline_status = baseline_resp.status_code
    except Exception:
        baseline_text = ""
        baseline_len = 0
        baseline_status = 200
    for param, values in list(params.items()):
        probe_params = {k: list(v) for k, v in params.items()}
        original = values[0] if values else "1"
        probe_params[param] = [str(original) + "'"]
        test_url = build_test_url(parsed, probe_params)
        try:
            resp = requests.get(test_url, headers=headers, timeout=timeout, allow_redirects=True)
        except Exception:
            continue
        text_lower = resp.text.lower()
        errors = [sig for sig in sql_errors if sig in text_lower and sig not in baseline_text]
        delta = abs(len(resp.text) - baseline_len)
        status_changed = resp.status_code != baseline_status
        threshold = max(120, int(max(baseline_len, 1) * 0.30))
        if errors or status_changed or delta > threshold:
            evidence_parts = []
            confidence = "Possible"
            risk = "Medium"
            if errors:
                confidence = "Likely"
                risk = "High"
                evidence_parts.append("Database-style error disclosure observed: " + ", ".join(errors[:3]))
            if status_changed:
                evidence_parts.append(f"Response status changed from {baseline_status} to {resp.status_code}.")
            if delta > threshold:
                evidence_parts.append(f"Response length changed significantly ({baseline_len} → {len(resp.text)} bytes).")
            findings.append({
                "type": f"SQL Injection Indicator ({param})",
                "risk": risk,
                "desc": "Parameter handling behaved inconsistently during a safe syntax probe, which can indicate unsafe SQL query construction.",
                "evidence": " ".join(evidence_parts),
                "confidence": confidence,
                "affected_param": param,
                "safe_check": f"The parameter '{param}' produced SQL-style error behavior or abnormal response changes during a non-destructive syntax test.",
                "mitigation": "1. Replace string-built queries with prepared statements.\n2. Validate parameter types before using them in DB logic.\n3. Remove verbose database errors from user-facing responses.\n4. Use least-privilege DB accounts.",
                "code_example": 'query = "SELECT * FROM users WHERE id = ?"\ncursor.execute(query, (user_id,))',
                "color": "#ff1744" if risk == "High" else "#ffb020"
            })
    return findings

def scan_vulnerabilities(url):
    url, error = normalize_target_url(url)
    if error:
        return [{
            "type": "Scan Error",
            "risk": "Info",
            "desc": error,
            "evidence": "",
            "confidence": "N/A",
            "affected_param": "-",
            "safe_check": None,
            "mitigation": "Use a full URL like http://example.com/page?id=1",
            "code_example": "",
            "color": "#0ea5e9"
        }]

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberOps/3.0"}
    timeout = 8
    results = []

    try:
        results.extend(detect_reflected_xss(url, headers, timeout))
    except Exception as e:
        results.append({
            "type": "XSS Scan Error",
            "risk": "Info",
            "desc": str(e),
            "evidence": "",
            "confidence": "N/A",
            "affected_param": "-",
            "safe_check": None,
            "mitigation": "Check target reachability and input parameters.",
            "code_example": "",
            "color": "#0ea5e9"
        })

    try:
        results.extend(detect_sqli_indicators(url, headers, timeout))
    except Exception as e:
        results.append({
            "type": "SQL Scan Error",
            "risk": "Info",
            "desc": str(e),
            "evidence": "",
            "confidence": "N/A",
            "affected_param": "-",
            "safe_check": None,
            "mitigation": "Check target reachability and input parameters.",
            "code_example": "",
            "color": "#0ea5e9"
        })

    try:
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        missing = [h for h in ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"] if h not in resp.headers]
        if missing:
            results.append({
                "type": "Missing Security Headers",
                "risk": "Low",
                "desc": f"The response is missing: {', '.join(missing)}.",
                "evidence": f"Observed response headers count: {len(resp.headers)}",
                "confidence": "Confirmed",
                "affected_param": "-",
                "safe_check": None,
                "mitigation": "1. Add CSP to limit script execution.\n2. Add X-Frame-Options to reduce clickjacking risk.\n3. Add X-Content-Type-Options: nosniff.",
                "code_example": "add_header Content-Security-Policy \"default-src 'self';\";\nadd_header X-Frame-Options DENY;\nadd_header X-Content-Type-Options nosniff;",
                "color": "#0ea5e9"
            })
    except Exception:
        pass

    if not results:
        results.append({
            "type": "No High-Signal Findings",
            "risk": "Info",
            "desc": "No reflected XSS or SQL error indicators were detected with safe probes.",
            "evidence": "This does not guarantee the application is secure; it only means the quick checks did not trigger.",
            "confidence": "N/A",
            "affected_param": "-",
            "safe_check": None,
            "mitigation": "Keep output encoding, prepared statements, input validation, and security headers in place.",
            "code_example": "",
            "color": "#00e676"
        })
    return results

def analyze_url_heuristics(url):
    if not url.startswith('http'): url = 'http://' + url
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    score = 0; reasons = []
    if re.match(r'\d+\.\d+\.\d+\.\d+', domain): score += 3; reasons.append("🚨 IP address used instead of domain.")
    if '@' in parsed.netloc: score += 3; reasons.append("🚨 Contains '@' to trick users.")
    if parsed.scheme == 'http': score += 1; reasons.append("⚠️ Uses unencrypted HTTP connection.")
    if any(short in domain for short in ['bit.ly', 'goo.gl', 'tinyurl.com', 'is.gd']): score += 2; reasons.append("⚠️ Uses URL shortener.")
    if len(domain.replace('www.', '').split('.')) > 3: score += 2; reasons.append("⚠️ Too many subdomains.")
    if any(domain.endswith(tld) for tld in ['.xyz', '.top', '.club', '.tk', '.ml']): score += 2; reasons.append("⚠️ Suspicious Top Level Domain (TLD).")
    
    if score == 0: risk, color = "SAFE ✅", "#00e676"
    elif score <= 2: risk, color = "SUSPICIOUS ⚠️", "#ffea00"
    else: risk, color = "MALICIOUS 🚨", "#ff1744"
    if not reasons: reasons.append("URL appears clean.")
    return {"score": score, "reasons": reasons, "risk": risk, "color": color, "domain": domain}

def ai_phishing_agent(text):
    score = 0; flags = []
    lower_text = text.lower()
    links = re.findall(r'http[s]?://[^\s]+', text)
    for word in ['urgent', 'password', 'bank', 'verify', 'account', 'login', 'click here', 'update', 'suspended', 'wallet', 'win']:
        if word in lower_text:
            score += 12
            flags.append(f"Suspicious keyword: '{word}'")
    if links:
        score += min(25, len(links) * 10)
        flags.append(f"Contains {len(links)} embedded URL(s)")
    if re.search(r'\b(immediately|urgent|asap|action required)\b', lower_text):
        score += 10
        flags.append("Pressure / urgency language detected")
    if re.search(r'\b(password|otp|code|verification code|credit card|cvv)\b', lower_text):
        score += 15
        flags.append("Sensitive credential or payment data requested")
    prob = min(score, 99)
    if prob >= 65: risk, color = "High Risk", "#ff1744"
    elif prob >= 35: risk, color = "Medium Risk", "#ffb020"
    else: risk, color = "Low Risk", "#00e676"
    return {"probability": prob, "risk_level": risk, "flags": flags if flags else ["No strong phishing indicators detected."], "color": color, "links": links}

def analyze_log_intelligence(text):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    failed = sum(1 for line in lines if re.search(r'(failed|invalid password|unauthorized|401|403)', line, re.I))
    not_found = sum(1 for line in lines if re.search(r'\b404\b|not found', line, re.I))
    admin_hits = sum(1 for line in lines if re.search(r'/admin|/wp-admin|/login|/phpmyadmin', line, re.I))
    ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    top_ips = Counter(ip_matches).most_common(5)
    findings = []
    recommendations = []
    score = 0
    if failed >= 5:
        score += 30
        findings.append(f"Repeated authentication failures detected ({failed}).")
        recommendations.append("Review authentication logs and consider rate limiting or account lockout controls.")
    if admin_hits >= 3:
        score += 20
        findings.append(f"Multiple hits to admin or login paths detected ({admin_hits}).")
        recommendations.append("Restrict administrative paths and review source IPs.")
    if not_found >= 8:
        score += 15
        findings.append(f"High number of 404 probes detected ({not_found}), which may indicate enumeration.")
        recommendations.append("Monitor for reconnaissance behavior and consider WAF or deny rules for repeated probes.")
    noisy_ips = [f"{ip} ({count} hits)" for ip, count in top_ips if count >= 3]
    if noisy_ips:
        score += 15
        findings.append("Repeated activity observed from: " + ", ".join(noisy_ips[:3]))
        recommendations.append("Review whether the repeated IPs are expected or should be blocked or challenged.")
    if not findings:
        findings.append("No strong suspicious operational patterns were detected in the provided log sample.")
        recommendations.append("Collect a larger log sample if you want higher-confidence triage.")
    return score, findings, recommendations, [ip for ip, _ in top_ips]

def analyze_code_security(text):
    findings = []
    recommendations = []
    score = 0
    checks = [
        (r'eval\s*\(', "Use of eval detected.", "Remove eval and use safe parsing or explicit dispatching instead.", 25),
        (r'subprocess\.(run|Popen)\(.*shell\s*=\s*True', "subprocess with shell=True detected.", "Avoid shell=True and pass arguments as a list.", 25),
        (r'SELECT.+["\']\s*\+|INSERT.+["\']\s*\+', "Possible string-built SQL query detected.", "Use parameterized queries or prepared statements.", 30),
        (r'render_template_string|innerHTML|document\.write', "Potential unsafe HTML rendering sink detected.", "Escape untrusted input and avoid unsafe DOM sinks.", 20),
        (r'password\s*=\s*["\'][^"\']+["\']', "Possible hard-coded password or secret detected.", "Move secrets to environment variables or a secrets manager.", 15),
    ]
    for regex, finding, rec, pts in checks:
        if re.search(regex, text, re.I | re.S):
            score += pts
            findings.append(finding)
            recommendations.append(rec)
    if not findings:
        findings.append("No high-signal insecure code patterns were detected in the pasted snippet.")
        recommendations.append("For deeper review, scan a larger code context and perform manual review.")
    return min(score, 99), findings, recommendations

def ai_security_analyst(text):
    raw = (text or "").strip()
    lower = raw.lower()
    urls = re.findall(r'http[s]?://[^\s]+', raw)
    looks_like_log = len(raw.splitlines()) >= 3 and bool(re.search(r'\b(GET|POST|PUT|DELETE|401|403|404|500|failed|error)\b', raw, re.I))
    looks_like_code = bool(re.search(r'(def\s+\w+\(|function\s+\w+\(|SELECT\s+.+FROM|<script|import\s+\w+|class\s+\w+)', raw, re.I))

    result = {
        "module": "AI Security Analyst",
        "summary": "",
        "category": "General Security Triage",
        "confidence": "Medium",
        "risk_level": "Info",
        "probability": 20,
        "findings": [],
        "recommendations": [],
        "indicators": [],
        "color": "#0ea5e9"
    }

    if looks_like_log:
        score, findings, recommendations, indicators = analyze_log_intelligence(raw)
        result.update({
            "category": "Log Intelligence",
            "summary": "Analyzed the pasted log sample for repeated failures, probing patterns, and concentrated activity.",
            "probability": min(score, 99),
            "risk_level": "High Risk" if score >= 60 else "Medium Risk" if score >= 30 else "Low Risk",
            "confidence": "High" if len(findings) >= 2 else "Medium",
            "findings": findings,
            "recommendations": recommendations,
            "indicators": indicators,
            "color": "#ff1744" if score >= 60 else "#ffb020" if score >= 30 else "#00e676"
        })
        return result

    if looks_like_code:
        score, findings, recommendations = analyze_code_security(raw)
        result.update({
            "category": "Secure Code Review",
            "summary": "Reviewed the pasted code for high-signal insecure patterns and implementation risks.",
            "probability": score,
            "risk_level": "High Risk" if score >= 60 else "Medium Risk" if score >= 25 else "Low Risk",
            "confidence": "Medium",
            "findings": findings,
            "recommendations": recommendations,
            "indicators": [],
            "color": "#ff1744" if score >= 60 else "#ffb020" if score >= 25 else "#00e676"
        })
        return result

    if urls or any(word in lower for word in ['urgent', 'verify', 'password', 'login', 'account', 'bank']):
        ph = ai_phishing_agent(raw)
        result.update({
            "category": "Message / Phishing Analysis",
            "summary": "Analyzed the message for phishing indicators such as urgency, credential requests, and embedded links.",
            "probability": ph['probability'],
            "risk_level": ph['risk_level'],
            "confidence": "Medium",
            "findings": ph['flags'],
            "recommendations": [
                "Verify sensitive requests through an official channel before taking action.",
                "Do not submit credentials through links embedded in unexpected messages.",
                "Treat messages asking for passwords, OTPs, or urgent account action as suspicious until verified."
            ],
            "indicators": ph.get('links', []),
            "color": ph['color']
        })
        return result

    if raw.startswith(("http://", "https://")):
        url_result = analyze_url_heuristics(raw)
        result.update({
            "category": "URL Risk Analysis",
            "summary": "Analyzed the URL structure for suspicious properties and risky patterns.",
            "probability": min(url_result['score'] * 10, 99),
            "risk_level": url_result['risk'],
            "confidence": "Medium",
            "findings": url_result['reasons'],
            "recommendations": [
                "Prefer HTTPS destinations from known domains.",
                "Be cautious with shortened links or domains using many subdomains.",
                "Verify brand domains manually before signing in."
            ],
            "indicators": [url_result['domain']],
            "color": url_result['color']
        })
        return result

    result.update({
        "summary": "Provided a general defensive triage of the submitted text.",
        "findings": ["The input does not strongly match a URL, log, code snippet, or phishing-style message."],
        "recommendations": ["Provide a fuller log sample, URL, code snippet, or message body for more precise analysis."]
    })
    return result

# =================================================================
# 3. ROUTES (Views)
# =================================================================

@app.route("/", methods=["GET"])
def home():
    return render_template('home_page', nmap_path=NMAP_EXE)

@app.route("/host-scan", methods=["GET", "POST"])
def host_scan():
    output, host, hosts = "", "", []
    if request.method == "POST":
        host = request.form.get("host", "").strip()
        if host:
            try:
                result = subprocess.run([NMAP_EXE, "-sn", host], capture_output=True, text=True, timeout=30)
                output = html.escape(result.stdout)
                hosts = parse_hosts(result.stdout)
                save_scan("Host Discovery", host, result.stdout)
            except Exception as e: output = f"Error: {e}"
    return render_template("ip_scan_template", output=output, host=host, hosts=hosts)

@app.route("/port-scan", methods=["GET", "POST"])
def port_scan():
    host, output, ports, service_info, ostype = "", "", [], None, None
    all_ports_checked, verisons, ostypes = False, False, False
    if request.method == "POST":
        host = request.form.get("host", "").strip()
        all_ports_checked = bool(request.form.get("all_ports"))
        verisons = bool(request.form.get("verisons"))
        ostypes = bool(request.form.get("ostypes"))
        if host:
            cmd = [NMAP_EXE, "-T4"] 
            if all_ports_checked: cmd.append("-p-")
            if ostypes: cmd.extend(["-O", "--osscan-limit"]) 
            if verisons: cmd.extend(["-sV", "--version-light"]) 
            cmd.append(host)
            try:
                result = subprocess.run(cmd, capture_output=True, text=True)
                output = html.escape(result.stdout)
                parsed = ports_info(result.stdout, host)
                ports, service_info, ostype = parsed['ports'], parsed.get('service_info'), parsed.get('os')
                save_scan("Port Scan", host, result.stdout)
            except Exception as e: output = f"Error: {e}"
    return render_template("ports_scan_template", output=output, host=host, ports=ports, service_info=service_info, ostype=ostype, all_ports=all_ports_checked, verisons=verisons, ostypes=ostypes)

@app.route("/subdomains", methods=["GET", "POST"])
def subdomains():
    domain, subs = "", []
    if request.method == "POST":
        domain = request.form.get("domain", "").strip()
        if domain:
            clean_domain = domain.replace("http://", "").replace("https://", "").replace("www.", "").split('/')[0]
            subs = fetch_subdomains(clean_domain)
            save_scan("Subdomain Enum", clean_domain, "\n".join(subs))
    return render_template("subdomain_template", domain=domain, subs=subs)

@app.route("/quick-check", methods=["GET", "POST"])
def vuln_scan():
    url, results = "", None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            results = scan_vulnerabilities(url)
            save_scan("Web Vuln Scan", url, results)
    return render_template("vuln_template", url=url, results=results)

@app.route("/url-scan", methods=["GET", "POST"])
def url_scan():
    url, result = "", None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            result = analyze_url_heuristics(url)
            save_scan("URL Scan", url, f"Risk: {result['risk']} | Score: {result['score']}")
    return render_template("url_scan_template", url=url, result=result)

@app.route("/crypto-tool", methods=["GET", "POST"])
def crypto_tool():
    input_text, output_text, algo, mode, key = "", "", "base64", "encrypt", 3
    if request.method == "POST":
        input_text = request.form.get("input_text", "")
        algo = request.form.get("algo", "base64")
        mode = request.form.get("mode", "encrypt")
        key = request.form.get("key", 3)
        try:
            if algo == "caesar":
                k = int(key) % 26 if mode == 'encrypt' else -(int(key) % 26)
                output_text = "".join(chr((ord(c) - ord('A') + k) % 26 + ord('A')) if 'A'<=c<='Z' else chr((ord(c) - ord('a') + k) % 26 + ord('a')) if 'a'<=c<='z' else c for c in input_text)
            elif algo == "base64": 
                output_text = base64.b64encode(input_text.encode()).decode() if mode == "encrypt" else base64.b64decode(input_text.encode()).decode()
            elif algo == "md5": 
                output_text = hashlib.md5(input_text.encode()).hexdigest()
            elif algo == "sha256": 
                output_text = hashlib.sha256(input_text.encode()).hexdigest()
        except Exception as e: output_text = f"Error: {e}"
    return render_template("crypto_tool_template", input_text=input_text, output_text=output_text, algo=algo, mode=mode, key=key)

@app.route("/ai-agent", methods=["GET", "POST"])
def ai_agent():
    input_text, result = "", None
    if request.method == "POST":
        input_text = request.form.get("input_text", "").strip()
        if input_text:
            result = ai_security_analyst(input_text)
            save_scan("AI Security Analyst", result.get("category", "Text Analysis"), result)
    return render_template("ai_agent_template", input_text=input_text, result=result)

@app.route("/history", methods=["GET"])
def history():
    conn = sqlite3.connect(DB_NAME); conn.row_factory = sqlite3.Row; c = conn.cursor()
    c.execute("SELECT id, scan_type, target, timestamp FROM scan_history ORDER BY id DESC LIMIT 50")
    records = c.fetchall(); conn.close()
    return render_template("history_template", records=records)

# =================================================================
# 4. EMBEDDED HTML TEMPLATES (INTERACTIVE EDITION)
# =================================================================

TEMPLATES['base_template'] = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Cyber Ops | Dashboard{% endblock %}</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root { 
            --bg-color: #0b1121; --sidebar-bg: #111827; --card-bg: #1e293b;
            --text-main: #f8fafc; --text-muted: #94a3b8; --accent-green: #00e676;
            --border-color: #334155; --hover-bg: #1f2937;
        }
        
        * { box-sizing: border-box; }
        body { margin: 0; font-family: 'Poppins', sans-serif; background: var(--bg-color); color: var(--text-main); display: flex; height: 100vh; overflow: hidden; }
        
        /* Animations */
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        @keyframes pulseGlow { 0% { box-shadow: 0 0 5px rgba(0, 230, 118, 0.2); } 50% { box-shadow: 0 0 20px rgba(0, 230, 118, 0.6); } 100% { box-shadow: 0 0 5px rgba(0, 230, 118, 0.2); } }

        .fade-in { animation: fadeIn 0.5s ease-out forwards; }
        
        /* Loader Overlay */
        #loader-overlay {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(11, 17, 33, 0.85); backdrop-filter: blur(5px);
            display: none; justify-content: center; align-items: center; flex-direction: column;
            z-index: 9999;
        }
        .spinner {
            width: 60px; height: 60px; border: 5px solid var(--border-color);
            border-top: 5px solid var(--accent-green); border-radius: 50%;
            animation: spin 1s linear infinite, pulseGlow 2s infinite;
        }
        .loader-text { margin-top: 20px; font-family: monospace; color: var(--accent-green); font-size: 16px; letter-spacing: 2px;}

        /* Sidebar Styles */
        .sidebar { width: 260px; background: var(--sidebar-bg); border-right: 1px solid var(--border-color); display: flex; flex-direction: column; z-index: 100; }
        .sidebar-logo { padding: 25px 20px; font-size: 20px; font-weight: 800; color: var(--accent-green); text-shadow: 0 0 10px rgba(0, 230, 118, 0.4); display: flex; align-items: center; justify-content: center; gap: 10px; letter-spacing: 1.5px; text-transform: uppercase; border-bottom: 1px solid var(--border-color); }
        .nav-links { flex: 1; padding: 10px 0; overflow-y: auto; }
        .nav-category { color: #64748b; font-size: 11px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; padding: 15px 25px 5px 25px; margin-top: 5px; }
        .nav-links a { padding: 12px 25px; color: var(--text-muted); text-decoration: none; display: flex; align-items: center; gap: 15px; font-size: 14px; font-weight: 500; transition: all 0.2s; border-left: 3px solid transparent; }
        .nav-links a i { width: 20px; text-align: center; font-size: 16px; }
        .nav-links a:hover, .nav-links a.active { background: rgba(0, 230, 118, 0.05); color: var(--accent-green); border-left-color: var(--accent-green); }
        .sidebar-footer { padding: 20px; text-align: center; border-top: 1px solid var(--border-color); font-size: 12px; color: var(--text-muted); }
        .sidebar-footer strong { color: var(--text-main); font-weight: 600;}

        /* Main Content Styles */
        .main-content { flex: 1; overflow-y: auto; padding: 30px 40px; }
        .top-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 1px solid var(--border-color); }
        .top-bar h1 { margin: 0; font-weight: 700; font-size: 24px; display: flex; align-items: center; gap: 10px; }
        .user-badge { background: rgba(0, 230, 118, 0.1); border: 1px solid var(--accent-green); padding: 8px 16px; border-radius: 20px; color: var(--accent-green); font-size: 13px; font-weight: 600; display: flex; align-items: center; gap: 8px; }

        /* Generic Forms/Containers */
        .container { background: var(--card-bg); padding: 30px; border-radius: 12px; border: 1px solid var(--border-color); max-width: 800px; margin-bottom: 20px; position: relative;}
        label { display: block; margin-bottom: 8px; font-weight: 500; color: var(--text-muted); font-size: 14px; margin-top: 20px; }
        input[type="text"], select, textarea { width: 100%; padding: 12px; background: #0b1120; border: 1px solid var(--border-color); border-radius: 8px; color: #fff; outline: none; transition: 0.3s; font-family: 'Poppins', sans-serif;}
        input:focus, select:focus { border-color: var(--accent-green); box-shadow: 0 0 8px rgba(0, 230, 118, 0.2);}
        button.action-btn { width: 100%; padding: 14px; margin-top: 25px; background: var(--accent-green); color: #000; border: none; border-radius: 8px; font-weight: 700; cursor: pointer; transition: 0.3s; text-transform: uppercase; letter-spacing: 1px;}
        button.action-btn:hover { background: #00c853; transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0, 230, 118, 0.3);}
        
        /* Tables */
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background: var(--card-bg); border-radius: 8px; overflow: hidden;}
        th, td { padding: 15px; text-align: left; border-bottom: 1px solid var(--border-color); font-size: 13px;}
        th { color: var(--accent-green); background: rgba(0, 230, 118, 0.05); font-weight: 600;}
        tr:hover td { background: var(--hover-bg); }

        /* Copy Button */
        .copy-btn { position: absolute; top: 15px; right: 15px; background: #334155; color: #fff; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; font-size: 12px; transition: 0.2s; }
        .copy-btn:hover { background: var(--accent-green); color: #000; }

        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: var(--bg-color); }
        ::-webkit-scrollbar-thumb { background: var(--border-color); border-radius: 4px; }
    </style>
</head>
<body>

    <div id="loader-overlay">
        <div class="spinner"></div>
        <div class="loader-text" id="loader-msg">INITIALIZING MODULE...</div>
    </div>

    <div class="sidebar">
        <div class="sidebar-logo">
            <i class="fas fa-shield-halved"></i> CYBER OPS
        </div>
        <div class="nav-links">
            <a href="/"><i class="fas fa-chart-line"></i> Dashboard</a>
            
            <div class="nav-category">NETWORK & HOSTS</div>
            <a href="/host-scan"><i class="fas fa-network-wired"></i> Host Discovery</a>
            <a href="/port-scan"><i class="fas fa-door-open"></i> Port Scan</a>
            
            <div class="nav-category">WEB & APP SEC</div>
            <a href="/quick-check"><i class="fas fa-bug"></i> Web Vuln Scan</a>
            <a href="/url-scan"><i class="fas fa-link"></i> URL Analyzer</a>
            <a href="/xsstrike"><i class="fas fa-spider"></i> XSStrike Scanner</a>
            <div class="nav-category">OSINT & RECON</div>
            <a href="/subdomains"><i class="fas fa-sitemap"></i> Subdomains</a>
            
            <div class="nav-category">UTILITIES</div>
            <a href="/crypto-tool"><i class="fas fa-lock"></i> Crypto Utils</a>
            <a href="/ai-agent"><i class="fas fa-robot"></i> AI Security Analyst</a>
            <a href="/history"><i class="fas fa-history"></i> Scan History</a>
        </div>
        <div class="sidebar-footer">
            Built by <strong>Ghaith Oday Ibrahim</strong>
        </div>
    </div>
    
    <div class="main-content">
        <div class="top-bar">
            <h1>{% block page_title %}{% endblock %}</h1>
            <div class="user-badge"><i class="fas fa-user"></i> Ghaith Oday</div>
        </div>
        {% block content %}{% endblock %}
    </div>

    <script>
        // Set Active Nav Link
        document.addEventListener("DOMContentLoaded", function() {
            const currentPath = window.location.pathname;
            document.querySelectorAll('.nav-links a').forEach(link => { 
                if(link.getAttribute('href') === currentPath) link.classList.add('active'); 
            });
        });

        // Show Loader on Form Submit
        document.querySelectorAll('form').forEach(form => {
            form.addEventListener('submit', function() {
                const btn = this.querySelector('button[type="submit"]');
                const overlay = document.getElementById('loader-overlay');
                const msg = document.getElementById('loader-msg');
                
                // Change text based on button
                if(btn && btn.innerText.includes('Scan')) msg.innerText = 'EXECUTING SCAN... PLEASE WAIT';
                else if(btn && btn.innerText.includes('Analyze')) msg.innerText = 'ANALYZING TARGET...';
                else msg.innerText = 'PROCESSING REQUEST...';

                overlay.style.display = 'flex';
            });
        });

        // Copy to Clipboard Function
        function copyToClipboard(elementId) {
            const text = document.getElementById(elementId).innerText;
            navigator.clipboard.writeText(text).then(() => {
                const btn = event.target;
                const originalText = btn.innerHTML;
                btn.innerHTML = '<i class="fas fa-check"></i> Copied!';
                btn.style.background = 'var(--accent-green)';
                btn.style.color = '#000';
                setTimeout(() => {
                    btn.innerHTML = originalText;
                    btn.style.background = '#334155';
                    btn.style.color = '#fff';
                }, 2000);
            });
        }
    </script>
</body>
</html>
"""

TEMPLATES['home_page'] = """
{% extends "base_template" %}
{% block page_title %}<i class="fas fa-chart-line" style="color: var(--accent-green);"></i> Command Center{% endblock %}
{% block content %}
<style>
    .status-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 30px; }
    .status-card { background: var(--card-bg); border-radius: 12px; padding: 25px; border-left: 4px solid var(--accent-green); transition: 0.3s; cursor: default; }
    .status-card:hover { transform: translateY(-5px); box-shadow: 0 10px 20px rgba(0,0,0,0.2); }
    .status-card h3 { margin: 0 0 15px 0; font-size: 16px; font-weight: 600; display: flex; align-items: center; gap: 10px; }
    .status-card p { margin: 5px 0; font-size: 13px; color: var(--text-muted); line-height: 1.6;}
    .badge-online { display: inline-block; margin-top: 15px; border: 1px solid var(--accent-green); color: var(--accent-green); padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; letter-spacing: 1px; animation: pulseGlow 2s infinite; }
    .view-logs-link { display: inline-block; margin-top: 15px; color: #f43f5e; text-decoration: none; font-size: 13px; font-weight: 600; transition: 0.2s; }
    .view-logs-link:hover { opacity: 0.8; transform: translateX(5px);}

    .action-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; }
    .action-btn-card { background: var(--card-bg); border-radius: 12px; padding: 25px 20px; text-align: center; text-decoration: none; color: #fff; border-left: 4px solid var(--accent-green); transition: transform 0.2s, background 0.2s; display: flex; flex-direction: column; align-items: center; gap: 12px; }
    .action-btn-card:hover { background: var(--hover-bg); transform: translateY(-3px); box-shadow: 0 5px 15px rgba(0,0,0,0.3); }
    .action-btn-card i { font-size: 24px; }
    .action-btn-card span { font-weight: 600; font-size: 14px; }
</style>

<div class="status-grid fade-in">
    <div class="status-card" style="border-left-color: #0ea5e9;">
        <h3><i class="fas fa-server" style="color: #0ea5e9;"></i> System Status</h3>
        <p>All modules are loaded and operational.</p>
        <span class="badge-online" style="border-color:#0ea5e9; color:#0ea5e9;">ONLINE</span>
    </div>
    <div class="status-card" style="border-left-color: #eab308; animation-delay: 0.1s;">
        <h3><i class="fas fa-bolt" style="color: #eab308;"></i> Active Engines</h3>
        <p><strong style="color: #fff;">Nmap:</strong> Detected at Core</p>
        <p><strong style="color: #fff;">Database:</strong> SQLite v3 Active</p>
    </div>
    <div class="status-card" style="border-left-color: #ec4899; animation-delay: 0.2s;">
        <h3><i class="fas fa-database" style="color: #ec4899;"></i> Database</h3>
        <p>SQLite logging is active. Scans are securely stored.</p>
        <a href="/history" class="view-logs-link">View Logs &rarr;</a>
    </div>
</div>

<div class="action-grid fade-in" style="animation-delay: 0.3s;">
    <a href="/host-scan" class="action-btn-card" style="border-left-color: #3b82f6;"><i class="fas fa-network-wired" style="color: #3b82f6;"></i><span>[1] Host Discovery</span></a>
    <a href="/port-scan" class="action-btn-card" style="border-left-color: #10b981;"><i class="fas fa-door-open" style="color: #10b981;"></i><span>[2] Port Scan</span></a>
    <a href="/url-scan" class="action-btn-card" style="border-left-color: #ef4444;"><i class="fas fa-link" style="color: #ef4444;"></i><span>[3] URL Analyzer</span></a>
    <a href="/quick-check" class="action-btn-card" style="border-left-color: #8b5cf6;"><i class="fas fa-bug" style="color: #8b5cf6;"></i><span>[4] Web Vuln Scan</span></a>
    <a href="/crypto-tool" class="action-btn-card" style="border-left-color: #06b6d4;"><i class="fas fa-lock" style="color: #06b6d4;"></i><span>[5] Crypto Utils</span></a>
    <a href="/subdomains" class="action-btn-card" style="border-left-color: #f59e0b;"><i class="fas fa-sitemap" style="color: #f59e0b;"></i><span>[6] Subdomains</span></a>
    <a href="/ai-agent" class="action-btn-card" style="border-left-color: #db2777;"><i class="fas fa-robot" style="color: #db2777;"></i><span>[7] AI Security Analyst</span></a>
    <a href="/xsstrike" class="action-btn-card" style="border-left-color: #f59e0b;">
    <i class="fas fa-spider" style="color: #f59e0b;"></i>
    <span>[8] XSStrike Scanner</span>
</a>
    <a href="/history" class="action-btn-card" style="border-left-color: #64748b;"><i class="fas fa-history" style="color: #64748b;"></i><span>[9] Scan History</span></a>
    
</div>
{% endblock %}
"""

TEMPLATES['vuln_template'] = """
{% extends "base_template" %}
{% block page_title %}<i class="fas fa-bug"></i> Web Vuln Scan{% endblock %}
{% block content %}
    <div class="container fade-in">
        <form method="POST">
            <label>Target URL:</label>
            <input type="text" name="url" value="{{ url }}" required placeholder="http://example.com/page?id=1">
            <button type="submit" class="action-btn"><i class="fas fa-search"></i> Run Safe XSS / SQL Checks</button>
        </form>
        <p style="color: var(--text-muted); font-size: 13px; margin-top: 14px; margin-bottom: 0;">This module uses safe probes to look for reflected XSS and SQL error indicators, then suggests remediation and secure code fixes.</p>
    </div>
    {% if results %}
        <div class="fade-in" style="animation-delay: 0.2s; display:grid; gap: 18px;">
            {% for res in results %}
                <div class="container" style="border-left: 4px solid {{ res.color }};">
                    <div style="display:flex; justify-content:space-between; gap:16px; align-items:flex-start; flex-wrap:wrap;">
                        <div>
                            <h3 style="color: {{ res.color }}; margin-top:0; margin-bottom:8px;"><i class="fas fa-exclamation-triangle"></i> {{ res.type }}</h3>
                            <p style="margin: 0 0 6px 0;"><strong>Risk:</strong> <span style="color: {{ res.color }}; font-weight:bold;">{{ res.risk }}</span></p>
                            <p style="margin: 0;"><strong>Confidence:</strong> {{ res.confidence }}</p>
                        </div>
                        {% if res.affected_param and res.affected_param != '-' %}
                        <div style="background:#0b1120; border:1px solid var(--border-color); padding:10px 14px; border-radius:8px; min-width:160px;">
                            <div style="font-size:12px; color:var(--text-muted);">Affected Parameter</div>
                            <div style="font-weight:700; margin-top:4px;">{{ res.affected_param }}</div>
                        </div>
                        {% endif %}
                    </div>
                    <p><strong>Details:</strong> {{ res.desc }}</p>
                    {% if res.evidence %}
                    <div style="background: rgba(14,165,233,0.08); border: 1px solid #0ea5e9; padding: 15px; border-radius: 8px; margin-top: 14px;">
                        <h4 style="margin-top:0; color:#7dd3fc;"><i class="fas fa-microscope"></i> Evidence</h4>
                        <p style="margin:0; font-size:14px; word-break:break-word;">{{ res.evidence|safe }}</p>
                    </div>
                    {% endif %}
                    {% if res.safe_check %}
                    <div style="background: rgba(245,158,11,0.08); border: 1px solid #f59e0b; padding: 15px; border-radius: 8px; margin-top: 14px;">
                        <h4 style="margin-top:0; color:#fbbf24;"><i class="fas fa-flask"></i> Safe Verification Note</h4>
                        <p style="margin:0; font-size:14px;">{{ res.safe_check }}</p>
                    </div>
                    {% endif %}
                    {% if res.mitigation %}
                    <div style="background: rgba(0, 230, 118, 0.05); border: 1px solid var(--accent-green); padding: 15px; border-radius: 8px; margin-top: 14px;">
                        <h4 style="margin-top: 0; color: var(--accent-green);"><i class="fas fa-shield-alt"></i> Recommended Fix</h4>
                        <p style="margin-bottom: 0; font-size: 14px; white-space: pre-line;">{{ res.mitigation }}</p>
                    </div>
                    {% endif %}
                    {% if res.code_example %}
                    <div style="margin-top: 14px;">
                        <h4 style="margin-bottom: 10px; color: var(--text-muted);"><i class="fas fa-code"></i> Secure Code Example</h4>
                        <pre style="color: #a7f3d0; background: #0b1120; padding: 15px; border-radius: 8px; word-wrap: break-word; font-family: monospace; white-space: pre-wrap;">{{ res.code_example }}</pre>
                    </div>
                    {% endif %}
                </div>
            {% endfor %}
        </div>
    {% endif %}
{% endblock %}
"""

TEMPLATES['ip_scan_template'] = """
{% extends "base_template" %}
{% block page_title %}<i class="fas fa-network-wired"></i> Host Discovery{% endblock %}
{% block content %}
    <div class="container fade-in">
        <form method="POST">
            <label>Target IP/Subnet (e.g. 192.168.1.0/24):</label>
            <input type="text" name="host" value="{{ host }}" required placeholder="Enter Target IP">
            <button type="submit" class="action-btn"><i class="fas fa-radar"></i> Discover Hosts</button>
        </form>
    </div>
    {% if hosts %}
    <div class="fade-in" style="animation-delay: 0.2s;">
        <h3 style="color: var(--text-muted);"><i class="fas fa-list"></i> Discovery Results</h3>
        <table>
            <tr><th>IP Address</th><th>Status</th><th>Latency</th><th>MAC / Vendor</th></tr>
            {% for h in hosts %}
            <tr>
                <td style="font-weight: 600;">{{ h.host }}</td>
                <td>{% if h.up %}<span style="background: rgba(0, 230, 118, 0.2); color:#00e676; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight:bold;">UP</span>{% else %}<span style="background: rgba(255, 23, 68, 0.2); color:#ff1744; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight:bold;">DOWN</span>{% endif %}</td>
                <td>{{ h.latency or '-' }}</td>
                <td style="color: var(--text-muted);">{{ h.mac or '-' }} <br><small>{{ h.vendor or '' }}</small></td>
            </tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}
{% endblock %}
"""

TEMPLATES['ports_scan_template'] = """
{% extends "base_template" %}
{% block page_title %}<i class="fas fa-door-open"></i> Port Scan{% endblock %}
{% block content %}
    <div class="container fade-in">
        <form method="POST">
            <label>Target IP:</label>
            <input type="text" name="host" value="{{ host }}" required placeholder="192.168.x.x">
            <button type="submit" class="action-btn"><i class="fas fa-search-location"></i> Scan Ports</button>
        </form>
    </div>
    {% if ports %}
    <div class="fade-in" style="animation-delay: 0.2s;">
        <h3 style="color: var(--text-muted);"><i class="fas fa-list"></i> Open Ports</h3>
        <table>
            <tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>
            {% for p in ports %}
            <tr>
                <td style="color: var(--accent-green); font-weight: bold;">{{ p.port }}</td>
                <td><span style="color:#0ea5e9;">{{ p.state }}</span></td>
                <td>{{ p.service }}</td>
                <td style="color: var(--text-muted);">{{ p.version or 'Unknown' }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}
{% endblock %}
"""

TEMPLATES['subdomain_template'] = """
{% extends "base_template" %}
{% block page_title %}<i class="fas fa-sitemap"></i> Subdomain Enumeration{% endblock %}
{% block content %}
    <div class="container fade-in">
        <form method="POST">
            <label>Target Domain (e.g., example.com):</label>
            <input type="text" name="domain" placeholder="example.com" value="{{ domain }}" required>
            <button type="submit" class="action-btn"><i class="fas fa-search"></i> Hunt Subdomains</button>
        </form>
    </div>

    {% if subs %}
    <div class="container fade-in">
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 15px; margin-bottom: 15px;">
            <h3 style="margin:0;">Discovered Subdomains ({{ subs|length if subs[0] != 'No subdomains found or APIs rate-limited.' else 0 }})</h3>
            <button class="copy-btn" onclick="copyToClipboard('sub-list')"><i class="fas fa-copy"></i> Copy List</button>
        </div>
        
        <div id="sub-list" style="background: #000; padding: 20px; border-radius: 8px; font-family: monospace; font-size: 14px; max-height: 400px; overflow-y: auto; line-height: 1.8;">
            {% for sub in subs %}
                <div>{{ sub | safe }}</div>
            {% endfor %}
        </div>
    </div>
    {% endif %}
{% endblock %}
"""

TEMPLATES['url_scan_template'] = """
{% extends "base_template" %}
{% block page_title %}<i class="fas fa-link"></i> URL Analyzer{% endblock %}
{% block content %}
    <div class="container fade-in">
        <form method="POST">
            <label>Suspicious URL to Analyze:</label>
            <input type="text" name="url" value="{{ url }}" required placeholder="http://suspicious-link.com/login">
            <button type="submit" class="action-btn"><i class="fas fa-shield-virus"></i> Analyze URL</button>
        </form>
    </div>
    {% if result %}
    <div class="container fade-in" style="border-left: 4px solid {{ result.color }}; animation-delay: 0.2s;">
        <h2 style="color: {{ result.color }}; margin-top:0;">{{ result.risk }}</h2>
        <p><strong>Threat Score:</strong> {{ result.score }}/10</p>
        <h4 style="margin-bottom: 10px; color: var(--text-muted);">Analysis Report:</h4>
        <ul style="line-height: 1.8; color: var(--text-main);">
            {% for r in result.reasons %}
                <li>{{ r }}</li>
            {% endfor %}
        </ul>
    </div>
    {% endif %}
{% endblock %}
"""

TEMPLATES['crypto_tool_template'] = """
{% extends "base_template" %}
{% block page_title %}<i class="fas fa-lock"></i> Crypto Utils{% endblock %}
{% block content %}
    <div class="container fade-in">
        <form method="POST">
            <label>Input Text:</label>
            <input type="text" name="input_text" value="{{ input_text }}" required placeholder="Enter text here...">
            
            <div style="display: flex; gap: 15px;">
                <div style="flex: 1;">
                    <label>Algorithm:</label>
                    <select name="algo">
                        <option value="base64" {% if algo == 'base64' %}selected{% endif %}>Base64</option>
                        <option value="md5" {% if algo == 'md5' %}selected{% endif %}>MD5 Hash</option>
                        <option value="sha256" {% if algo == 'sha256' %}selected{% endif %}>SHA-256 Hash</option>
                        <option value="caesar" {% if algo == 'caesar' %}selected{% endif %}>Caesar Cipher</option>
                    </select>
                </div>
                <div style="flex: 1;">
                    <label>Mode:</label>
                    <select name="mode">
                        <option value="encrypt" {% if mode == 'encrypt' %}selected{% endif %}>Encrypt / Encode</option>
                        <option value="decrypt" {% if mode == 'decrypt' %}selected{% endif %}>Decrypt / Decode</option>
                    </select>
                </div>
            </div>
            
            <button type="submit" class="action-btn"><i class="fas fa-key"></i> Execute</button>
        </form>
    </div>
    {% if output_text %}
    <div class="container fade-in" style="animation-delay: 0.2s; padding-top: 40px;">
        <button class="copy-btn" onclick="copyToClipboard('crypto-result')"><i class="fas fa-copy"></i> Copy</button>
        <label style="margin-top: 0;">Output Result:</label>
        <pre id="crypto-result" style="color: #a7f3d0; background: #0b1120; padding: 15px; border-radius: 8px; word-wrap: break-word; font-family: monospace;">{{ output_text }}</pre>
    </div>
    {% endif %}
{% endblock %}
"""

TEMPLATES['ai_agent_template'] = """
{% extends "base_template" %}
{% block page_title %}<i class="fas fa-robot"></i> AI Security Analyst{% endblock %}
{% block content %}
    <div class="container fade-in">
        <form method="POST">
            <label>Paste a message, URL, log sample, or code snippet:</label>
            <textarea name="input_text" required placeholder="Paste suspicious text, logs, code, or a URL here..." style="width:100%; min-height: 180px; padding: 14px; background:#0b1120; border:1px solid var(--border-color); border-radius:8px; color:#fff; resize:vertical; font-family:Consolas, monospace;">{{ input_text }}</textarea>
            <button type="submit" class="action-btn"><i class="fas fa-brain"></i> Run AI Analysis</button>
        </form>
        <p style="color: var(--text-muted); font-size: 13px; margin-top: 14px; margin-bottom: 0;">The analyst can triage phishing-style messages, logs, code snippets, and URLs with explanations and recommendations.</p>
    </div>
    {% if result %}
    <div class="container fade-in" style="border-left: 4px solid {{ result.color }}; animation-delay: 0.2s;">
        <div style="display: flex; justify-content: space-between; align-items: center; gap:16px; flex-wrap:wrap;">
            <div>
                <h2 style="color: {{ result.color }}; margin-top:0; margin-bottom:8px;">{{ result.risk_level }}</h2>
                <div style="color: var(--text-muted); font-size: 14px;">{{ result.category }}</div>
            </div>
            <div style="display:flex; gap:12px; flex-wrap:wrap;">
                <div style="background: #0b1120; padding: 10px 18px; border-radius: 8px; border: 1px solid var(--border-color);">
                    Probability: <strong style="color: {{ result.color }}; font-size: 18px;">{{ result.probability }}%</strong>
                </div>
                <div style="background: #0b1120; padding: 10px 18px; border-radius: 8px; border: 1px solid var(--border-color);">
                    Confidence: <strong>{{ result.confidence }}</strong>
                </div>
            </div>
        </div>
        <div style="margin-top:18px; background: rgba(14,165,233,0.08); border:1px solid #0ea5e9; padding:14px; border-radius:8px;">
            <strong style="color:#7dd3fc;">Summary:</strong>
            <div style="margin-top:8px;">{{ result.summary }}</div>
        </div>
        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-top:18px;">
            <div style="background:#111827; border:1px solid var(--border-color); border-radius:10px; padding:16px;">
                <h4 style="margin-top:0; color: var(--text-muted);">Detected Findings</h4>
                <ul style="line-height:1.8; padding-left:18px; margin-bottom:0;">
                    {% for f in result.findings %}
                        <li>{{ f }}</li>
                    {% endfor %}
                </ul>
            </div>
            <div style="background:#111827; border:1px solid var(--border-color); border-radius:10px; padding:16px;">
                <h4 style="margin-top:0; color: var(--text-muted);">Recommendations</h4>
                <ul style="line-height:1.8; padding-left:18px; margin-bottom:0;">
                    {% for rec in result.recommendations %}
                        <li>{{ rec }}</li>
                    {% endfor %}
                </ul>
            </div>
        </div>
        {% if result.indicators %}
        <div style="margin-top:18px; background: rgba(219,39,119,0.08); border:1px solid #db2777; padding:14px; border-radius:8px;">
            <h4 style="margin-top:0; color:#f9a8d4;">Indicators</h4>
            <div style="display:flex; gap:8px; flex-wrap:wrap;">
                {% for item in result.indicators %}
                    <span style="background:#0b1120; border:1px solid var(--border-color); border-radius:999px; padding:8px 12px; font-size:13px;">{{ item }}</span>
                {% endfor %}
            </div>
        </div>
        {% endif %}
    </div>
    {% endif %}
{% endblock %}
"""

TEMPLATES['history_template'] = """
{% extends "base_template" %}
{% block page_title %}<i class="fas fa-history"></i> Scan History{% endblock %}
{% block content %}
    <div class="fade-in">
        <table>
            <tr><th>Scan ID</th><th>Module Type</th><th>Target</th><th>Timestamp</th></tr>
            {% for r in records %}
            <tr>
                <td>#{{ r.id }}</td>
                <td style="font-weight: bold; color: var(--accent-green);">{{ r.scan_type }}</td>
                <td>{{ r.target }}</td>
                <td style="color: var(--text-muted);">{{ r.timestamp }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
{% endblock %}
"""
TEMPLATES['xsstrike_template'] = """
{% extends "base_template" %}
{% block page_title %}<i class="fas fa-spider"></i> XSStrike Scanner{% endblock %}
{% block content %}
<div class="container fade-in">
    <form method="POST" action="/xsstrike">
        <label>Target URL:</label>
        <input type="text" name="url" value="{{ url }}" placeholder="http://example.com/page?id=1" required>
        
        <label style="display: flex; align-items: center; gap: 10px; cursor: pointer; margin-top: 15px;">
            <input type="checkbox" name="crawl" value="true" style="width: auto;">
            Crawl target (--crawl)
        </label>
        
        <button type="submit" class="action-btn">Launch XSStrike</button>
    </form>
</div>

{% if output %}
<div class="container fade-in">
    <h3>Terminal Output</h3>
    <pre>{{ output | safe }}</pre>
</div>
{% endif %}
{% endblock %}
"""
if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
