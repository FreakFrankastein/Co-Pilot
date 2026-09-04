#!/usr/bin/env python3
"""
Pentest Co-Pilot Scanner - Advanced Edition
=============================================
Menggabungkan tool open-source terbaik:
  - Nuclei  : ALL templates (bukan hanya beberapa tag)
  - sqlmap  : termasuk JSON parameter (inject marker * otomatis)
  - Dalfox  : XSS dengan syarat ketat (param + evidence wajib ada)
  - Smuggler: HTTP Smuggling check

Status finding:
  confirmed = bukti eksplisit dari tool (sqlmap injectable, Dalfox param+evidence)
  candidate = indikasi template/heuristic → WAJIB verifikasi manual

Cara pakai:
  python3 scanner.py --insecure             ← mode Burp (ITDC pakai ini)
  python3 scanner.py --insecure --skip-sqlmap ← kalau target sangat lambat
  python3 scanner.py --url https://target.com ← mode crawl tanpa Burp
"""

import argparse, json, os, re, subprocess, sys, time, tempfile, shutil
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

# ── Dependencies ─────────────────────────────────────────────────────────────
try:
    from cvss4 import calculate as cvss4_calculate, CVSS4Error
except ImportError:
    print("[!] cvss4.py tidak ditemukan. Letakkan di folder yang sama.")
    sys.exit(1)

try:
    from poc_generator import generate_poc
    HAS_POC = True
except ImportError:
    HAS_POC = False

# ── Konstanta ─────────────────────────────────────────────────────────────────
CAPTURED_DIR  = "captured_requests"
FINDINGS_PATH = "findings.json"
QUEUE_PATH    = "scan_queue.json"
MAX_RETRIES   = 2
BACKOFF       = [15, 45]

# Semua template Nuclei (tanpa filter tag = coverage maksimal)
NUCLEI_TAGS_DEFAULT = None  # None = pakai semua template

CVSS_VECTOR = {
    "critical": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "high":     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
    "medium":   "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "low":      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "info":     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
}

# ── Storage ───────────────────────────────────────────────────────────────────
def load_findings():
    if not os.path.exists(FINDINGS_PATH):
        return []
    try:
        with open(FINDINGS_PATH) as f:
            return json.load(f)
    except Exception:
        return []

def save_finding(finding):
    findings = load_findings()
    # Dedup: skip kalau endpoint + name sudah ada
    key = (finding.get("endpoint",""), finding.get("name",""))
    for ex in findings:
        if (ex.get("endpoint",""), ex.get("name","")) == key:
            return
    if HAS_POC and not finding.get("poc"):
        try:
            finding["poc"] = generate_poc(finding)
        except Exception:
            pass
    findings.append(finding)
    with open(FINDINGS_PATH, "w") as f:
        json.dump(findings, f, indent=2)

def make_finding(endpoint, name, sev, source, status,
                  param=None, method=None, inj_type=None,
                  evidence=None, note=None):
    vector = CVSS_VECTOR.get(sev, CVSS_VECTOR["info"])
    try:
        r = cvss4_calculate(vector)
        score, csev = r.base_score, r.severity
    except CVSS4Error:
        score, csev = None, None
    return {
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "endpoint":      endpoint, "source":        source,
        "name":          name,     "severity":      sev,
        "status":        status,   "cvss_vector":   vector,
        "cvss_score":    score,    "cvss_severity": csev,
        "parameter":     param,    "method":        method,
        "injection_type": inj_type, "evidence":     evidence,
        "note":          note,
    }

# ── Queue ─────────────────────────────────────────────────────────────────────
def load_queue():
    if not os.path.exists(CAPTURED_DIR):
        print(f"[!] Folder '{CAPTURED_DIR}' tidak ada.")
        print("    Load CopilotExtension.py ke Burp dan browsing via Burp Proxy dulu.")
        sys.exit(1)
    files = sorted(f for f in os.listdir(CAPTURED_DIR) if f.endswith(".txt"))
    if not files:
        print(f"[!] '{CAPTURED_DIR}' kosong. Browsing dulu via Burp Proxy.")
        sys.exit(1)
    if os.path.exists(QUEUE_PATH):
        with open(QUEUE_PATH) as f:
            q = json.load(f)
        existing = {i["file"] for i in q}
        for fn in files:
            if fn not in existing:
                q.append({"file": fn, "status": "pending", "attempts": 0})
        return q
    return [{"file": fn, "status": "pending", "attempts": 0} for fn in files]

def save_queue(q):
    with open(QUEUE_PATH, "w") as f:
        json.dump(q, f, indent=2)

# ── Request parser ────────────────────────────────────────────────────────────
def parse_request(filepath):
    info = {
        "method": "GET", "path": "/", "host": "", "url": "",
        "content_type": "", "has_url_params": False,
        "has_form_body": False, "is_json": False,
        "json_body": None, "raw_body": "",
    }
    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
        lines = content.splitlines()
        if not lines:
            return info
        m = re.match(r"(GET|POST|PUT|DELETE|PATCH)\s+(\S+)\s+HTTP", lines[0].strip())
        if m:
            info["method"] = m.group(1)
            info["path"]   = m.group(2)
            info["has_url_params"] = "?" in info["path"]
        header_done = False
        body_lines  = []
        for line in lines[1:]:
            if not header_done:
                ll = line.lower().strip()
                if not line.strip():
                    header_done = True
                    continue
                if ll.startswith("host:"):
                    info["host"] = line.split(":",1)[1].strip() \
                                        .replace(":443","").replace(":80","")
                if ll.startswith("content-type:"):
                    ct = line.split(":",1)[1].strip().lower()
                    info["content_type"] = ct
                    info["is_json"]      = "application/json" in ct
                    info["has_form_body"]= ("application/x-www-form-urlencoded" in ct
                                             or "multipart" in ct)
            else:
                body_lines.append(line)
        info["raw_body"] = "\n".join(body_lines).strip()
        if info["is_json"] and info["raw_body"]:
            try:
                info["json_body"] = json.loads(info["raw_body"])
            except Exception:
                pass
        if info["host"]:
            info["url"] = f"https://{info['host']}{info['path']}"
    except Exception:
        pass
    return info

# ── JSON SQLi helper ──────────────────────────────────────────────────────────
def make_json_sqlmap_files(filepath, info):
    """
    Untuk JSON body, buat file request terpisah dengan tanda * di tiap
    nilai string/integer JSON. sqlmap akan injeksikan payload di tanda *.
    Return list of (filepath, field_name) yang bisa ditest.
    """
    if not info["json_body"] or not isinstance(info["json_body"], dict):
        return []

    result = []
    body   = info["json_body"]

    for key, val in body.items():
        if not isinstance(val, (str, int, float)):
            continue
        # Buat copy body dengan tanda * di nilai ini
        modified = dict(body)
        modified[key] = f"{val}*"
        new_body = json.dumps(modified)

        # Buat file request baru dengan body yang sudah dimodifikasi
        try:
            with open(filepath, "r", errors="ignore") as f:
                original = f.read()
            # Ganti body lama dengan body baru
            parts   = original.split("\r\n\r\n", 1)
            if len(parts) < 2:
                parts = original.split("\n\n", 1)
            if len(parts) == 2:
                new_content = parts[0] + "\r\n\r\n" + new_body
            else:
                new_content = original + "\r\n\r\n" + new_body

            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False,
                prefix=f"sqlmap_json_{key}_"
            )
            tmp.write(new_content)
            tmp.close()
            result.append((tmp.name, key))
        except Exception:
            pass

    return result

# ── Tool wrappers ─────────────────────────────────────────────────────────────
def run_nuclei(filepath, url, tags, timeout=90):
    """
    Nuclei pakai ALL templates (kalau tags=None) atau filter tag tertentu.
    Hasil selalu 'candidate' — Nuclei itu template match, bukan eksploitasi.
    """
    cmd = ["nuclei", "-l", filepath, "-im", "burp",
           "-jsonl", "-silent", "-timeout", "10", "-retries", "1"]
    if tags:
        cmd += ["-tags", tags]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        # Fallback ke -u kalau -im burp tidak didukung versi nuclei ini
        if "unknown flag" in r.stderr.lower() or "invalid" in r.stderr.lower() or not r.stdout:
            cmd2 = ["nuclei", "-u", url, "-jsonl", "-silent", "-timeout", "10"]
            if tags:
                cmd2 += ["-tags", tags]
            r = subprocess.run(cmd2, capture_output=True, text=True, timeout=timeout)
        return [json.loads(l) for l in r.stdout.splitlines() if l.strip()]
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        return []

def _parse_sqlmap_output(out):
    """Parse output sqlmap, return dict/string hasil."""
    # Frasa negatif → tidak ada temuan
    if any(p in out.lower() for p in [
        "do not appear to be injectable",
        "does not seem to be injectable",
        "all tested parameters do not appear",
    ]):
        return "not_found"
    # Frasa positif → confirmed
    if any(p in out.lower() for p in [
        "is vulnerable",
        "the following injection point",
        "sqlmap identified the following injection",
    ]):
        param, method, inj, payload = None, None, None, None
        m1 = re.search(r"Parameter:\s*([^\s(]+)\s*\(([^)]+)\)", out)
        m2 = re.search(r"(GET|POST|COOKIE)\s+parameter\s+'([^']+)'", out, re.I)
        if m1: param, method = m1.group(1), m1.group(2)
        elif m2: method, param = m2.group(1), m2.group(2)
        mt = re.search(r"Type:\s*(.+)", out)
        mp = re.search(r"Payload:\s*(.+)", out)
        if mt: inj     = mt.group(1).strip()
        if mp: payload = mp.group(1).strip()[:300]
        return {"param": param, "method": method, "inj": inj, "payload": payload}
    # Banyak HTTP 500 → indikasi WAF
    if out.lower().count("500 (internal server error)") >= 5:
        return "waf"
    return "not_found"

def _run_sqlmap_cmd(cmd, timeout):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return _parse_sqlmap_output(r.stdout)
    except subprocess.TimeoutExpired:
        return "timeout"
    except FileNotFoundError:
        return "missing"

def run_sqlmap(filepath, info, insecure, level, tamper, timeout):
    """
    sqlmap runner yang mendukung:
    - GET parameter di URL
    - Form POST body
    - JSON body (inject tanda * di tiap nilai)
    """
    base_cmd = ["sqlmap", "-r", filepath, "--batch",
                  f"--level={level}", "--risk=1",
                  "--timeout=15", "--retries=1", "--delay=2", "--threads=1",
                  "--output-dir=sqlmap_out"]
    if insecure: base_cmd += ["--force-ssl"]
    if tamper:   base_cmd += ["--tamper", tamper]

    results = []

    # Untuk GET / form POST → jalankan langsung
    if info["has_url_params"] or info["has_form_body"]:
        r = _run_sqlmap_cmd(base_cmd, timeout)
        if r not in ("not_found", "timeout", "missing", None):
            results.append(("standard", r))

    # Untuk JSON body → buat file per parameter dengan tanda *
    if info["is_json"] and info["json_body"]:
        json_files = make_json_sqlmap_files(filepath, info)
        for (tmp_path, field_name) in json_files:
            try:
                cmd = ["sqlmap", "-r", tmp_path, "--batch",
                        f"--level={level}", "--risk=1",
                        "--timeout=15", "--retries=1", "--delay=2",
                        "--threads=1", "--output-dir=sqlmap_out"]
                if insecure: cmd += ["--force-ssl"]
                if tamper:   cmd += ["--tamper", tamper]
                r = _run_sqlmap_cmd(cmd, timeout)
                if r not in ("not_found", "timeout", "missing", None):
                    if isinstance(r, dict):
                        r["param"] = r.get("param") or field_name
                    results.append((f"json:{field_name}", r))
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

    return results

def run_dalfox(url, cookie, timeout=60):
    """
    Dalfox XSS — syarat ketat:
    param harus ada & bukan N/A, evidence harus ada & tidak kosong.
    Kalau tidak memenuhi syarat → dibuang, tidak disimpan.
    """
    cmd = ["dalfox", "url", url, "--silence", "--format", "json"]
    if cookie: cmd += ["--cookie", cookie]
    try:
        r    = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        hits = json.loads(r.stdout) if r.stdout.strip() else []
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return []
    return [h for h in hits
            if h.get("param") and h.get("param") not in ("N/A","null","none","")
            and h.get("evidence") and h.get("evidence").strip()]




def verify_xss_browser(url, param, payload=None, cookie=None,
                         insecure=False, timeout_ms=10000):
    """
    Verifikasi XSS via headless browser (Playwright/Chromium).
    Cara kerja:
    1. Buka URL dengan payload XSS di parameter yang dicurigai
    2. Pasang listener untuk dialog alert/confirm/prompt
    3. Kalau dialog muncul → XSS benar-benar ter-eksekusi di browser
    4. Return True kalau XSS confirmed via browser rendering

    Ini cara yang sama dipakai Burp Suite Pro dan Acunetix untuk
    konfirmasi XSS — bukan cuma cek reflection di HTML mentah.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False, "Playwright tidak terinstall"

    # Payload-payload yang dicoba (dari yang paling sederhana)
    payloads = [
        payload,                                          # dari Dalfox kalau ada
        '<script>alert(document.domain)</script>',
        '<img src=x onerror=alert(document.domain)>',
        '"><script>alert(document.domain)</script>',
        "'><img src=x onerror=alert(document.domain)>",
        '<svg onload=alert(document.domain)>',
        'javascript:alert(document.domain)',
    ]
    payloads = [p for p in payloads if p]  # buang None

    # Bangun URL dengan parameter payload
    sep = "&" if "?" in url else "?"

    for pl in payloads:
        test_url = f"{url}{sep}{param}={pl}" if param else url
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                ctx     = browser.new_context(
                    ignore_https_errors=insecure,
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                               "AppleWebKit/537.36"
                )
                if cookie:
                    parsed = urlparse(url)
                    cookies = []
                    for part in cookie.split(";"):
                        if "=" in part:
                            name, val = part.strip().split("=", 1)
                            cookies.append({
                                "name": name, "value": val,
                                "domain": parsed.netloc, "path": "/"
                            })
                    if cookies:
                        ctx.add_cookies(cookies)

                page    = ctx.new_page()
                alerted = []

                # Tangkap semua dialog (alert/confirm/prompt)
                page.on("dialog", lambda d: (alerted.append(d.message), d.dismiss()))

                try:
                    page.goto(test_url, timeout=timeout_ms,
                               wait_until="domcontentloaded")
                    # Tunggu sebentar untuk JS async
                    page.wait_for_timeout(2000)
                except Exception:
                    pass

                browser.close()

                if alerted:
                    return True, pl  # ← XSS terkonfirmasi via browser!

        except Exception:
            continue

    return False, None


def browser_dom_xss_scan(url, cookie=None, insecure=False):
    """
    DOM-based XSS scanner via Playwright (headless Chromium).

    Berbeda dari Reflected XSS:
    - Reflected XSS: payload dikirim ke server → server reflect di response → browser eksekusi
    - DOM XSS: payload diproses LANGSUNG oleh JavaScript di browser (tidak melalui server)
               Source: window.location.hash, location.search, document.referrer
               Sink: innerHTML, document.write, eval, setTimeout(string)

    Cara kerja:
    1. Inject payload di URL hash (#) dan query param
    2. Buka di headless browser, tunggu JavaScript jalan
    3. Monitor apakah alert() terpanggil (payload ter-eksekusi di DOM)
    4. Cek DOM sinks yang diketahui berbahaya
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return []  # Playwright tidak terinstall

    # Payload untuk test DOM XSS via berbagai source
    dom_payloads = [
        # Via URL hash (source: location.hash)
        {"source": "hash",   "url": f"{url}#<img src=x onerror=alert(1)>"},
        {"source": "hash",   "url": f"{url}#<script>alert(1)</script>"},
        # Via query param dengan nama umum DOM sink
        {"source": "search", "url": f"{url}?next=javascript:alert(1)"},
        {"source": "search", "url": f"{url}?url=javascript:alert(1)"},
        {"source": "search", "url": f"{url}?redirect=javascript:alert(1)"},
        {"source": "search", "url": f"{url}?callback=alert"},
        {"source": "search", "url": f"{url}?jsonp=alert"},
    ]

    # Tambah payload ke semua URL param yang ada
    parsed = urlparse(url)
    if parsed.query:
        for kv in parsed.query.split("&"):
            if "=" in kv:
                key = kv.split("=")[0]
                # Ganti nilai param dengan payload DOM
                modified = re.sub(
                    rf"({re.escape(key)}=)[^&]*",
                    rf"\1<img src=x onerror=window.__dom_xss=1>",
                    url
                )
                dom_payloads.append({"source": f"param:{key}", "url": modified})

    findings = []

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            ctx = browser.new_context(
                ignore_https_errors=insecure,
                java_script_enabled=True
            )

            # Set cookie kalau ada
            if cookie:
                domain = parsed.netloc
                cookies = []
                for part in cookie.split(";"):
                    if "=" in part:
                        n, v = part.strip().split("=", 1)
                        cookies.append({
                            "name": n.strip(), "value": v.strip(),
                            "domain": domain, "path": "/"
                        })
                if cookies:
                    ctx.add_cookies(cookies)

            page = ctx.new_page()
            alerts_fired = []

            def handle_dialog(dialog):
                alerts_fired.append(dialog.message)
                dialog.dismiss()

            page.on("dialog", handle_dialog)

            for test in dom_payloads:
                try:
                    alerts_fired.clear()
                    page.goto(test["url"], timeout=10000,
                               wait_until="domcontentloaded")
                    page.wait_for_timeout(1500)

                    # Cek via alert dialog
                    if alerts_fired:
                        findings.append({
                            "source": test["source"],
                            "url":    test["url"],
                            "type":  "dom-based",
                            "trigger": "alert dialog",
                        })
                        continue

                    # Cek via window.__dom_xss marker
                    dom_found = page.evaluate(
                        "() => window.__dom_xss === 1"
                    )
                    if dom_found:
                        findings.append({
                            "source": test["source"],
                            "url":    test["url"],
                            "type":  "dom-based",
                            "trigger": "window.__dom_xss marker",
                        })

                except Exception:
                    continue

            browser.close()

    except Exception:
        return []

    return findings
    """
    Browser-based XSS scan via Playwright — setara Burp Pro/Acunetix.
    Mencakup:
    1. Reflected XSS  — inject payload ke tiap URL parameter, cek alert()
    2. DOM-based XSS  — inject via URL fragment (#), document.referrer,
                        window.name, dan periksa DOM sink berbahaya
    3. Stored XSS     — cek apakah payload dari sebelumnya muncul lagi

    Kenapa ini lebih baik dari Dalfox saja:
    - JavaScript benar-benar dijalankan (bukan cuma cek reflection di HTML)
    - Bisa deteksi DOM XSS yang tidak kelihatan di source HTML
    - Tidak ada false positive dari JSON endpoint atau encoded output
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return []

    # Payload yang dicoba — cukup 3 untuk speed, cukup untuk coverage
    PAYLOADS = [
        "<img src=x onerror=window.__xss=1>",                    # img onerror
        "<svg onload=window.__xss=1>",                           # svg onload
        "javascript:window.__xss=1",                             # js: URI
    ]

    # DOM sources yang dicek untuk DOM XSS
    DOM_SOURCES = [
        # Format: (cara inject, deskripsi)
        ("fragment", "URL Fragment (#payload)"),
        ("referrer", "document.referrer"),
    ]

    found = []

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)

            for payload in PAYLOADS:
                encoded = payload.replace("<", "%3C").replace(">", "%3E") \
                                  .replace("\"", "%22").replace("'", "%27") \
                                  .replace("(", "%28").replace(")", "%29")

                # ── 1) Reflected XSS via URL parameters ─────────────────
                if "?" in url:
                    # Coba inject ke setiap parameter yang ada
                    base, qs = url.split("?", 1)
                    params   = qs.split("&")
                    for i, part in enumerate(params):
                        if "=" not in part:
                            continue
                        key, _ = part.split("=", 1)
                        new_params      = params.copy()
                        new_params[i]   = f"{key}={encoded}"
                        test_url        = f"{base}?{'&'.join(new_params)}"
                        ctx             = browser.new_context(
                            ignore_https_errors=insecure
                        )
                        _add_cookies(ctx, cookie, url)
                        page     = ctx.new_page()
                        alert_ok = []
                        page.on("dialog", lambda d, a=alert_ok: (a.append(1), d.dismiss()))
                        try:
                            page.goto(test_url, timeout=10000,
                                       wait_until="domcontentloaded")
                            page.wait_for_timeout(1500)
                            if alert_ok or page.evaluate("()=>window.__xss"):
                                found.append({
                                    "type": "reflected",
                                    "param": key,
                                    "url":   test_url,
                                    "payload": payload,
                                })
                        except Exception:
                            pass
                        finally:
                            ctx.close()

                # ── 2) DOM XSS via URL fragment (#) ─────────────────────
                # Banyak aplikasi SPA/Angular baca location.hash lalu tulis
                # ke DOM tanpa sanitasi → DOM XSS via fragment
                frag_url = f"{url}#{encoded}"
                ctx      = browser.new_context(ignore_https_errors=insecure)
                _add_cookies(ctx, cookie, url)
                page     = ctx.new_page()
                alert_ok = []
                page.on("dialog", lambda d, a=alert_ok: (a.append(1), d.dismiss()))
                try:
                    page.goto(frag_url, timeout=10000,
                               wait_until="domcontentloaded")
                    page.wait_for_timeout(2000)  # SPA butuh lebih lama render
                    # Cek juga via innerHTML dan eval sinks di DOM
                    dom_check = page.evaluate("""() => {
                        return document.body.innerHTML.includes('onerror') ||
                               document.body.innerHTML.includes('onload') ||
                               window.__xss === 1;
                    }""")
                    if alert_ok or dom_check:
                        found.append({
                            "type":    "dom-based (fragment)",
                            "param":   "location.hash",
                            "url":     frag_url,
                            "payload": payload,
                        })
                except Exception:
                    pass
                finally:
                    ctx.close()

            browser.close()

    except Exception:
        pass

    return found


def _add_cookies(ctx, cookie_str, url):
    """Helper: tambahkan cookie ke Playwright context."""
    if not cookie_str:
        return
    domain = urlparse(url).netloc
    cookies = []
    for part in cookie_str.split(";"):
        if "=" in part:
            n, v = part.strip().split("=", 1)
            cookies.append({"name": n, "value": v,
                             "domain": domain, "path": "/"})
    if cookies:
        try:
            ctx.add_cookies(cookies)
        except Exception:
            pass
    """
    Scan XSS berbasis browser untuk semua parameter di URL.
    Ini yang dilakukan Burp Pro/Acunetix — render di browser sungguhan,
    bukan cuma cek reflection di HTML mentah.
    Hanya untuk halaman HTML, bukan JSON API.
    """
    if info["is_json"]:
        return []

    # Kumpulkan parameter dari URL
    params_to_test = []
    if "?" in info["path"]:
        qs = info["path"].split("?", 1)[1]
        for part in qs.split("&"):
            if "=" in part:
                params_to_test.append(part.split("=", 1)[0])

    # Kalau tidak ada parameter di URL, tetap coba tanpa parameter spesifik
    # (untuk kasus seperti halaman Angular yang punya router params)
    if not params_to_test:
        confirmed, payload = verify_xss_browser(
            url, param=None, cookie=cookie, insecure=insecure
        )
        if confirmed:
            return [{"param": "unknown", "payload": payload, "url": url}]
        return []

    results = []
    for param in params_to_test:
        confirmed, payload = verify_xss_browser(
            url, param=param, cookie=cookie, insecure=insecure
        )
        if confirmed:
            results.append({"param": param, "payload": payload, "url": url})

    return results

# ── Process satu request ──────────────────────────────────────────────────────
def process_one(filepath, args, smuggling_done):
    info  = parse_request(filepath)
    label = f"{info['method']} {info['path'][:55]} ({info['host']})"
    print(f"\n[→] {label}")
    saved = []

    # 1) Nuclei — ALL templates, hasil = candidate
    print(f"    Nuclei (all templates)...", end=" ", flush=True)
    hits = run_nuclei(filepath, info["url"],
                       args.nuclei_tags or None,   # None = semua template
                       timeout=90)
    for h in hits:
        i   = h.get("info", {})
        sev = i.get("severity","info")
        f   = make_finding(
            endpoint=h.get("matched-at", info["url"]),
            name=i.get("name","Nuclei Finding"),
            sev=sev, source="nuclei",
            status="candidate",  # ← selalu candidate, bukan confirmed
            note=f"Template: {h.get('template-id','')}. "
                 "Verifikasi manual sebelum masuk laporan."
        )
        save_finding(f)
        saved.append(f)
    print(f"⚠️  {len(hits)} kandidat" if hits else "tidak ada temuan")

    # 2) sqlmap — GET param, form body, DAN JSON body
    if not args.skip_sqlmap:
        can_sql = (info["has_url_params"] or info["has_form_body"] or
                    (info["is_json"] and info["json_body"]))
        if can_sql:
            mode_info = []
            if info["has_url_params"]: mode_info.append("URL param")
            if info["has_form_body"]:  mode_info.append("form body")
            if info["is_json"]:        mode_info.append("JSON body")
            print(f"    sqlmap ({', '.join(mode_info)})...", end=" ", flush=True)
            results = run_sqlmap(filepath, info, args.insecure,
                                  args.sqlmap_level, args.tamper,
                                  args.request_timeout)
            if results:
                for (ctx, r) in results:
                    if isinstance(r, dict):
                        f = make_finding(
                            endpoint=info["url"],
                            name="SQL Injection",
                            sev="high", source="sqlmap",
                            status="confirmed",  # ← confirmed: sqlmap eksplisit
                            param=r.get("param"),
                            method=r.get("method"),
                            inj_type=r.get("inj"),
                            note=f"Context: {ctx}. Payload: {r.get('payload') or 'lihat sqlmap_out/'}"
                        )
                        save_finding(f)
                        saved.append(f)
                        print(f"✅ SQLi confirmed! [{ctx}] param={r.get('param')}")
                    elif r == "waf":
                        f = make_finding(
                            endpoint=info["url"],
                            name="SQL Injection (indikasi — WAF aktif)",
                            sev="high", source="sqlmap",
                            status="candidate",
                            note=f"Context: {ctx}. WAF memblokir payload. "
                                 "Validasi manual via Burp Repeater."
                        )
                        save_finding(f)
                        saved.append(f)
                        print(f"⚠️  WAF terdeteksi [{ctx}] — candidate")
            else:
                print("tidak ada indikasi SQLi")
        else:
            print("    sqlmap... skip (tidak ada parameter yang bisa ditest)")
    else:
        print("    sqlmap... skip (--skip-sqlmap aktif)")

    # 3) XSS — Dua fase (seperti Burp Pro/Acunetix):
    #    Fase 1: Dalfox (cari kandidat parameter + payload)
    #    Fase 2: Browser Playwright (konfirmasi alert() benar-benar ter-eksekusi)
    if not info["is_json"] and info["url"] and not args.skip_dalfox:

        # Fase 1 — Dalfox cari kandidat
        print(f"    XSS Fase 1 (Dalfox scan)...", end=" ", flush=True)
        dalfox_hits = run_dalfox(info["url"], args.cookie)
        if dalfox_hits:
            print(f"{len(dalfox_hits)} kandidat ditemukan")
        else:
            print("tidak ada kandidat dari Dalfox")

        # Fase 2 — Verifikasi via headless browser
        print(f"    XSS Fase 2 (Browser verify)...", end=" ", flush=True)

        # Scan browser mandiri (parameter dari URL)
        browser_hits = browser_xss_scan(
            info["url"], info, args.cookie, args.insecure
        )

        # Verifikasi tiap kandidat Dalfox via browser
        for h in dalfox_hits:
            already = any(b.get("param") == h.get("param") for b in browser_hits)
            if not already:
                confirmed, payload = verify_xss_browser(
                    info["url"], h.get("param"),
                    payload=h.get("evidence",""),
                    cookie=args.cookie, insecure=args.insecure
                )
                if confirmed:
                    browser_hits.append({
                        "param": h.get("param"),
                        "payload": payload,
                        "url": info["url"]
                    })

        if browser_hits:
            for hit in browser_hits:
                f = make_finding(
                    endpoint=hit.get("url", info["url"]),
                    name="XSS (browser-verified)",
                    sev="medium", source="playwright+dalfox",
                    status="confirmed",
                    param=hit.get("param"),
                    method=info["method"],
                    evidence=f"alert() ter-eksekusi di Chromium. Payload: {hit.get('payload','')}",
                    note="Dikonfirmasi via headless Chromium (Playwright) — "
                         "JavaScript alert() benar-benar dieksekusi browser, "
                         "bukan cuma reflection di HTML. Setara metode Burp Pro/Acunetix."
                )
                save_finding(f)
                saved.append(f)
            print(f"✅ {len(browser_hits)} XSS terkonfirmasi via browser!")
        else:
            print("tidak ada XSS yang terkonfirmasi di browser")

    elif info["is_json"]:
        print("    XSS scan... skip (JSON API)")
    elif args.skip_dalfox:
        print("    XSS scan... skip (--skip-dalfox aktif)")

    # 3b) DOM-based XSS scan via Playwright
    if not info["is_json"] and info["url"] and not args.skip_dalfox:
        print(f"    DOM XSS scan (Playwright)...", end=" ", flush=True)
        dom_hits = browser_dom_xss_scan(
            info["url"], cookie=args.cookie, insecure=args.insecure
        )
        if dom_hits:
            for hit in dom_hits:
                f = make_finding(
                    endpoint=hit["url"],
                    name="DOM-based XSS",
                    sev="high", source="playwright_dom",
                    status="confirmed",
                    param=hit.get("source"),
                    evidence=f"Payload ter-eksekusi via {hit['trigger']}",
                    note=f"DOM XSS terkonfirmasi via Playwright/Chromium. "
                         f"Source: {hit['source']}. "
                         f"Payload masuk langsung ke DOM tanpa melalui server."
                )
                save_finding(f)
                saved.append(f)
            print(f"✅ {len(dom_hits)} DOM XSS terkonfirmasi!")
        else:
            print("tidak ada DOM XSS")

    # 4) HTTP Smuggling — 1x per host, hasil = candidate
    if args.smuggling and info["host"]:
        host_key = f"https://{info['host']}"
        if host_key not in smuggling_done:
            smuggling_done.add(host_key)
            print(f"    Smuggling {host_key}...", end=" ", flush=True)
            try:
                r = subprocess.run(
                    ["smuggler", "-u", host_key],
                    capture_output=True, text=True, timeout=60
                )
                if "VULNERABLE" in r.stdout.upper():
                    f = make_finding(
                        endpoint=host_key,
                        name="HTTP Request Smuggling (indikasi)",
                        sev="critical", source="smuggler",
                        status="candidate",
                        note="Indikasi Smuggler. WAJIB verifikasi manual."
                    )
                    save_finding(f)
                    saved.append(f)
                    print("⚠️  indikasi (candidate)")
                else:
                    print("tidak ada indikasi")
            except (FileNotFoundError, subprocess.TimeoutExpired):
                print("skip (smuggler tidak ada / timeout)")
    return saved

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(
        description="Pentest Co-Pilot Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Status temuan:
  confirmed = bukti eksplisit (sqlmap injectable, Dalfox param+evidence ada)
  candidate = indikasi perlu verifikasi manual (Nuclei, WAF hint, Smuggling)

Contoh:
  python3 scanner.py --insecure              (ITDC / target SSL internal)
  python3 scanner.py --insecure --skip-sqlmap (target sangat lambat)
  python3 scanner.py --url https://target.com (crawl tanpa Burp)
        """
    )
    p.add_argument("--url",             help="Mode crawl: URL target")
    p.add_argument("--insecure",        action="store_true",
                    help="Skip SSL verify (target self-signed/internal)")
    p.add_argument("--cookie",          default=None,
                    help="Cookie session: --cookie \"PHPSESSID=abc\"")
    p.add_argument("--nuclei-tags",     default=None,
                    help="Filter Nuclei tag (default: SEMUA template). "
                         "Contoh: sqli,xss,rce")
    p.add_argument("--sqlmap-level",    type=int, default=1, choices=range(1,6),
                    help="Level sqlmap 1-5 (default: 1)")
    p.add_argument("--tamper",          default=None,
                    help="Tamper sqlmap: space2comment,between")
    p.add_argument("--request-timeout", type=int, default=300,
                    help="Timeout sqlmap per request (detik, default: 300)")
    p.add_argument("--skip-sqlmap",     action="store_true",
                    help="Skip sqlmap (target sangat lambat)")
    p.add_argument("--skip-dalfox",     action="store_true",
                    help="Skip Dalfox")
    p.add_argument("--smuggling",       action="store_true",
                    help="Aktifkan HTTP Smuggling check (butuh: smuggler)")
    args = p.parse_args()

    print("=" * 58)
    print("       🔍  PENTEST CO-PILOT SCANNER")
    print("=" * 58)
    print()
    print("  confirmed = bukti langsung dari tool")
    print("  candidate = indikasi → verifikasi manual dulu sebelum laporan")
    print()

    if args.url:
        # Mode crawl — Nuclei langsung ke URL
        print(f"[*] Mode Crawl: {args.url}")
        try:
            import requests as req_lib
            from bs4 import BeautifulSoup
            urls  = set([args.url])
            base  = urlparse(args.url).netloc
            hdrs  = {"Cookie": args.cookie} if args.cookie else {}
            resp  = req_lib.get(args.url, timeout=15,
                                 verify=not args.insecure, headers=hdrs)
            soup  = BeautifulSoup(resp.text, "html.parser")
            for a in soup.find_all("a", href=True):
                link = urljoin(args.url, a["href"]).split("#")[0]
                if urlparse(link).netloc == base:
                    urls.add(link)
            print(f"[*] {len(urls)} URL ditemukan")
        except Exception as e:
            print(f"[!] Crawl terbatas: {e}")
            urls = set([args.url])
        total = 0
        for url in urls:
            print(f"    Nuclei: {url}")
            with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".txt", delete=False) as tmp:
                tmp.write(f"GET / HTTP/1.1\r\nHost: {urlparse(url).netloc}\r\n\r\n")
                tp = tmp.name
            hits = run_nuclei(tp, url, args.nuclei_tags)
            os.unlink(tp)
            for h in hits:
                i   = h.get("info", {})
                f   = make_finding(
                    endpoint=url,
                    name=i.get("name",""),
                    sev=i.get("severity","info"),
                    source="nuclei_crawl", status="candidate",
                    note=f"Template: {h.get('template-id','')}. Verifikasi manual."
                )
                save_finding(f)
                total += 1
            if hits:
                print(f"    ⚠️  {len(hits)} kandidat")
        print(f"\n[+] Selesai. {total} kandidat (semua perlu verifikasi manual).")
    else:
        # Mode Burp
        queue   = load_queue()
        pending = [i for i in queue if i["status"] != "done"]
        done    = [i for i in queue if i["status"] == "done"]
        print(f"[*] Burp traffic: {len(queue)} request tertangkap")
        print(f"    Belum diproses: {len(pending)} | Sudah: {len(done)}")
        print(f"\n[*] Konfigurasi:")
        print(f"    Nuclei  : ALL templates (coverage maksimal)")
        print(f"    sqlmap  : {'SKIP' if args.skip_sqlmap else f'ON — level={args.sqlmap_level}, timeout={args.request_timeout}s'}")
        print(f"             (termasuk JSON parameter injection)")
        print(f"    Dalfox  : {'SKIP' if args.skip_dalfox else 'ON — syarat ketat (param+evidence)'}")
        print(f"    Smuggling: {'ON' if args.smuggling else 'OFF (--smuggling untuk aktifkan)'}")
        print(f"    SSL     : {'dilewati' if args.insecure else 'normal'}")
        print()

        smuggling_done = set()
        for item in queue:
            if item["status"] == "done":
                continue
            if item["status"] == "failed" and item["attempts"] >= MAX_RETRIES:
                continue
            item["status"] = "scanning"
            save_queue(queue)
            try:
                process_one(
                    os.path.join(CAPTURED_DIR, item["file"]),
                    args, smuggling_done
                )
                item["status"] = "done"
            except KeyboardInterrupt:
                print("\n[!] Dihentikan. Jalankan ulang untuk lanjutkan.")
                item["status"] = "pending"
                save_queue(queue)
                break
            except Exception as e:
                item["attempts"] += 1
                if item["attempts"] >= MAX_RETRIES:
                    item["status"] = "failed"
                    print(f"    ❌ Gagal: {e}")
                else:
                    item["status"] = "pending"
                    wait = BACKOFF[min(item["attempts"]-1, len(BACKOFF)-1)]
                    print(f"    Retry dalam {wait}s... ({e})")
                    time.sleep(wait)
            save_queue(queue)

    # Summary
    all_f     = load_findings()
    confirmed = [f for f in all_f if f.get("status") == "confirmed"]
    candidate = [f for f in all_f if f.get("status") == "candidate"]
    sev_c     = {}
    for f in confirmed + candidate:
        s = f.get("severity","info")
        sev_c[s] = sev_c.get(s,0) + 1
    print(f"\n{'='*58}")
    print(f"  SCAN SELESAI")
    print(f"  Confirmed (bukti langsung)   : {len(confirmed)}")
    print(f"  Candidate (perlu verifikasi) : {len(candidate)}")
    for sev in ("critical","high","medium","low","info"):
        if sev_c.get(sev,0):
            print(f"    {sev.capitalize():<12}: {sev_c[sev]}")
    print(f"\n  Cek hasil  : http://127.0.0.1:8787/findings")
    print(f"  Laporan    : python3 report_generator.py \\")
    print(f"               --output Laporan.docx \\")
    print(f"               --client 'Nama Client' --tester 'Nama Kamu'")
    print(f"{'='*58}")

if __name__ == "__main__":
    main()
