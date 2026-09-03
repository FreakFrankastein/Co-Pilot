"""
JavaScript Secret Scanner
===========================
Fetch file JavaScript milik target dan scan untuk sensitive information
yang sering "kebawa" ke client-side bundle: API key, credential hardcoded,
internal endpoint, cloud config, dll.

Cara pakai:
    # Dari daftar URL file .js langsung
    python js_scanner.py --urls-file js_urls.txt

    # Atau otomatis extract <script src="..."> dari sebuah halaman dulu
    python js_scanner.py --page "https://target.local/app"

Catatan: ini hanya membaca/menganalisis konten JS yang memang sudah
dipublikasikan target ke browser (publicly served), bukan mengakses apa pun
yang di luar itu.
"""

import argparse
import json
import re
import sys
import warnings
from datetime import datetime, timezone
from urllib.parse import urljoin

import requests

from cvss4 import calculate as cvss4_calculate, CVSS4Error
from detectors import SENSITIVE_DATA_PATTERNS

FINDINGS_PATH = "findings.json"

# Pola tambahan yang spesifik sering muncul di JS bundle
JS_SPECIFIC_PATTERNS = {
    "google_api_key": r"AIza[0-9A-Za-z\-_]{35}",
    "firebase_config": r"(?i)apiKey\s*[:=]\s*[\"']AIza[0-9A-Za-z\-_]{35}[\"']",
    "stripe_key": r"(?:sk|pk)_(live|test)_[0-9a-zA-Z]{16,}",
    "slack_webhook": r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
    "generic_bearer_token": r"(?i)bearer\s+[A-Za-z0-9\-_\.=]{20,}",
    "hardcoded_password_var": r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"'][^\"']{4,}[\"']",
    "internal_endpoint_comment": r"(?i)//\s*(TODO|FIXME|internal|debug).{0,80}(api|endpoint|url)",
    "basic_auth_in_url": r"https?://[^/\s:]+:[^/\s@]+@[^/\s]+",
}

ALL_PATTERNS = {**SENSITIVE_DATA_PATTERNS, **JS_SPECIFIC_PATTERNS}

SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)


def discover_js_files(page_url, timeout=15, verify=True):
    """Extract semua <script src="...js"> dari sebuah halaman HTML."""
    resp = requests.get(page_url, timeout=timeout, verify=verify)
    resp.raise_for_status()
    matches = SCRIPT_SRC_RE.findall(resp.text)
    return [urljoin(page_url, m) for m in matches]


def scan_js_content(js_url, content):
    findings = []
    for label, pattern in ALL_PATTERNS.items():
        matches = re.findall(pattern, content)
        if matches:
            snippet_count = len(matches)
            findings.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "endpoint": js_url,
                "source": "js_scanner",
                "category": "Sensitive Information Disclosure",
                "name": f"Exposed secret in JS bundle: {label}",
                "severity": "high" if label in (
                    "aws_key", "private_key", "stripe_key", "google_api_key",
                    "firebase_config", "generic_bearer_token"
                ) else "medium",
                "status": "candidate",  # tetap wajib verifikasi manual (bisa dummy/test key)
                "evidence": f"{snippet_count} match(es) untuk pola '{label}'",
                "note": "Pastikan ini bukan dummy/placeholder value sebelum dilaporkan "
                        "sebagai temuan final.",
            })

    for f in findings:
        vector = ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
                   if f["severity"] == "high" else
                   "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N")
        try:
            result = cvss4_calculate(vector)
            f["cvss_vector"] = vector
            f["cvss_score"] = result.base_score
            f["cvss_severity"] = result.severity
        except CVSS4Error:
            pass

    return findings


def scan_js_url(js_url, timeout=15, cookie=None, verify=True):
    headers = {"Cookie": cookie} if cookie else {}
    try:
        resp = requests.get(js_url, headers=headers, timeout=timeout, verify=verify)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] Gagal fetch {js_url}: {e}")
        return []
    return scan_js_content(js_url, resp.text)


def save_findings(new_findings):
    findings = []
    try:
        with open(FINDINGS_PATH, "r") as f:
            findings = json.load(f)
    except FileNotFoundError:
        pass
    findings.extend(new_findings)
    with open(FINDINGS_PATH, "w") as f:
        json.dump(findings, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Scan file JavaScript target untuk sensitive info")
    parser.add_argument("--urls-file", help="File berisi daftar URL .js, satu per baris")
    parser.add_argument("--page", help="URL halaman - auto-extract semua <script src>")
    parser.add_argument("--cookie", default=None,
                         help='Cookie session untuk akses JS yang butuh login')
    parser.add_argument("--insecure", action="store_true",
                         help="Lewati verifikasi sertifikat SSL - dipakai untuk target "
                              "internal/self-signed cert (umum di aplikasi korporat internal)")
    args = parser.parse_args()

    verify = not args.insecure
    if args.insecure:
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")
        print("[!] Mode --insecure aktif: verifikasi sertifikat SSL DILEWATI. "
              "Pastikan ini memang target internal yang authorized.")

    js_urls = []
    if args.page:
        print(f"[*] Extracting script src dari {args.page} ...")
        js_urls = discover_js_files(args.page, verify=verify)
        print(f"[*] Ditemukan {len(js_urls)} file JS")
    elif args.urls_file:
        with open(args.urls_file, "r") as f:
            js_urls = [line.strip() for line in f if line.strip()]
    else:
        print("Gunakan --urls-file atau --page")
        sys.exit(1)

    all_findings = []
    for url in js_urls:
        print(f"[*] Scanning {url} ...")
        findings = scan_js_url(url, cookie=args.cookie, verify=verify)
        if findings:
            print(f"    -> {len(findings)} kandidat temuan")
        all_findings.extend(findings)

    save_findings(all_findings)
    print(f"\n[+] Total kandidat temuan dari JS scan: {len(all_findings)}")
    print(f"[+] Tersimpan ke {FINDINGS_PATH} (status: candidate, perlu verifikasi manual)")


if __name__ == "__main__":
    main()
