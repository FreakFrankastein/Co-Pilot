"""
Bug Bounty Mode Pipeline
=========================
Mode khusus untuk Bug Bounty hunting — beda dengan pentest standar yang
fokus ke aplikasi tertentu (scope terbatas), Bug Bounty hunting butuh
fase recon lebih luas dulu untuk nemuin attack surface.

Pipeline Bug Bounty:
1. Waybackurls        -- cari URL historis target dari Wayback Machine
2. GF patterns        -- filter URL dengan parameter menarik (IDOR, SSRF, redirect, dll)
3. CORS checker       -- deteksi misconfiguration CORS
4. IDOR/BOLA check    -- cek parameter yang berpotensi IDOR (via Nuclei + pola GF)
5. Nuclei scan        -- template-based scan untuk semua temuan diatas
6. Dalfox             -- XSS scan per endpoint yang menarik
7. Semua hasil masuk findings.json (CVSS scored, siap laporan)

Tools yang dibutuhkan (install sekali saja):
    go install github.com/tomnomnom/waybackurls@latest
    go install github.com/tomnomnom/gf@latest
    go install github.com/hahwul/dalfox/v2@latest
    pip3 install requests --break-system-packages
    (nuclei sudah ada dari mode pentest)

Pastikan Go binary ada di PATH:
    echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc && source ~/.bashrc

Cara pakai:
    python3 bugbounty.py --domain "target.com"
    python3 bugbounty.py --domain "target.com" --insecure
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from cvss4 import calculate as cvss4_calculate, CVSS4Error

FINDINGS_PATH = "findings.json"
BB_WORK_DIR   = "bugbounty_work"

MAX_RETRIES          = 3
RETRY_BACKOFF        = [10, 30, 90]
DEFAULT_TIMEOUT      = 120

# Template Nuclei yang paling relevan untuk Bug Bounty
NUCLEI_BB_TAGS = (
    "exposures,misconfig,default-login,exposed-panels,"
    "takeover,sqli,ssti,rce,lfi,xxe,injection,"
    "cors,idor,ssrf,redirect,xss"
)

# GF pattern sets yang paling sering menghasilkan temuan di Bug Bounty
GF_PATTERNS = [
    ("idor",     "Potential IDOR",          "medium"),
    ("ssrf",     "Potential SSRF",          "high"),
    ("redirect", "Open Redirect",           "medium"),
    ("xss",      "Reflected XSS candidate", "medium"),
    ("sqli",     "SQL Injection candidate", "high"),
    ("lfi",      "Local File Inclusion",    "high"),
    ("rce",      "Remote Code Execution",   "critical"),
    ("cors",     "CORS Misconfiguration",   "medium"),
]

SEVERITY_TO_VECTOR = {
    "critical": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "high":     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
    "medium":   "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "low":      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ensure_workdir():
    os.makedirs(BB_WORK_DIR, exist_ok=True)


def load_findings():
    if not os.path.exists(FINDINGS_PATH):
        return []
    try:
        with open(FINDINGS_PATH, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, ValueError):
        return []


def save_finding(finding):
    findings = load_findings()
    findings.append(finding)
    with open(FINDINGS_PATH, "w") as f:
        json.dump(findings, f, indent=2)


def make_finding(endpoint, name, severity, source, status="candidate",
                  parameter=None, method=None, evidence=None, note=None):
    vector = SEVERITY_TO_VECTOR.get(severity,
             "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N")
    try:
        result = cvss4_calculate(vector)
        cvss_score, cvss_sev = result.base_score, result.severity
    except CVSS4Error:
        cvss_score, cvss_sev = None, None

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoint":  endpoint,
        "source":    source,
        "name":      name,
        "severity":  severity,
        "status":    status,
        "cvss_vector":   vector,
        "cvss_score":    cvss_score,
        "cvss_severity": cvss_sev,
        "parameter": parameter,
        "method":    method,
        "evidence":  evidence,
        "note":      note or "Dihasilkan dari Bug Bounty pipeline. Wajib verifikasi manual.",
    }


def run_cmd(cmd, timeout=DEFAULT_TIMEOUT):
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except FileNotFoundError:
        return None  # tool belum terinstall, skip diam-diam
    except subprocess.TimeoutExpired:
        return None


# ---------------------------------------------------------------------------
# Step 1 — Waybackurls: cari URL historis target
# ---------------------------------------------------------------------------

def step_waybackurls(domain):
    print(f"\n[BB Step 1] Waybackurls: mencari URL historis untuk {domain} ...")
    out = run_cmd(["waybackurls", domain], timeout=120)
    if out is None:
        print("    [!] waybackurls tidak ditemukan di PATH — skip.")
        print("        Install: go install github.com/tomnomnom/waybackurls@latest")
        return []

    urls = [u for u in out.splitlines() if u.startswith("http")]
    urls = list(dict.fromkeys(urls))  # dedup sambil jaga urutan
    print(f"    -> {len(urls)} URL historis ditemukan")

    path = os.path.join(BB_WORK_DIR, "wayback_urls.txt")
    with open(path, "w") as f:
        f.write("\n".join(urls))
    return urls


# ---------------------------------------------------------------------------
# Step 2 — GF patterns: filter URL berdasarkan pola parameter menarik
# ---------------------------------------------------------------------------

def step_gf_filter(urls):
    print(f"\n[BB Step 2] GF patterns: filter {len(urls)} URL untuk parameter menarik ...")

    # Simpan dulu semua URL ke file untuk di-pipe ke gf
    all_urls_path = os.path.join(BB_WORK_DIR, "all_urls.txt")
    with open(all_urls_path, "w") as f:
        f.write("\n".join(urls))

    gf_results = {}
    for pattern, label, severity in GF_PATTERNS:
        try:
            result = subprocess.run(
                ["gf", pattern],
                input="\n".join(urls),
                capture_output=True, text=True, timeout=30
            )
            matched = [u for u in result.stdout.splitlines() if u.startswith("http")]
            if matched:
                gf_results[pattern] = {"urls": matched, "label": label, "severity": severity}
                path = os.path.join(BB_WORK_DIR, f"gf_{pattern}.txt")
                with open(path, "w") as f:
                    f.write("\n".join(matched))
                print(f"    -> [{pattern}] {len(matched)} URL cocok ({label})")
        except FileNotFoundError:
            print("    [!] gf tidak ditemukan di PATH — skip.")
            print("        Install: go install github.com/tomnomnom/gf@latest")
            print("        Pattern: https://github.com/tomnomnom/gf (lihat bagian example-patterns)")
            break
        except subprocess.TimeoutExpired:
            continue

    return gf_results


# ---------------------------------------------------------------------------
# Step 3 — CORS checker: cek misconfiguration CORS
# ---------------------------------------------------------------------------

def step_cors_check(urls, insecure=False):
    print(f"\n[BB Step 3] CORS check: test {len(urls)} URL ...")
    import requests as req_lib
    import warnings
    if insecure:
        warnings.filterwarnings("ignore")

    new_findings = []
    checked = 0
    for url in urls[:100]:  # batasi 100 URL untuk CORS check (cepat)
        try:
            # Inject Origin palsu dan lihat apakah server meng-echo balik
            test_origin = "https://evil.attacker.com"
            resp = req_lib.get(
                url, timeout=10, verify=not insecure,
                headers={"Origin": test_origin}
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            # Pola rentan: origin di-echo balik + Allow-Credentials: true
            if test_origin in acao or acao == "*":
                severity = "high" if "true" in acac.lower() else "medium"
                finding = make_finding(
                    endpoint=url,
                    name="CORS Misconfiguration",
                    severity=severity,
                    source="cors_checker",
                    status="candidate",
                    method="GET",
                    evidence=f"ACAO: {acao} | ACAC: {acac}",
                    note="Origin palsu (evil.attacker.com) diterima. "
                         "Kalau ACAC: true, ini High karena bisa dipakai untuk credential theft. "
                         "Wajib verifikasi manual.",
                )
                new_findings.append(finding)
                save_finding(finding)
                print(f"    -> CORS issue ditemukan: {url}")
            checked += 1
        except Exception:
            continue

    print(f"    -> Selesai CORS check ({checked} URL), {len(new_findings)} temuan")
    return new_findings


# ---------------------------------------------------------------------------
# Step 4 — IDOR/BOLA check: scan Nuclei di URL GF-filtered
# ---------------------------------------------------------------------------

def step_nuclei_bb(gf_results, insecure=False):
    print(f"\n[BB Step 4] Nuclei: scan endpoint yang terfilter GF ...")
    new_findings = []

    # Kumpulkan semua URL unik dari semua GF pattern
    all_interesting = set()
    for data in gf_results.values():
        for url in data["urls"][:30]:  # maks 30 per pattern biar tidak terlalu lambat
            all_interesting.add(url)

    if not all_interesting:
        print("    -> Tidak ada URL menarik dari GF — skip Nuclei step.")
        return []

    # Simpan ke file, jalankan nuclei sekaligus
    targets_path = os.path.join(BB_WORK_DIR, "nuclei_targets.txt")
    with open(targets_path, "w") as f:
        f.write("\n".join(all_interesting))

    cmd = ["nuclei", "-l", targets_path, "-tags", NUCLEI_BB_TAGS,
           "-jsonl", "-silent", "-timeout", "10"]
    if insecure:
        cmd += ["-no-mcheck"]

    print(f"    -> Nuclei scanning {len(all_interesting)} URL ...")
    out = run_cmd(cmd, timeout=600)
    if out is None:
        print("    [!] Nuclei tidak ditemukan di PATH — skip.")
        return []

    for line in out.splitlines():
        try:
            hit = json.loads(line.strip())
        except json.JSONDecodeError:
            continue
        info = hit.get("info", {})
        severity = info.get("severity", "info")
        vector = SEVERITY_TO_VECTOR.get(severity,
                 "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")
        try:
            result = cvss4_calculate(vector)
            cvss_score, cvss_sev = result.base_score, result.severity
        except CVSS4Error:
            cvss_score, cvss_sev = None, None
        finding = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "endpoint":  hit.get("matched-at", "unknown"),
            "source":    "nuclei_bugbounty",
            "template_id": hit.get("template-id"),
            "name":      info.get("name"),
            "severity":  severity,
            "status":    "confirmed",
            "cvss_vector":   vector,
            "cvss_score":    cvss_score,
            "cvss_severity": cvss_sev,
            "note": "Ditemukan dari Bug Bounty pipeline (GF-filtered URL → Nuclei).",
        }
        new_findings.append(finding)
        save_finding(finding)

    print(f"    -> Nuclei selesai: {len(new_findings)} temuan")
    return new_findings


# ---------------------------------------------------------------------------
# Step 5 — Dalfox XSS scan khusus URL yang GF-flagged sebagai XSS candidate
# ---------------------------------------------------------------------------

def step_dalfox_bb(gf_results, insecure=False):
    xss_candidates = gf_results.get("xss", {}).get("urls", [])
    if not xss_candidates:
        print(f"\n[BB Step 5] Dalfox: tidak ada XSS candidate dari GF — skip.")
        return []

    print(f"\n[BB Step 5] Dalfox: XSS scan {len(xss_candidates[:20])} URL ...")
    new_findings = []

    for url in xss_candidates[:20]:  # maks 20, Dalfox agak lambat
        cmd = ["dalfox", "url", url, "--silence", "--format", "json"]
        out = run_cmd(cmd, timeout=60)
        if out is None:
            print("    [!] Dalfox tidak ditemukan di PATH — skip.")
            print("        Install: go install github.com/hahwul/dalfox/v2@latest")
            break
        try:
            hits = json.loads(out) if out else []
        except json.JSONDecodeError:
            hits = []
        for hit in hits:
            finding = make_finding(
                endpoint=url,
                name=f"XSS Confirmed (Bug Bounty) - {hit.get('type','reflected')}",
                severity="medium",
                source="dalfox_bugbounty",
                status="confirmed",
                parameter=hit.get("param"),
                method=hit.get("method", "GET"),
                evidence=hit.get("evidence", ""),
            )
            new_findings.append(finding)
            save_finding(finding)

    print(f"    -> Dalfox selesai: {len(new_findings)} XSS terkonfirmasi")
    return new_findings


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(domain, all_findings):
    from collections import Counter
    sev_count = Counter(f.get("severity", "info") for f in all_findings)
    print(f"""
╔══════════════════════════════════════════╗
║       Bug Bounty Pipeline Selesai        ║
╠══════════════════════════════════════════╣
║  Domain  : {domain:<30} ║
║  Critical: {sev_count.get('critical',0):<30} ║
║  High    : {sev_count.get('high',0):<30} ║
║  Medium  : {sev_count.get('medium',0):<30} ║
║  Low     : {sev_count.get('low',0):<30} ║
╠══════════════════════════════════════════╣
║  Cek detail: http://127.0.0.1:8787/findings
╚══════════════════════════════════════════╝
""")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Bug Bounty Mode Pipeline")
    parser.add_argument("--domain", required=True,
                         help="Domain target Bug Bounty, contoh: 'target.com' (tanpa https://)")
    parser.add_argument("--insecure", action="store_true",
                         help="Lewati verifikasi SSL (untuk target self-signed cert)")
    parser.add_argument("--skip-wayback", action="store_true",
                         help="Skip waybackurls (pakai urls dari file wayback_urls.txt yang sudah ada)")
    parser.add_argument("--skip-cors", action="store_true",
                         help="Skip CORS check (lebih cepat, tapi kehilangan 1 kategori temuan)")
    parser.add_argument("--max-urls", type=int, default=500,
                         help="Batas maksimal URL yang diproses dari waybackurls (default: 500)")
    args = parser.parse_args()

    ensure_workdir()
    print(f"\n🔍 Bug Bounty Pipeline starting untuk domain: {args.domain}")
    print(f"   Working dir: {BB_WORK_DIR}/")

    # Step 1: Waybackurls
    if args.skip_wayback:
        wayback_path = os.path.join(BB_WORK_DIR, "wayback_urls.txt")
        if os.path.exists(wayback_path):
            with open(wayback_path) as f:
                urls = [u.strip() for u in f if u.strip().startswith("http")]
            print(f"\n[BB Step 1] --skip-wayback: pakai {len(urls)} URL dari file yang ada")
        else:
            print("[!] --skip-wayback tapi file wayback_urls.txt belum ada. Jalankan tanpa --skip-wayback dulu.")
            sys.exit(1)
    else:
        urls = step_waybackurls(args.domain)

    # Batasi jumlah URL
    urls = urls[:args.max_urls]
    if not urls:
        print("[!] Tidak ada URL ditemukan. Pipeline berhenti.")
        return

    # Step 2: GF patterns
    gf_results = step_gf_filter(urls)

    # Step 3: CORS check
    if not args.skip_cors:
        step_cors_check(urls, insecure=args.insecure)

    # Step 4: Nuclei scan (pada URL yang terfilter GF)
    nuclei_findings = step_nuclei_bb(gf_results, insecure=args.insecure)

    # Step 5: Dalfox XSS pada XSS candidates dari GF
    dalfox_findings = step_dalfox_bb(gf_results, insecure=args.insecure)

    # Print summary
    all_new = load_findings()
    print_summary(args.domain, all_new)


if __name__ == "__main__":
    main()
