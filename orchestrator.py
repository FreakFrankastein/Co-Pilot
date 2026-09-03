"""
Scan Orchestrator - Resilient untuk LAN yang tidak stabil
============================================================
Menjalankan Nuclei & sqlmap (native Windows binaries, tidak perlu Kali/VM)
terhadap daftar endpoint, dengan checkpoint + retry supaya tahan terhadap:
  - Koneksi putus-nyambung saat scan jalan
  - Target timeout/unreachable sementara
  - VPN/LAN internal down di tengah proses

Cara pakai:
    python orchestrator.py targets.txt

targets.txt berisi satu URL per baris. Jalankan ulang command yang sama
kapan saja - otomatis skip yang sudah 'done', lanjut yang 'pending'/'failed'.

Requirement:
    - nuclei.exe di PATH (download: https://github.com/projectdiscovery/nuclei/releases)
    - sqlmap.py / sqlmap.exe di PATH (https://github.com/sqlmapproject/sqlmap)
    - python -m pip install requests --break-system-packages
"""

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from cvss4 import calculate as cvss4_calculate, CVSS4Error

QUEUE_PATH = "scan_queue.json"
FAILED_LOG = "failed_targets.json"
FINDINGS_PATH = "findings.json"

MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = [10, 30, 90]   # jeda sebelum retry ke-1, ke-2, ke-3
PER_TARGET_TIMEOUT = 180               # detik, sesuaikan kalau endpoint berat


# ---------------------------------------------------------------------------
# Queue management (checkpoint/resume)
# ---------------------------------------------------------------------------

def load_queue(targets_file):
    if os.path.exists(QUEUE_PATH):
        with open(QUEUE_PATH, "r") as f:
            queue = json.load(f)
        # Tambahkan target baru dari file yang belum ada di queue
        existing = {item["url"] for item in queue}
        with open(targets_file, "r") as f:
            for line in f:
                url = line.strip()
                if url and url not in existing:
                    queue.append({"url": url, "status": "pending", "attempts": 0})
        return queue

    queue = []
    with open(targets_file, "r") as f:
        for line in f:
            url = line.strip()
            if url:
                queue.append({"url": url, "status": "pending", "attempts": 0})
    return queue


def save_queue(queue):
    with open(QUEUE_PATH, "w") as f:
        json.dump(queue, f, indent=2)


def log_failed(url, reason):
    failed = []
    if os.path.exists(FAILED_LOG):
        with open(FAILED_LOG, "r") as f:
            failed = json.load(f)
    failed.append({"url": url, "reason": reason, "timestamp": datetime.now(timezone.utc).isoformat()})
    with open(FAILED_LOG, "w") as f:
        json.dump(failed, f, indent=2)


def save_findings(new_findings):
    findings = []
    if os.path.exists(FINDINGS_PATH):
        with open(FINDINGS_PATH, "r") as f:
            findings = json.load(f)
    findings.extend(new_findings)
    with open(FINDINGS_PATH, "w") as f:
        json.dump(findings, f, indent=2)


# ---------------------------------------------------------------------------
# Scanner wrappers (memanggil tool eksternal resmi, bukan payload custom)
# ---------------------------------------------------------------------------

def run_nuclei(url, cookie=None, extra_headers=None, tags=None):
    """Jalankan nuclei terhadap satu target. Return list of dict hasil (JSON lines).

    tags: filter template Nuclei resmi, misal 'exposures,misconfig,default-login,
    exposed-panels,takeover' - semua ini template community Nuclei yang memang
    dirancang untuk deteksi auth bypass / misconfig, bukan payload custom.
    """
    cmd = ["nuclei", "-u", url, "-jsonl", "-silent",
           "-timeout", "10", "-retries", "1"]
    if cookie:
        cmd += ["-H", f"Cookie: {cookie}"]
    for h in (extra_headers or []):
        cmd += ["-H", h]
    if tags:
        cmd += ["-tags", tags]
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=PER_TARGET_TIMEOUT
    )
    findings = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return findings


def run_sqlmap(url, cookie=None, extra_headers=None, tamper=None):
    """Jalankan sqlmap batch-mode terhadap satu target (deteksi saja, tidak dump data).

    tamper: nama tamper script bawaan sqlmap (comma-separated), contoh:
    'space2comment,between,charencode' - ini script resmi sqlmap untuk membantu
    payload lolos dari WAF/filter sederhana (encoding & reformatting query),
    bukan teknik evasion custom yang saya tulis sendiri.
    Daftar lengkap: sqlmap --list-tampers
    """
    cmd = ["sqlmap", "-u", url, "--batch", "--level=2", "--risk=1",
           "--timeout=10", "--retries=1", "--output-dir=sqlmap_out"]
    if cookie:
        cmd += ["--cookie", cookie]
    for h in (extra_headers or []):
        cmd += ["--header", h]
    if tamper:
        cmd += ["--tamper", tamper]
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=PER_TARGET_TIMEOUT
    )
    output = result.stdout
    vulnerable = "is vulnerable" in output.lower() or "parameter" in output.lower() and "injectable" in output.lower()

    param_name, param_method, injection_type = None, None, None
    match1 = re.search(r"Parameter:\s*([^\s(]+)\s*\(([^)]+)\)", output)
    match2 = re.search(r"(GET|POST|PUT|COOKIE|HEADER)\s+parameter\s+'([^']+)'", output, re.IGNORECASE)
    if match1:
        param_name, param_method = match1.group(1), match1.group(2)
    elif match2:
        param_method, param_name = match2.group(1), match2.group(2)
    type_match = re.search(r"Type:\s*(.+)", output)
    if type_match:
        injection_type = type_match.group(1).strip()

    return {
        "raw_output_tail": output[-2000:],
        "vulnerable_indicator": vulnerable,
        "parameter": param_name,
        "method": param_method,
        "injection_type": injection_type,
    }


def nuclei_to_finding(url, nuclei_hit):
    info = nuclei_hit.get("info", {})
    severity = info.get("severity", "info")
    severity_to_vector = {
        "critical": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "high":     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
        "medium":   "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
        "low":      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        "info":     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    }
    vector = severity_to_vector.get(severity, severity_to_vector["info"])
    try:
        score = cvss4_calculate(vector)
        cvss_score, cvss_sev = score.base_score, score.severity
    except CVSS4Error:
        cvss_score, cvss_sev = None, None

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoint": url,
        "source": "nuclei",
        "template_id": nuclei_hit.get("template-id"),
        "name": info.get("name"),
        "category": info.get("tags", []),
        "severity": severity,
        "status": "confirmed",  # nuclei template match = sudah terverifikasi sesuai template
        "cvss_vector": vector,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_sev,
        "matched_at": nuclei_hit.get("matched-at"),
    }


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run_commix(url, cookie=None):
    """Commix: setara sqlmap tapi khusus OS command injection. Tool resmi
    open-source (https://github.com/commixproject/commix) - saya orchestrate
    saja, bukan menulis payload command injection sendiri."""
    cmd = ["commix", "--url", url, "--batch", "--level=2"]
    if cookie:
        cmd += ["--cookie", cookie]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=PER_TARGET_TIMEOUT)
    except FileNotFoundError:
        return {"vulnerable_indicator": False, "raw_output_tail": ""}
    output = result.stdout
    vulnerable = "is vulnerable" in output.lower() or "vulnerable parameter" in output.lower()
    return {"raw_output_tail": output[-2000:], "vulnerable_indicator": vulnerable}


def run_dalfox(url, cookie=None):
    """Dalfox: XSS scanner khusus yang benar-benar verifikasi eksekusi payload
    (bukan cuma cek reflection seperti heuristic detector kita). Tool resmi
    open-source (https://github.com/hahwul/dalfox) - saya orchestrate saja,
    bukan menulis payload XSS sendiri."""
    cmd = ["dalfox", "url", url, "--silence", "--format", "json"]
    if cookie:
        cmd += ["--cookie", cookie]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=PER_TARGET_TIMEOUT)
    except FileNotFoundError:
        return None  # dalfox belum terinstall, skip diam-diam
    try:
        data = json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError:
        data = []
    return data


def dalfox_to_finding(url, hit):
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
    try:
        result = cvss4_calculate(vector)
        cvss_score, cvss_sev = result.base_score, result.severity
    except CVSS4Error:
        cvss_score, cvss_sev = None, None
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoint": url,
        "source": "dalfox",
        "name": f"XSS Confirmed - {hit.get('type', 'reflected')}",
        "severity": "medium",
        "status": "confirmed",  # dalfox verifikasi eksekusi beneran, bukan cuma reflection
        "cvss_vector": vector,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_sev,
        "parameter": hit.get("param", "N/A"),
        "method": hit.get("method", "GET"),
        "evidence": hit.get("evidence", ""),
        "note": "Dikonfirmasi oleh Dalfox (verifikasi eksekusi payload, bukan heuristic reflection).",
    }


def run_smuggling_check(base_url, timeout=120):
    """Cek HTTP Request Smuggling (CL.TE/TE.CL/TE.TE) pakai Smuggler
    (https://github.com/defparam/smuggler) - tool resmi open-source yang
    melakukan probing non-destructive, sudah teruji luas di komunitas
    pentest. Saya orchestrate saja, bukan menulis teknik desync sendiri.

    Dicek 1x per host (bukan per-endpoint), karena smuggling itu sifatnya
    di level koneksi/server, bukan spesifik ke satu URL.
    """
    parsed = urlparse(base_url) if isinstance(base_url, str) else None
    try:
        cmd = ["smuggler", "-u", base_url]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except FileNotFoundError:
        return None  # smuggler belum terinstall, skip diam-diam
    except subprocess.TimeoutExpired:
        return None


def smuggling_output_to_finding(host, output):
    """Parse output smuggler.py - dia print baris 'VULNERABLE' kalau ketemu indikasi desync."""
    if not output or "VULNERABLE" not in output.upper():
        return None

    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    try:
        result = cvss4_calculate(vector)
        cvss_score, cvss_sev = result.base_score, result.severity
    except CVSS4Error:
        cvss_score, cvss_sev = None, None

    # Ambil baris relevan untuk evidence (potong biar ringkas)
    relevant_lines = [l for l in output.splitlines() if "VULNERABLE" in l.upper() or "CL.TE" in l or "TE.CL" in l or "TE.TE" in l]
    evidence = " | ".join(relevant_lines[:5])

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoint": host,
        "source": "smuggler",
        "name": "HTTP Request Smuggling (indikasi desync CL.TE/TE.CL/TE.TE)",
        "severity": "critical",
        "status": "candidate",  # tetap wajib verifikasi manual - dampaknya besar, false positive costly
        "cvss_vector": vector,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_sev,
        "evidence": evidence or "Lihat output lengkap smuggler untuk detail",
        "note": "HTTP smuggling berdampak besar (bisa bypass auth/WAF, cache poisoning). "
                "WAJIB verifikasi manual hati-hati sebelum dilaporkan - banyak false positive "
                "karena perbedaan implementasi load balancer/proxy chain.",
    }


def process_target(item, cookie=None, extra_headers=None, nuclei_tags=None, sqlmap_tamper=None,
                    check_smuggling=False, smuggling_checked_hosts=None):
    url = item["url"]
    print(f"\n[*] Scanning: {url} (attempt {item['attempts'] + 1})")

    new_findings = []
    try:
        item["status"] = "scanning"
        save_queue_ref[0] and save_queue(save_queue_ref[0])

        nuclei_hits = run_nuclei(url, cookie=cookie, extra_headers=extra_headers, tags=nuclei_tags)
        for hit in nuclei_hits:
            new_findings.append(nuclei_to_finding(url, hit))

        sqlmap_result = run_sqlmap(url, cookie=cookie, extra_headers=extra_headers, tamper=sqlmap_tamper)
        if sqlmap_result["vulnerable_indicator"]:
            try:
                score = cvss4_calculate("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
                cvss_score, cvss_sev = score.base_score, score.severity
            except CVSS4Error:
                cvss_score, cvss_sev = None, None
            new_findings.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "endpoint": url,
                "source": "sqlmap",
                "name": "SQL Injection (confirmed by sqlmap)",
                "severity": "high",
                "status": "confirmed",
                "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                "cvss_score": cvss_score,
                "cvss_severity": cvss_sev,
                "parameter": sqlmap_result.get("parameter") or "Lihat sqlmap_out/ untuk detail",
                "method": sqlmap_result.get("method"),
                "injection_type": sqlmap_result.get("injection_type"),
                "note": "Lihat sqlmap_out/ untuk detail teknis lengkap",
            })

        dalfox_hits = run_dalfox(url, cookie=cookie)
        if dalfox_hits:
            for hit in dalfox_hits:
                new_findings.append(dalfox_to_finding(url, hit))

        if check_smuggling and smuggling_checked_hosts is not None:
            parsed = urlparse(url)
            host_key = f"{parsed.scheme}://{parsed.netloc}"
            if host_key not in smuggling_checked_hosts:
                smuggling_checked_hosts.add(host_key)
                print(f"    -> Cek HTTP smuggling untuk host {host_key} (1x per host)...")
                smuggling_output = run_smuggling_check(host_key)
                smuggling_finding = smuggling_output_to_finding(host_key, smuggling_output)
                if smuggling_finding:
                    new_findings.append(smuggling_finding)
                    print("    -> Indikasi HTTP smuggling ditemukan! Wajib verifikasi manual.")

        save_findings(new_findings)
        item["status"] = "done"
        print(f"    -> done, {len(new_findings)} finding(s)")
        return True

    except subprocess.TimeoutExpired:
        item["attempts"] += 1
        reason = f"timeout after {PER_TARGET_TIMEOUT}s"
        print(f"    -> TIMEOUT ({reason})")
        _handle_failure(item, reason)
        return False

    except FileNotFoundError as e:
        # nuclei/sqlmap tidak ditemukan di PATH - bukan masalah LAN, langsung stop
        print(f"[!] Tool tidak ditemukan: {e}. Pastikan nuclei/sqlmap ada di PATH.")
        sys.exit(1)

    except Exception as e:
        item["attempts"] += 1
        reason = f"error: {str(e)}"
        print(f"    -> ERROR ({reason})")
        _handle_failure(item, reason)
        return False


def _handle_failure(item, reason):
    if item["attempts"] >= MAX_RETRIES:
        item["status"] = "failed"
        log_failed(item["url"], reason)
        print(f"    -> menyerah setelah {MAX_RETRIES}x percobaan, dicatat di {FAILED_LOG}")
    else:
        item["status"] = "pending"  # akan dicoba lagi di pass berikutnya
        backoff = RETRY_BACKOFF_SECONDS[min(item["attempts"] - 1, len(RETRY_BACKOFF_SECONDS) - 1)]
        print(f"    -> retry dalam {backoff}s...")
        time.sleep(backoff)


save_queue_ref = [None]  # helper supaya bisa save_queue di dalam process_target


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("targets_file")
    parser.add_argument("--cookie", default=None,
                         help='Cookie session untuk pentest authenticated, contoh: "PHPSESSID=abc; auth=xyz"')
    parser.add_argument("--header", action="append", default=[],
                         help='Header tambahan (bisa berkali-kali), contoh: --header "Authorization: Bearer xxx"')
    parser.add_argument("--nuclei-tags", default="exposures,misconfig,default-login,exposed-panels,"
                                                  "takeover,sqli,ssti,rce,lfi,xxe,injection",
                         help="Filter template Nuclei resmi - default sudah cover auth-bypass, "
                              "misconfig, DAN injection umum (SQLi, SSTI, RCE, LFI, XXE). "
                              "Kosongkan (--nuclei-tags '') untuk pakai semua template.")
    parser.add_argument("--sqlmap-tamper", default=None,
                         help="Tamper script bawaan sqlmap untuk bantu lolos WAF sederhana, "
                              "contoh: 'space2comment,between,charencode'. Lihat daftar lengkap: "
                              "sqlmap --list-tampers")
    parser.add_argument("--check-smuggling", action="store_true",
                         help="Aktifkan pengecekan HTTP Request Smuggling (via tool Smuggler), "
                              "dicek 1x per host. Butuh: pip install smuggler atau clone dari "
                              "https://github.com/defparam/smuggler")
    args = parser.parse_args()

    targets_file = args.targets_file
    queue = load_queue(targets_file)
    save_queue_ref[0] = queue

    pending = [i for i in queue if i["status"] in ("pending", "scanning")]
    print(f"[*] Total target: {len(queue)} | Pending: {len(pending)} | "
          f"Done: {len([i for i in queue if i['status'] == 'done'])} | "
          f"Failed: {len([i for i in queue if i['status'] == 'failed'])}")
    if args.cookie:
        print("[*] Mode authenticated: cookie session akan disertakan ke Nuclei & sqlmap.")
    if args.nuclei_tags:
        print(f"[*] Nuclei tags aktif: {args.nuclei_tags}")
    if args.sqlmap_tamper:
        print(f"[*] sqlmap tamper aktif: {args.sqlmap_tamper}")
    if args.check_smuggling:
        print("[*] HTTP Smuggling check AKTIF (1x per host).")

    smuggling_checked_hosts = set()

    for item in queue:
        if item["status"] == "done":
            continue
        if item["status"] == "failed" and item["attempts"] >= MAX_RETRIES:
            continue
        process_target(item, cookie=args.cookie, extra_headers=args.header,
                        nuclei_tags=args.nuclei_tags, sqlmap_tamper=args.sqlmap_tamper,
                        check_smuggling=args.check_smuggling,
                        smuggling_checked_hosts=smuggling_checked_hosts)
        save_queue(queue)  # checkpoint setiap selesai satu target

    print("\n[*] Selesai. Jalankan ulang command yang sama kapan saja untuk retry yang gagal/lanjut yang pending.")
    print(f"[*] Findings tersimpan di: {FINDINGS_PATH}")
    print(f"[*] Target yang gagal total: {FAILED_LOG}")


if __name__ == "__main__":
    main()
