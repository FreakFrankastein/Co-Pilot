"""
Replay Scanner - Test dari Raw Request Asli (setara Burp Pro / Acunetix)
============================================================================
Nuclei/sqlmap yang dijalankan dari daftar URL biasa (orchestrator.py) sering
"buta" terhadap aplikasi yang komunikasinya lewat POST body kompleks (contoh:
ZK Framework, SPA modern). Script ini mengambil RAW REQUEST ASLI yang sudah
ditangkap CopilotExtension.py (lengkap dengan cookie, header, POST body persis
seperti yang benar-benar dikirim aplikasi), lalu suruh sqlmap test dari situ
pakai opsi -r. Ini jauh lebih akurat - sama seperti cara kerja Burp Active
Scanner Pro atau Acunetix yang menguji traffic asli, bukan menebak dari URL.

Cara pakai:
    python replay_scan.py

(otomatis baca semua file di folder captured_requests/ yang dibuat extension)

Fitur resiliensi sama seperti orchestrator.py: checkpoint + retry + timeout
per-request, supaya tahan kalau LAN putus di tengah proses.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

from cvss4 import calculate as cvss4_calculate, CVSS4Error

CAPTURED_DIR = "captured_requests"
QUEUE_PATH = "replay_queue.json"
FAILED_LOG = "replay_failed.json"
FINDINGS_PATH = "findings.json"

MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = [10, 30, 90]
PER_REQUEST_TIMEOUT = 180  # default, bisa dioverride via --request-timeout


def load_queue():
    if not os.path.exists(CAPTURED_DIR):
        print(f"[!] Folder '{CAPTURED_DIR}' belum ada. Pastikan extension sudah "
              f"jalan dan kamu sudah browsing lewat Burp Proxy dulu.")
        sys.exit(1)

    files = sorted(os.listdir(CAPTURED_DIR))
    files = [f for f in files if f.endswith(".txt")]

    if os.path.exists(QUEUE_PATH):
        with open(QUEUE_PATH, "r") as f:
            queue = json.load(f)
        existing = {item["file"] for item in queue}
        for fname in files:
            if fname not in existing:
                queue.append({"file": fname, "status": "pending", "attempts": 0})
        return queue

    return [{"file": fname, "status": "pending", "attempts": 0} for fname in files]


def save_queue(queue):
    with open(QUEUE_PATH, "w") as f:
        json.dump(queue, f, indent=2)


def log_failed(fname, reason):
    failed = []
    if os.path.exists(FAILED_LOG):
        with open(FAILED_LOG, "r") as f:
            failed = json.load(f)
    failed.append({"file": fname, "reason": reason, "timestamp": datetime.now(timezone.utc).isoformat()})
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


def extract_url_from_request_file(filepath):
    """Ambil baris pertama request untuk ditampilkan sebagai referensi endpoint."""
    try:
        with open(filepath, "r", errors="ignore") as f:
            first_line = f.readline().strip()
        host_line = ""
        with open(filepath, "r", errors="ignore") as f:
            for line in f:
                if line.lower().startswith("host:"):
                    host_line = line.split(":", 1)[1].strip()
                    break
        return f"{first_line} (Host: {host_line})"
    except Exception:
        return filepath


def build_full_url(filepath, default_scheme="https"):
    """Rekonstruksi full URL (untuk Dalfox/smuggling) dari raw request file."""
    try:
        with open(filepath, "r", errors="ignore") as f:
            lines = f.readlines()
        first_line = lines[0].strip() if lines else ""
        match = re.match(r"(GET|POST|PUT|DELETE|PATCH)\s+(\S+)\s+HTTP", first_line)
        path = match.group(2) if match else "/"
        host = ""
        for line in lines[1:]:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break
        return f"{default_scheme}://{host}{path}", host
    except Exception:
        return None, None


def run_dalfox_replay(url, cookie=None, timeout=120):
    """Dalfox: XSS scanner yang verifikasi eksekusi payload beneran (bukan cuma
    reflection). Tool resmi open-source (github.com/hahwul/dalfox)."""
    cmd = ["dalfox", "url", url, "--silence", "--format", "json"]
    if cookie:
        cmd += ["--cookie", cookie]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return None
    try:
        return json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError:
        return []


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
        "source": "dalfox_replay",
        "name": f"XSS Confirmed - {hit.get('type', 'reflected')}",
        "severity": "medium",
        "status": "confirmed",
        "cvss_vector": vector,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_sev,
        "parameter": hit.get("param", "N/A"),
        "method": hit.get("method", "GET"),
        "evidence": hit.get("evidence", ""),
        "note": "Dikonfirmasi oleh Dalfox (verifikasi eksekusi payload beneran).",
    }


def run_smuggling_check(base_url, timeout=120):
    """Cek HTTP Request Smuggling pakai Smuggler (github.com/defparam/smuggler),
    tool resmi open-source, probing non-destructive."""
    try:
        cmd = ["smuggler", "-u", base_url]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None


def smuggling_output_to_finding(host_url, output):
    if not output or "VULNERABLE" not in output.upper():
        return None
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    try:
        result = cvss4_calculate(vector)
        cvss_score, cvss_sev = result.base_score, result.severity
    except CVSS4Error:
        cvss_score, cvss_sev = None, None
    relevant_lines = [l for l in output.splitlines()
                       if "VULNERABLE" in l.upper() or "CL.TE" in l or "TE.CL" in l or "TE.TE" in l]
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoint": host_url,
        "source": "smuggler_replay",
        "name": "HTTP Request Smuggling (indikasi desync CL.TE/TE.CL/TE.TE)",
        "severity": "critical",
        "status": "candidate",
        "cvss_vector": vector,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_sev,
        "evidence": " | ".join(relevant_lines[:5]) or "Lihat output lengkap smuggler untuk detail",
        "note": "WAJIB verifikasi manual - HTTP smuggling berdampak besar tapi rawan false positive.",
    }


def parse_sqlmap_output(output):
    """Parse output sqlmap secara teliti untuk bedakan:
    - confirmed    : benar-benar injectable
    - waf_protected: indikasi ada WAF yang memblokir payload
    - not_found    : tidak ada tanda apa-apa
    """
    result = {
        "verdict":         "not_found",
        "parameter":       None,
        "method":          None,
        "injection_type":  None,
        "payload":         None,
        "error_500_count": 0,
        "waf_detected":    False,
    }

    output_low = output.lower()

    # Hitung berapa kali server balas 500
    result["error_500_count"] = output_low.count("500 (internal server error)")

    # Deteksi tanda WAF
    waf_keywords = ["waf", "firewall", "protection mechanism",
                    "connection reset", "intrusion detection"]
    if any(k in output_low for k in waf_keywords):
        result["waf_detected"] = True

    # Frasa negatif yang HARUS dikecualikan supaya tidak false positive
    negative_phrases = [
        "do not appear to be injectable",
        "does not seem to be injectable",
        "not injectable",
        "all tested parameters do not appear",
    ]
    is_negative = any(p in output_low for p in negative_phrases)

    # Frasa positif (konfirmasi kuat)
    positive_phrases = [
        "is vulnerable",
        "the following injection point",
        "sqlmap identified the following injection",
    ]
    has_positive = any(p in output_low for p in positive_phrases) or \
                   bool(re.search(r"parameter '[^']+' is injectable", output_low))

    confirmed = has_positive and not is_negative

    if confirmed:
        result["verdict"] = "confirmed"
        m1 = re.search(r"Parameter:\s*([^\s(]+)\s*\(([^)]+)\)", output)
        m2 = re.search(r"(GET|POST|PUT|COOKIE|HEADER)\s+parameter\s+'([^']+)'",
                         output, re.IGNORECASE)
        if m1:
            result["parameter"] = m1.group(1)
            result["method"]    = m1.group(2)
        elif m2:
            result["method"]    = m2.group(1)
            result["parameter"] = m2.group(2)
        m3 = re.search(r"Type:\s*(.+)", output)
        if m3:
            result["injection_type"] = m3.group(1).strip()
        m4 = re.search(r"Payload:\s*(.+)", output)
        if m4:
            result["payload"] = m4.group(1).strip()[:300]
        return result

    # Indikasi WAF: banyak 500 + tanda WAF tapi belum confirmed
    if (result["error_500_count"] >= 5 and result["waf_detected"]) or \
       result["error_500_count"] >= 10:
        result["verdict"] = "waf_protected"

    return result


def run_sqlmap_stage(filepath, insecure, tamper, level, risk,
                      technique, http_timeout):
    """Jalankan 1 stage sqlmap, return parsed result."""
    cmd = ["sqlmap", "-r", filepath, "--batch",
           f"--level={level}", f"--risk={risk}",
           "--timeout=15", "--retries=1",
           "--delay=2", "--threads=1",
           "--output-dir=sqlmap_out"]
    if insecure:
        cmd += ["--force-ssl"]
    if tamper:
        cmd += ["--tamper", tamper]
    if technique:
        cmd += [f"--technique={technique}"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=http_timeout
        )
        return parse_sqlmap_output(result.stdout)
    except subprocess.TimeoutExpired:
        raise
    except Exception as e:
        return {"verdict": "not_found", "error": str(e),
                "error_500_count": 0, "waf_detected": False}


def run_sqlmap_replay(filepath, insecure=False, tamper=None,
                       level=2, risk=1, http_timeout=300):
    """Multi-stage SQLi testing:
    Stage 1 (cepat): Teknik BT saja, level=1
    Stage 2 (medium): Semua teknik, level=level arg
    Stage 3 (tamper): Pakai tamper script untuk lolos WAF sederhana
    Berhenti segera di stage yang berhasil confirm - hemat waktu.
    """
    stage_timeout = max(http_timeout // 3, 60)

    print(f"    -> sqlmap Stage 1 (cepat: BT only, level=1)...")
    s1 = run_sqlmap_stage(filepath, insecure, None, 1, 1, "BT", stage_timeout)
    if s1["verdict"] == "confirmed":
        print(f"    -> ✅ Terkonfirmasi di Stage 1!")
        return s1

    print(f"    -> sqlmap Stage 2 (semua teknik, level={level})...")
    s2 = run_sqlmap_stage(filepath, insecure, None, level, risk, None, stage_timeout)
    if s2["verdict"] == "confirmed":
        print(f"    -> ✅ Terkonfirmasi di Stage 2!")
        return s2

    # Deteksi WAF dari kedua stage
    waf_hint = (s1.get("verdict") == "waf_protected" or
                s2.get("verdict") == "waf_protected" or
                s1.get("error_500_count", 0) >= 5 or
                s2.get("error_500_count", 0) >= 5 or
                s1.get("waf_detected") or s2.get("waf_detected"))

    if waf_hint:
        used_tamper = tamper or "space2comment,between,charencode"
        print(f"    -> Indikasi WAF, Stage 3 (tamper: {used_tamper})...")
        s3 = run_sqlmap_stage(
            filepath, insecure, used_tamper, level, risk, None, stage_timeout
        )
        if s3["verdict"] == "confirmed":
            print(f"    -> ✅ Terkonfirmasi di Stage 3 (bypass WAF)!")
            return s3
        print(f"    -> ⚠️  WAF aktif memblokir payload → marking waf_protected")
        return {
            "verdict": "waf_protected",
            "error_500_count": max(
                s1.get("error_500_count", 0),
                s2.get("error_500_count", 0),
                s3.get("error_500_count", 0)
            ),
            "waf_detected": True,
            "parameter": None, "method": None,
            "injection_type": None, "payload": None,
        }

    return {"verdict": "not_found", "parameter": None, "method": None,
            "injection_type": None, "payload": None, "error_500_count": 0}



def run_nuclei_replay(filepath, tags=None):
    """Nuclei punya mode -im burp yang bisa baca raw request Burp langsung
    sebagai target - jadi dia test persis dari request asli (cookie, header,
    POST body lengkap), bukan cuma dari URL biasa."""
    cmd = ["nuclei", "-l", filepath, "-im", "burp", "-jsonl", "-silent",
           "-timeout", "10", "-retries", "1"]
    if tags:
        cmd += ["-tags", tags]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=PER_REQUEST_TIMEOUT)
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


def nuclei_hit_to_finding(endpoint_ref, hit):
    info = hit.get("info", {})
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
        result = cvss4_calculate(vector)
        cvss_score, cvss_sev = result.base_score, result.severity
    except CVSS4Error:
        cvss_score, cvss_sev = None, None

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoint": endpoint_ref,
        "source": "nuclei_replay",
        "template_id": hit.get("template-id"),
        "name": info.get("name"),
        "severity": severity,
        "status": "confirmed",
        "cvss_vector": vector,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_sev,
    }


def process_item(item, insecure=False, tamper=None, nuclei_tags=None, cookie=None,
                  check_smuggling=False, smuggling_checked_hosts=None, smuggling_scope="host",
                  request_timeout=180, sqlmap_level=2, sqlmap_risk=1):
    filepath = os.path.join(CAPTURED_DIR, item["file"])
    endpoint_ref = extract_url_from_request_file(filepath)
    print(f"\n[*] Replay testing: {endpoint_ref} (attempt {item['attempts'] + 1})")

    try:
        item["status"] = "scanning"

        # --- Nuclei: test dari raw request asli (SQLi, SSTI, RCE, LFI, XXE, dll) ---
        nuclei_hits = run_nuclei_replay(filepath, tags=nuclei_tags)
        if nuclei_hits:
            findings = [nuclei_hit_to_finding(endpoint_ref, h) for h in nuclei_hits]
            save_findings(findings)
            print(f"    -> Nuclei: {len(findings)} temuan (auto-confirmed by template match)")

        # --- sqlmap: test dari raw request asli ---
        sqlmap_result = run_sqlmap_replay(filepath, insecure=insecure, tamper=tamper,
                                            level=sqlmap_level, risk=sqlmap_risk,
                                            http_timeout=request_timeout)

        verdict = sqlmap_result.get("verdict", "not_found")

        if verdict == "confirmed":
            vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
            try:
                result = cvss4_calculate(vector)
                cvss_score, cvss_sev = result.base_score, result.severity
            except CVSS4Error:
                cvss_score, cvss_sev = None, None

            finding = {
                "timestamp":      datetime.now(timezone.utc).isoformat(),
                "endpoint":       endpoint_ref,
                "source":         "sqlmap_replay",
                "name":           "SQL Injection (confirmed - multi-stage)",
                "severity":       "high",
                "status":         "confirmed",
                "cvss_vector":    vector,
                "cvss_score":     cvss_score,
                "cvss_severity":  cvss_sev,
                "parameter":      sqlmap_result.get("parameter") or "Lihat sqlmap_out/",
                "method":         sqlmap_result.get("method"),
                "injection_type": sqlmap_result.get("injection_type"),
                "payload":        sqlmap_result.get("payload"),
                "note": f"Dikonfirmasi sqlmap multi-stage dari raw request asli ({item['file']}).",
            }
            save_findings([finding])
            print("    -> ✅ SQL Injection TERKONFIRMASI! Tersimpan ke findings.json")

        elif verdict == "waf_protected":
            vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
            try:
                result = cvss4_calculate(vector)
                cvss_score, cvss_sev = result.base_score, result.severity
            except CVSS4Error:
                cvss_score, cvss_sev = None, None

            finding = {
                "timestamp":     datetime.now(timezone.utc).isoformat(),
                "endpoint":      endpoint_ref,
                "source":        "sqlmap_replay",
                "name":          "SQL Injection (indikasi - WAF/filter aktif memblokir payload)",
                "severity":      "high",
                "status":        "waf_protected",
                "cvss_vector":   vector,
                "cvss_score":    cvss_score,
                "cvss_severity": cvss_sev,
                "parameter":     "Lihat sqlmap_out/ untuk detail",
                "note": f"Payload diblokir WAF/filter ({sqlmap_result.get('error_500_count',0)}x HTTP 500). "
                        f"Perlu validasi manual via Burp Repeater: coba inject karakter quote (') "
                        f"ke parameter dan amati perbedaan response.",
            }
            save_findings([finding])
            print("    -> ⚠️  WAF terdeteksi, disimpan sebagai waf_protected → validasi manual via Burp")

        else:
            print("    -> sqlmap: tidak ada indikasi injection")

        # --- Dalfox: cek XSS (verifikasi eksekusi beneran) ---
        full_url, host = build_full_url(filepath)
        if full_url:
            dalfox_hits = run_dalfox_replay(full_url, cookie=cookie)
            if dalfox_hits:
                findings = [dalfox_to_finding(full_url, h) for h in dalfox_hits]
                save_findings(findings)
                print(f"    -> Dalfox: {len(findings)} XSS terkonfirmasi")

            # --- Smuggling: default 1x per host (rekomendasi), atau per-path kalau diminta ---
            if check_smuggling and host and smuggling_checked_hosts is not None:
                scope_key = f"https://{host}" if smuggling_scope == "host" else full_url
                if scope_key not in smuggling_checked_hosts:
                    smuggling_checked_hosts.add(scope_key)
                    target_for_check = f"https://{host}" if smuggling_scope == "host" else full_url
                    print(f"    -> Cek HTTP smuggling untuk {scope_key} "
                          f"(scope: {smuggling_scope})...")
                    output = run_smuggling_check(target_for_check)
                    finding = smuggling_output_to_finding(scope_key, output)
                    if finding:
                        save_findings([finding])
                        print("    -> Indikasi HTTP smuggling ditemukan! Wajib verifikasi manual.")

        item["status"] = "done"
        return True

    except subprocess.TimeoutExpired:
        item["attempts"] += 1
        _handle_failure(item, f"timeout after {request_timeout}s (naikkan dengan --request-timeout kalau target lambat)")
        return False
    except FileNotFoundError as e:
        print(f"[!] sqlmap tidak ditemukan di PATH: {e}")
        sys.exit(1)
    except Exception as e:
        item["attempts"] += 1
        _handle_failure(item, f"error: {str(e)}")
        return False


def _handle_failure(item, reason):
    print(f"    -> Detail error: {reason}")
    if item["attempts"] >= MAX_RETRIES:
        item["status"] = "failed"
        log_failed(item["file"], reason)
        print(f"    -> menyerah setelah {MAX_RETRIES}x percobaan, dicatat di {FAILED_LOG}")
    else:
        item["status"] = "pending"
        backoff = RETRY_BACKOFF_SECONDS[min(item["attempts"] - 1, len(RETRY_BACKOFF_SECONDS) - 1)]
        print(f"    -> retry dalam {backoff}s...")
        time.sleep(backoff)


def main():
    parser = argparse.ArgumentParser(description="Replay sqlmap+nuclei+dalfox dari raw request Burp yang tertangkap")
    parser.add_argument("--insecure", action="store_true",
                         help="Untuk target dengan SSL self-signed/internal")
    parser.add_argument("--tamper", default=None,
                         help="Tamper script sqlmap bawaan, contoh: 'space2comment,between'")
    parser.add_argument("--nuclei-tags", default="exposures,misconfig,default-login,exposed-panels,"
                                                  "takeover,sqli,ssti,rce,lfi,xxe,injection",
                         help="Filter template Nuclei resmi - default sudah cover auth-bypass, "
                              "misconfig, DAN injection umum. Kosongkan untuk pakai semua template.")
    parser.add_argument("--cookie", default=None,
                         help="Cookie session untuk Dalfox (kalau butuh login untuk XSS test)")
    parser.add_argument("--check-smuggling", action="store_true",
                         help="Aktifkan pengecekan HTTP Request Smuggling")
    parser.add_argument("--smuggling-scope", choices=["host", "path"], default="host",
                         help="'host' (default, direkomendasikan): test 1x per host - smuggling "
                              "adalah isu level server, bukan level URL, jadi lebih cepat & aman. "
                              "'path': test tiap endpoint unik terpisah (lebih lambat & lebih "
                              "berisiko mengganggu koneksi, pakai hanya kalau ada alasan khusus)")
    parser.add_argument("--request-timeout", type=int, default=180,
                         help="Timeout (detik) per request untuk sqlmap - naikkan kalau target "
                              "lambat/sering timeout (default: 180)")
    parser.add_argument("--sqlmap-level", type=int, default=2, choices=range(1, 6),
                         help="Level testing sqlmap 1-5 (default: 2). Lebih rendah = lebih cepat "
                              "tapi kurang menyeluruh; lebih tinggi = lebih lambat tapi lebih dalam.")
    parser.add_argument("--sqlmap-risk", type=int, default=1, choices=range(1, 4),
                         help="Risk testing sqlmap 1-3 (default: 1). Lebih tinggi = lebih banyak "
                              "payload dicoba (lebih lambat, lebih intrusif).")
    args = parser.parse_args()

    queue = load_queue()
    if not queue:
        print(f"[!] Tidak ada file di '{CAPTURED_DIR}/'. Browsing dulu lewat Burp Proxy "
              f"supaya extension menangkap request-nya.")
        return

    print(f"[*] Total request tertangkap: {len(queue)} | "
          f"Done: {len([i for i in queue if i['status']=='done'])} | "
          f"Pending: {len([i for i in queue if i['status'] in ('pending','scanning')])}")
    if args.check_smuggling:
        print(f"[*] HTTP Smuggling check AKTIF (scope: {args.smuggling_scope}).")
    print(f"[*] sqlmap level={args.sqlmap_level} risk={args.sqlmap_risk} timeout={args.request_timeout}s")

    smuggling_checked_hosts = set()

    for item in queue:
        if item["status"] == "done":
            continue
        if item["status"] == "failed" and item["attempts"] >= MAX_RETRIES:
            continue
        process_item(item, insecure=args.insecure, tamper=args.tamper, nuclei_tags=args.nuclei_tags,
                     cookie=args.cookie, check_smuggling=args.check_smuggling,
                     smuggling_checked_hosts=smuggling_checked_hosts,
                     smuggling_scope=args.smuggling_scope,
                     request_timeout=args.request_timeout,
                     sqlmap_level=args.sqlmap_level, sqlmap_risk=args.sqlmap_risk)
        save_queue(queue)

    print(f"\n[+] Replay scan selesai. Cek hasil di http://127.0.0.1:8787/findings")
    print(f"[+] Jalankan ulang command yang sama kapan saja untuk retry yang gagal/lanjut yang pending.")


if __name__ == "__main__":
    main()
