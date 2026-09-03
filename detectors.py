"""
Heuristic Detectors
====================
Modul ini MENANDAI kandidat temuan berdasarkan pola pada HTTP request/response
yang ditangkap dari Burp Suite (traffic pasif). Ini BUKAN exploit engine -
semua hasil berstatus "candidate" yang WAJIB diverifikasi manual oleh pentester
sebelum dimasukkan ke laporan resmi.

Kategori yang dicek:
  - Indikasi error-based injection (SQL/NoSQL/Command/LDAP)
  - Reflected parameter (indikasi awal XSS - butuh verifikasi manual)
  - Sensitive information disclosure (API key, token, stack trace, internal IP, PII)
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class Finding:
    category: str
    subtype: str
    confidence: str          # "low" | "medium" | "high"
    endpoint: str
    evidence: str
    note: str
    suggested_cvss_vector: str = ""


# ---------------------------------------------------------------------------
# Pattern banks (deteksi berbasis tanda/pesan error, bukan payload aktif)
# ---------------------------------------------------------------------------

SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*\Wmysqli?_",
    r"PostgreSQL.*ERROR",
    r"ORA-\d{5}",
    r"Microsoft SQL Server",
    r"SQLite/JDBCDriver",
    r"System\.Data\.SqlClient\.SqlException",
]

COMMAND_INJECTION_PATTERNS = [
    r"/bin/sh:.*not found",
    r"'.*' is not recognized as an internal or external command",
    r"sh: line \d+:",
]

STACK_TRACE_PATTERNS = [
    r"at [\w\.]+\([\w\.]+:\d+\)",       # Java stack trace
    r"Traceback \(most recent call last\)",  # Python
    r"Fatal error:.*on line \d+",       # PHP
]

SENSITIVE_DATA_PATTERNS = {
    "aws_key": r"AKIA[0-9A-Z]{16}",
    "generic_api_key": r"(?i)(api[_-]?key|secret)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']",
    "jwt": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "private_key": r"-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
    "internal_ip": r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b",
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
}


def check_injection_indicators(endpoint: str, response_body: str) -> List[Finding]:
    findings = []
    for pattern in SQL_ERROR_PATTERNS:
        if re.search(pattern, response_body):
            findings.append(Finding(
                category="Injection",
                subtype="SQL Injection (error-based indicator)",
                confidence="medium",
                endpoint=endpoint,
                evidence=f"Pattern matched: {pattern}",
                note="Pesan error database terdeteksi di response. Verifikasi manual "
                     "dengan payload boolean/time-based untuk konfirmasi.",
                suggested_cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
            ))
    for pattern in COMMAND_INJECTION_PATTERNS:
        if re.search(pattern, response_body):
            findings.append(Finding(
                category="Injection",
                subtype="OS Command Injection (indicator)",
                confidence="medium",
                endpoint=endpoint,
                evidence=f"Pattern matched: {pattern}",
                note="Pesan shell/OS error terdeteksi. Verifikasi manual dengan payload "
                     "command chaining yang aman (mis. sleep/timing) sebelum konfirmasi.",
                suggested_cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            ))
    return findings


def check_sensitive_disclosure(endpoint: str, response_body: str) -> List[Finding]:
    findings = []
    for label, pattern in SENSITIVE_DATA_PATTERNS.items():
        matches = re.findall(pattern, response_body)
        if matches:
            findings.append(Finding(
                category="Sensitive Information Disclosure",
                subtype=label,
                confidence="high" if label in ("aws_key", "private_key", "jwt") else "medium",
                endpoint=endpoint,
                evidence=f"{len(matches)} match(es) untuk pola '{label}'",
                note="Data sensitif tampak di response body. Pastikan ini bukan false "
                     "positive (mis. dummy/test data) sebelum dilaporkan.",
                suggested_cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            ))

    for pattern in STACK_TRACE_PATTERNS:
        if re.search(pattern, response_body):
            findings.append(Finding(
                category="Sensitive Information Disclosure",
                subtype="Verbose Error / Stack Trace",
                confidence="medium",
                endpoint=endpoint,
                evidence=f"Pattern matched: {pattern}",
                note="Stack trace terekspos ke client - bisa membocorkan struktur "
                     "internal aplikasi/library version.",
                suggested_cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
            ))
    return findings


def check_reflected_params(endpoint: str, request_params: Dict[str, str], response_body: str) -> List[Finding]:
    """Deteksi reflected input - indikasi AWAL untuk XSS, WAJIB verifikasi manual
    dengan payload benign (mis. penanda unik) sebelum konfirmasi eksploitasi."""
    findings = []
    for key, value in request_params.items():
        if len(value) >= 4 and value in response_body:
            findings.append(Finding(
                category="Injection",
                subtype="Reflected Input (possible XSS - unconfirmed)",
                confidence="low",
                endpoint=endpoint,
                evidence=f"Parameter '{key}' direfleksikan apa adanya di response",
                note="Ini baru indikasi reflection, BUKAN konfirmasi XSS. Cek manual "
                     "apakah output di-encode/di-sanitize sebelum masuk laporan.",
                suggested_cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
            ))
    return findings


def analyze_transaction(endpoint: str, request_params: Dict[str, str], response_body: str) -> List[Finding]:
    """Entry point utama: jalankan semua checker untuk satu request/response pair."""
    findings: List[Finding] = []
    findings += check_injection_indicators(endpoint, response_body)
    findings += check_sensitive_disclosure(endpoint, response_body)
    findings += check_reflected_params(endpoint, request_params, response_body)
    return findings
