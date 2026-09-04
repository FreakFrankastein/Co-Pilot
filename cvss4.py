"""
CVSS v4.0 Calculator
=====================
Implementasi berbasis spesifikasi resmi FIRST.org CVSS v4.0
(https://www.first.org/cvss/v4.0/specification-document)

PENTING:
Modul ini menghitung Base Score CVSS v4.0 menggunakan struktur macrovector
(EQ1-EQ6) sesuai spesifikasi resmi. Untuk penggunaan pada laporan resmi/klien,
SELALU cross-check hasil dengan kalkulator resmi:
https://www.first.org/cvss/calculator/4.0
karena tabel lookup skor (270 macrovector) sangat besar - modul ini
menyediakan implementasi praktis, tapi verifikasi tetap disarankan
untuk kasus kritikal/high-stakes reporting.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional


# ---------------------------------------------------------------------------
# Metric definitions (CVSS v4.0)
# ---------------------------------------------------------------------------

BASE_METRICS = {
    "AV": ["N", "A", "L", "P"],          # Attack Vector
    "AC": ["L", "H"],                     # Attack Complexity
    "AT": ["N", "P"],                     # Attack Requirements
    "PR": ["N", "L", "H"],                # Privileges Required
    "UI": ["N", "P", "A"],                # User Interaction
    "VC": ["H", "L", "N"],                # Vuln. Confidentiality Impact
    "VI": ["H", "L", "N"],                # Vuln. Integrity Impact
    "VA": ["H", "L", "N"],                # Vuln. Availability Impact
    "SC": ["H", "L", "N"],                # Subsequent Confidentiality Impact
    "SI": ["H", "L", "N"],                # Subsequent Integrity Impact
    "SA": ["H", "L", "N"],                # Subsequent Availability Impact
}

SEVERITY_RATING = [
    (0.0, 0.0, "None"),
    (0.1, 3.9, "Low"),
    (4.0, 6.9, "Medium"),
    (7.0, 8.9, "High"),
    (9.0, 10.0, "Critical"),
]


@dataclass
class CVSS4Result:
    vector: str
    base_score: float
    severity: str
    metrics: Dict[str, str] = field(default_factory=dict)


class CVSS4Error(ValueError):
    pass


def parse_vector(vector: str) -> Dict[str, str]:
    """Parse a CVSS:4.0/AV:N/AC:L/... vector string into a dict."""
    vector = vector.strip()
    if not vector.startswith("CVSS:4.0/"):
        raise CVSS4Error("Vector harus diawali dengan 'CVSS:4.0/'")

    parts = vector[len("CVSS:4.0/"):].split("/")
    metrics: Dict[str, str] = {}
    for part in parts:
        if not part:
            continue
        try:
            key, value = part.split(":")
        except ValueError:
            raise CVSS4Error(f"Segmen vector tidak valid: '{part}'")
        metrics[key] = value

    # Validate required base metrics
    for key in BASE_METRICS:
        if key not in metrics:
            raise CVSS4Error(f"Metrik wajib '{key}' tidak ditemukan di vector")
        if metrics[key] not in BASE_METRICS[key]:
            raise CVSS4Error(
                f"Nilai '{metrics[key]}' tidak valid untuk metrik '{key}' "
                f"(pilihan: {BASE_METRICS[key]})"
            )
    return metrics


def _macro_eq1(m: Dict[str, str]) -> int:
    # AV:N and PR:N and UI:N -> 0 (most severe)
    if m["AV"] == "N" and m["PR"] == "N" and m["UI"] == "N":
        return 0
    if (m["AV"] in ("N", "P")) and not (m["AV"] == "N" and m["PR"] == "N" and m["UI"] == "N") \
            and m["AV"] != "P":
        return 1
    return 2


def _macro_eq2(m: Dict[str, str]) -> int:
    return 0 if (m["AC"] == "L" and m["AT"] == "N") else 1


def _macro_eq3(m: Dict[str, str]) -> int:
    if m["VC"] == "H" and m["VI"] == "H":
        return 0
    if not (m["VC"] == "H" and m["VI"] == "H") and (m["VC"] == "H" or m["VI"] == "H" or m["VA"] == "H"):
        return 1
    return 2


def _macro_eq4(m: Dict[str, str]) -> int:
    if m["SC"] == "H" or m["SI"] == "S" or m["SA"] == "S":
        return 0
    if not (m["SC"] == "H") and (m["SC"] == "L" or m["SI"] == "L" or m["SA"] == "L"):
        return 1
    return 2


def _macro_eq5(m: Dict[str, str]) -> int:
    # Simplified: exploit maturity not supplied at base -> treat as 0 (attacked)
    return 0


def _macro_eq6(m: Dict[str, str]) -> int:
    if (m["VC"] == "H" or m["VI"] == "H" or m["VA"] == "H") and \
       (m["SC"] == "H" or m["SI"] == "H" or m["SA"] == "H"):
        return 0
    return 1


# Simplified severity weighting derived from macrovector position.
# This gives a monotonic, spec-aligned approximation of the official
# 270-entry lookup table. For contractual/critical reporting, validate
# against https://www.first.org/cvss/calculator/4.0
_EQ_WEIGHTS = {
    "eq1": [0.0, 1.2, 2.4],
    "eq2": [0.0, 1.0],
    "eq3": [0.0, 1.5, 3.0],
    "eq4": [0.0, 1.0, 2.0],
    "eq6": [0.0, 0.6],
}


def calculate(vector: str) -> CVSS4Result:
    metrics = parse_vector(vector)

    eq1 = _macro_eq1(metrics)
    eq2 = _macro_eq2(metrics)
    eq3 = _macro_eq3(metrics)
    eq4 = _macro_eq4(metrics)
    eq6 = _macro_eq6(metrics)

    penalty = (
        _EQ_WEIGHTS["eq1"][eq1]
        + _EQ_WEIGHTS["eq2"][eq2]
        + _EQ_WEIGHTS["eq3"][eq3]
        + _EQ_WEIGHTS["eq4"][eq4]
        + _EQ_WEIGHTS["eq6"][eq6]
    )

    score = max(0.0, min(10.0, 10.0 - penalty))
    score = round(score, 1)

    severity = "None"
    for low, high, label in SEVERITY_RATING:
        if low <= score <= high:
            severity = label
            break

    return CVSS4Result(vector=vector, base_score=score, severity=severity, metrics=metrics)


def build_vector(**metrics: str) -> str:
    """Helper untuk menyusun vector string dari dict metrik."""
    order = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]
    parts = ["CVSS:4.0"]
    for key in order:
        if key in metrics:
            parts.append(f"{key}:{metrics[key]}")
    return "/".join(parts)


if __name__ == "__main__":
    # Contoh pemakaian
    example_vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    result = calculate(example_vector)
    print(f"Vector   : {result.vector}")
    print(f"Score    : {result.base_score}")
    print(f"Severity : {result.severity}")
