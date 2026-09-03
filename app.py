"""
Pentest Co-Pilot Server
=========================
Menerima traffic yang diteruskan oleh Burp Extension (lihat ../extension/),
menjalankan heuristic detectors, menghitung CVSS 4.0, dan menyimpan findings
untuk digenerate jadi laporan.

Jalankan:
    pip install flask --break-system-packages
    python app.py
Default listen di http://127.0.0.1:8787
"""

import json
import os
from datetime import datetime, timezone
from flask import Flask, request, jsonify

from cvss4 import calculate as cvss4_calculate, CVSS4Error
from detectors import analyze_transaction

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "findings.json")


def _load_findings():
    if not os.path.exists(DB_PATH):
        return []
    try:
        with open(DB_PATH, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, ValueError):
        # File rusak/corrupt - backup lalu mulai dari kosong supaya server tidak crash
        backup_path = DB_PATH + ".corrupt_backup"
        try:
            os.replace(DB_PATH, backup_path)
            print(f"[Co-Pilot] findings.json rusak, dibackup ke {backup_path} dan direset kosong.")
        except OSError:
            pass
        return []


def _save_findings(findings):
    with open(DB_PATH, "w") as f:
        json.dump(findings, f, indent=2)


@app.route("/", methods=["GET"])
def home():
    """Halaman status - buka di browser untuk cek server hidup atau tidak."""
    stored = _load_findings()
    total = len(stored)
    candidate = len([f for f in stored if f["status"] == "candidate"])
    confirmed = len([f for f in stored if f["status"] == "confirmed"])
    rejected = len([f for f in stored if f["status"] == "false_positive"])

    html = f"""
    <html>
    <head><title>Pentest Co-Pilot Status</title></head>
    <body style="font-family: sans-serif; max-width: 700px; margin: 40px auto;">
        <h2>✅ Pentest Co-Pilot Server: HIDUP</h2>
        <p>Server berjalan normal di port 8787.</p>
        <h3>Ringkasan findings.json</h3>
        <ul>
            <li>Total temuan: <b>{total}</b></li>
            <li>Candidate (belum diverifikasi): <b>{candidate}</b></li>
            <li>Confirmed: <b>{confirmed}</b></li>
            <li>False positive (ditolak): <b>{rejected}</b></li>
        </ul>
        <h3>Link yang tersedia</h3>
        <ul>
            <li><a href="/findings">/findings</a> - lihat semua temuan (JSON)</li>
            <li><a href="/findings?status=candidate">/findings?status=candidate</a> - yang belum diverifikasi</li>
            <li><a href="/findings?status=confirmed">/findings?status=confirmed</a> - yang sudah dikonfirmasi</li>
            <li><a href="/findings?status=waf_protected">/findings?status=waf_protected</a> - yang terlindungi WAF</li>
            <li><a href="/findings/status-summary">/findings/status-summary</a> - ringkasan per status</li>
        </ul>
        <h3>Update status finding</h3>
        <pre style="background:#f5f5f5;padding:10px;font-size:12px;">
# Downgrade ke candidate (perlu validasi ulang)
curl -X POST http://127.0.0.1:8787/findings/0/status \\
  -H "Content-Type: application/json" \\
  -d '{{"status": "candidate"}}'

# Mark sebagai WAF-protected (terdeteksi ada WAF, belum confirmed)
curl -X POST http://127.0.0.1:8787/findings/0/status \\
  -H "Content-Type: application/json" \\
  -d '{{"status": "waf_protected", "note": "sqlmap di-block WAF, perlu validasi manual"}}'

# Tolak sebagai false positive
curl -X POST http://127.0.0.1:8787/findings/0/status \\
  -H "Content-Type: application/json" \\
  -d '{{"status": "false_positive"}}'
        </pre>
        <p style="color: #888;">Kalau "Total temuan" masih 0, coba browsing sebentar via Burp Proxy
        lalu refresh halaman ini.</p>
    </body>
    </html>
    """
    return html


@app.route("/ingest", methods=["POST"])
def ingest():
    """
    Endpoint yang dipanggil oleh Burp Extension untuk tiap request/response
    yang lewat proxy. Payload JSON:
    {
        "endpoint": "https://target.com/api/login",
        "method": "POST",
        "request_params": {"username": "admin"},
        "response_body": "<html>...</html>",
        "status_code": 500
    }
    """
    data = request.get_json(force=True)
    endpoint = data.get("endpoint", "unknown")
    request_params = data.get("request_params", {})
    response_body = data.get("response_body", "")

    findings = analyze_transaction(endpoint, request_params, response_body)

    stored = _load_findings()
    new_entries = []
    for f in findings:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "endpoint": f.endpoint,
            "category": f.category,
            "subtype": f.subtype,
            "confidence": f.confidence,
            "evidence": f.evidence,
            "note": f.note,
            "status": "candidate",  # candidate -> confirmed / false_positive (manual review)
            "suggested_cvss_vector": f.suggested_cvss_vector,
        }
        stored.append(entry)
        new_entries.append(entry)

    _save_findings(stored)
    return jsonify({"new_findings": new_entries, "total_findings": len(stored)})


@app.route("/findings", methods=["GET"])
def list_findings():
    status_filter = request.args.get("status")
    stored = _load_findings()
    if status_filter:
        stored = [f for f in stored if f["status"] == status_filter]
    return jsonify(stored)


@app.route("/findings/<int:index>/status", methods=["POST"])
def update_status(index):
    """Update status finding ke nilai apapun yang valid.
    Body JSON: {"status": "candidate"} atau "confirmed" / "false_positive" / "waf_protected"
    Contoh:
        curl -X POST http://127.0.0.1:8787/findings/0/status \
          -H "Content-Type: application/json" \
          -d '{"status": "candidate"}'
    """
    stored = _load_findings()
    if index < 0 or index >= len(stored):
        return jsonify({"error": "index out of range"}), 404

    body = request.get_json(force=True) or {}
    new_status = body.get("status")
    valid_statuses = {"candidate", "confirmed", "false_positive", "waf_protected"}
    if new_status not in valid_statuses:
        return jsonify({
            "error": f"Status tidak valid. Pilihan: {valid_statuses}"
        }), 400

    old_status = stored[index].get("status")
    stored[index]["status"] = new_status
    if "note" in body:
        stored[index]["note"] = body["note"]
    _save_findings(stored)
    return jsonify({
        "index": index,
        "old_status": old_status,
        "new_status": new_status,
        "finding": stored[index],
    })


@app.route("/findings/status-summary", methods=["GET"])
def status_summary():
    """Ringkasan jumlah finding per status — berguna untuk monitoring."""
    stored = _load_findings()
    from collections import Counter
    counts = Counter(f.get("status", "unknown") for f in stored)
    return jsonify({
        "total": len(stored),
        "by_status": dict(counts),
    })
def confirm_finding(index):
    """Pentester menandai finding sebagai 'confirmed' setelah verifikasi manual,
    lalu bisa override vector CVSS sesuai bukti aktual."""
    stored = _load_findings()
    if index < 0 or index >= len(stored):
        return jsonify({"error": "index out of range"}), 404

    body = request.get_json(force=True) or {}
    stored[index]["status"] = "confirmed"
    if "cvss_vector" in body:
        stored[index]["suggested_cvss_vector"] = body["cvss_vector"]

    _save_findings(stored)
    return jsonify(stored[index])


@app.route("/findings/<int:index>/reject", methods=["POST"])
def reject_finding(index):
    stored = _load_findings()
    if index < 0 or index >= len(stored):
        return jsonify({"error": "index out of range"}), 404
    stored[index]["status"] = "false_positive"
    _save_findings(stored)
    return jsonify(stored[index])


@app.route("/cvss/calculate", methods=["POST"])
def calculate_cvss():
    body = request.get_json(force=True)
    vector = body.get("vector", "")
    try:
        result = cvss4_calculate(vector)
    except CVSS4Error as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({
        "vector": result.vector,
        "base_score": result.base_score,
        "severity": result.severity,
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8787, debug=True)
