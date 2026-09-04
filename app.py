"""
Pentest Co-Pilot Server
=========================
Server pusat co-pilot. Fungsi:
- Simpan findings dari scanner.py ke findings.json
- Terima traffic raw dari CopilotExtension.py (Burp)
- Expose API untuk lihat & update status findings
- Halaman status di http://127.0.0.1:8787

Jalankan:
    python3 app.py
"""

import json
import os
from collections import Counter
from datetime import datetime, timezone
from flask import Flask, request, jsonify

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "findings.json")


# ── Storage helpers ───────────────────────────────────────────────────────────

def _load_findings():
    if not os.path.exists(DB_PATH):
        return []
    try:
        with open(DB_PATH, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, ValueError):
        backup = DB_PATH + ".corrupt_backup"
        try:
            os.replace(DB_PATH, backup)
            print(f"[Co-Pilot] findings.json rusak, dibackup ke {backup}")
        except OSError:
            pass
        return []


def _save_findings(findings):
    with open(DB_PATH, "w") as f:
        json.dump(findings, f, indent=2)


# ── Halaman status ────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def home():
    stored   = _load_findings()
    total    = len(stored)
    counts   = Counter(f.get("status","unknown") for f in stored)
    sev      = Counter(f.get("severity","info") for f in stored
                        if f.get("status") == "confirmed")

    html = f"""<!DOCTYPE html>
<html><head><title>Pentest Co-Pilot</title>
<style>
  body {{ font-family: sans-serif; max-width: 750px; margin: 40px auto; color: #333; }}
  h2 {{ color: #2c3e50; }} h3 {{ color: #34495e; margin-top: 24px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
  td, th {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
  th {{ background: #34495e; color: #fff; }}
  .ok {{ color: #27ae60; font-weight: bold; }}
  .warn {{ color: #e67e22; font-weight: bold; }}
  code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-size: 13px; }}
  pre {{ background: #f4f4f4; padding: 12px; border-radius: 4px; font-size: 13px; overflow-x: auto; }}
</style></head><body>
<h2>✅ Pentest Co-Pilot — Server Aktif</h2>
<p>Server berjalan normal di <b>http://127.0.0.1:8787</b></p>

<h3>📊 Ringkasan Findings</h3>
<table>
  <tr><th>Status</th><th>Jumlah</th></tr>
  <tr><td>Total</td><td><b>{total}</b></td></tr>
  <tr><td>✅ Confirmed (bukti langsung)</td><td><b style="color:#27ae60">{counts.get('confirmed',0)}</b></td></tr>
  <tr><td>⚠️ Candidate (perlu verifikasi manual)</td><td><b style="color:#e67e22">{counts.get('candidate',0)}</b></td></tr>
  <tr><td>❌ False Positive</td><td>{counts.get('false_positive',0)}</td></tr>
  <tr><td>🛡️ WAF Protected</td><td>{counts.get('waf_protected',0)}</td></tr>
</table>

<h3>🔥 Severity (Confirmed saja)</h3>
<table>
  <tr><th>Severity</th><th>Jumlah</th></tr>
  {''.join(f'<tr><td>{s.capitalize()}</td><td>{sev.get(s,0)}</td></tr>'
            for s in ('critical','high','medium','low','info') if sev.get(s,0))}
</table>

<h3>🔗 Link API</h3>
<table>
  <tr><th>URL</th><th>Keterangan</th></tr>
  <tr><td><a href="/findings">/findings</a></td><td>Semua temuan</td></tr>
  <tr><td><a href="/findings?status=confirmed">/findings?status=confirmed</a></td><td>Terkonfirmasi</td></tr>
  <tr><td><a href="/findings?status=candidate">/findings?status=candidate</a></td><td>Perlu verifikasi manual</td></tr>
  <tr><td><a href="/findings?status=waf_protected">/findings?status=waf_protected</a></td><td>WAF protected</td></tr>
  <tr><td><a href="/findings/status-summary">/findings/status-summary</a></td><td>Ringkasan per status</td></tr>
</table>

<h3>⚙️ Update Status Finding</h3>
<pre># Update status (0 = index finding pertama)
curl -X POST http://127.0.0.1:8787/findings/0/status \\
  -H "Content-Type: application/json" \\
  -d '{{"status": "false_positive"}}'

# Status yang tersedia: confirmed | candidate | false_positive | waf_protected</pre>

<p style="color:#888; font-size:13px;">
  {'⚠️ Belum ada findings — browsing via Burp Proxy atau jalankan scanner.py dulu.' if total == 0 else ''}
</p>
</body></html>"""
    return html


# ── API endpoints ─────────────────────────────────────────────────────────────

@app.route("/ingest", methods=["POST"])
def ingest():
    """
    Dipanggil oleh CopilotExtension.py (Burp) untuk setiap request/response.
    Sekarang hanya menyimpan raw traffic info — analisis dilakukan oleh scanner.py.
    """
    data     = request.get_json(force=True) or {}
    endpoint = data.get("endpoint", "unknown")
    method   = data.get("method", "GET")
    status   = data.get("status_code", 0)

    # Hanya catat, tidak lagi analisis heuristik di sini
    # (analisis sekarang di scanner.py via Nuclei/sqlmap/Dalfox)
    print(f"[Co-Pilot] Traffic: {method} {endpoint} [{status}]")
    stored = _load_findings()
    return jsonify({"status": "ok", "total_findings": len(stored)})


@app.route("/findings", methods=["GET"])
def list_findings():
    status_filter = request.args.get("status")
    sev_filter    = request.args.get("severity")
    stored        = _load_findings()
    if status_filter:
        stored = [f for f in stored if f.get("status") == status_filter]
    if sev_filter:
        stored = [f for f in stored if f.get("severity") == sev_filter]
    # Urutkan: severity tertinggi dulu
    sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
    stored.sort(key=lambda f: sev_order.get(f.get("severity","info"), 5))
    return jsonify(stored)


@app.route("/findings/<int:index>/status", methods=["POST"])
def update_status(index):
    """Update status finding. Body: {"status": "confirmed"/"candidate"/"false_positive"/"waf_protected"}"""
    stored = _load_findings()
    if index < 0 or index >= len(stored):
        return jsonify({"error": "index out of range"}), 404
    body       = request.get_json(force=True) or {}
    new_status = body.get("status")
    valid      = {"confirmed", "candidate", "false_positive", "waf_protected"}
    if new_status not in valid:
        return jsonify({"error": f"Status tidak valid. Pilihan: {valid}"}), 400
    old_status              = stored[index].get("status")
    stored[index]["status"] = new_status
    if body.get("note"):
        stored[index]["note"] = body["note"]
    _save_findings(stored)
    return jsonify({
        "index": index, "old_status": old_status,
        "new_status": new_status, "finding": stored[index]
    })


@app.route("/findings/<int:index>/confirm", methods=["POST"])
def confirm_finding(index):
    """Shortcut: langsung confirm satu finding."""
    stored = _load_findings()
    if index < 0 or index >= len(stored):
        return jsonify({"error": "index out of range"}), 404
    body = request.get_json(force=True) or {}
    stored[index]["status"] = "confirmed"
    if body.get("cvss_vector"):
        stored[index]["cvss_vector"] = body["cvss_vector"]
    if body.get("note"):
        stored[index]["note"] = body["note"]
    _save_findings(stored)
    return jsonify(stored[index])


@app.route("/findings/<int:index>/reject", methods=["POST"])
def reject_finding(index):
    """Shortcut: tandai false positive."""
    stored = _load_findings()
    if index < 0 or index >= len(stored):
        return jsonify({"error": "index out of range"}), 404
    stored[index]["status"] = "false_positive"
    _save_findings(stored)
    return jsonify(stored[index])


@app.route("/findings/status-summary", methods=["GET"])
def status_summary():
    stored = _load_findings()
    counts = Counter(f.get("status","unknown") for f in stored)
    sev    = Counter(f.get("severity","info") for f in stored
                      if f.get("status") == "confirmed")
    return jsonify({
        "total":    len(stored),
        "by_status": dict(counts),
        "confirmed_by_severity": dict(sev),
    })


@app.route("/cvss/calculate", methods=["POST"])
def calculate_cvss():
    """Hitung CVSS 4.0 dari vector string."""
    from cvss4 import calculate as cvss4_calculate, CVSS4Error
    body   = request.get_json(force=True) or {}
    vector = body.get("vector", "")
    try:
        result = cvss4_calculate(vector)
        return jsonify({
            "vector":     result.vector,
            "base_score": result.base_score,
            "severity":   result.severity,
        })
    except CVSS4Error as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    print("[Co-Pilot] Server starting di http://127.0.0.1:8787")
    app.run(host="127.0.0.1", port=8787, debug=False)
