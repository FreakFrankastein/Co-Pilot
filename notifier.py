"""
Notifier - Alert High-Severity Findings via Telegram
=======================================================
Kirim notifikasi saat ada temuan severity tinggi. Karena Mi Band (dan
smartwatch lain umumnya) TIDAK punya API publik untuk push notifikasi
langsung dari script, cara paling reliable adalah lewat notification
mirroring bawaan HP:

    Co-Pilot --> Telegram Bot --> Notifikasi masuk ke HP
                                        |
                                        v
                        Mi Band otomatis mirror (via Zepp app,
                        asal notification mirroring utk Telegram di-enable)

Setup (sekali saja):
1. Buka Telegram, chat ke @BotFather -> /newbot -> ikuti instruksi -> dapat BOT_TOKEN
2. Chat bot kamu sekali (apa saja) supaya bot bisa balas ke kamu
3. Ambil CHAT_ID: buka https://api.telegram.org/bot<BOT_TOKEN>/getUpdates
   setelah kirim pesan ke bot, cari field "chat":{"id": ...}
4. Set environment variable:
   Windows (cmd):      set COPILOT_TG_TOKEN=xxxx & set COPILOT_TG_CHATID=xxxx
   Windows (PowerShell): $env:COPILOT_TG_TOKEN="xxxx"; $env:COPILOT_TG_CHATID="xxxx"
5. Di HP: Zepp Life app -> Notifications -> aktifkan mirroring untuk Telegram
   (dan pastikan Do Not Disturb Mi Band tidak nyala)

Cara pakai:
    python notifier.py --check-and-notify
    (jalankan manual, atau panggil otomatis dari orchestrator.py/app.py
     setiap kali ada finding baru dengan severity high/critical)
"""

import argparse
import json
import os
import requests

FINDINGS_PATH = "findings.json"
NOTIFIED_LOG = "notified_findings.json"

TG_TOKEN = os.environ.get("COPILOT_TG_TOKEN")
TG_CHAT_ID = os.environ.get("COPILOT_TG_CHATID")

HIGH_SEVERITY = {"high", "critical"}


def send_telegram(message):
    if not TG_TOKEN or not TG_CHAT_ID:
        print("[!] COPILOT_TG_TOKEN / COPILOT_TG_CHATID belum di-set. Lihat docstring untuk setup.")
        return False

    url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
    try:
        resp = requests.post(url, data={"chat_id": TG_CHAT_ID, "text": message}, timeout=10)
        resp.raise_for_status()
        return True
    except requests.RequestException as e:
        print(f"[!] Gagal kirim notifikasi Telegram: {e}")
        return False


def load_notified_ids():
    if not os.path.exists(NOTIFIED_LOG):
        return set()
    with open(NOTIFIED_LOG, "r") as f:
        return set(json.load(f))


def save_notified_ids(ids):
    with open(NOTIFIED_LOG, "w") as f:
        json.dump(list(ids), f)


def check_and_notify():
    if not os.path.exists(FINDINGS_PATH):
        print("[!] findings.json belum ada.")
        return

    with open(FINDINGS_PATH, "r") as f:
        findings = json.load(f)

    notified = load_notified_ids()
    new_notified = 0

    for idx, f in enumerate(findings):
        sev = (f.get("severity") or f.get("cvss_severity") or "").lower()
        uid = f.get("timestamp", "") + f.get("endpoint", "") + str(idx)

        if sev in HIGH_SEVERITY and uid not in notified:
            message = (
                f"🚨 Pentest Co-Pilot Alert\n"
                f"Severity: {sev.upper()}\n"
                f"Finding : {f.get('name') or f.get('subtype', 'Unknown')}\n"
                f"Endpoint: {f.get('endpoint', '-')}\n"
                f"Source  : {f.get('source', 'manual/heuristic')}\n"
                f"Status  : {f.get('status', 'candidate')}"
            )
            if send_telegram(message):
                notified.add(uid)
                new_notified += 1

    save_notified_ids(notified)
    print(f"[+] {new_notified} notifikasi baru terkirim.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-and-notify", action="store_true")
    args = parser.parse_args()

    if args.check_and_notify:
        check_and_notify()
    else:
        print("Gunakan --check-and-notify")
