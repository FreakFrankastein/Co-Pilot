# -*- coding: utf-8 -*-
"""
Pentest Co-Pilot - Burp Suite Extension (Jython)
==================================================
Kompatibel dengan Burp Suite Professional & Community.

Cara pakai:
1. Burp Suite -> Extender/Extensions -> Options -> Python Environment
   set path ke Jython standalone JAR (download dari jython.org)
2. Extender/Extensions -> Extensions -> Add -> Extension type: Python -> pilih file ini
3. Pastikan copilot server (../server/app.py) sudah jalan di http://127.0.0.1:8787
4. Traffic yang lewat Proxy akan otomatis diteruskan ke server untuk dianalisis

Extension ini HANYA meneruskan data (pasif) - tidak mengubah traffic dan
tidak melakukan aksi otomatis apa pun terhadap target.

BARU: Extension ini juga menyimpan RAW REQUEST LENGKAP (header, cookie, POST
body persis seperti aslinya) untuk request yang punya parameter, ke folder
'captured_requests/'. File-file ini bisa langsung dipakai sqlmap dengan
opsi -r untuk testing yang jauh lebih akurat dibanding cuma dikasih URL biasa
- ini setara dengan cara kerja Burp Active Scanner Pro / Acunetix yang
menguji traffic asli, bukan menebak dari URL.
"""

from burp import IBurpExtender, IProxyListener
from java.net import URL
from java.io import DataOutputStream, File, FileOutputStream
import json
import time

COPILOT_SERVER = "http://127.0.0.1:8787/ingest"

# PENTING: pakai absolute path supaya folder ini SELALU dibuat di lokasi yang
# sama, tidak peduli dari mana Burp Suite dijalankan. Sesuaikan path ini
# dengan lokasi folder project kamu.
CAPTURED_DIR = "/home/kali/Desktop/My Programs/Co Pilot/captured_requests"


class BurpExtender(IBurpExtender, IProxyListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Pentest Co-Pilot")
        callbacks.registerProxyListener(self)

        capture_dir = File(CAPTURED_DIR)
        if not capture_dir.exists():
            capture_dir.mkdirs()

        print("[Co-Pilot] Extension loaded. Forwarding traffic to %s" % COPILOT_SERVER)
        print("[Co-Pilot] Raw request dengan parameter akan disimpan ke folder '%s/'" % CAPTURED_DIR)

    def processProxyMessage(self, messageIsRequest, message):
        # Kita proses saat response sudah diterima supaya bisa analisis body-nya
        if messageIsRequest:
            return

        try:
            messageInfo = message.getMessageInfo()
            request_bytes = messageInfo.getRequest()
            response_bytes = messageInfo.getResponse()
            if response_bytes is None:
                return

            analyzed_request = self._helpers.analyzeRequest(messageInfo)
            url = str(analyzed_request.getUrl())
            method = str(analyzed_request.getMethod())

            # Ambil parameter request (untuk cek reflected input)
            params = {}
            for p in analyzed_request.getParameters():
                try:
                    params[str(p.getName())] = str(p.getValue())
                except Exception:
                    pass

            analyzed_response = self._helpers.analyzeResponse(response_bytes)
            body_offset = analyzed_response.getBodyOffset()
            response_body = self._helpers.bytesToString(response_bytes)[body_offset:]
            status_code = analyzed_response.getStatusCode()

            payload = {
                "endpoint": url,
                "method": method,
                "request_params": params,
                "response_body": response_body,
                "status_code": status_code,
            }

            self._send_to_copilot(payload)

            # Simpan raw request LENGKAP ke file kalau ada parameter
            # (query string ATAU POST body) - ini yang dipakai sqlmap -r nanti
            has_query_param = len(params) > 0
            has_post_body = (method == "POST")
            if has_query_param or has_post_body:
                self._save_raw_request(request_bytes, url)

        except Exception as e:
            print("[Co-Pilot] Error processing message: %s" % str(e))

    def _save_raw_request(self, request_bytes, url):
        try:
            # Nama file unik: timestamp + potongan URL supaya gampang ditelusuri
            safe_name = "".join(c if c.isalnum() else "_" for c in url)[-60:]
            filename = "%s/%d_%s.txt" % (CAPTURED_DIR, int(time.time() * 1000), safe_name)

            raw_bytes = self._helpers.bytesToString(request_bytes)
            fos = FileOutputStream(filename)
            fos.write(raw_bytes.encode("utf-8") if hasattr(raw_bytes, "encode") else raw_bytes)
            fos.close()
        except Exception as e:
            print("[Co-Pilot] Gagal simpan raw request: %s" % str(e))

    def _send_to_copilot(self, payload):
        try:
            data = json.dumps(payload).encode("utf-8")
            conn = URL(COPILOT_SERVER).openConnection()
            conn.setRequestMethod("POST")
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setDoOutput(True)
            out = DataOutputStream(conn.getOutputStream())
            out.write(data)
            out.flush()
            out.close()
            conn.getResponseCode()  # trigger request
        except Exception as e:
            print("[Co-Pilot] Failed to reach server (is app.py running?): %s" % str(e))
