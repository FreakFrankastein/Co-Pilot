"""
Auto Crawler + Pipeline Runner
=================================
Satu perintah untuk: crawl target -> kumpulkan semua endpoint & file JS ->
otomatis jalankan orchestrator.py (Nuclei+sqlmap) dan js_scanner.py ->
semua hasil masuk findings.json.

Kamu tinggal jadi VALIDATOR MANUAL atas hasil yang sudah terkumpul di
findings.json (status: candidate / confirmed dari active scan).

Cara pakai:
    python crawler.py --start-url "https://target.local" --max-pages 100

Yang dilakukan crawler ini SENDIRI (bukan lewat tool lain):
    - Mengikuti link <a href> dalam domain yang sama
    - Mengumpulkan URL dengan parameter (?id=1, ?q=..., dll) sebagai kandidat
      target injection testing
    - Mengumpulkan semua <script src="....js">

Yang dilakukan tool LAIN (dipanggil otomatis dari sini):
    - Nuclei & sqlmap (via orchestrator.py) -> active testing sungguhan
    - js_scanner.py -> cek sensitive info di file JS yang ditemukan

Crawler ini TIDAK mengirim payload apa pun sendiri - murni traversal pasif
seperti browser biasa mengklik link.
"""

import argparse
import subprocess
import sys
from collections import deque
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

DEFAULT_HEADERS = {"User-Agent": "PentestCoPilot-Crawler/1.0"}


def build_headers(cookie=None, extra_header=None):
    headers = dict(DEFAULT_HEADERS)
    if cookie:
        headers["Cookie"] = cookie
    if extra_header:
        # format: "Name: Value"
        for h in extra_header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
    return headers


def same_domain(url, base_domain):
    return urlparse(url).netloc == base_domain


def crawl(start_url, max_pages=100, timeout=10, headers=None, verify=True):
    headers = headers or DEFAULT_HEADERS
    base_domain = urlparse(start_url).netloc
    visited = set()
    queue = deque([start_url])

    page_urls = set()
    param_urls = set()      # URL dengan query string - kandidat injection test
    js_files = set()

    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        try:
            resp = requests.get(url, headers=headers, timeout=timeout, verify=verify)
        except requests.RequestException as e:
            print(f"[!] Gagal akses {url}: {e}")
            continue

        # Deteksi kemungkinan ke-redirect ke halaman login (sesi tidak valid)
        if resp.history and any("login" in r.url.lower() for r in resp.history):
            print(f"[!] Peringatan: {url} redirect ke halaman yang mengandung 'login' - "
                  f"cek apakah cookie/session masih valid.")

        page_urls.add(url)
        if urlparse(url).query:
            param_urls.add(url)

        print(f"[*] Crawled ({len(visited)}/{max_pages}): {url}")

        if "text/html" not in resp.headers.get("Content-Type", ""):
            continue

        soup = BeautifulSoup(resp.text, "html.parser")

        # Kumpulkan link <a href>
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"])
            link = link.split("#")[0]  # buang fragment
            if same_domain(link, base_domain) and link not in visited:
                queue.append(link)

        # Kumpulkan form action (untuk deteksi endpoint yang punya input)
        for form in soup.find_all("form", action=True):
            action_url = urljoin(url, form["action"])
            if same_domain(action_url, base_domain):
                param_urls.add(action_url)

        # Kumpulkan file JS
        for script in soup.find_all("script", src=True):
            js_url = urljoin(url, script["src"])
            js_files.add(js_url)

    return {
        "all_pages": sorted(page_urls),
        "param_urls": sorted(param_urls),
        "js_files": sorted(js_files),
    }


def write_lines(path, items):
    with open(path, "w") as f:
        for item in items:
            f.write(item + "\n")


def crawl_js_rendered(start_url, max_pages=50, headers=None, wait_ms=2500, verify=True):
    """
    Mode crawling untuk aplikasi berat JavaScript (ZK Framework, React, Angular,
    Vue, dll) yang kontennya tidak muncul di HTML mentah. Pakai headless
    browser (Playwright) supaya JS-nya benar-benar dijalankan seperti browser
    asli, baru diambil HTML hasil render-nya.

    Butuh: pip install playwright --break-system-packages
           playwright install chromium
    """
    from playwright.sync_api import sync_playwright

    base_domain = urlparse(start_url).netloc
    visited = set()
    queue = deque([start_url])

    page_urls = set()
    param_urls = set()
    js_files = set()

    cookie_header = (headers or {}).get("Cookie")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent=DEFAULT_HEADERS["User-Agent"],
            ignore_https_errors=not verify,
        )

        if cookie_header:
            # Playwright butuh cookie dalam format list-of-dict, bukan header string
            cookies = []
            for part in cookie_header.split(";"):
                if "=" in part:
                    name, value = part.strip().split("=", 1)
                    cookies.append({
                        "name": name, "value": value,
                        "domain": base_domain, "path": "/",
                    })
            if cookies:
                context.add_cookies(cookies)

        page = context.new_page()

        while queue and len(visited) < max_pages:
            url = queue.popleft()
            if url in visited:
                continue
            visited.add(url)

            print(f"[*] Rendering ({len(visited)}/{max_pages}): {url}")
            try:
                page.goto(url, timeout=20000, wait_until="networkidle")
                page.wait_for_timeout(wait_ms)  # kasih waktu extra untuk komponen async
            except Exception as e:
                print(f"[!] Gagal render {url}: {e}")
                continue

            final_url = page.url
            if "login" in final_url.lower() and "login" not in url.lower():
                print(f"[!] Peringatan: {url} ter-redirect ke {final_url} - "
                      f"cek apakah cookie/session masih valid.")

            page_urls.add(url)
            if urlparse(url).query:
                param_urls.add(url)

            html = page.content()
            soup = BeautifulSoup(html, "html.parser")

            for a in soup.find_all("a", href=True):
                link = urljoin(url, a["href"]).split("#")[0]
                if same_domain(link, base_domain) and link not in visited:
                    queue.append(link)

            for form in soup.find_all("form", action=True):
                action_url = urljoin(url, form["action"])
                if same_domain(action_url, base_domain):
                    param_urls.add(action_url)

            # Elemen interaktif khas ZK Framework/SPA (button/div dengan onclick,
            # data-* attributes) tidak selalu <a href> - dicatat sebagai info tambahan
            for script in soup.find_all("script", src=True):
                js_files.add(urljoin(url, script["src"]))

        browser.close()

    return {
        "all_pages": sorted(page_urls),
        "param_urls": sorted(param_urls),
        "js_files": sorted(js_files),
    }


def main():
    parser = argparse.ArgumentParser(description="Auto crawl + trigger scan pipeline")
    parser.add_argument("--start-url", required=True)
    parser.add_argument("--max-pages", type=int, default=100)
    parser.add_argument("--cookie", default=None,
                         help='Cookie session hasil login manual, contoh: --cookie "PHPSESSID=abc123; auth=xyz"')
    parser.add_argument("--header", action="append", default=[],
                         help='Header tambahan, bisa dipakai berkali-kali, contoh: --header "Authorization: Bearer xxx"')
    parser.add_argument("--js-render", action="store_true",
                         help="Pakai headless browser (Playwright) untuk aplikasi berat JS "
                              "seperti ZK Framework, React, Angular, Vue. Butuh: "
                              "pip install playwright && playwright install chromium")
    parser.add_argument("--nuclei-tags", default=None,
                         help="Filter template Nuclei resmi, contoh: 'exposures,misconfig,"
                              "default-login,exposed-panels,takeover' (auth-bypass focus)")
    parser.add_argument("--sqlmap-tamper", default=None,
                         help="Tamper script bawaan sqlmap untuk bantu lolos WAF sederhana, "
                              "contoh: 'space2comment,between,charencode'")
    parser.add_argument("--insecure", action="store_true",
                         help="Lewati verifikasi sertifikat SSL - untuk target internal/self-signed cert")
    parser.add_argument("--skip-scan", action="store_true",
                         help="Cuma crawl, jangan auto-trigger orchestrator/js_scanner")
    args = parser.parse_args()

    headers = build_headers(cookie=args.cookie, extra_header=args.header)
    if args.cookie:
        print("[*] Mode authenticated: menggunakan cookie session yang diberikan.")

    verify = not args.insecure
    if args.insecure:
        import warnings
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")
        print("[!] Mode --insecure aktif: verifikasi sertifikat SSL DILEWATI untuk seluruh pipeline.")

    print(f"[*] Mulai crawling dari {args.start_url} (maks {args.max_pages} halaman)...")
    if args.js_render:
        print("[*] Mode JS-render aktif (Playwright/headless Chromium)...")
        result = crawl_js_rendered(args.start_url, max_pages=args.max_pages, headers=headers, verify=verify)
    else:
        result = crawl(args.start_url, max_pages=args.max_pages, headers=headers, verify=verify)

    print(f"\n[+] Selesai crawling:")
    print(f"    - Total halaman dikunjungi : {len(result['all_pages'])}")
    print(f"    - Endpoint dengan parameter: {len(result['param_urls'])}")
    print(f"    - File JavaScript ditemukan: {len(result['js_files'])}")

    write_lines("targets.txt", result["param_urls"] or result["all_pages"])
    write_lines("js_urls.txt", result["js_files"])
    print("\n[+] Tersimpan: targets.txt, js_urls.txt")

    if args.skip_scan:
        print("\n[*] --skip-scan aktif, berhenti di sini. Jalankan manual:")
        print("    python orchestrator.py targets.txt" + (f' --cookie "{args.cookie}"' if args.cookie else ""))
        print("    python js_scanner.py --urls-file js_urls.txt")
        return

    orchestrator_cmd = [sys.executable, "orchestrator.py", "targets.txt"]
    if args.cookie:
        orchestrator_cmd += ["--cookie", args.cookie]
    for h in args.header:
        orchestrator_cmd += ["--header", h]
    if args.nuclei_tags is not None:
        orchestrator_cmd += ["--nuclei-tags", args.nuclei_tags]
    if args.sqlmap_tamper:
        orchestrator_cmd += ["--sqlmap-tamper", args.sqlmap_tamper]

    if result["param_urls"] or result["all_pages"]:
        print("\n[*] Menjalankan orchestrator.py (Nuclei + sqlmap) otomatis...")
        subprocess.run(orchestrator_cmd)

    if result["js_files"]:
        print("\n[*] Menjalankan js_scanner.py otomatis...")
        js_cmd = [sys.executable, "js_scanner.py", "--urls-file", "js_urls.txt"]
        if args.cookie:
            js_cmd += ["--cookie", args.cookie]
        if args.insecure:
            js_cmd += ["--insecure"]
        subprocess.run(js_cmd)

    print("\n[+] Pipeline selesai. Semua kandidat & temuan terkonfirmasi ada di findings.json")
    print("[+] Langkah kamu selanjutnya: buka http://127.0.0.1:8787/findings?status=candidate")
    print("    dan validasi manual satu per satu.")


if __name__ == "__main__":
    main()
