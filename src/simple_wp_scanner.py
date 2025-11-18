#!/usr/bin/env python3

import sys
from urllib.parse import urlparse, urljoin
import requests

COMMON_PATHS = [
    "/", "/wp-login.php", "/wp-admin/", "/xmlrpc.php",
    "/readme.html", "/license.txt", "/wp-content/",
    "/wp-content/uploads/", "/wp-content/debug.log",
    "/.git/", "/backup.zip", "/site-backup.zip",
    "/staging/"
]

def normalize_base_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def analyze_response(path, status, text, headers):
    findings = []
    lower = text.lower()

    if path in ("/wp-login.php", "/wp-admin/"):
        if "user_login" in lower or "wp-login" in lower:
            findings.append("🔴 WordPress login publicly accessible")

    if path == "/xmlrpc.php" and "xmlrpc" in lower and status == 200:
        findings.append("🟠 xmlrpc.php enabled")

    if path == "/readme.html" and "wordpress" in lower and status == 200:
        findings.append("🟠 readme.html accessible")

    if path == "/wp-content/debug.log" and status == 200:
        findings.append("🔴 debug.log exposed")

    if "index of /" in lower and status == 200:
        findings.append("🔴 Directory listing enabled")

    if path in ("/backup.zip", "/site-backup.zip") and status == 200:
        findings.append("🔴 Backup archive exposed")

    if path == "/.git/" and status == 200:
        findings.append("🔴 .git exposed")

    if path == "/" and "/wp-content/" in lower:
        findings.append("ℹ️ WordPress markers detected")

    return findings

def scan_site(base_url):
    base = normalize_base_url(base_url)
    print(f"\n=== Scanning: {base} ===\n")

    session = requests.Session()
    session.headers["User-Agent"] = "WPScanner/1.0"

    for path in COMMON_PATHS:
        url = urljoin(base, path.lstrip("/"))
        try:
            resp = session.get(url, timeout=10, allow_redirects=True)
            status = resp.status_code
            text_sample = resp.text[:2000] if resp.text else ""

            print(f"[{status}] {url}")

            findings = analyze_response(path, status, text_sample, resp.headers)
            for f in findings:
                print("   ->", f)

        except requests.RequestException as e:
            print(f"[ERR] {url} ({e})")

    print("\nScan complete.\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        target = input("Enter site: ").strip()
    else:
        target = sys.argv[1]

    if not target:
        print("No target, exiting.")
        sys.exit(1)

    scan_site(target)
