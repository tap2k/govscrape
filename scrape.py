#!/usr/bin/env python3
"""Scan websites for reachability, llms.txt, robots.txt, and bot detection."""

import argparse
import csv
import html
import os
import re
import sys
import time
from urllib.parse import urljoin, urlparse

import requests

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
TIMEOUT = 15

AI_BOTS = [
    "GPTBot", "ChatGPT-User", "ClaudeBot", "Claude-Web", "CCBot",
    "Bytespider", "GoogleOther", "Google-Extended", "PerplexityBot",
    "Amazonbot", "anthropic-ai", "cohere-ai",
]

FIELDNAMES = [
    "country",
    "url",
    "status",
    "status_code",
    "final_url",
    "latency_ms",
    "title",
    "language",
    "has_robots_txt",
    "ai_bot_blocks",
    "has_llms_txt",
    "bot_detection",
    "error",
]


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def fetch(url: str, session: requests.Session) -> tuple[requests.Response | None, int]:
    """Returns (response, latency_ms)."""
    try:
        start = time.monotonic()
        resp = session.get(url, timeout=TIMEOUT, allow_redirects=True)
        latency = int((time.monotonic() - start) * 1000)
        # Fix encoding: if the server didn't declare a charset, use detected encoding
        if resp.encoding and resp.encoding.lower() == "iso-8859-1" and "charset" not in resp.headers.get("Content-Type", "").lower():
            resp.encoding = resp.apparent_encoding
        return resp, latency
    except requests.RequestException:
        return None, 0


def extract_title(page_html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", page_html, re.IGNORECASE | re.DOTALL)
    return html.unescape(m.group(1).strip()) if m else ""


def extract_language(resp: requests.Response) -> str:
    lang = resp.headers.get("Content-Language", "")
    if lang:
        return lang
    m = re.search(r'<html[^>]*\slang=["\']([^"\']+)', resp.text[:5000], re.IGNORECASE)
    return m.group(1) if m else ""


def find_ai_bot_blocks(robots_txt: str) -> list[str]:
    """Find AI bots that are disallowed in robots.txt."""
    blocked = []
    current_agents = []
    for line in robots_txt.splitlines():
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        if line.lower().startswith("user-agent:"):
            agent = line.split(":", 1)[1].strip()
            current_agents = [agent]
        elif line.lower().startswith("disallow:") and current_agents:
            path = line.split(":", 1)[1].strip()
            if path == "/" or path == "/*":
                for agent in current_agents:
                    for bot in AI_BOTS:
                        if agent.lower() == bot.lower() or agent == "*":
                            if agent != "*":
                                blocked.append(bot)
    return sorted(set(blocked))


def detect_bot_protection(resp: requests.Response) -> list[str]:
    detections = []
    headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
    body = resp.text[:50000].lower()

    # Cloudflare
    if "cf-ray" in headers or headers.get("server", "").startswith("cloudflare"):
        detections.append("Cloudflare")

    # Akamai
    if headers.get("server", "").startswith("akamaighost") or any(
        k.startswith("x-akamai") for k in headers
    ):
        detections.append("Akamai")

    # AWS WAF
    if any(k.startswith("x-amzn-waf") for k in headers):
        detections.append("AWS WAF")

    # Imperva / Incapsula
    if "x-iinfo" in headers:
        detections.append("Imperva/Incapsula")
    if resp.cookies and any(
        c.name.startswith("visid_incap") for c in resp.cookies
    ):
        detections.append("Imperva/Incapsula (cookie)")

    # Sucuri
    if "x-sucuri-id" in headers:
        detections.append("Sucuri")

    # Distil / Shape
    if "x-distil-cs" in headers:
        detections.append("Distil/Shape")

    # CAPTCHAs
    if "recaptcha" in body:
        detections.append("reCAPTCHA")
    if "hcaptcha" in body:
        detections.append("hCaptcha")

    # JS challenge patterns
    js_challenge_markers = [
        "just a moment", "challenge-platform", "challenge validation",
        "access denied", "checking your browser",
    ]
    if "<meta http-equiv=\"refresh\"" in body or any(m in body for m in js_challenge_markers):
        detections.append("JS challenge")

    # HTTP status
    if resp.status_code == 403:
        detections.append("HTTP 403 Forbidden")
    elif resp.status_code == 429:
        detections.append("HTTP 429 Rate Limited")

    return detections


def save_raw(data_dir: str, domain: str, filename: str, content: str) -> None:
    domain_dir = os.path.join(data_dir, domain)
    os.makedirs(domain_dir, exist_ok=True)
    with open(os.path.join(domain_dir, filename), "w") as f:
        f.write(content)


def scan_site(url: str, session: requests.Session, data_dir: str) -> dict:
    row = {f: "" for f in FIELDNAMES}
    row["url"] = url
    base = normalize_url(url)
    parsed = urlparse(base)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    domain = parsed.netloc

    # Homepage
    resp, latency = fetch(base, session)
    if resp is None:
        row["status"] = "error"
        row["error"] = "Failed to connect"
        return row

    row["status_code"] = resp.status_code
    row["latency_ms"] = latency
    row["final_url"] = resp.url if resp.url != base else ""
    row["title"] = extract_title(resp.text)
    row["language"] = extract_language(resp)
    detections = detect_bot_protection(resp)

    # robots.txt
    robots_resp, _ = fetch(urljoin(origin, "/robots.txt"), session)
    if robots_resp and robots_resp.status_code == 200 and robots_resp.text.strip():
        content = robots_resp.text.strip()
        if content.lower().startswith(("<!doctype", "<html", "<head")):
            row["has_robots_txt"] = "no"
        else:
            row["has_robots_txt"] = "yes"
            row["ai_bot_blocks"] = ", ".join(find_ai_bot_blocks(robots_resp.text))
            save_raw(data_dir, domain, "robots.txt", robots_resp.text)
    else:
        row["has_robots_txt"] = "no"

    # llms.txt
    llms_resp, _ = fetch(urljoin(origin, "/llms.txt"), session)
    if llms_resp and llms_resp.status_code == 200 and llms_resp.text.strip():
        content = llms_resp.text.strip()
        # Reject soft 404s: if it looks like HTML, it's not a real llms.txt
        if content.lower().startswith(("<!doctype", "<html", "<head")):
            row["has_llms_txt"] = "no"
        else:
            row["has_llms_txt"] = "yes"
            save_raw(data_dir, domain, "llms.txt", llms_resp.text)
    else:
        row["has_llms_txt"] = "no"

    row["bot_detection"] = ", ".join(detections)
    if "JS challenge" in detections:
        row["title"] = ""
        row["status"] = "blocked"
    elif resp.status_code == 200:
        row["status"] = "ok"
    else:
        row["status"] = f"http_{resp.status_code}"
    return row


def main():
    parser = argparse.ArgumentParser(description="Scan websites for reachability and bot detection")
    parser.add_argument("--input", "-i", required=True, help="Input CSV with 'url' column")
    parser.add_argument("--output", "-o", default="results.csv", help="Output CSV path")
    args = parser.parse_args()

    with open(args.input, newline="") as f:
        reader = csv.DictReader(f)
        if "url" not in reader.fieldnames:
            print("Error: input CSV must have a 'url' column", file=sys.stderr)
            sys.exit(1)
        rows = [row for row in reader if row["url"].strip()]

    # Detect extra columns to pass through (e.g. "country")
    extra_keys = [k for k in rows[0].keys() if k != "url"] if rows else []

    data_dir = os.path.join(os.path.dirname(args.output) or ".", "data")
    os.makedirs(data_dir, exist_ok=True)

    print(f"Scanning {len(rows)} sites...")

    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT

    results = []
    for i, input_row in enumerate(rows, 1):
        url = input_row["url"]
        print(f"  [{i}/{len(rows)}] {url}")
        result = scan_site(url, session, data_dir)
        # Pass through extra columns from input
        for k in extra_keys:
            result[k] = input_row.get(k, "")
        results.append(result)

    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(results)

    print(f"Done. Results written to {args.output}")


if __name__ == "__main__":
    main()
