#!/usr/bin/env python3
"""Extract URLs from chat HTML files and produce a CSV for scrape.py."""

import csv
import html
import os
import re
import sys
from collections import Counter
from urllib.parse import urlparse


HTML_DIR = os.path.join("data", "html", "countries")

# Domains to skip (generic, not country-specific portals)
SKIP_DOMAINS = {
    "google.com", "youtube.com", "wikipedia.org", "facebook.com",
    "twitter.com", "instagram.com", "linkedin.com", "reddit.com",
    "github.com", "stackoverflow.com", "medium.com", "apple.com",
    "microsoft.com", "amazon.com", "whatsapp.com",
}


def extract_urls_from_file(filepath: str) -> list[str]:
    """Extract all URLs from an HTML file's chat content."""
    with open(filepath) as f:
        text = f.read()

    # Only look inside message-content divs (LLM responses)
    messages = re.findall(
        r'<div class="message-content">(.*?)</div>', text, re.DOTALL
    )
    content = html.unescape("\n".join(messages))

    # Extract URLs — both bare and inside href/markdown
    urls = re.findall(r'https?://[^\s"\'<>)\]]+', content)

    cleaned = []
    for url in urls:
        url = url.rstrip(".,;:!?)*")
        if len(url) < 10:
            continue
        cleaned.append(url)
    return cleaned


def domain_root(url: str) -> str:
    """Get the root domain from a URL, stripping www."""
    host = urlparse(url).netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def should_skip(domain: str) -> bool:
    """Skip generic non-portal domains."""
    for skip in SKIP_DOMAINS:
        if domain == skip or domain.endswith("." + skip):
            return True
    return False


def main():
    if not os.path.isdir(HTML_DIR):
        print(f"Error: {HTML_DIR} not found", file=sys.stderr)
        sys.exit(1)

    countries = sorted(os.listdir(HTML_DIR))
    results = []

    for country_dir in countries:
        country_path = os.path.join(HTML_DIR, country_dir)
        if not os.path.isdir(country_path):
            continue

        country = country_dir.replace("_", " ")

        # Extract URLs per source LLM
        source_urls: dict[str, list[str]] = {}
        for filename in os.listdir(country_path):
            if filename.startswith("chat_") and filename.endswith(".html"):
                source = filename.removeprefix("chat_").removesuffix(".html")
                filepath = os.path.join(country_path, filename)
                source_urls[source] = extract_urls_from_file(filepath)

        # Group by (domain, source)
        key_counts: Counter[tuple[str, str]] = Counter()
        domain_to_url: dict[str, str] = {}

        for source, urls in source_urls.items():
            for url in urls:
                try:
                    parsed = urlparse(url)
                except ValueError:
                    continue
                domain = domain_root(url)
                if not domain or "." not in domain or should_skip(domain):
                    continue
                key_counts[(domain, source)] += 1
                if domain not in domain_to_url:
                    domain_to_url[domain] = f"{parsed.scheme}://{parsed.netloc}"

        # One row per unique domain, with per-model mention counts
        if key_counts:
            domain_totals: Counter[str] = Counter()
            for (domain, source), count in key_counts.items():
                domain_totals[domain] += count

            all_sources = sorted(source_urls.keys())
            for domain, total in domain_totals.most_common():
                row = {"country": country, "url": domain_to_url[domain], "mentions": total}
                for source in all_sources:
                    row[source] = key_counts.get((domain, source), 0)
                results.append(row)

            top_domain = domain_totals.most_common(1)[0]
            print(f"  {country}: {len(domain_totals)} domains (top: {top_domain[0]}, {top_domain[1]}x)")
        else:
            results.append({"country": country, "url": "", "mentions": 0})
            print(f"  {country}: NO URLS FOUND")

    output = "extracted_portals.csv"
    with open(output, "w", newline="") as f:
        # Detect all source columns from the data
        source_cols = sorted({k for r in results for k in r if k not in ("country", "url", "mentions")})
        writer = csv.DictWriter(f, fieldnames=["country", "url", "mentions"] + source_cols)
        writer.writeheader()
        writer.writerows(results)

    countries_with = len(set(r["country"] for r in results if r["url"]))
    total_countries = len(set(r["country"] for r in results))
    print(f"\nDone. {countries_with}/{total_countries} countries with URLs, {len(results)} total rows.")
    print(f"Written to {output}")


if __name__ == "__main__":
    main()
