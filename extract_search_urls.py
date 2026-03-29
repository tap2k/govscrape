#!/usr/bin/env python3
"""Extract unique domain URLs from Google Search result CSVs for scrape.py."""

import argparse
import csv
import sys
from collections import Counter, defaultdict
from urllib.parse import urlparse

SKIP_DOMAINS = {
    "google.com", "youtube.com", "wikipedia.org", "facebook.com",
    "twitter.com", "instagram.com", "linkedin.com", "reddit.com",
    "github.com", "stackoverflow.com", "medium.com", "apple.com",
    "microsoft.com", "amazon.com", "whatsapp.com",
}


def domain_root(url: str) -> str:
    host = urlparse(url.strip()).netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def should_skip(domain: str) -> bool:
    for skip in SKIP_DOMAINS:
        if domain == skip or domain.endswith("." + skip):
            return True
    return False


def parse_urls(pipe_str: str) -> list[str]:
    if not pipe_str or not pipe_str.strip():
        return []
    return [u.strip() for u in pipe_str.split("|") if u.strip().startswith("http")]


def main():
    parser = argparse.ArgumentParser(description="Extract URLs from search result CSVs")
    parser.add_argument("--input", "-i", required=True, help="Input CSV (english or multilingual)")
    parser.add_argument("--output", "-o", required=True, help="Output CSV path")
    args = parser.parse_args()

    with open(args.input, newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    if not rows:
        print("Error: empty input", file=sys.stderr)
        sys.exit(1)

    # Per (country, domain): aggregate stats
    domain_url: dict[tuple[str, str], str] = {}          # canonical URL
    ai_mentions: Counter[tuple[str, str]] = Counter()
    organic_mentions: Counter[tuple[str, str]] = Counter()
    ai_share_sum: defaultdict[tuple[str, str], float] = defaultdict(float)
    ai_share_count: Counter[tuple[str, str]] = Counter()
    organic_share_sum: defaultdict[tuple[str, str], float] = defaultdict(float)
    organic_share_count: Counter[tuple[str, str]] = Counter()
    categories: defaultdict[tuple[str, str], set] = defaultdict(set)

    for row in rows:
        if row.get("is_error", "").lower() == "true":
            continue
        country = row.get("country", "").strip()
        if not country:
            continue

        category = row.get("category", "").strip()

        # Parse gov_ai_sources and all_organic_urls
        ai_urls = parse_urls(row.get("gov_ai_sources", ""))
        organic_urls = parse_urls(row.get("all_organic_urls", ""))

        try:
            gov_ai_share = float(row.get("gov_ai_share") or 0)
        except ValueError:
            gov_ai_share = 0.0
        try:
            organic_gov_share = float(row.get("organic_gov_share") or 0)
        except ValueError:
            organic_gov_share = 0.0

        for url in ai_urls:
            domain = domain_root(url)
            if not domain or "." not in domain or should_skip(domain):
                continue
            key = (country, domain)
            ai_mentions[key] += 1
            if key not in domain_url:
                parsed = urlparse(url)
                domain_url[key] = f"{parsed.scheme}://{parsed.netloc}"
            if gov_ai_share:
                ai_share_sum[key] += gov_ai_share
                ai_share_count[key] += 1
            if category:
                categories[key].add(category)

        for url in organic_urls:
            domain = domain_root(url)
            if not domain or "." not in domain or should_skip(domain):
                continue
            key = (country, domain)
            organic_mentions[key] += 1
            if key not in domain_url:
                parsed = urlparse(url)
                domain_url[key] = f"{parsed.scheme}://{parsed.netloc}"
            if organic_gov_share:
                organic_share_sum[key] += organic_gov_share
                organic_share_count[key] += 1
            if category:
                categories[key].add(category)

    # Combine all keys
    all_keys = set(ai_mentions.keys()) | set(organic_mentions.keys())

    results = []
    for key in all_keys:
        country, domain = key
        total = ai_mentions[key] + organic_mentions[key]
        avg_ai_share = (
            round(ai_share_sum[key] / ai_share_count[key], 3)
            if ai_share_count[key] else ""
        )
        avg_organic_share = (
            round(organic_share_sum[key] / organic_share_count[key], 3)
            if organic_share_count[key] else ""
        )
        results.append({
            "country": country,
            "url": domain_url[key],
            "mentions": total,
            "ai_mentions": ai_mentions[key],
            "organic_mentions": organic_mentions[key],
            "avg_gov_ai_share": avg_ai_share,
            "avg_organic_gov_share": avg_organic_share,
            "categories": ", ".join(sorted(categories[key])),
        })

    # Sort by country then mentions desc
    results.sort(key=lambda r: (r["country"], -r["mentions"]))

    fieldnames = [
        "country", "url", "mentions", "ai_mentions", "organic_mentions",
        "avg_gov_ai_share", "avg_organic_gov_share", "categories",
    ]
    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    countries_with = len(set(r["country"] for r in results))
    print(f"Done. {len(results)} domain rows across {countries_with} countries.")
    print(f"Written to {args.output}")


if __name__ == "__main__":
    main()
