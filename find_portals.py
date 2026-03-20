#!/usr/bin/env python3
"""Find official government portal URLs via DuckDuckGo search."""

import argparse
import csv
import sys
import time

from ddgs import DDGS


def find_portal_url(country: str, ddgs: DDGS) -> str | None:
    """Search for the official government portal of a country."""
    query = f"{country} government portal"
    try:
        results = ddgs.text(query, max_results=5)
        return results[0]["href"] if results else None
    except Exception as e:
        print(f"    Error searching for {country}: {e}", file=sys.stderr)
        return None


def main():
    parser = argparse.ArgumentParser(description="Find government portal URLs via DuckDuckGo search")
    parser.add_argument("--input", "-i", required=True, help="Input CSV with 'country' column")
    parser.add_argument("--output", "-o", default="portals.csv", help="Output CSV path")
    parser.add_argument("--delay", "-d", type=float, default=2.0, help="Delay between searches in seconds (default: 2)")
    args = parser.parse_args()

    with open(args.input, newline="") as f:
        reader = csv.DictReader(f)
        countries = [row["country"] for row in reader if row.get("country", "").strip()]

    print(f"Searching for portal URLs for {len(countries)} countries...")

    ddgs = DDGS()
    results = []
    for i, country in enumerate(countries, 1):
        print(f"  [{i}/{len(countries)}] {country}")
        url = find_portal_url(country, ddgs)
        results.append({"country": country, "url": url or ""})
        if i < len(countries):
            time.sleep(args.delay)

    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["country", "url"])
        writer.writeheader()
        writer.writerows(results)

    found = sum(1 for r in results if r["url"])
    print(f"Done. Found {found}/{len(countries)} URLs. Written to {args.output}")


if __name__ == "__main__":
    main()
