# CLAUDE.md

## Project

Python script that scans government portals for reachability, bot detection, and LLM accessibility (robots.txt, llms.txt). Uses plain `requests` — no browser automation.

## Commands

```bash
source venv/bin/activate
python scrape.py --input countries.csv --output results.csv
```

## Structure

- `scrape.py` — main scanner script
- `countries.csv` — input list (country, url)
- `results.csv` — output
- `data/` — raw robots.txt and llms.txt files per domain (gitignored)

## Conventions

- Keep dependencies minimal (just `requests`)
- Soft 404 detection: reject robots.txt/llms.txt that look like HTML
- JS challenge pages (Cloudflare "Just a moment...") are marked `status=blocked` with title cleared
- CSV is the primary output format; keep columns scalar (no nested data)
