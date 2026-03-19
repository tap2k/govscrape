# govscrape

Scans government portal websites for reachability, bot detection, and LLM accessibility.

## Usage

```bash
python3 -m venv venv
source venv/bin/activate
pip install requests

python scrape.py --input countries.csv --output results.csv
```

## Input CSV format

CSV with `country` and `url` columns:

```
country,url
United Kingdom,https://www.gov.uk
France,https://www.service-public.fr
```

## Output

- `results.csv` — one row per site with status, title, language, bot detection, robots.txt/llms.txt presence, and AI bot blocks
- `data/` — raw robots.txt and llms.txt files saved per domain

## Key columns

| Column | Values |
|--------|--------|
| `status` | `ok`, `blocked`, `error`, `http_XXX` |
| `has_robots_txt` | `yes` / `no` |
| `has_llms_txt` | `yes` / `no` |
| `ai_bot_blocks` | Comma-separated list of blocked AI bots (GPTBot, ClaudeBot, etc.) |
| `bot_detection` | Cloudflare, Akamai, AWS WAF, Imperva, Sucuri, reCAPTCHA, JS challenge, etc. |
