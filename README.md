# Bugbounty monitor

Yet another automated intelligence feed for **real-world** vulnerabilities disclosed on [HackerOne](https://hackerone.com/hacktivity).

## What's inside

| Directory | Contents |
|-----------|----------|
| `reports/` | Full HackerOne report JSONs, organised by category → weakness → year |
| `skills/` | AI-generated hunter playbooks (one per vuln class) + `bughunter.md` master |
| `fuzzing/` | Per-category payload wordlists — one payload per line, ready for fuzzing tools |

## Features

- **Hourly updates** - GitHub Actions fetches newly disclosed reports every hour and rebuilds the index.
- **Hunter playbooks** - each `skills/*.md` file covers root causes, attack surface, recon checklist, hunt methodology, payload library, WAF bypass tips, triage guidance, and real bounty examples.
- **Fuzzing payloads** - extracted and curated from real reports.
- **Telegram notifications** 👉 [https://t.me/lowhangingvulns](https://t.me/lowhangingvulns)

## Telegram channel

Join to get notified about freshly disclosed bug bounty reports:

👉 [https://t.me/lowhangingvulns](https://t.me/lowhangingvulns)

## Vulnerability categories

`xss` · `sqli` · `rce` · `ssrf` · `idor` · `lfi` · `csrf` · `authn` · `privesc` · `info_disclosure` · `memory` · `dos` · `business_logic` · `secrets` · `open_redirect` · `http_injection` · `deserialization` · `injection` · `xxe` · `crypto` · `tls` · `race_condition` · `clickjacking` · `cors` · `file_upload` · `llm` · `supply_chain` · `misc`

## Data source

 [HackerOne Hacktivity](https://hackerone.com/hacktivity)
