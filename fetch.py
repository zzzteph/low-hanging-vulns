import re
import requests
import json
import os
import time

from categories import get_category

# Public Hacker API (no auth needed). hackerone.com/graphql is behind a
# Cloudflare WAF rule that blocks scripted requests since late Oct 2026.
HACKTIVITY_URL = "https://api.hackerone.com/v1/hackers/hacktivity"
INDEX_FILE  = "bugbounty/H1/reports.json"
REPORTS_DIR = "bugbounty/H1/reports"

PAGE_SIZE = 50    # API maximum; larger values are silently capped
MAX_PAGES = 200   # safety cap (10 000 entries)
HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0",
}


# ── Step 1: fetch the index ───────────────────────────────────────────────────

def fetch_index_page(page: int, size: int = PAGE_SIZE) -> list[dict]:
    """One page of disclosed hacktivity, newest-first. `links.next` is not
    reliably present, so callers page until an empty `data` list."""
    params = {
        "queryString": "disclosed:true",
        "page[number]": page,
        "page[size]": size,
    }
    resp = requests.get(HACKTIVITY_URL, headers=HEADERS, params=params, timeout=30)
    _raise_for_status_verbose(resp)
    return resp.json()["data"]


def _raise_for_status_verbose(resp: requests.Response) -> None:
    """raise_for_status, but first log enough of the response to tell a
    Cloudflare block (cf-mitigated header / challenge page) from an API error."""
    if resp.ok:
        return
    hdrs = {k: resp.headers[k] for k in ("server", "cf-ray", "cf-mitigated") if k in resp.headers}
    print(f"  HTTP {resp.status_code} from {resp.url} {hdrs}")
    print(f"  body: {resp.text[:500]!r}")
    resp.raise_for_status()


def build_index() -> tuple[list[dict], int]:
    """
    Load existing index, fetch only new stubs (newest-first), save and return
    (all_entries, new_count).

    We stop after MAX_PAGES so a missing/stale index can't turn into an
    unbounded crawl of the whole hacktivity feed.
    """
    existing: list[dict] = []
    if os.path.exists(INDEX_FILE):
        with open(INDEX_FILE, encoding="utf-8") as f:
            existing = json.load(f)

    known_urls = {e["url"] for e in existing}
    new_entries: list[dict] = []
    page = 1

    while True:
        items = fetch_index_page(page)
        if not items:
            break
        hit_existing = False
        for item in items:
            entry = _item_to_entry(item)
            if entry["url"] in known_urls:
                hit_existing = True
                break
            new_entries.append(entry)
        if hit_existing:
            break
        page += 1
        if page > MAX_PAGES:
            print(f"  NOTE: reached page limit ({MAX_PAGES}); stopping index walk.")
            break
        time.sleep(0.5)

    if not new_entries:
        return existing, 0

    all_entries = new_entries + existing
    with open(INDEX_FILE, "w", encoding="utf-8") as f:
        json.dump(all_entries, f, indent=2, ensure_ascii=False)
    print(f"Index updated: +{len(new_entries)} new stubs ({len(all_entries)} total)")
    return all_entries, len(new_entries)


def _item_to_entry(item: dict) -> dict:
    attrs = item.get("attributes") or {}
    program = ((item.get("relationships") or {}).get("program") or {}).get("data") or {}
    team = program.get("attributes") or {}
    return {
        "title": attrs.get("title"),
        "url": attrs.get("url"),
        "disclosed_at": attrs.get("disclosed_at"),
        "severity": attrs.get("severity_rating"),
        "cwe": attrs.get("cwe"),
        "cve_ids": attrs.get("cve_ids"),
        "team_handle": team.get("handle"),
        "team_name": team.get("name"),
    }


# ── Step 2: fetch full report JSON for each entry ────────────────────────────

def report_id_from_url(url: str) -> str:
    return url.rstrip("/").split("/")[-1]


def fetch_full_report(report_id: str) -> dict:
    url = f"https://hackerone.com/reports/{report_id}.json"
    resp = requests.get(url, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    return resp.json()


def _report_year(report: dict) -> str:
    for field in ("created_at", "submitted_at", "disclosed_at"):
        val = report.get(field, "")
        if val and len(val) >= 4:
            return val[:4]
    return "unknown"


def _weakness_slug(report: dict) -> str:
    name = (report.get("weakness") or {}).get("name", "") or "unknown"
    slug = name.lower()
    slug = re.sub(r"[^a-z0-9]+", "_", slug)
    return slug.strip("_")[:60]


def _existing_report_ids() -> set:
    ids = set()
    for _, _, files in os.walk(REPORTS_DIR):
        for f in files:
            if f.endswith(".json"):
                ids.add(os.path.splitext(f)[0])
    return ids


def download_reports(entries: list[dict]) -> None:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    existing = _existing_report_ids()
    total = len(entries)
    fetched = skipped = failed = 0

    for i, entry in enumerate(entries, 1):
        report_id = report_id_from_url(entry.get("url", ""))

        if report_id in existing:
            skipped += 1
            continue

        try:
            data = fetch_full_report(report_id)
            year = _report_year(data)
            slug = _weakness_slug(data)
            category = get_category(slug)
            out_dir = os.path.join(REPORTS_DIR, category, slug, year)
            os.makedirs(out_dir, exist_ok=True)
            out_path = os.path.join(out_dir, f"{report_id}.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            fetched += 1
            print(f"[{i}/{total}] saved {category}/{slug}/{year}/{report_id}")
        except requests.HTTPError as e:
            failed += 1
            print(f"[{i}/{total}] HTTP {e.response.status_code} — {report_id}")
        except Exception as e:
            failed += 1
            print(f"[{i}/{total}] error {report_id}: {e}")

        time.sleep(0.3)

    print(f"\nDone. fetched={fetched}  skipped={skipped}  failed={failed}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    entries, new_count = build_index()
    if new_count == 0:
        print("Nothing new.")
        return
    download_reports(entries)


if __name__ == "__main__":
    main()
