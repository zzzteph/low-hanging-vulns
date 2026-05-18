import re
import requests
import json
import os
import time

from categories import get_category

GRAPHQL_URL = "https://hackerone.com/graphql"
INDEX_FILE  = "bugbounty/H1/reports.json"
REPORTS_DIR = "bugbounty/H1/reports"
MISC_DIR    = "misc"

# Categories routed to top-level misc/ instead of bugbounty/H1/reports/
_MISC_CATEGORIES = {"misc/fuzzing", "misc/skills"}
PAGE_SIZE = 25
MAX_OFFSET = 10000
HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0",
}

QUERY = """
query HacktivitySearchQuery($queryString: String!, $from: Int, $size: Int, $sort: SortInput!) {
  search(
    index: CompleteHacktivityReportIndex
    query_string: $queryString
    from: $from
    size: $size
    sort: $sort
  ) {
    total_count
    nodes {
      ... on HacktivityDocument {
        report {
          title
          url
          disclosed_at
        }
        severity_rating
        cwe
        cve_ids
        team {
          handle
          name
        }
      }
    }
  }
}
"""


# ── Step 1: fetch the index ───────────────────────────────────────────────────

def fetch_index_page(from_offset: int, size: int = PAGE_SIZE) -> dict:
    payload = {
        "operationName": "HacktivitySearchQuery",
        "variables": {
            "queryString": "disclosed:true",
            "size": size,
            "from": from_offset,
            "sort": {"field": "disclosed_at", "direction": "DESC"},
        },
        "query": QUERY,
    }
    resp = requests.post(GRAPHQL_URL, headers=HEADERS, json=payload, timeout=30)
    resp.raise_for_status()
    return resp.json()


def build_index() -> tuple[list[dict], int]:
    """
    Load existing index, fetch only new stubs (newest-first), save and return
    (all_entries, new_count).

    HackerOne's Elasticsearch backend caps pagination at 10 000 results.
    We stop at MAX_OFFSET to avoid hitting that wall — older reports beyond
    that point are simply inaccessible via this API.
    """
    existing: list[dict] = []
    if os.path.exists(INDEX_FILE):
        with open(INDEX_FILE, encoding="utf-8") as f:
            existing = json.load(f)

    known_urls = {e["url"] for e in existing}
    new_entries: list[dict] = []
    offset = 0

    while True:
        data = fetch_index_page(offset)
        nodes = data["data"]["search"]["nodes"]
        if not nodes:
            break
        hit_existing = False
        for node in nodes:
            entry = _node_to_entry(node)
            if entry["url"] in known_urls:
                hit_existing = True
                break
            new_entries.append(entry)
        if hit_existing:
            break
        offset += PAGE_SIZE
        if offset > MAX_OFFSET:
            print(f"  NOTE: reached Elasticsearch offset limit ({MAX_OFFSET}); older reports not accessible via API.")
            break
        time.sleep(0.5)

    if not new_entries:
        return existing, 0

    all_entries = new_entries + existing
    with open(INDEX_FILE, "w", encoding="utf-8") as f:
        json.dump(all_entries, f, indent=2, ensure_ascii=False)
    print(f"Index updated: +{len(new_entries)} new stubs ({len(all_entries)} total)")
    return all_entries, len(new_entries)


def _node_to_entry(node: dict) -> dict:
    report = node.get("report") or {}
    return {
        "title": report.get("title"),
        "url": report.get("url"),
        "disclosed_at": report.get("disclosed_at"),
        "severity": node.get("severity_rating"),
        "cwe": node.get("cwe"),
        "cve_ids": node.get("cve_ids"),
        "team_handle": (node.get("team") or {}).get("handle"),
        "team_name": (node.get("team") or {}).get("name"),
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
            base = MISC_DIR if category in _MISC_CATEGORIES else REPORTS_DIR
            out_dir = os.path.join(base, category, slug, year)
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
