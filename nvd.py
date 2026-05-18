import json
import os
import re
import time
from datetime import datetime, timedelta, timezone

import requests

TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN")
TG_CHAT_ID   = os.environ.get("TG_CHAT_ID")
NVD_KEY      = os.environ.get("NVD_KEY")

NVD_DIR = "nvd"

ALLOWED_CWES = {
    "CWE-22", "CWE-23", "CWE-35",
    "CWE-77", "CWE-78", "CWE-79", "CWE-80",
    "CWE-88", "CWE-89", "CWE-90", "CWE-91",
    "CWE-94", "CWE-95", "CWE-96", "CWE-97", "CWE-98",
    "CWE-359", "CWE-538", "CWE-548", "CWE-552", "CWE-564",
    "CWE-566", "CWE-643", "CWE-652", "CWE-862", "CWE-863",
    "CWE-917", "CWE-918",
}

CWE_TAG = {
    "CWE-22": "Traversal", "CWE-23": "Traversal", "CWE-35": "Traversal",
    "CWE-77": "RCE", "CWE-78": "RCE", "CWE-94": "RCE",
    "CWE-95": "RCE", "CWE-96": "RCE",
    "CWE-79": "XSS", "CWE-80": "XSS",
    "CWE-88": "SQL", "CWE-89": "SQL", "CWE-564": "SQL", "CWE-566": "SQL",
    "CWE-90": "LDAP", "CWE-91": "XML", "CWE-97": "SSI", "CWE-98": "RFI",
    "CWE-359": "Exposure", "CWE-538": "Disclosure", "CWE-548": "Disclosure",
    "CWE-552": "Auth", "CWE-862": "Auth", "CWE-863": "Auth",
    "CWE-643": "XPath", "CWE-652": "XQuery", "CWE-917": "ELI", "CWE-918": "SSRF",
}


def _html(s: str) -> str:
    return re.sub(r"[<>&]", lambda m: {"<": "&lt;", ">": "&gt;", "&": "&amp;"}[m.group()], s)


def _extract_metrics(metrics: dict) -> tuple:
    for key, av_key, ac_key in [
        ("cvssMetricV40", "attackVector", "attackComplexity"),
        ("cvssMetricV31", "attackVector", "attackComplexity"),
    ]:
        m = metrics.get(key, [])
        if m:
            d = m[0].get("cvssData", {})
            return d.get("baseScore"), d.get("baseSeverity"), d.get(av_key), d.get(ac_key)
    m = metrics.get("cvssMetricV2", [])
    if m:
        d = m[0].get("cvssData", {})
        return d.get("baseScore"), m[0].get("baseSeverity"), d.get("accessVector"), d.get("accessComplexity")
    return None, None, None, None


def _has_exploit(references: list) -> bool:
    return any("Exploit" in e.get("tags", []) for e in references)


def fetch_cve_data() -> dict:
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=24)
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0/"
        f"?pubStartDate={start.strftime('%Y-%m-%dT%H:%M:%S.000')}"
        f"&pubEndDate={end.strftime('%Y-%m-%dT%H:%M:%S.000')}"
    )
    resp = requests.get(url, headers={"apiKey": NVD_KEY}, timeout=30)
    resp.raise_for_status()
    return resp.json()


def extract_cve_info(data: dict) -> list[dict]:
    result = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id")
        score, severity, av, ac = _extract_metrics(cve.get("metrics", {}))

        if severity not in ("CRITICAL", "HIGH"):
            print(f"  skip {cve_id}: severity={severity}")
            continue
        if av != "NETWORK" or ac != "LOW":
            print(f"  skip {cve_id}: av={av} ac={ac}")
            continue

        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
        if "firmware" in desc.lower():
            print(f"  skip {cve_id}: firmware")
            continue

        weaknesses = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                v = d.get("value", "")
                if v in ALLOWED_CWES:
                    weaknesses.append(v)
        if not weaknesses:
            print(f"  skip {cve_id}: no matching CWEs")
            continue

        refs = cve.get("references", [])
        result.append({
            "id": cve_id,
            "published": datetime.fromisoformat(cve.get("published", "")).strftime("%Y-%m-%d %H:%M"),
            "description": desc,
            "baseScore": score,
            "baseSeverity": severity,
            "hasExploit": _has_exploit(refs),
            "weakness": weaknesses,
            "references": refs,
            "nvd": vuln,
        })
        print(f"  queued {cve_id} ({severity})")
    return result


def _cve_folder(cve: dict) -> str:
    year = cve["id"].split("-")[1]
    return os.path.join(NVD_DIR, year, cve["baseSeverity"], cve["id"])


def save_cve(cve: dict) -> bool:
    folder = _cve_folder(cve)
    json_path = os.path.join(folder, f"{cve['id']}.json")
    if os.path.exists(json_path):
        return False
    os.makedirs(folder, exist_ok=True)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(cve["nvd"], f, indent=2)
    with open(os.path.join(folder, "README.md"), "w", encoding="utf-8") as f:
        f.write(_to_markdown(cve))
    return True


def _to_markdown(cve: dict) -> str:
    lines = [f"# {cve['id']}", f"**{cve['published']}**", "", "## Description", cve["description"], ""]
    if cve["hasExploit"]:
        lines.append("![](https://img.shields.io/static/v1?label=Exploit&message=Yes&color=red)")
    lines += [
        f"![](https://img.shields.io/static/v1?label=Score&message={cve['baseScore']}&color=red)",
        f"![](https://img.shields.io/static/v1?label=Severity&message={cve['baseSeverity']}&color=red)",
    ]
    for cwe in cve["weakness"]:
        tag = CWE_TAG.get(cwe)
        if tag:
            lines.append(f"![](https://img.shields.io/static/v1?label=CWE&message={tag}&color=green)")
    lines += ["", "## Links"]
    for ref in cve["references"]:
        u = ref.get("url", "")
        lines.append(f"- [{u}]({u})")
    return "\n".join(lines)


def _format_telegram(cve: dict) -> str:
    sev = cve["baseSeverity"]
    url = f"https://nvd.nist.gov/vuln/detail/{cve['id']}"
    emoji = "🔥" if sev == "CRITICAL" else "🟠"

    tags = [f"#{sev.lower()}"]
    if cve["hasExploit"]:
        tags.insert(0, "#exploit")
    if "wordpress" in cve["description"].lower():
        tags.append("#wordpress")
    for cwe in cve["weakness"]:
        tag = CWE_TAG.get(cwe)
        if tag:
            tags.append(f"#{tag.lower()}")
    tags.append("#nvd")

    return "\n".join([
        f'{emoji} <a href="{url}"><b>{_html(cve["id"])}</b></a>',
        "",
        f"<pre>{_html(cve['description'])}</pre>",
        "",
        " ".join(tags),
    ])


def _send(text: str) -> None:
    resp = requests.post(
        f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
        json={
            "chat_id": TG_CHAT_ID,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        },
        timeout=15,
    )
    resp.raise_for_status()


def main() -> None:
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        print("TG_BOT_TOKEN or TG_CHAT_ID not set — skipping notifications.")

    print("Fetching CVEs from NVD (last 24h)...")
    data = fetch_cve_data()
    cves = extract_cve_info(data)
    print(f"Matched {len(cves)} CVEs after filtering.")

    sent = skipped = failed = 0
    for cve in cves:
        is_new = save_cve(cve)
        if not is_new:
            skipped += 1
            print(f"  already stored: {cve['id']}")
            continue
        print(f"  saved: {cve['id']}")
        if TG_BOT_TOKEN and TG_CHAT_ID:
            try:
                time.sleep(2)
                _send(_format_telegram(cve))
                sent += 1
            except Exception as e:
                print(f"  notify error {cve['id']}: {e}")
                failed += 1

    print(f"\nDone. sent={sent}  skipped={skipped}  failed={failed}")


if __name__ == "__main__":
    main()
