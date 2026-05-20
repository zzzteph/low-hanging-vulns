import json
import os
import pathlib
import subprocess
import sys
import time

import requests

TG_BOT_TOKEN = os.environ.get("TELEGRAM_BOT")
TG_CHAT_ID   = os.environ.get("TELEGRAM_GROUP")

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "none":     "⚪",
}


def _new_report_paths() -> list[str]:
    # -uall expands new untracked directories so individual JSON files are listed,
    # not collapsed to a single `?? dir/` line that the .json filter would drop.
    result = subprocess.run(
        ["git", "status", "--porcelain", "-uall", "bugbounty/H1/reports/"],
        capture_output=True, text=True,
    )
    paths = []
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            path = parts[1].strip()
            if path.endswith(".json") and os.path.exists(path):
                paths.append(path)
    return paths


def _html(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _bounty_emoji(amount: float) -> str:
    if amount >= 2000:
        return "🤑"
    if amount >= 500:
        return "💰"
    return "💸"


def _category_from_path(path: str) -> str:
    # bugbounty/H1/reports/{category}/... → return category
    parts = pathlib.Path(path).parts
    idx = next((i for i, p in enumerate(parts) if p == "reports"), -1)
    if idx >= 0 and idx + 1 < len(parts):
        return parts[idx + 1]
    return ""


def _team_summary(report: dict) -> str:
    for s in (report.get("summaries") or []):
        if s.get("category") == "team" and s.get("content"):
            return s["content"].strip()
    return ""


def _format(report: dict, path: str) -> str:
    title     = report.get("title") or "Untitled"
    url       = report.get("url") or ""
    sev_raw   = (report.get("severity_rating") or "none").lower()
    sev_emoji = SEVERITY_EMOJI.get(sev_raw, "⚪")
    cwe       = (report.get("weakness") or {}).get("name") or "Unknown"
    amount    = float(report.get("bounty_amount") or 0)
    bounty    = report.get("formatted_bounty") or f"${amount:,.0f}"
    category  = _category_from_path(path)
    tags      = f"#h1 #{category}" if category else "#h1"

    team        = report.get("team") or {}
    team_name   = (team.get("profile") or {}).get("name") or team.get("handle") or ""
    team_url    = team.get("url") or ""
    scope       = report.get("structured_scope") or {}
    asset       = scope.get("asset_identifier") or ""
    summary     = _team_summary(report)

    lines = [f'{sev_emoji} <a href="{url}">{_html(title)}</a>', ""]

    if team_name:
        if team_url:
            lines.append(f'🏢 <a href="{team_url}">{_html(team_name)}</a>')
        else:
            lines.append(f"🏢 {_html(team_name)}")

    if asset:
        lines.append(f"🏹 {_html(asset)}")

    lines += [
        f"🎯 CWE: {_html(cwe)}",
        f"{_bounty_emoji(amount)} Amount: {_html(bounty)}",
    ]

    if summary:
        lines += ["", f"📝 {_html(summary)}"]

    lines += ["", tags]
    return "\n".join(lines)


def _send(text: str) -> None:
    resp = requests.post(
        f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
        json={
            "chat_id":                  TG_CHAT_ID,
            "text":                     text,
            "parse_mode":               "HTML",
            "disable_web_page_preview": False,
        },
        timeout=15,
    )
    resp.raise_for_status()


def main() -> None:
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        print("TELEGRAM_BOT or TELEGRAM_GROUP not configured — skipping notifications.")
        return

    paths = sys.argv[1:] if len(sys.argv) > 1 else _new_report_paths()
    if not paths:
        print("No new report files found.")
        return

    sent = skipped = failed = 0
    for i, path in enumerate(paths):
        # Telegram rate limit on a single channel is ~1 msg/sec sustained;
        # bursting 378+ messages back-to-back triggers HTTP 429.
        if i > 0:
            time.sleep(2)
        try:
            with open(path, encoding="utf-8") as f:
                report = json.load(f)

            _send(_format(report, path))
            amount = float(report.get("bounty_amount") or 0)
            print(f"  sent: {report.get('url', path)}  ({report.get('formatted_bounty', f'${amount:,.0f}')})")
            sent += 1

        except Exception as e:
            print(f"  ERROR {path}: {e}")
            failed += 1

    print(f"\nDone. sent={sent}  skipped={skipped}  failed={failed}")


if __name__ == "__main__":
    main()
