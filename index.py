"""
Generate README.md index tables for each vulnerability class and category.

For every reports/{category}/{class}/ directory, reads all report JSONs and
writes a per-class README.md sorted by bounty (highest first):

  | Title | Paid | Program | Date | Link |

Also writes a per-category reports/{category}/README.md summarising all classes
in that category.

Run after h1_fetch.py. Safe to re-run — always regenerates from current data.
"""
import glob
import json
import os

from categories import CATEGORY_LABELS


REPORTS_DIR = "reports"


def _parse_bounty(report: dict) -> float:
    val = report.get("bounty_amount")
    try:
        return float(val) if val else 0.0
    except (TypeError, ValueError):
        return 0.0


def _short_date(report: dict) -> str:
    for field in ("disclosed_at", "submitted_at", "created_at"):
        val = report.get(field, "")
        if val and len(val) >= 10:
            return val[:10]
    return ""


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").replace("\r", "")


def _load_class_rows(class_dir: str) -> list[tuple]:
    """Return list of (bounty, title, paid, program, date, url) for a class dir."""
    rows = []
    for path in glob.glob(os.path.join(class_dir, "**", "*.json"), recursive=True):
        report_id = os.path.splitext(os.path.basename(path))[0]
        try:
            with open(path, encoding="utf-8") as f:
                report = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        title = _md_escape(report.get("title", "") or f"Report {report_id}")
        bounty = _parse_bounty(report)
        paid = f"${bounty:,.0f}" if bounty else "—"
        program = _md_escape((report.get("team") or {}).get("handle", "") or "—")
        date = _short_date(report)
        url = report.get("url") or f"https://hackerone.com/reports/{report_id}"
        rows.append((bounty, title, paid, program, date, url))

    rows.sort(key=lambda r: r[0], reverse=True)
    return rows


def _table_lines(rows: list[tuple]) -> list[str]:
    lines = [
        "| Title | Paid | Program | Date | Link |",
        "|-------|------|---------|------|------|",
    ]
    for _, title, paid, program, date, url in rows:
        report_id = url.rstrip("/").split("/")[-1]
        lines.append(f"| {title} | {paid} | {program} | {date} | [#{report_id}]({url}) |")
    return lines


def generate_class_readme(class_slug: str, class_dir: str) -> list[tuple]:
    rows = _load_class_rows(class_dir)
    if not rows:
        return []

    class_name = class_slug.replace("_", " ").title()
    lines = [
        f"# {class_name}",
        "",
        f"**{len(rows)} report(s)**",
        "",
    ] + _table_lines(rows) + [""]

    readme_path = os.path.join(class_dir, "README.md")
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return rows


def generate_category_readme(category_slug: str, category_dir: str) -> None:
    label = CATEGORY_LABELS.get(category_slug, category_slug.replace("_", " ").title())

    class_dirs = sorted(
        d for d in glob.glob(os.path.join(category_dir, "*"))
        if os.path.isdir(d) and not os.path.basename(d).startswith(".")
    )

    all_rows: list[tuple] = []
    class_summaries: list[tuple[str, int, float]] = []  # (name, count, top_bounty)

    for class_dir in class_dirs:
        class_slug = os.path.basename(class_dir)
        if class_slug == "README.md":
            continue
        rows = _load_class_rows(class_dir)
        if rows:
            all_rows.extend(rows)
            top = rows[0][0] if rows else 0.0
            class_summaries.append((class_slug, len(rows), top))

    if not all_rows:
        return

    all_rows.sort(key=lambda r: r[0], reverse=True)
    class_summaries.sort(key=lambda x: x[1], reverse=True)

    lines = [
        f"# {label}",
        "",
        f"**{len(all_rows)} report(s) across {len(class_summaries)} class(es)**",
        "",
        "## Classes",
        "",
        "| Class | Reports | Top Bounty |",
        "|-------|---------|------------|",
    ]
    for slug, count, top in class_summaries:
        name = slug.replace("_", " ").title()
        top_str = f"${top:,.0f}" if top else "—"
        lines.append(f"| [{name}]({slug}/README.md) | {count} | {top_str} |")

    lines += [
        "",
        "## All Reports",
        "",
    ] + _table_lines(all_rows) + [""]

    readme_path = os.path.join(category_dir, "README.md")
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"  {category_slug}: {len(all_rows)} reports, {len(class_summaries)} classes")


def main():
    if not os.path.isdir(REPORTS_DIR):
        print(f"No {REPORTS_DIR}/ directory found. Run h1_fetch.py first.")
        return

    # Find all category dirs (depth 1 under reports/)
    category_dirs = sorted(
        d for d in glob.glob(os.path.join(REPORTS_DIR, "*"))
        if os.path.isdir(d) and not os.path.basename(d).isdigit()
    )

    if not category_dirs:
        print("No category directories found under reports/.")
        return

    total_classes = 0
    for cat_dir in category_dirs:
        category_slug = os.path.basename(cat_dir)

        # Generate per-class READMEs
        class_dirs = sorted(
            d for d in glob.glob(os.path.join(cat_dir, "*"))
            if os.path.isdir(d)
        )
        for class_dir in class_dirs:
            class_slug = os.path.basename(class_dir)
            rows = generate_class_readme(class_slug, class_dir)
            if rows:
                total_classes += 1

        # Generate per-category README
        generate_category_readme(category_slug, cat_dir)

    print(f"\nGenerated READMEs for {total_classes} class(es) across {len(category_dirs)} category/ies.")


if __name__ == "__main__":
    main()
