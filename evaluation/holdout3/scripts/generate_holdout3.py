"""Generate Unseen Holdout #3 corpus (locked before first evaluation)."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from cases_sqli_xss import register as register_sqli_xss
from cases_ssrf_upload_idor import register as register_rest

CASES: list[dict] = []


def main() -> None:
    register_sqli_xss(CASES)
    register_rest(CASES)

    if len(CASES) != 150:
        raise SystemExit(f"Expected 150 cases, got {len(CASES)}")

    ids = [c["id"] for c in CASES]
    if len(ids) != len(set(ids)):
        raise SystemExit("Duplicate case IDs")

    by_cat: dict[str, Counter] = {}
    for c in CASES:
        by_cat.setdefault(c["category"], Counter())
        key = "v" if c["expected_vulnerable"] else "s"
        by_cat[c["category"]][key] += 1

    expected_cats = {
        "sql_injection",
        "xss",
        "ssrf",
        "file_upload",
        "idor",
    }
    if set(by_cat) != expected_cats:
        raise SystemExit(f"Unexpected categories: {sorted(by_cat)}")

    for cat, counts in sorted(by_cat.items()):
        if counts["v"] != 15 or counts["s"] != 15:
            raise SystemExit(f"{cat}: {counts['v']} vuln / {counts['s']} safe (need 15/15)")

    vuln = sum(1 for c in CASES if c["expected_vulnerable"])
    safe = sum(1 for c in CASES if not c["expected_vulnerable"])
    if vuln != 75 or safe != 75:
        raise SystemExit(f"Expected 75/75 vuln/safe, got {vuln}/{safe}")

    for case in CASES:
        dest = ROOT / case["path"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(case["source"], encoding="utf-8")

    manifest = {
        "version": "1.0",
        "description": "Unseen Holdout #3 — locked before first scanner evaluation",
        "scanner": "analyze_source",
        "checkpoint": "fe1cecc",
        "cases": [
            {
                "id": c["id"],
                "path": c["path"],
                "language": "python",
                "category": c["category"],
                "expected_vulnerable": c["expected_vulnerable"],
                "expected_issue_type": c["expected_issue_type"],
                "explanation": c["explanation"],
            }
            for c in CASES
        ],
    }
    (ROOT / "ground_truth.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Generated {len(CASES)} cases under {ROOT}")
    print(f"Vulnerable={vuln} Safe={safe}")
    for cat, counts in sorted(by_cat.items()):
        print(f"  {cat}: {counts['v']} vuln / {counts['s']} safe")


if __name__ == "__main__":
    main()
