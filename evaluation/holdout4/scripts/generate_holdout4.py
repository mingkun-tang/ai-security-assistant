"""Generate Unseen Holdout #4 corpus (locked before first evaluation)."""

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

    if len(CASES) != 100:
        raise SystemExit(f"Expected 100 cases, got {len(CASES)}")
    ids = [c["id"] for c in CASES]
    if len(ids) != len(set(ids)):
        raise SystemExit("Duplicate case IDs")
    if any(not i.startswith("u4_") for i in ids):
        raise SystemExit("All IDs must use u4_ prefix")

    by_cat: dict[str, Counter] = {}
    for c in CASES:
        by_cat.setdefault(c["category"], Counter())
        by_cat[c["category"]]["v" if c["expected_vulnerable"] else "s"] += 1

    expected = {"sql_injection", "xss", "ssrf", "file_upload", "idor"}
    if set(by_cat) != expected:
        raise SystemExit(f"Unexpected categories: {sorted(by_cat)}")
    for cat, counts in sorted(by_cat.items()):
        if counts["v"] != 10 or counts["s"] != 10:
            raise SystemExit(f"{cat}: {counts['v']}/{counts['s']} (need 10/10)")

    vuln = sum(1 for c in CASES if c["expected_vulnerable"])
    safe = 100 - vuln
    if vuln != 50 or safe != 50:
        raise SystemExit(f"Expected 50/50, got {vuln}/{safe}")

    for case in CASES:
        dest = ROOT / case["path"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(case["source"], encoding="utf-8")

    manifest = {
        "version": "1.0",
        "description": "Unseen Holdout #4 — final blind evaluation before V1 release gate",
        "scanner": "analyze_source",
        "checkpoint": "763cb97",
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
