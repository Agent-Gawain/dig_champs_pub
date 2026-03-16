"""
output.py — Output helpers and standalone collation runner.

Public API
----------
    write_methodology_suggestions(suggestions, target, out_path)
    run_collation(findings_path, target, out_path) -> list[dict]
"""

import json
import sys
from datetime import datetime
from pathlib import Path

from wan_si_tong.collator import collate_findings


def write_methodology_suggestions(
    suggestions: list[dict],
    target: str,
    out_path: str,
) -> None:
    """
    Write collated methodology suggestions to a JSON file.

    Output schema:
    {
        "schema_version": "2.0",
        "source": "wan_si_tong",
        "target": <target>,
        "generated": <ISO timestamp>,
        "count": <int>,
        "suggestions": [ { ...methodology fields..., "relevance_score": float } ]
    }
    """
    doc = {
        "schema_version": "2.0",
        "source":         "wan_si_tong",
        "target":         target,
        "generated":      datetime.utcnow().isoformat() + "Z",
        "count":          len(suggestions),
        "suggestions":    suggestions,
    }
    Path(out_path).write_text(json.dumps(doc, indent=2), encoding="utf-8")
    print(f"[wan_si_tong] Wrote {len(suggestions)} methodology suggestions → {out_path}")


def run_collation(
    findings_path: str,
    target: str,
    out_path: str,
    min_score: float = 0.3,
    os_tag: str | None = None,
) -> list[dict]:
    """
    Load findings from a JSON file, collate against the library,
    and write suggestions to out_path.

    Accepts both a raw findings list and the dig_champs report format
    (dict with "findings" key).

    Returns the suggestions list.
    """
    raw = json.loads(Path(findings_path).read_text(encoding="utf-8"))

    if isinstance(raw, list):
        findings = raw
    elif isinstance(raw, dict) and "findings" in raw:
        findings = raw["findings"]
    else:
        print(
            f"[wan_si_tong] Unrecognised findings format in {findings_path}",
            file=sys.stderr,
        )
        return []

    suggestions = collate_findings(findings, min_score=min_score, os_tag=os_tag)
    write_methodology_suggestions(suggestions, target, out_path)
    return suggestions
