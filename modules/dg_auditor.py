#!/usr/bin/env python3
"""
dg_auditor.py — dig_champs Scan Auditor
================================================================
A standalone review interface for completed dig_champs scans.

Allows an operator or analyst to:
  - Browse all previous scan sessions stored in ~/.dc_sessions/
  - Search sessions by target, date range, or finding type
  - Display the human-readable narrative (trajectory_human.md)
  - Display the machine trajectory (trajectory.json) in a readable format
  - Display the audit diff (trajectory_audit.json / trajectory_audit.md)
  - Compare two scan sessions against the same target (delta view)
  - Export a combined operator report for a given session

STATUS: Notes and architecture sketch only. Not yet implemented.

────────────────────────────────────────────────────────────────────────────────
INTENDED BEHAVIOUR
────────────────────────────────────────────────────────────────────────────────

Interactive mode (no args):
    python3 dg_auditor.py
    → Browse ~/.dc_sessions/ with a Rich-rendered session picker.
      Select a session → view sub-menu: narrative / machine log / audit diff / export.

Targeted mode:
    python3 dg_auditor.py --target 10.0.0.1
    → List all sessions for that target, most recent first.

    python3 dg_auditor.py --session ~/.dc_sessions/10.0.0.1_20260313_142201/
    → Jump directly to a specific session sub-menu.

    python3 dg_auditor.py --compare <session_a> <session_b>
    → Side-by-side delta: new findings in B not in A, resolved findings, phase timing diffs.

    python3 dg_auditor.py --export <session> --out report.pdf
    → Generate a combined PDF/Markdown operator report (narrative + audit + findings).

────────────────────────────────────────────────────────────────────────────────
ARCHITECTURE NOTES
────────────────────────────────────────────────────────────────────────────────

Data sources (all in <sdir>/):
    session.json           — scan args + start timestamp
    trajectory.json        — machine event log (phase timing, findings IDs, adapt events)
    trajectory_human.md    — Claude/template narrative prose
    trajectory_audit.json  — machine-readable discrepancy report
    trajectory_audit.md    — human-readable audit summary
    report_<target>_<ts>.json  — full findings list (structured)
    report_<target>_<ts>.md    — findings Markdown table

Key concerns:
  - Sessions may be incomplete (scan was killed mid-run). The auditor should
    handle missing files gracefully and indicate partial scan status.
  - trajectory.json is always valid JSON at any crash point (atomic writes),
    but scan_end may be null if the process was killed.
  - The human narrative may not exist if the scan crashed before Phase 2/3,
    or if ANTHROPIC_API_KEY was not set (template fallback should still exist).
  - Comparing sessions: finding IDs (_finding_id SHA256[:8]) are deterministic
    so the same finding on two scans will have the same ID. Use this for delta.

────────────────────────────────────────────────────────────────────────────────
FUNCTION STUBS (not yet implemented)
────────────────────────────────────────────────────────────────────────────────
"""

# NOTE: All function bodies are stubs (raise NotImplementedError).
# Signatures are final; implementation is deferred.

from pathlib import Path


# ── Session Discovery ─────────────────────────────────────────────────────────

def list_sessions(dc_sessions_dir: str | None = None) -> list[dict]:
    """
    Return a list of all sessions in ~/.dc_sessions/ (or given dir).

    Each entry:
    {
        "path":        str,        # absolute path to sdir
        "target":      str,        # from session.json
        "started":     str,        # ISO timestamp from session.json
        "scan_end":    str | None, # from trajectory.json, None if incomplete
        "total_findings": int,     # from trajectory.json
        "has_narrative": bool,     # trajectory_human.md exists
        "has_audit":     bool,     # trajectory_audit.json exists
        "complete":      bool,     # scan_end is not None
    }

    Sorted most-recent-first by started.
    """
    raise NotImplementedError


def find_sessions(target: str, dc_sessions_dir: str | None = None) -> list[dict]:
    """
    Filter list_sessions() to sessions matching the given target string.
    Partial match (e.g. "10.0.0" matches "10.0.0.1").
    """
    raise NotImplementedError


def load_session(sdir: str) -> dict:
    """
    Load all available data files for a session into a single dict.

    Returns:
    {
        "sdir":        str,
        "session_meta": dict,           # session.json
        "trajectory":  dict | None,     # trajectory.json
        "narrative":   str | None,      # trajectory_human.md text
        "audit":       dict | None,     # trajectory_audit.json
        "findings":    list[dict] | None, # report_*.json findings
    }

    Missing files result in None for that key. Never raises.
    """
    raise NotImplementedError


# ── Display ───────────────────────────────────────────────────────────────────

def show_narrative(session: dict) -> None:
    """
    Render trajectory_human.md in the terminal using Rich Markdown.
    Falls back to plain text if Rich is unavailable.
    If narrative is None, print a warning and display the machine log summary instead.
    """
    raise NotImplementedError


def show_machine_log(session: dict) -> None:
    """
    Render trajectory.json as a Rich-formatted timeline table:
      Phase | Duration | Tools | Findings Added | Errors | Cached

    For adapt events, render as a highlighted panel showing old→new queue
    and the rules that fired.

    For scan_resumed events, show a divider with the resume timestamp.
    """
    raise NotImplementedError


def show_audit(session: dict) -> None:
    """
    Render trajectory_audit.md (or trajectory_audit.json if .md is absent)
    as a Rich panel with:
      - Summary counts table
      - Highlighted critical omissions (findings in machine log not in narrative)
      - Phantom findings (narrative IDs not in machine log) flagged in red
      - Timing anomalies
      - Unexplained queue decisions
    """
    raise NotImplementedError


def show_findings_summary(session: dict) -> None:
    """
    Render the findings list from report_*.json as a Rich table grouped by severity.
    Reuses _sev_label logic from dig_champs (or reimplements it locally).
    """
    raise NotImplementedError


# ── Comparison ────────────────────────────────────────────────────────────────

def compare_sessions(session_a: dict, session_b: dict) -> dict:
    """
    Produce a delta report between two sessions on the same (or different) target.

    Returns:
    {
        "new_findings":     list[dict],   # in B not in A (by finding_id)
        "resolved_findings": list[dict],  # in A not in B
        "shared_findings":  list[dict],   # in both
        "phase_timing_delta": {           # per-phase duration change
            "<phase>": {"a_s": float, "b_s": float, "delta_s": float}
        },
        "queue_diff": {                   # final phase_order comparison
            "a_order": list[str],
            "b_order": list[str],
        },
        "adapt_count_delta": int,         # B.adapt_events - A.adapt_events
    }

    NOTE: finding_id hashes are deterministic, so the same vulnerability
    found on two separate scans of the same target will have the same ID.
    """
    raise NotImplementedError


def show_comparison(delta: dict) -> None:
    """
    Render compare_sessions() output as a side-by-side Rich panel.
    New findings highlighted green, resolved highlighted yellow.
    """
    raise NotImplementedError


# ── Export ────────────────────────────────────────────────────────────────────

def export_report(session: dict, out_path: str, fmt: str = "md") -> str:
    """
    Combine narrative + findings table + audit summary into a single file.

    fmt="md"  → Combined Markdown (default, no dependencies)
    fmt="pdf" → PDF via weasyprint (optional dependency)

    The combined report structure:
        # Operator Report — <target> — <date>
        ## Executive Summary      (narrative overview paragraph)
        ## Phase Timeline         (machine log table)
        ## Findings               (severity-grouped findings table)
        ## Audit Notes            (audit summary)

    Returns the path written.
    """
    raise NotImplementedError


# ── Interactive UI ────────────────────────────────────────────────────────────

def interactive_session_picker() -> dict | None:
    """
    Display a Rich-rendered list of all sessions. Operator selects one.
    Returns the loaded session dict, or None if the operator exits.

    Intended UX:
        ┌─────────────────────────────────────────────────────┐
        │  DIG CHAMPS — SCAN AUDITOR                          │
        ├──┬──────────────────┬─────────────────┬────────────┤
        │# │ Target           │ Date            │ Findings   │
        ├──┼──────────────────┼─────────────────┼────────────┤
        │1 │ 10.0.0.1         │ 2026-03-13 14:22│ 47         │
        │2 │ 192.168.1.100    │ 2026-03-12 09:15│ 23 ⚠ partial│
        └──┴──────────────────┴─────────────────┴────────────┘
        Select [1-N] or q to quit:
    """
    raise NotImplementedError


def interactive_session_menu(session: dict) -> None:
    """
    Sub-menu for a selected session:
        [1] Narrative report
        [2] Machine timeline
        [3] Audit diff
        [4] Findings summary
        [5] Export combined report
        [b] Back
    """
    raise NotImplementedError


# ── CLI Entry Point ───────────────────────────────────────────────────────────

def main() -> None:
    """
    Argument parsing and dispatch.

    python3 dg_auditor.py                            → interactive_session_picker()
    python3 dg_auditor.py --target <t>               → find_sessions() + picker
    python3 dg_auditor.py --session <path>           → interactive_session_menu()
    python3 dg_auditor.py --compare <path_a> <path_b>→ compare_sessions() + show_comparison()
    python3 dg_auditor.py --export <path> [--out f]  → export_report()
    """
    raise NotImplementedError


if __name__ == "__main__":
    main()
