"""
wan_si_tong — Library of All Things (万事通)
================================================================
The attack methodology encyclopedia for dig_champs.

Named after the mythological library that contains all knowledge.
Stores structured attack playbooks, cross-references them against
live scan findings, and outputs a prioritised methodology list for
the Trajectory Path Designer.

Usage (standalone):
    python -m wan_si_tong --findings findings.json
    python -m wan_si_tong --tracker-report
    python -m wan_si_tong --design-path --findings findings.json --mode 2

Usage (from dig_champs):
    from wan_si_tong import collate_findings, TrajectoryPathDesigner, EngagementTracker
    suggestions = collate_findings(findings, cred_results)
"""

# ── Trigger all self-registrations ────────────────────────────────────────────
# This import causes every methodology module to execute its _R.register() calls
from wan_si_tong.methodologies import (  # noqa: F401
    generic, linux, windows, macos, android,
)

# ── Public API ────────────────────────────────────────────────────────────────
from wan_si_tong.schema import Methodology, CATEGORIES, PHASES, TRIGGER_TYPES
from wan_si_tong.registry import MethodologyRegistry
from wan_si_tong.collator import collate_findings, get_next_steps
from wan_si_tong.router import OSRouter, DetectedOS
from wan_si_tong.path_designer import TrajectoryPathDesigner, PathStep
from wan_si_tong.tracker import EngagementTracker
from wan_si_tong.output import write_methodology_suggestions, run_collation

__all__ = [
    # Schema
    "Methodology",
    "CATEGORIES",
    "PHASES",
    "TRIGGER_TYPES",
    # Registry
    "MethodologyRegistry",
    # Collation
    "collate_findings",
    "get_next_steps",
    # Router
    "OSRouter",
    "DetectedOS",
    # Path Designer
    "TrajectoryPathDesigner",
    "PathStep",
    # Tracker
    "EngagementTracker",
    # Output
    "write_methodology_suggestions",
    "run_collation",
]

# ── Post-import validation ────────────────────────────────────────────────────
# Warn about any broken next_ids references or malformed IDs.
# Does not raise — warnings are informational only.
_registry = MethodologyRegistry.get()
_warnings = _registry.validate()
if _warnings:
    import sys
    for _w in _warnings:
        print(f"[wan_si_tong] WARNING: {_w}", file=sys.stderr)

__version__ = "2.0.0"
