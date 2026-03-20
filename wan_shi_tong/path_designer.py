"""
path_designer.py — TrajectoryPathDesigner: DAG sort + phase queue translation.

Implements Tier 0 of the kitsunebi orchestration hierarchy.
Replaces the Path Designer stub in the old wan_shi_tong.py monolith.

Algorithm
---------
1. Build a directed graph (DAG) from methodology suggestions using
   prerequisites and next_ids chains.
2. Assign node weights:
     weight = relevance_score × (1 + tracker.success_rate(id) × TRACKER_WEIGHT) × mode_factor
3. Kahn's topological sort with tie-breaking by weight descending.
4. Translate the ordered methodology list to kitsunebi phase names
   using PHASE_TO_METHODOLOGY_MAP (first-seen phase order, terminals last).
5. Cap at MAX_PATH_STEPS.

Usage
-----
    from wan_shi_tong.path_designer import TrajectoryPathDesigner

    designer = TrajectoryPathDesigner(
        trajectory={},          # pre-scan: empty; or contents of trajectory.json
        suggestions=suggestions, # from collate_findings()
        mode=2,
        tracker=tracker,         # optional EngagementTracker
    )
    phase_queue = designer.to_phase_queue()
    print(designer.explain())
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional

# Blend weight for tracker feedback (mirrors collator.TRACKER_WEIGHT)
TRACKER_WEIGHT   = 0.30
MAX_PATH_STEPS   = 20

# Composite floor: minimum blended relevance_score required to enter the path.
# Checked against the collator-produced relevance_score (trigger 70% + success_rate 30%).
# Scaled by mode so Ghost engagements are pickier, BOSS mode is permissive.
_COMPOSITE_FLOOR_BY_MODE: dict[int, float] = {
    1: 0.65,   # Ghost   — high bar; failed probes = noise + detection risk
    2: 0.60,   # Careful — default balanced threshold
    3: 0.55,   # Normal  — moderately permissive
    4: 0.35,   # BOSS    — spray everything with a heartbeat
}

# Methodologies with fewer than this many recorded invocations are treated as
# cold-start and exempted from the composite floor (no reliable data yet).
_COLD_START_MIN_INVOCATIONS = 5

# ── Phase → Methodology mapping ───────────────────────────────────────────────
# Maps kitsunebi phase names to the methodology IDs that represent work
# done during that phase. Used by:
#   - to_phase_queue()     (designer → kitsunebi)
#   - tracker.flush_session() (phase → outcomes)

PHASE_TO_METHODOLOGY_MAP: dict[str, list[str]] = {
    "filehunt": [
        "wsit_smb_filehunt",
        "wsit_ftp_filehunt",
        "wsit_lin_ssh_key_harvest",
        "wsit_and_app_data_extract",
    ],
    "webfuzz": [
        "wsit_web_fuzz",
        "wsit_vhost_fuzz",
        "wsit_and_cert_pin_bypass",
    ],
    "postauth": [
        "wsit_ssh_postauth",
        "wsit_cred_extract",
        "wsit_lin_suid_search",
        "wsit_lin_sudo_enum",
        "wsit_lin_cron_abuse",
        "wsit_lin_lxd_esc",
        "wsit_lin_passwd_hash",
        "wsit_lin_hash_crack",
        "wsit_lin_env_var_leak",
        "wsit_lin_writable_service",
        "wsit_lin_path_hijack",
        "wsit_lin_capabilities",
        "wsit_win_token_impersonate",
        "wsit_win_unquoted_svc",
        "wsit_win_dpapi_extract",
        "wsit_win_sam_dump",
        "wsit_win_winrm_session",
        "wsit_win_reg_autologon",
        "wsit_win_alwaysinstall",
        "wsit_win_scheduled_tasks",
        "wsit_win_lsass_dump",
        "wsit_win_kerberoast",
        "wsit_mac_keychain_extract",
        "wsit_mac_sudo_tty",
        "wsit_mac_osascript_priv",
        "wsit_mac_mdm_enroll",
        "wsit_mac_disk_arb",
        "wsit_mac_ssh_agent",
        "wsit_mac_spotlight_meta",
        "wsit_mac_tcc_bypass",
        "wsit_mac_dylib_hijack",
        "wsit_mac_launch_agent",
        "wsit_and_adb_shell",
        "wsit_and_frida_hook",
        "wsit_and_backup_extract",
        "wsit_and_root_detect",
        "wsit_and_broadcast_recv",
        "wsit_and_logcat_harvest",
        "wsit_privesc_sudo",
        "wsit_privesc_suid",
        "wsit_privesc_kernel",
        "wsit_cred_reuse",
    ],
    "vulnprobe": [
        "wsit_smb_vuln_probe",
        "wsit_ssl_probe",
        "wsit_db_enum",
        "wsit_sqli_probe",
        "wsit_cms_attack",
    ],
    "vulnreport": [],   # terminal — no methodology mapping; always runs
    "artifacts":  [],   # terminal — no methodology mapping; always runs
}

# Reverse map: methodology_id → phase name (first match wins)
_METHODOLOGY_TO_PHASE: dict[str, str] = {
    mid: phase
    for phase, mids in PHASE_TO_METHODOLOGY_MAP.items()
    for mid in mids
}

_TERMINAL_PHASES = {"vulnreport", "artifacts"}


# ── PathStep ──────────────────────────────────────────────────────────────────

@dataclass
class PathStep:
    step:             int
    methodology_id:   str
    rationale:        str
    expected_impact:  float             # 0.0–1.0 weighted score
    opsec_cost:       int               # cumulative opsec_level so far in path
    depends_on:       list[str]         = field(default_factory=list)
    kitsunebi_phase: Optional[str]     = None
    satisfiable:      bool              = True


# ── TrajectoryPathDesigner ────────────────────────────────────────────────────

class TrajectoryPathDesigner:
    """
    Produces an ordered multi-step attack path from scored methodology suggestions.

    Inputs
    ------
    trajectory  : Contents of trajectory.json (may be empty dict pre-scan)
    suggestions : Output of collate_findings() — list of scored methodology dicts
    mode        : kitsunebi engagement mode (1=Ghost .. 4=BOSS)
    tracker     : Optional EngagementTracker for success-rate weighting
    """

    def __init__(
        self,
        trajectory: dict,
        suggestions: list[dict],
        mode: int,
        tracker=None,
    ) -> None:
        self._trajectory  = trajectory
        self._suggestions = suggestions
        self._mode        = max(1, min(4, mode))
        self._tracker     = tracker
        self._path: Optional[list[PathStep]] = None

    # ── Weight computation ────────────────────────────────────────────────────

    def _mode_factor(self, opsec_level: int) -> float:
        """
        Mode factor applied to node weight.
        Ghost modes penalise noisy methods; BOSS mode rewards them.
        """
        m = self._mode
        if m == 1:
            return 1.0 if opsec_level >= 3 else 0.05
        if m == 2:
            return 1.0 if opsec_level >= 2 else 0.2
        if m == 3:
            return 1.0
        # mode == 4 (BOSS)
        return 1.2 if opsec_level <= 2 else 1.0

    def _node_weight(self, s: dict) -> float:
        """Compute final node weight for DAG sort tie-breaking."""
        relevance = s.get("relevance_score", 0.0)
        opsec     = s.get("opsec_level", 3)
        mid       = s.get("id", "")

        if self._tracker is not None:
            rate = self._tracker.success_rate(mid)
        else:
            rate = 0.50

        raw_score = relevance * (1 + rate * TRACKER_WEIGHT)
        return round(raw_score * self._mode_factor(opsec), 4)

    # ── Mode hard-veto ────────────────────────────────────────────────────────

    def _passes_mode_veto(self, s: dict) -> bool:
        """Return False if this methodology is too noisy for the current mode."""
        opsec = s.get("opsec_level", 3)
        if self._mode == 1 and opsec < 3:
            return False
        if self._mode == 2 and opsec < 2:
            return False
        return True

    # ── Composite floor ───────────────────────────────────────────────────────

    def _passes_composite_floor(self, s: dict) -> bool:
        """
        Return False if the methodology's blended relevance_score is below the
        mode-scaled composite floor.

        Cold-start exemption: methodologies with fewer than
        _COLD_START_MIN_INVOCATIONS recorded runs are always allowed through —
        we have no reliable data to penalise them yet.
        """
        mid = s.get("id", "")

        # No tracker → every technique is cold-start; let them all through.
        if self._tracker is None:
            return True

        if self._tracker.invocation_count(mid) < _COLD_START_MIN_INVOCATIONS:
            return True

        floor = _COMPOSITE_FLOOR_BY_MODE[self._mode]
        return s.get("relevance_score", 0.0) >= floor

    # ── DAG Construction ──────────────────────────────────────────────────────

    def _build_dag(
        self,
        pool: list[dict],
    ) -> tuple[dict[str, dict], dict[str, set[str]], dict[str, set[str]]]:
        """
        Build adjacency structures for the DAG.

        Returns
        -------
        nodes        : id → suggestion dict (with weight added)
        successors   : id → set of successor IDs (A→B means B should run after A)
        predecessors : id → set of predecessor IDs
        """
        id_set = {s["id"] for s in pool}

        nodes: dict[str, dict] = {}
        successors:   dict[str, set[str]] = {s["id"]: set() for s in pool}
        predecessors: dict[str, set[str]] = {s["id"]: set() for s in pool}

        for s in pool:
            mid = s["id"]
            entry = dict(s)
            entry["_weight"] = self._node_weight(s)
            nodes[mid] = entry

        # Build edges from next_ids
        for s in pool:
            mid = s["id"]
            for nid in s.get("next_ids", []):
                if nid in id_set:
                    successors[mid].add(nid)
                    predecessors[nid].add(mid)

        return nodes, successors, predecessors

    # ── Kahn's Topological Sort ───────────────────────────────────────────────

    def _kahn_sort(
        self,
        nodes: dict[str, dict],
        successors: dict[str, set[str]],
        predecessors: dict[str, set[str]],
    ) -> list[str]:
        """
        Kahn's algorithm with weight-based tie-breaking.
        Nodes with no predecessors are ready; among those, pick highest weight first.
        """
        in_degree = {mid: len(preds) for mid, preds in predecessors.items()}
        ready: list[str] = [mid for mid, deg in in_degree.items() if deg == 0]

        # Sort by weight descending for initial queue
        ready.sort(key=lambda mid: nodes[mid]["_weight"], reverse=True)

        order: list[str] = []
        ready_q: deque[str] = deque(ready)

        while ready_q:
            # Pick the highest-weight ready node
            # Since we maintain ready_q sorted, take from front
            mid = ready_q.popleft()
            order.append(mid)

            # Reduce in-degree for successors
            newly_ready: list[str] = []
            for nid in successors[mid]:
                in_degree[nid] -= 1
                if in_degree[nid] == 0:
                    newly_ready.append(nid)

            # Insert newly-ready nodes in weight-descending order
            newly_ready.sort(key=lambda m: nodes[m]["_weight"], reverse=True)
            # Merge into front of queue, respecting existing queue weights
            # Simple approach: extend then re-sort the prefix
            remaining = list(ready_q) + newly_ready
            remaining.sort(key=lambda m: nodes[m]["_weight"], reverse=True)
            ready_q = deque(remaining)

        return order

    # ── Path Building ─────────────────────────────────────────────────────────

    def build_path(self) -> list[PathStep]:
        """Build and cache the ordered PathStep list."""
        if self._path is not None:
            return self._path

        # Filter to mode-allowed methodologies that clear the composite floor
        pool = [
            s for s in self._suggestions
            if self._passes_mode_veto(s) and self._passes_composite_floor(s)
        ]

        if not pool:
            self._path = []
            return self._path

        nodes, successors, predecessors = self._build_dag(pool)
        order = self._kahn_sort(nodes, successors, predecessors)

        # Cap at MAX_PATH_STEPS
        order = order[:MAX_PATH_STEPS]

        path: list[PathStep] = []
        cumulative_opsec = 0

        for i, mid in enumerate(order, 1):
            s = nodes[mid]
            opsec   = s.get("opsec_level", 3)
            weight  = s["_weight"]
            preds   = [p for p in predecessors.get(mid, set()) if p in {ps.methodology_id for ps in path}]
            phase   = _METHODOLOGY_TO_PHASE.get(mid)

            # Build rationale string
            triggers_matched = [
                t for t in s.get("triggers", [])
                if not t.startswith("always")
            ]
            rationale_parts = []
            if triggers_matched:
                rationale_parts.append(f"triggers: {', '.join(triggers_matched[:3])}")
            if preds:
                rationale_parts.append(f"after: {', '.join(preds[:2])}")
            rationale_parts.append(f"score={weight:.3f}")
            rationale = "; ".join(rationale_parts)

            cumulative_opsec += opsec

            path.append(PathStep(
                step=i,
                methodology_id=mid,
                rationale=rationale,
                expected_impact=weight,
                opsec_cost=cumulative_opsec,
                depends_on=preds,
                kitsunebi_phase=phase,
                satisfiable=True,
            ))

        self._path = path
        return self._path

    def to_phase_queue(self) -> list[str]:
        """
        Convert the ordered PathStep list to a kitsunebi-compatible phase queue.

        Walk the path; emit each kitsunebi_phase in first-seen order.
        Terminal phases (vulnreport, artifacts) are always appended last.
        """
        path = self.build_path()
        seen: list[str] = []

        for step in path:
            ph = step.kitsunebi_phase
            if ph and ph not in seen and ph not in _TERMINAL_PHASES:
                seen.append(ph)

        # Ensure all standard scannable phases are represented
        # (path may not cover every phase if suggestions pool is narrow)
        all_scannable = [p for p in PHASE_TO_METHODOLOGY_MAP if p not in _TERMINAL_PHASES]
        for p in all_scannable:
            if p not in seen:
                seen.append(p)

        # Append terminal phases last
        for p in ["vulnreport", "artifacts"]:
            seen.append(p)

        return seen

    def explain(self) -> str:
        """Return a human-readable explanation of the path."""
        path = self.build_path()
        if not path:
            return "[path_designer] No methodologies matched current findings."

        lines = [
            f"[path_designer] mode={self._mode}  steps={len(path)}  "
            f"queue={self.to_phase_queue()!r}",
        ]
        for step in path[:10]:
            lines.append(
                f"  {step.step:2d}. [{step.methodology_id}]  "
                f"impact={step.expected_impact:.3f}  "
                f"opsec={step.opsec_cost}  {step.rationale}"
            )
        if len(path) > 10:
            lines.append(f"  ... and {len(path)-10} more steps")

        return "\n".join(lines)
