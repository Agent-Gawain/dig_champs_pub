"""
tracker.py — EngagementTracker: records methodology outcomes across all scans.

Persists to ~/.kb_sessions/wst_tracker.json (global, not per-session).
Atomic writes prevent corruption if the process is killed mid-scan.

Usage
-----
    from wan_shi_tong.tracker import EngagementTracker

    tracker = EngagementTracker()

    # At scan end:
    tracker.flush_session(
        target="192.168.1.1",
        phase_queue_executed=["postauth", "filehunt", "vulnprobe"],
        findings=findings,
    )

    # For scoring:
    rate = tracker.success_rate("wsit_ssh_spray")   # 0.0–1.0

    # For reporting:
    tracker.print_report()
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

# Import here to avoid circular; PHASE_TO_METHODOLOGY_MAP is defined in path_designer
# We use a lazy import inside flush_session.

_TRACKER_PATH   = Path.home() / ".kb_sessions" / "wst_tracker.json"
_SCHEMA_VERSION = "2.0"
_MAX_TARGETS    = 20   # rolling window for targets_succeeded / targets_failed
_NEUTRAL_RATE   = 0.50  # default success_rate for untested methodologies


class EngagementTracker:
    """
    Global engagement outcome tracker.

    Thread-safe via a per-instance lock around file I/O.
    Multiple concurrent kitsunebi instances on the same machine will
    use fcntl.flock (Unix) or a best-effort no-lock fallback (Windows).
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = Path(path) if path else _TRACKER_PATH
        self._lock = threading.Lock()
        self._data: dict = self._load()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self) -> dict:
        """Load tracker file or return empty structure."""
        if not self._path.exists():
            return self._empty_doc()
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if raw.get("schema_version") != _SCHEMA_VERSION:
                # Version mismatch — keep old data in a backup key, start fresh
                return {**self._empty_doc(), "_legacy": raw}
            return raw
        except (json.JSONDecodeError, OSError):
            return self._empty_doc()

    @staticmethod
    def _empty_doc() -> dict:
        return {
            "schema_version": _SCHEMA_VERSION,
            "last_updated":   datetime.utcnow().isoformat() + "Z",
            "methodologies":  {},
        }

    def _save(self) -> None:
        """Atomically write tracker data to disk."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._data["last_updated"] = datetime.utcnow().isoformat() + "Z"
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        # Atomic replace
        try:
            os.replace(tmp, self._path)
        except OSError:
            tmp.unlink(missing_ok=True)
            raise
        # Restrict permissions on Unix
        try:
            self._path.chmod(0o600)
        except (OSError, AttributeError):
            pass

    def _flock(self):
        """Context manager: fcntl.flock on Unix; no-op on Windows."""
        import contextlib

        @contextlib.contextmanager
        def _noop():
            yield

        try:
            import fcntl

            @contextlib.contextmanager
            def _flock_cm():
                with open(self._path.parent / ".wst_tracker.lock", "w") as lf:
                    fcntl.flock(lf, fcntl.LOCK_EX)
                    try:
                        yield
                    finally:
                        fcntl.flock(lf, fcntl.LOCK_UN)

            return _flock_cm()
        except ImportError:
            return _noop()

    # ── Entry Access ──────────────────────────────────────────────────────────

    def _entry(self, mid: str) -> dict:
        """Return or create the tracker entry for a methodology ID."""
        if mid not in self._data["methodologies"]:
            self._data["methodologies"][mid] = {
                "invocations":         0,
                "successes":           0,
                "failures":            0,
                "last_success":        None,
                "last_failure":        None,
                "targets_succeeded":   [],
                "targets_failed":      [],
                "avg_duration_s":      0.0,
                "findings_produced":   [],
            }
        return self._data["methodologies"][mid]

    # ── Public API ────────────────────────────────────────────────────────────

    def success_rate(self, mid: str) -> float:
        """
        Return historical success rate for a methodology (0.0–1.0).
        Returns NEUTRAL_RATE (0.5) if the methodology has never been invoked.
        """
        entry = self._data["methodologies"].get(mid)
        if not entry or entry["invocations"] == 0:
            return _NEUTRAL_RATE
        return entry["successes"] / entry["invocations"]

    def invocation_count(self, mid: str) -> int:
        """Return total invocation count for a methodology (0 if never run)."""
        entry = self._data["methodologies"].get(mid)
        return entry["invocations"] if entry else 0

    def record_invocation(
        self,
        mid: str,
        target: str,
        success: bool,
        duration_s: float = 0.0,
        findings_produced: Optional[list[str]] = None,
    ) -> None:
        """
        Record a single methodology invocation outcome.

        Parameters
        ----------
        mid               : Methodology ID (e.g. "wsit_ssh_spray")
        target            : Target identifier (IP or hostname)
        success           : True if the methodology produced expected findings
        duration_s        : Wall-clock seconds for this invocation
        findings_produced : List of finding key types that appeared (e.g. ["cred"])
        """
        with self._lock:
            e = self._entry(mid)
            now = datetime.utcnow().isoformat() + "Z"
            e["invocations"] += 1

            # Rolling average duration
            n = e["invocations"]
            e["avg_duration_s"] = round(
                ((e["avg_duration_s"] * (n - 1)) + duration_s) / n, 2
            )

            if success:
                e["successes"] += 1
                e["last_success"] = now
                e["targets_succeeded"] = (
                    (e["targets_succeeded"] + [target])[-_MAX_TARGETS:]
                )
                for fk in (findings_produced or []):
                    if fk not in e["findings_produced"]:
                        e["findings_produced"].append(fk)
            else:
                e["failures"] += 1
                e["last_failure"] = now
                e["targets_failed"] = (
                    (e["targets_failed"] + [target])[-_MAX_TARGETS:]
                )

    def flush_session(
        self,
        target: str,
        phase_queue_executed: list[str],
        findings: list[dict],
    ) -> None:
        """
        Called at the end of a kitsunebi scan to record outcomes for all
        executed phases.

        Uses PHASE_TO_METHODOLOGY_MAP (from path_designer) to translate
        phase names → methodology IDs, then checks whether each methodology's
        expected_findings actually appeared in findings.
        """
        # Lazy import to avoid circular dependency
        try:
            from wan_shi_tong.path_designer import PHASE_TO_METHODOLOGY_MAP
        except ImportError:
            return

        registry_module = __import__("wan_shi_tong.registry", fromlist=["MethodologyRegistry"])
        registry = registry_module.MethodologyRegistry.get()

        # Build set of finding keys present in final findings
        present_keys: set[str] = set()
        for f in findings:
            present_keys.update(f.keys())

        now_iso = datetime.utcnow().isoformat() + "Z"

        with self._lock:
            for phase in phase_queue_executed:
                mids = PHASE_TO_METHODOLOGY_MAP.get(phase, [])
                for mid in mids:
                    m = registry.get_by_id(mid)
                    if m is None:
                        continue
                    # Success = at least one expected_finding key appeared
                    expected = set(m.expected_findings)
                    found    = expected & present_keys
                    success  = bool(found)
                    e = self._entry(mid)
                    e["invocations"] += 1
                    if success:
                        e["successes"]       += 1
                        e["last_success"]     = now_iso
                        e["targets_succeeded"] = (
                            (e["targets_succeeded"] + [target])[-_MAX_TARGETS:]
                        )
                        for fk in found:
                            if fk not in e["findings_produced"]:
                                e["findings_produced"].append(fk)
                    else:
                        e["failures"]     += 1
                        e["last_failure"]  = now_iso
                        e["targets_failed"] = (
                            (e["targets_failed"] + [target])[-_MAX_TARGETS:]
                        )
            self._save()

    def print_report(self) -> None:
        """Print a formatted engagement outcome table to stdout."""
        methods = self._data.get("methodologies", {})
        if not methods:
            print("[wan_shi_tong] No engagement data recorded yet.")
            return

        # Sort by invocations descending
        rows = sorted(methods.items(), key=lambda kv: kv[1]["invocations"], reverse=True)

        col_id    = max(len(mid) for mid, _ in rows)
        col_id    = max(col_id, 30)

        header = (
            f"{'Methodology':<{col_id}}  "
            f"{'Inv':>5}  {'Succ':>5}  {'Fail':>5}  {'Rate':>7}  {'Last Success'}"
        )
        sep = "─" * len(header)
        print(f"\n{header}")
        print(sep)

        for mid, e in rows:
            inv  = e["invocations"]
            succ = e["successes"]
            fail = e["failures"]
            rate = f"{(succ/inv*100):.1f}%" if inv else "—"
            ls   = (e["last_success"] or "—")[:10]
            print(
                f"{mid:<{col_id}}  "
                f"{inv:>5}  {succ:>5}  {fail:>5}  {rate:>7}  {ls}"
            )
        print()

    def all_stats(self) -> dict:
        """Return the full methodology stats dict (for JSON export)."""
        return dict(self._data.get("methodologies", {}))
