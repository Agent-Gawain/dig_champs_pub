"""
registry.py — MethodologyRegistry singleton.

All methodology modules (generic.py, linux.py, windows.py, etc.) call
MethodologyRegistry.get().register(...) at import time to self-register.

The registry is then consumed by:
  - collator.py   (scoring against findings)
  - router.py     (OS-specific filtering)
  - path_designer.py (DAG construction)

Usage
-----
    from wan_shi_tong.registry import MethodologyRegistry
    _R = MethodologyRegistry.get()
    _R.register(methodology_instance, os_tags=["linux"])
"""

import threading
from typing import Optional
from wan_shi_tong.schema import Methodology


class MethodologyRegistry:
    """
    Thread-safe singleton registry of all Methodology entries.

    Every methodology module registers its entries at import time via:
        MethodologyRegistry.get().register(m, os_tags=["linux"])

    os_tags controls which OS context activates the methodology.
    Use ["any"] for OS-agnostic methodologies.
    """

    _instance: Optional["MethodologyRegistry"] = None
    _lock: threading.Lock = threading.Lock()

    def __init__(self) -> None:
        self._entries: dict[str, Methodology] = {}
        # os_tag → [methodology_id, ...]
        self._by_os: dict[str, list[str]] = {}

    @classmethod
    def get(cls) -> "MethodologyRegistry":
        """Return the global singleton registry, creating it if needed."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = MethodologyRegistry()
        return cls._instance

    @classmethod
    def _reset(cls) -> None:
        """Reset singleton. Used in tests only."""
        with cls._lock:
            cls._instance = None

    # ── Registration ──────────────────────────────────────────────────────────

    def register(
        self,
        m: Methodology,
        os_tags: Optional[list[str]] = None,
    ) -> None:
        """
        Register a methodology.

        Parameters
        ----------
        m        : Methodology instance to register
        os_tags  : List of OS tags this methodology applies to.
                   Use ["any"] for OS-agnostic (default).
                   Valid values: "any", "linux", "windows", "macos", "android"
                   (or any future OS tag added to a new methodology file).
        """
        tags = os_tags or ["any"]
        self._entries[m.id] = m
        for tag in tags:
            self._by_os.setdefault(tag, [])
            if m.id not in self._by_os[tag]:
                self._by_os[tag].append(m.id)

    # ── Retrieval ─────────────────────────────────────────────────────────────

    def all(self) -> list[Methodology]:
        """Return all registered methodologies."""
        return list(self._entries.values())

    def for_os(self, os_tag: str) -> list[Methodology]:
        """
        Return methodologies applicable to a specific OS.
        Always includes "any" (OS-agnostic) methodologies.
        """
        ids: set[str] = set(self._by_os.get("any", []))
        ids |= set(self._by_os.get(os_tag.lower(), []))
        return [self._entries[mid] for mid in ids if mid in self._entries]

    def get_by_id(self, mid: str) -> Optional[Methodology]:
        """Return a methodology by ID, or None if not found."""
        return self._entries.get(mid)

    def os_tags(self) -> list[str]:
        """Return all registered OS tags (excluding 'any')."""
        return [t for t in self._by_os if t != "any"]

    # ── Validation ────────────────────────────────────────────────────────────

    def validate(self) -> list[str]:
        """
        Post-import consistency check. Returns a list of warning strings.
        Called once from wan_shi_tong/__init__.py after all modules are imported.
        """
        warnings: list[str] = []
        import re
        id_pattern = re.compile(r"^wsit_[a-z0-9_]+$")

        for m in self._entries.values():
            # ID format check
            if not id_pattern.match(m.id):
                warnings.append(f"[registry] Bad ID format: '{m.id}' (expected wsit_<lower_snake>)")

            # opsec_level range check
            if not (1 <= m.opsec_level <= 5):
                warnings.append(
                    f"[registry] {m.id}: opsec_level={m.opsec_level} out of range 1-5"
                )

            # next_ids resolution check
            for nid in m.next_ids:
                if nid not in self._entries:
                    warnings.append(
                        f"[registry] {m.id}: next_id '{nid}' not found in registry"
                    )

        return warnings

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return (
            f"MethodologyRegistry({len(self._entries)} methodologies, "
            f"os_tags={self.os_tags()})"
        )
