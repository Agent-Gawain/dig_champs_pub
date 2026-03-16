"""
router.py — OSRouter: OS detection from findings + routing decision tree.

The router does two things:
  1. Detects the target OS from scan findings (nmap os_guess, service fingerprints,
     web technology signals).
  2. Applies the routing decision tree to filter and weight methodology suggestions
     based on OS, credential availability, post-auth data, and mode.

The router does NOT emit a phase_queue directly — it returns a DetectedOS and
influences which methodology pool the collator uses (via os_tag). The Path
Designer (path_designer.py) translates methodology IDs → phase names.

Usage
-----
    from wan_si_tong.router import OSRouter, DetectedOS
    router = OSRouter()
    detected = router.detect_os(findings)
    # detected.os_tag, detected.confidence
    filtered = router.apply_routing(suggestions, findings, cred_results, mode)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class OS(str, Enum):
    LINUX   = "linux"
    WINDOWS = "windows"
    MACOS   = "macos"
    ANDROID = "android"
    UNKNOWN = "unknown"


class Confidence(str, Enum):
    HIGH    = "high"
    MEDIUM  = "medium"
    LOW     = "low"
    NONE    = "none"


@dataclass
class DetectedOS:
    os_tag:     str          # OS.value — "linux", "windows", "macos", "android", "unknown"
    confidence: str          # Confidence.value
    signals:    list[str]    # human-readable signals that triggered this detection


class OSRouter:
    """
    Detects target OS from findings and applies routing constraints.

    Detection priority (highest to lowest):
      P1 — Explicit nmap os_guess keyword match
      P2 — Service fingerprint inference (port + service combination)
      P3 — Web technology inference (IIS → Windows, PHP alone → Linux)
      P4 — No signal → OS.UNKNOWN
    """

    # P1 keyword maps
    _OS_KEYWORDS: dict[str, list[str]] = {
        "linux":   ["linux", "ubuntu", "debian", "centos", "fedora", "kali",
                    "red hat", "rhel", "arch", "alpine"],
        "windows": ["windows", "microsoft", "win32", "win64", "windows server",
                    "windows 10", "windows 11"],
        "macos":   ["mac os", "macos", "darwin", "os x"],
        "android": ["android"],
    }

    # P2 service fingerprint rules: (port_str, service_substr) → OS
    _SERVICE_RULES: list[tuple[str | None, str, str]] = [
        # (port,  service_fragment,  os_tag)
        ("5555",  "adb",             OS.ANDROID),
        (None,    "android",         OS.ANDROID),
        ("548",   "afp",             OS.MACOS),
        (None,    "bonjour",         OS.MACOS),
        (None,    "mdns",            OS.MACOS),
        ("445",   "microsoft-ds",    OS.WINDOWS),
        (None,    "ms-wbt-server",   OS.WINDOWS),    # RDP
        ("88",    "kerberos",        OS.WINDOWS),    # Kerberos → AD
        (None,    "rpcbind",         OS.LINUX),
        (None,    "nfs",             OS.LINUX),
        (None,    "portmapper",      OS.LINUX),
    ]

    # P3 web tech inference
    _WEB_WINDOWS_TECHS = {"iis", "asp.net", "asp"}
    _WEB_LINUX_TECHS   = {"apache", "nginx", "php"}  # used only as a weak signal

    def detect_os(self, findings: list[dict]) -> DetectedOS:
        """
        Analyse findings and return a DetectedOS with confidence level.

        If multiple OS signals are found, the one with the most supporting
        evidence wins. Ties go to the first-highest-priority detection.
        """
        scores: dict[str, int] = {
            OS.LINUX: 0, OS.WINDOWS: 0, OS.MACOS: 0, OS.ANDROID: 0,
        }
        signals: dict[str, list[str]] = {
            OS.LINUX: [], OS.WINDOWS: [], OS.MACOS: [], OS.ANDROID: [],
        }

        # P1 — nmap os_guess
        for f in findings:
            og = str(f.get("os_guess", "")).lower()
            if not og:
                continue
            for os_tag, keywords in self._OS_KEYWORDS.items():
                for kw in keywords:
                    if kw in og:
                        scores[os_tag] += 3   # high weight
                        signals[os_tag].append(f"os_guess:{og!r}")
                        break

        # P2 — service fingerprint
        for f in findings:
            port_str = str(f.get("port", ""))
            svc = str(f.get("service", "")).lower()
            for rule_port, rule_svc, os_tag in self._SERVICE_RULES:
                port_match = (rule_port is None) or (port_str == rule_port)
                svc_match  = rule_svc in svc
                if port_match and svc_match:
                    scores[os_tag] += 2
                    signals[os_tag].append(
                        f"service:{svc!r} port:{port_str}"
                    )

        # P3 — web technology signals
        for f in findings:
            tech = str(f.get("tech", "")).lower()
            if any(t in tech for t in self._WEB_WINDOWS_TECHS):
                scores[OS.WINDOWS] += 1
                signals[OS.WINDOWS].append(f"tech:{tech!r}")
            elif any(t in tech for t in self._WEB_LINUX_TECHS):
                # Only if no SMB signal yet (weak inference)
                if not any("445" in str(f2.get("port", "")) for f2 in findings):
                    scores[OS.LINUX] += 1
                    signals[OS.LINUX].append(f"tech:{tech!r}")

        # Pick winner
        best_os  = max(scores, key=lambda k: scores[k])
        best_score = scores[best_os]

        if best_score == 0:
            return DetectedOS(os_tag=OS.UNKNOWN, confidence=Confidence.NONE, signals=[])

        if best_score >= 4:
            conf = Confidence.HIGH
        elif best_score >= 2:
            conf = Confidence.MEDIUM
        else:
            conf = Confidence.LOW

        return DetectedOS(
            os_tag=best_os,
            confidence=conf,
            signals=list(dict.fromkeys(signals[best_os])),  # deduplicate, preserve order
        )

    # ── Routing Decision Tree ─────────────────────────────────────────────────

    def apply_routing(
        self,
        suggestions: list[dict],
        findings: list[dict],
        cred_results: list[dict],
        mode: int,
    ) -> list[dict]:
        """
        Apply the routing decision tree to a scored suggestions list.

        Rules applied in order:
          1. Mode hard-veto: remove methodologies too noisy for the mode
          2. Prerequisite satisfaction: mark unsatisfiable methodologies
          3. Credential-chain prioritisation: boost cred-chain methods if creds exist
          4. Post-auth data gating: skip post-auth-dependent methods if no post-auth yet
          5. Re-sort by adjusted score

        Returns a filtered+re-sorted suggestions list. Each dict may gain:
            "satisfiable": bool
            "routing_boost": float  (added to relevance_score for sorting)
        """
        has_creds    = bool(cred_results) or any("cred" in f for f in findings)
        has_postauth = any("post_auth_data" in f for f in findings)

        # Mode hard-veto thresholds
        min_opsec = {1: 3, 2: 2, 3: 1, 4: 1}[mode]

        result = []
        for s in suggestions:
            opsec = s.get("opsec_level", 3)

            # Rule 1: mode hard-veto
            if opsec < min_opsec:
                continue  # drop entirely

            boost  = 0.0
            satisfiable = True

            # Rule 2: prerequisite satisfaction gating
            prereqs = s.get("prerequisites", [])
            if "post_auth_data" in " ".join(prereqs) or any(
                p.startswith("post_auth_data") for p in s.get("triggers", [])
                if "post_auth_data" in p and "*" not in p
            ):
                if not has_postauth:
                    satisfiable = False

            # Rule 3: credential-chain boost
            if has_creds and any(
                t == "finding:cred" for t in s.get("triggers", [])
            ):
                boost += 0.15

            # Rule 4: mode 4 (BOSS) boosts high-impact noisy methods
            if mode == 4 and opsec <= 2:
                boost += 0.10

            # Rule 5: mode 1/2 stealth bonus for silent methods
            if mode <= 2 and opsec >= 4:
                boost += 0.05

            entry = dict(s)
            entry["satisfiable"]    = satisfiable
            entry["routing_boost"]  = round(boost, 3)
            entry["_sort_score"]    = round(s["relevance_score"] + boost, 3)

            if satisfiable:
                result.append(entry)
            # Unsatisfiable entries are dropped from routing output but callers
            # can retrieve them by calling detect_os + collate directly.

        result.sort(key=lambda x: x["_sort_score"], reverse=True)

        # Clean up internal sort key
        for entry in result:
            entry.pop("_sort_score", None)

        return result
