"""
collator.py — Collation engine: match scan findings against the library.

Public API
----------
    collate_findings(findings, cred_results, min_score, os_tag) -> list[dict]
    get_next_steps(methodology_id) -> list[Methodology]

The collation engine scores every registered methodology against the current
findings list and returns those above min_score, sorted by relevance.

When a tracker is provided, the final score blends trigger relevance (70%)
with historical success rate (30%), so methodologies that have worked well
on similar targets score higher.
"""

from dataclasses import asdict
from wan_shi_tong.registry import MethodologyRegistry
from wan_shi_tong.schema import Methodology

# Blend weights: trigger match vs. historical success
_TRIGGER_WEIGHT  = 0.70
TRACKER_WEIGHT   = 0.30   # exposed so path_designer can reference it
_NEUTRAL_RATE    = 0.50   # success rate assigned to untested methodologies


# ── Trigger Matching ──────────────────────────────────────────────────────────

def _trigger_matches(trigger: str, findings: list[dict], cred_results: list[dict]) -> bool:
    """Return True if a single trigger condition is satisfied by the current findings."""
    if trigger == "always":
        return True

    key, _, value = trigger.partition(":")

    if key == "port":
        return any(str(f.get("port")) == value for f in findings)

    if key == "service":
        return any(
            value.lower() in str(f.get("service", "")).lower()
            for f in findings
        )

    if key == "tech":
        return any(
            value.lower() in str(f.get("tech", "")).lower()
            for f in findings
        )

    if key == "issue":
        return any(
            value.lower() in str(f.get("issue", "")).lower()
            for f in findings
        )

    if key == "juicy":
        return any(
            value.lower() in str(f.get("juicy", "")).lower()
            for f in findings
        )

    if key == "finding":
        return any(value in f for f in findings)

    if key == "fuzz_status":
        return any(str(f.get("fuzz_status", "")) == value for f in findings)

    if key == "fuzz_url":
        return any("fuzz_url" in f for f in findings)

    if key == "cve":
        # wildcard: "cve:CVE-*" matches any CVE
        if value == "CVE-*" or value.endswith("*"):
            return any("cve" in f for f in findings)
        return any(value.lower() == str(f.get("cve", "")).lower() for f in findings)

    if key == "os":
        return any(
            value.lower() in str(f.get("os_guess", "")).lower()
            for f in findings
        )

    if key == "hvf_category":
        return any(f.get("hvf_category") == value for f in findings)

    if key == "hvf_path":
        return any("hvf_path" in f for f in findings)

    if key == "vuln_confirmed":
        return any(f.get("vuln_confirmed") for f in findings)

    if key == "post_auth_data":
        # value "*" matches any post_auth_data presence
        if value == "*":
            return any("post_auth_data" in f for f in findings)
        # value is a specific key within post_auth_data
        return any(
            value in f.get("post_auth_data", {})
            for f in findings
            if "post_auth_data" in f
        )

    if key == "dns":
        return any("dns" in f for f in findings)

    if key == "user":
        return any("user" in f for f in findings)

    # Unknown trigger type — skip
    return False


def _score_methodology(
    m: Methodology,
    findings: list[dict],
    cred_results: list[dict],
) -> float:
    """
    Score a methodology 0.0–1.0 based on how many of its triggers match.
    Methodologies with more matching triggers are more relevant.
    """
    if not m.triggers:
        return 0.0
    matched = sum(
        1 for t in m.triggers
        if _trigger_matches(t, findings, cred_results)
    )
    return matched / len(m.triggers)


# ── Public API ────────────────────────────────────────────────────────────────

def collate_findings(
    findings: list[dict],
    cred_results: list[dict] | None = None,
    min_score: float = 0.3,
    os_tag: str | None = None,
    tracker=None,   # EngagementTracker | None — avoids circular import
) -> list[dict]:
    """
    Match current scan findings against the Wan Si Tong library.

    Returns a list of methodology dicts sorted by relevance score descending,
    filtered to score >= min_score.

    Each returned dict has an extra key:
        "relevance_score": float  # 0.0–1.0 (blended trigger + tracker)

    Parameters
    ----------
    findings      : Accumulated scan findings list from kitsunebi
    cred_results  : Cracked credentials (list of {user, password, service, port})
    min_score     : Minimum relevance threshold (default 0.3)
    os_tag        : Detected OS tag ("linux", "windows", "macos", "android", or None)
                    When None, the full methodology pool is used.
    tracker       : Optional EngagementTracker for success-rate blending
    """
    cred_results = cred_results or []
    registry = MethodologyRegistry.get()

    if os_tag:
        pool = registry.for_os(os_tag)
    else:
        pool = registry.all()

    results: list[tuple[float, Methodology]] = []

    for m in pool:
        trigger_score = _score_methodology(m, findings, cred_results)
        if trigger_score < min_score:
            continue

        # Blend with historical success rate if tracker available
        if tracker is not None:
            rate = tracker.success_rate(m.id)
        else:
            rate = _NEUTRAL_RATE

        blended = (trigger_score * _TRIGGER_WEIGHT) + (rate * TRACKER_WEIGHT)
        results.append((blended, m))

    results.sort(key=lambda x: x[0], reverse=True)

    output = []
    for score, m in results:
        d = asdict(m)
        d["relevance_score"] = round(score, 3)
        output.append(d)

    return output


def get_next_steps(methodology_id: str) -> list[Methodology]:
    """Given a methodology ID, return the recommended next methodologies."""
    registry = MethodologyRegistry.get()
    m = registry.get_by_id(methodology_id)
    if not m:
        return []
    return [
        registry.get_by_id(nid)
        for nid in m.next_ids
        if registry.get_by_id(nid) is not None
    ]
