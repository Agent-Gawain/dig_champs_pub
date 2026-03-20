"""
schema.py — Methodology dataclass and shared constants.

All other wan_shi_tong modules import from here; nothing in this file
imports from elsewhere in the package (no circular dependencies).
"""

from dataclasses import dataclass, field


# ── Methodology dataclass ─────────────────────────────────────────────────────

@dataclass
class Methodology:
    """
    A single attack methodology entry in the library.

    Fields
    ------
    id              : Unique identifier (e.g. "wsit_ssh_spray")
    name            : Human-readable name
    category        : Top-level grouping (see CATEGORIES)
    phase           : Lifecycle phase (see PHASES)
    triggers        : Conditions that activate this methodology.
                      Each trigger is a string like "port:22", "service:ftp",
                      "cve:CVE-*", "issue:SMB null session", "finding:cred",
                      "os:linux", "tech:wordpress"
    mitre           : MITRE ATT&CK technique IDs
    prerequisites   : What must be true before this can run
    tools           : Recommended tools (in order of preference)
    description     : What this methodology does and why
    opsec_level     : 1 (very noisy) → 5 (very stealthy)
    expected_findings: What `src` keys should appear in findings after success
    next_ids        : IDs of methodologies that logically follow this one
    detection_notes : How defenders detect this; useful for the audit diff
    """
    id:                 str
    name:               str
    category:           str
    phase:              str
    triggers:           list[str]
    mitre:              list[str]
    prerequisites:      list[str]
    tools:              list[str]
    description:        str
    opsec_level:        int           # 1 = loud, 5 = silent
    expected_findings:  list[str]    = field(default_factory=list)
    next_ids:           list[str]    = field(default_factory=list)
    detection_notes:    str          = ""


# ── Category constants ────────────────────────────────────────────────────────

CATEGORIES: dict[str, str] = {
    "recon":            "Initial Reconnaissance",
    "credential":       "Credential Attacks",
    "web":              "Web Exploitation",
    "smb":              "SMB / Windows Lateral Movement",
    "network_service":  "Network Service Exploitation",
    "post_exploit":     "Post-Exploitation",
    "privilege_esc":    "Privilege Escalation",
    "lateral":          "Lateral Movement",
    "persistence":      "Persistence",
    "exfil_prep":       "Exfiltration Preparation",
}

# ── Phase constants (maps to kitsunebi stage names) ─────────────────────────

PHASES: dict[str, str] = {
    "looking":          "Stage 1 — Initial Recon",
    "looking_deeper":   "Stage 2 — Deep Recon",
    "predicting":       "Stage 3 — Prediction",
    "live_adapt":       "Stage 4 — Live Adaptation",
}

# ── Trigger key constants ─────────────────────────────────────────────────────

TRIGGER_TYPES: list[str] = [
    "always",
    "port",
    "service",
    "tech",
    "issue",
    "juicy",
    "finding",
    "fuzz_status",
    "fuzz_url",
    "cve",
    "os",
    "hvf_category",
    "hvf_path",
    "vuln_confirmed",
    "post_auth_data",
    "dns",
    "user",
]
