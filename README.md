# Digital Ghost — DIG CHAMPS

Red-team recon and post-exploitation framework. Automated multi-phase attack surface mapping with live adaptive phase sequencing and optional Claude-powered analysis.


> ⚠️ **AUTHORIZED USE ONLY**
>
> This tool is for **authorized penetration testing and security research only.**
> You must have explicit written permission from the owner of any system you
> target before running dig_champs against it.
>
> Unauthorized use is illegal. The author accepts no liability for misuse.
> See [DISCLAIMER.md](./DISCLAIMER.md) and [LICENSE](./LICENSE) for full terms.
> 
---

## Table of Contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [Air-Gapped / Offline Deployment](#air-gapped--offline-deployment)
4. [Quick Start](#quick-start)
5. [Scan Modes](#scan-modes)
6. [The Sharingan Plan — Phase Architecture](#the-sharingan-plan--phase-architecture)
7. [Live Adapt Engine](#live-adapt-engine)
8. [All Flags Reference](#all-flags-reference)
9. [Session Persistence & Resume](#session-persistence--resume)
10. [Claude API Integration](#claude-api-integration)
11. [Output Files](#output-files)
12. [Credential Loot Files](#credential-loot-files)
13. [Security Notes](#security-notes)
14. [File Map](#file-map)

---

## Requirements

### System tools (must be on PATH)

| Tool | Required | Purpose |
| --- | --- | --- |
| `nmap` | Yes | Port scanning and service detection |
| `nikto` | Yes | Web server vulnerability scanning |
| `enum4linux` | Yes | SMB/NetBIOS enumeration |
| `whatweb` | Yes | Web technology fingerprinting |
| `dnsrecon` | Yes | DNS reconnaissance |
| `hydra` | Recommended | Network brute-force (cred phase) |
| `crackmapexec` | Recommended | SMB credential attacks |
| `searchsploit` | Recommended | Local exploit DB lookups |
| `gobuster` / `ffuf` / `feroxbuster` | Recommended | Web directory and vhost fuzzing |
| `sshpass` | Optional | SSH post-auth enum without stdin prompt |
| `smbclient` | Optional | SMB share listing |

Install on Kali:
```bash
sudo apt install nmap nikto enum4linux whatweb dnsrecon hydra crackmapexec smbclient sshpass exploitdb gobuster ffuf feroxbuster
```

### Python

Python 3.10 or higher required.

### Python packages

```bash
pip install requests rich anthropic
```

`anthropic` is optional. If not installed, all Claude features are silently disabled. `requests` and `rich` can also be omitted if you use the air-gapped deployment path below.

---

## Installation

```bash
git clone <repo>
cd dig_champs
pip install requests rich anthropic   # anthropic optional
python3 dig_champs.py -t <target>
```

---

## Air-Gapped / Offline Deployment

Dig Champs is designed to run on fully air-gapped engagement boxes with zero pip access. There are three tiers:

### Tier 1 — Standard (pip available)

```bash
pip install requests rich anthropic
python3 dig_champs.py -t <target>
```

### Tier 2 — Vendored (prep on connected machine, deploy air-gapped)

On your internet-connected prep machine:

```bash
python3 build_vendor.py
```

This downloads `requests`, `rich`, and `anthropic` into a `_vendor/` directory. Transfer the following to the target:

```
dig_champs.py
_vendor/          ← full real packages
_dc_http.py
_dc_rich.py
build_vendor.py   ← optional, for reference
```

The tool auto-detects `_vendor/` at startup and loads packages from it.

**Single-file option:** Pass `--pyz` to produce a single portable archive instead of a directory:

```bash
python3 build_vendor.py --pyz
# produces: dig_champs.pyz
python3 dig_champs.pyz -t <target>
```

### Tier 3 — Cold drop (no prep, no pip, no vendor)

If nothing is pre-installed, the tool automatically falls back to `_dc_http.py` and `_dc_rich.py` — stdlib-only companion stubs bundled alongside the script. Drop these three files and run:

```
dig_champs.py
_dc_http.py
_dc_rich.py
```

Output will be plain text instead of color/tables, but all scan functionality is fully intact.

### Offline mode flag

If the box has no outbound internet but is connected to your target network (the common engagement scenario), pass `--offline` to immediately suppress CVE database lookups and Claude API calls without waiting for timeouts:

```bash
python3 dig_champs.py -t 192.168.1.10 --offline
```

If `--offline` is not passed, the tool probes `8.8.8.8:53` at startup and sets offline mode automatically if unreachable.

---

## Quick Start

### Interactive mode (prompts for target and mode)

```bash
python3 dig_champs.py
```

### Argparse mode

```bash
# Basic recon + all phases, mode 2
python3 dig_champs.py -t 192.168.1.10 -m 2

# Stealth mode, skip creds and web fuzzing
python3 dig_champs.py -t 192.168.1.10 -m 1 --no-creds --no-webfuzz

# Aggressive scan with custom port list and loot file
python3 dig_champs.py -t 10.0.0.5 -m 3 --ports "1-65535" --loot creds.txt

# Full send — mode 4 requires explicit confirmation
python3 dig_champs.py -t 10.0.0.5 -m 4 --confirm-boss

# Air-gapped engagement
python3 dig_champs.py -t 172.16.0.1 -m 2 --offline
```

---

## Scan Modes

| Mode | Name | Behavior |
| --- | --- | --- |
| 1 | Ghost | Stealthy. Slow timing (`-T2`), minimal footprint. |
| 2 | Standard | Balanced speed and noise. Default for most engagements. |
| 3 | Aggressive | Faster scans, broader coverage, more requests. |
| 4 | BOSS | All guns. Requires `--confirm-boss`. Loud — use only when noise doesn't matter. |

Mode affects nmap timing flags, hydra thread counts, and tool aggressiveness across all phases.

---

## The Sharingan Plan — Phase Architecture

Dig Champs runs in four conceptual phases, automatically sequenced:

### Phase 1 — Looking (Recon)

Always runs first. Establishes the full picture of the target.

- **nmap** — port scan, service/version detection, OS fingerprinting, NSE scripts
- **nikto** — web server vuln scan (runs if HTTP/HTTPS detected)
- **whatweb** — web technology stack fingerprinting
- **enum4linux** — SMB/Samba share and user enumeration
- **dnsrecon** — DNS zone and record enumeration
- **searchsploit** — local exploit-db lookup against detected service versions

### Phase 2 — Looking Deeper

Targets services identified in Phase 1. Modules run based on what was found.

- **Credential attacks** (`creds`) — hydra/crackmapexec brute-force against FTP, SSH, RDP, SMB. Uses a built-in default credential list plus any user-supplied loot file. Cracked creds are automatically retried against HTTP ports.
- **High-value file hunt** (`filehunt`) — NSE script enumeration + smbclient recursive share listing for sensitive filenames (config files, backups, keys, etc.).
- **Web fuzzing** (`webfuzz`) — gobuster/ffuf/feroxbuster directory and vhost brute-force.

### Phase 3 — Predicting

Aggregates findings and applies intelligence.

- **Vuln report** (`vulnreport`) — queries NVD, MITRE CVE Program, OSV, and Go Vuln DB. Ranks discovered CVEs by CVSS score, attack vector, and exploitability.
- **Artifact analysis** (`artifacts`) — Claude-powered (requires API key): forensic artifact mapping per CVE, attacker/victim artifacts, IoC generation, kill-chain narrative.
- **Vuln probe** (`vulnprobe`) — nmap `--script vuln` confirmation pass against services where high-severity CVEs were found.

### Phase 4 — Live Adapting

After each phase, the Live Adapt Engine re-evaluates and reorders remaining phases dynamically (see below). Post-auth enumeration runs here when credentials have been cracked.

- **Post-auth enum** (`postauth`) — SSH shell enumeration (identity, kernel, sudo privs, SUID binaries, cron jobs, interesting files, network interfaces). FTP directory listing. Triggered automatically when cred phase produces hits.

---

## Live Adapt Engine

After the credential phase, the engine applies two layers of dynamic reordering:

**Tier 1 — Claude Strategic Advisor** (requires API key): Sends all current findings to Claude, which recommends an optimal remaining phase order based on discovered attack surface.

**Tier 2 — Rule-based micro-adjustment** (no API required): After every phase, rules fire to pull high-value phases forward:

| Rule trigger | Effect |
| --- | --- |
| Credentials cracked | `postauth` moves to front of remaining queue |
| SMB null session found | `filehunt` prioritized |
| High-severity CVEs found | `vulnprobe` pulled forward |
| Juicy web paths discovered | `webfuzz` prioritized |

Terminal phases (`vulnreport`, `artifacts`) are always pinned to the end regardless of reordering.

---

## All Flags Reference

| Flag | Default | Description |
| --- | --- | --- |
| `-t`, `--target` | — | Target IP or hostname (required, or prompted) |
| `-m`, `--mode` | — | Scan mode 1–4 (required, or prompted) |
| `--loot FILE` | — | Credential loot file, one `user:pass` per line |
| `--wordlist FILE` | — | Custom wordlist for web fuzzing |
| `--vuln-output FILE` | — | Save vuln report top-10 JSON to this path |
| `--ports PORTS` | pentest-wide list | Custom nmap port spec, e.g. `"1-65535"` or `"80,443,8080"` |
| `--exclude-ports PORTS` | — | Ports to exclude from nmap scan |
| `--inter-phase-delay SECS` | 0 | Seconds to sleep between phases (rate-limiting stealth) |
| `--confirm-boss` | — | Required to run mode 4 |
| `--offline` | auto-detect | Disable CVE DB + Claude API calls (safe for air-gapped) |
| `--resume PATH` | — | Resume from an existing session directory |
| `--no-creds` | — | Skip credential attack phase |
| `--no-artifacts` | — | Skip Claude artifact analysis |
| `--no-vulnreport` | — | Skip CVE vulnerability report |
| `--no-searchsploit` | — | Skip searchsploit lookups |
| `--no-filehunt` | — | Skip high-value file hunt |
| `--no-webfuzz` | — | Skip web directory/vhost fuzzing |
| `--no-postauth` | — | Skip post-auth SSH/FTP enumeration |
| `--no-vulnprobe` | — | Skip nmap vuln script confirmation pass |

---

## Session Persistence & Resume

Every run creates a session directory at:

```
~/.dc_sessions/<target>_<timestamp>/
```

Each phase writes a `.done_<phase>` marker when complete. If a run is interrupted, resume it with:

```bash
python3 dig_champs.py --resume ~/.dc_sessions/192.168.1.10_20260314_143022
```

Completed phases are skipped and their cached results are loaded. Only incomplete phases re-run. This means you can safely Ctrl-C and resume without repeating noisy scans.

Session directories are created with `700` permissions. Credential files within sessions are created with `600` permissions.

---

## Claude API Integration

Set your API key before running:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
python3 dig_champs.py -t <target>
```

Claude features (all optional, tool runs fully without them):

| Feature | When it runs | What it does |
| --- | --- | --- |
| Strategic Advisor | After creds phase | Recommends optimal phase execution order |
| Artifact Analysis | After vuln report | Per-CVE forensic artifacts, IoCs, kill-chain narrative |
| Human Narrative | End of scan | Converts machine trajectory log to readable pentest report |

If the API key is not set, or if `--offline` is active, or if the `anthropic` package is not installed, all three features are silently skipped. The tool does not exit or error.

---

## Output Files

All output lands in the session directory (`~/.dc_sessions/<target>_<ts>/`):

| File | Contents |
| --- | --- |
| `session.json` | Args and metadata for this run |
| `nmap.txt` / `nmap.xml` | Raw nmap output |
| `cred_results.json` | Cracked credentials (permissions: 600) |
| `trajectory.json` | Machine-readable scan event log |
| `trajectory_human.md` | Claude-generated (or template) narrative report |
| `trajectory_audit.json` | Cross-reference audit: findings vs narrative |
| `trajectory_audit.md` | Human-readable audit diff |
| Phase-specific `.txt` files | Raw tool output per phase |

A final JSON + Markdown report is also written to the home directory:

```
~/report_<target>_<timestamp>.json
~/report_<target>_<timestamp>.md
~/report_<target>_<timestamp>_narrative.md
```

---

## Credential Loot Files

Supply a wordlist of credentials to try during the cred phase:

```bash
python3 dig_champs.py -t <target> --loot my_creds.txt
```

Format — one credential pair per line:

```
admin:password
root:toor
service:service123
```

Loot file credentials are tried first, followed by the built-in default/common credential list. Duplicate pairs are deduplicated automatically.

---

## Security Notes

These apply when using the tool on an operator machine shared with others, or when logs are collected by a SIEM:

- **Credential display** — cracked passwords are shown as `[REDACTED]` in terminal output. Full credentials are stored only in `cred_results.json` (permissions: 600).
- **Subprocess credential passing** — passwords are never passed as command-line arguments. sshpass uses the `SSHPASS` environment variable (`-e` flag); smbclient uses the `PASSWD` environment variable; FTP curl calls use a temp `.netrc` file (600 permissions, deleted after use).
- **API key safety** — `ANTHROPIC_API_KEY` is read from the environment and never logged. Authentication errors from the Anthropic SDK print only the exception type, not the message body.
- **Session directory permissions** — `~/.dc_sessions/` and all session subdirectories are created with `700` permissions (explicit chmod to override process umask).

---

## File Map

| Path | Purpose |
| --- | --- |
| `dig_champs.py` | Main framework — all phases, entry point |
| `_dc_http.py` | stdlib drop-in for `requests` (air-gapped fallback) |
| `_dc_rich.py` | stdlib drop-in for `rich` (air-gapped fallback) |
| `build_vendor.py` | Pre-download deps into `_vendor/` for offline use |
| `wan_si_tong/` | Attack methodology library — 65+ techniques, OS routing, path designer, engagement tracker |
| `modules/dig_champs_mini.py` | Stage 1 only (recon, no creds/exploit) |
| `modules/dg_creds.py` | Standalone credential attack module |
| `modules/dg_artifacts.py` | Standalone CVE artifact analyzer |
| `modules/dg_vulnreport.py` | Standalone vuln ranking tool |
| `modules/dg_auditor.py` | Scan auditor (in development) |
