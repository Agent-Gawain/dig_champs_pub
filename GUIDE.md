# dig_champs — Step-by-Step Usage Guide

This guide walks you through a real engagement from zero to report.
For a flags reference, see [README.md](README.md).

---

## Step 0 — Prerequisites

Before your first run, confirm the required tools are on your PATH:

```bash
which nmap nikto enum4linux whatweb dnsrecon
```

Install any that are missing (Kali example):

```bash
sudo apt install nmap nikto enum4linux whatweb dnsrecon \
                 hydra crackmapexec smbclient sshpass \
                 exploitdb gobuster ffuf feroxbuster
```

Install Python dependencies:

```bash
pip install requests rich          # required
pip install anthropic              # optional — enables Claude features
```

If you're on an air-gapped engagement box with no pip access, see
[Air-gapped deployment](#air-gapped-deployment) at the bottom of this guide.

---

## Step 1 — Set Your API Key (optional)

Claude features (strategic advisor, artifact analysis, human narrative) require
an Anthropic API key. Skip this step if you don't have one — everything else
runs without it.

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

Add it to your `.bashrc` / `.zshrc` to persist it across sessions.

---

## Step 2 — Choose Your Entry Mode

### Option A — Interactive (recommended for first-timers)

```bash
python3 dig_champs.py
```

You'll see the banner, then an **AFK mode prompt**:

```
Run in AFK mode? All prompts use defaults and the scan runs unattended (y/n) [n]
(auto-default in 10s):
```

- Type `y` + Enter → scan runs fully unattended with all defaults. Good for
  leaving a scan running overnight.
- Type `n` + Enter (or wait 10 seconds) → you'll be walked through setup
  prompt by prompt. Each prompt times out in 30 seconds and accepts its default
  if you don't respond.

After the AFK prompt, you'll be asked for:

| Prompt | What to enter | Default |
|--------|---------------|---------|
| Target IP/domain | `192.168.1.10` | (none — required) |
| Mode [1-4] | `2` for most engagements | `2` |
| Run credential attack? | `y` / `n` | `y` |
| Loot file path | path to `user:pass` file, or blank | (none) |
| Run searchsploit? | `y` / `n` | `y` |
| Run vuln DB report? | `y` / `n` | `y` |
| Run artifact analysis? | `y` / `n` | `y` |
| Run file hunt? | `y` / `n` | `y` |
| Run web fuzzing? | `y` / `n` | `y` |
| Wordlist path | custom wordlist, or blank for built-in | (built-in) |
| Run post-auth enum? | `y` / `n` | `y` |
| Run vuln probe? | `y` / `n` | `y` |

### Option B — Flags only (recommended once you know what you want)

```bash
python3 dig_champs.py -t 192.168.1.10 -m 2
```

Passing `-t` and `-m` skips the interactive prompts entirely. Add `--no-*`
flags to skip specific phases.

---

## Step 3 — Pick a Mode

| Mode | Name | When to use |
|------|------|-------------|
| `1` | Ghost | IDS-aware engagements. Slow nmap timing (`-T2`), minimal footprint. |
| `2` | Standard | Most engagements. Balanced speed vs. noise. |
| `3` | Aggressive | Time-limited windows. Broader coverage, faster scans. |
| `4` | BOSS | Noise-doesn't-matter situations. Requires `--confirm-boss`. |

Rule of thumb: start at 2. If you need stealth, drop to 1. If you're working
against a target with no detection capability and a short window, use 3.

```bash
# Standard engagement
python3 dig_champs.py -t 10.0.0.5 -m 2

# Stealth engagement, longer inter-phase pauses
python3 dig_champs.py -t 10.0.0.5 -m 1 --inter-phase-delay 60

# Full send (explicit confirmation required)
python3 dig_champs.py -t 10.0.0.5 -m 4 --confirm-boss
```

---

## Step 4 — Watch the Scan Run

The scan executes in phases. You'll see live status as each one completes:

```
[+] Nmap…
[+] Web / SMB / DNS recon…
[+] Credential attacks…
[WST] Tier 0 path designed: OS=linux(0.82)  queue=[postauth, filehunt, webfuzz, vulnprobe, vulnreport, artifacts]
[~] Strategic advisor: analysing attack surface…
[+] Phase queue:  postauth  →  filehunt  →  webfuzz  →  vulnprobe  →  vulnreport  →  artifacts
```

The phase queue is dynamically reordered after the credential phase. What runs
next depends on what was found:

- Credentials cracked → `postauth` moves to the front
- SMB null session → `filehunt` is prioritized
- High-CVSS CVEs → `vulnprobe` is pulled forward
- Juicy web paths → `webfuzz` is boosted

After each phase completes, the Live Adapt Engine re-evaluates the remaining
queue. You may see lines like:

```
[~] Adapt: filehunt → [webfuzz, vulnprobe]  rules: cve_severity_critical
```

This means the queue was reordered mid-scan because new findings changed the
priority.

---

## Step 5 — Interrupted? Resume.

Press `Ctrl-C` at any point. The session is saved. Resume with:

```bash
python3 dig_champs.py --resume ~/.dc_sessions/192.168.1.10_20260314_143022
```

Each completed phase has a `.done_<phase>` marker. The scan picks up exactly
where it left off — completed phases are skipped and their cached results are
loaded.

To find the session directory path if you've lost it:

```bash
ls -lt ~/.dc_sessions/
```

The most recent directory is your last run.

---

## Step 6 — Read the Output

### Terminal summary

At scan end you'll see a ranked findings table in the terminal. CVEs, cracked
credentials, and high-value findings are highlighted.

### Session directory

All output lands in `~/.dc_sessions/<target>_<timestamp>/`:

| File | What's in it |
|------|--------------|
| `trajectory.json` | Machine-readable log of every event in the scan |
| `trajectory_human.md` | Narrative report (Claude-generated or template fallback) |
| `trajectory_audit.json` | Cross-reference: every finding mapped to narrative mentions |
| `trajectory_audit.md` | Human-readable audit diff |
| `cred_results.json` | Cracked credentials (permissions: 600) |
| `nmap.txt` / `nmap.xml` | Raw nmap output |
| `hvf_findings.json` | High-value file hunt results |
| `fuzz_findings.json` | Web fuzzing results |
| `probe_findings.json` | Vuln probe results |
| `artifact_findings.json` | Claude artifact analysis results |

### Home directory report

A summary is also written directly to your home directory:

```
~/report_<target>_<timestamp>.json    ← machine-readable findings
~/report_<target>_<timestamp>.md      ← formatted markdown report
~/report_<target>_<timestamp>_narrative.md  ← narrative (if Claude was used)
```

---

## Step 7 — Common Scenarios

### Recon only (no exploitation)

```bash
python3 dig_champs.py -t 192.168.1.10 -m 1 \
    --no-creds --no-filehunt --no-webfuzz --no-postauth --no-vulnprobe
```

Runs nmap, nikto, whatweb, enum4linux, dnsrecon, and searchsploit. Produces a
CVE report. No active exploitation attempts.

### Credential stuffing with a custom loot file

```bash
python3 dig_champs.py -t 192.168.1.10 -m 2 --loot /path/to/found_creds.txt
```

Loot file format — one `user:pass` per line:

```
admin:admin
root:toor
service:Welcome1
```

Loot file credentials are tried first, then the built-in default list.

### Web-focused engagement

```bash
python3 dig_champs.py -t 192.168.1.10 -m 2 \
    --no-creds --no-filehunt --no-postauth \
    --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

### AFK overnight run

```bash
python3 dig_champs.py -t 192.168.1.10 -m 2 --loot creds.txt
```

When the AFK prompt appears, type `y`. The full scan runs unattended with all
modules enabled and all phase-level prompts auto-accepted.

Alternatively, skip the interactive prompt entirely by providing all flags:

```bash
python3 dig_champs.py -t 192.168.1.10 -m 2 --loot creds.txt \
    --wordlist /path/to/wordlist.txt
```

### Custom port range

```bash
# Full port sweep
python3 dig_champs.py -t 192.168.1.10 -m 2 --ports "1-65535"

# Specific ports only
python3 dig_champs.py -t 192.168.1.10 -m 2 --ports "22,80,443,445,3306,8080,8443"

# Exclude noisy ports
python3 dig_champs.py -t 192.168.1.10 -m 2 --exclude-ports "135,137,138,139"
```

---

## Using wan_si_tong Standalone

wan_si_tong is the attack methodology library embedded in dig_champs. It also
runs as a standalone CLI for post-scan analysis and path planning.

### List all methodologies

```bash
python3 -m wan_si_tong --list
```

Output example:

```
Wan Si Tong — 65 methodologies registered

  [wsit_cms_attack]       CMS-Targeted Attack           (phase=vulnprobe, opsec=3/5, cat=web)
  [wsit_cred_extract]     Credential Extraction          (phase=postauth,  opsec=2/5, cat=privesc)
  [wsit_db_enum]          Database Service Enumeration   (phase=vulnprobe, opsec=3/5, cat=web)
  ...
```

### Score methodologies against a findings file

Pass a dig_champs JSON report and get ranked methodology suggestions:

```bash
python3 -m wan_si_tong \
    --findings ~/report_192.168.1.10_20260314_143022.json \
    --target 192.168.1.10 \
    --out suggestions.json
```

Output (top 5 printed to terminal, full list in `suggestions.json`):

```
Top suggestions for '192.168.1.10':
  [wsit_win_kerberoast]  Kerberoasting  score=0.91
  [wsit_smb_vuln_probe]  SMB Vuln Probe  score=0.88
  [wsit_win_lsass_dump]  LSASS Dump     score=0.81
  ...
```

### Run the Path Designer

Get a recommended phase queue for an existing report:

```bash
python3 -m wan_si_tong \
    --findings ~/report_192.168.1.10_20260314_143022.json \
    --design-path \
    --mode 2
```

Output:

```
Path Designer — mode 2 — recommended phase queue:
  1. postauth
  2. filehunt
  3. vulnprobe
  4. webfuzz
  5. vulnreport
  6. artifacts

[path_designer] mode=2  steps=12  queue=['postauth', 'filehunt', 'vulnprobe', ...]
   1. [wsit_win_kerberoast]  impact=0.923  opsec=7  triggers: service:smb, ...
   ...
```

### Filter by OS

```bash
python3 -m wan_si_tong \
    --findings ~/report_192.168.1.10_20260314_143022.json \
    --os windows \
    --design-path
```

### View engagement statistics

After multiple scans, check how each methodology has performed historically:

```bash
python3 -m wan_si_tong --tracker-report
```

Output:

```
Methodology                          Inv   Succ   Fail    Rate  Last Success
──────────────────────────────────────────────────────────────────────────────
wsit_win_kerberoast                    8      7      1   87.5%    2026-03-14
wsit_smb_filehunt                     12      9      3   75.0%    2026-03-15
wsit_cms_attack                        5      2      3   40.0%    2026-03-10
...
```

---

## Air-gapped Deployment

### Prep on your connected machine

```bash
python3 build_vendor.py
```

This creates `_vendor/` containing `requests`, `rich`, and `anthropic`.

### Transfer to the engagement box

```
dig_champs.py
_dc_http.py
_dc_rich.py
_vendor/
wan_si_tong/
dc_mind/
```

### Run — no pip needed

```bash
python3 dig_champs.py -t 192.168.1.10 -m 2 --offline
```

`--offline` disables CVE database lookups and Claude API calls immediately,
without waiting for network timeouts. The tool auto-detects no internet access
at startup and sets offline mode automatically if `--offline` isn't passed.

### Single-file portable archive

```bash
python3 build_vendor.py --pyz
python3 dig_champs.pyz -t 192.168.1.10 -m 2 --offline
```

---

## Prompt Timeout Reference

Every interactive prompt times out and auto-accepts its default:

| Prompt | Default | Timeout |
|--------|---------|---------|
| AFK mode? | `n` | 10 seconds |
| Target IP/domain | (none) | 30 seconds |
| Mode [1-4] | `2` | 30 seconds |
| All y/n module prompts | `y` | 30 seconds |
| Loot file / wordlist paths | (blank) | 30 seconds |

The timeout is printed inline with each prompt so you always know the clock is
running. To change the global timeout, edit `_PROMPT_TIMEOUT` near the top of
`dig_champs.py`.
