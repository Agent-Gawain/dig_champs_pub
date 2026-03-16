#!/usr/bin/env python3
"""
dc_artifacts.py — Post-exploitation artifact awareness tool
Given a CVE ID, looks up the vulnerability, then uses Claude to reason about
the most common forensic artifacts that would betray its use on a target host.

Requirements:
    pip install requests rich anthropic
"""

import sys, os, time, json
import requests

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    import anthropic
except ImportError:
    sys.exit("[!] Missing deps — run: pip install requests rich anthropic")

console = Console()
client  = anthropic.Anthropic()   # reads ANTHROPIC_API_KEY from env

# ── CVE lookup (NVD) ──────────────────────────────────────────────────────────

def fetch_cve(cve_id: str) -> dict | None:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    try:
        r = requests.get(url, params={"cveId": cve_id}, timeout=12,
                         headers={"User-Agent": "dc_artifacts/1.0"})
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        if not vulns:
            return None
        cve = vulns[0]["cve"]
        desc = next((d["value"] for d in cve.get("descriptions", [])
                     if d.get("lang") == "en"), "No description available.")
        metrics = cve.get("metrics", {})
        cvss = {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                data = entries[0].get("cvssData", {})
                cvss = {
                    "version":   data.get("version",""),
                    "baseScore": data.get("baseScore"),
                    "severity":  entries[0].get("baseSeverity") or data.get("baseSeverity",""),
                    "vector":    data.get("vectorString",""),
                    "attackVector": data.get("attackVector") or data.get("accessVector",""),
                    "attackComplexity": data.get("attackComplexity") or data.get("accessComplexity",""),
                    "privilegesRequired": data.get("privilegesRequired") or data.get("authentication",""),
                    "userInteraction": data.get("userInteraction",""),
                    "scope": data.get("scope",""),
                    "confidentialityImpact": data.get("confidentialityImpact",""),
                    "integrityImpact": data.get("integrityImpact",""),
                    "availabilityImpact": data.get("availabilityImpact",""),
                }
                break
        refs = [r["url"] for r in cve.get("references", [])[:5]]
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
            "published":   cve.get("published",""),
        }
    except Exception as e:
        console.print(f"[red]NVD lookup failed: {e}[/red]")
        return None

# ── Claude artifact analysis ──────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a senior red team operator and forensic analyst.
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
Limit victim_artifacts and attacker_artifacts to the 6 most impactful each.
"""

def analyze_artifacts(cve_data: dict) -> dict | None:
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

    with console.status("[bold cyan]Asking Claude to reason about artifacts…[/bold cyan]"):
        try:
            msg = client.messages.create(
                model="claude-opus-4-6",
                max_tokens=2048,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = msg.content[0].text.strip()
            raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            return json.loads(raw)
        except json.JSONDecodeError as e:
            console.print(f"[red]Failed to parse Claude response as JSON: {e}[/red]")
            console.print(f"[dim]{raw[:500]}[/dim]")
            return None
        except Exception as e:
            console.print(f"[red]Claude API error: {e}[/red]")
            return None

# ── Display ───────────────────────────────────────────────────────────────────

TYPE_COLOR = {
    "log": "yellow", "file": "cyan", "registry": "magenta",
    "memory": "red", "network": "blue", "process": "green",
}

def print_cve_header(cve: dict):
    sev = cve["cvss"].get("severity","?")
    score = cve["cvss"].get("baseScore","?")
    sev_color = {"CRITICAL":"bold red","HIGH":"red","MEDIUM":"yellow","LOW":"green"}.get(sev,"white")
    console.print(Panel(
        f"[bold white]{cve['id']}[/bold white]  [{sev_color}]{sev} {score}[/{sev_color}]\n\n"
        f"[white]{cve['description']}[/white]\n\n"
        f"[dim]Vector: {cve['cvss'].get('vector','—')}[/dim]",
        title="[bold red]◈ CVE DETAILS ◈[/bold red]",
        border_style="red",
    ))

def print_artifacts(analysis: dict, cve_id: str):
    console.print(Panel(
        f"[bold white]Exploit class:[/bold white] [cyan]{analysis.get('exploit_class','—')}[/cyan]\n"
        f"[bold white]Attack phases:[/bold white] {' → '.join(analysis.get('attack_phases',[]))}",
        title="[bold red]◈ EXPLOIT PROFILE ◈[/bold red]",
        border_style="red",
    ))

    for section, key in [("VICTIM ARTIFACTS", "victim_artifacts"),
                          ("ATTACKER ARTIFACTS", "attacker_artifacts")]:
        items = analysis.get(key, [])
        if not items:
            continue
        t = Table(title=f"[bold red]{section}[/bold red]",
                  box=box.SIMPLE_HEAD, show_lines=True, expand=True)
        t.add_column("Type",     width=10)
        t.add_column("OS",       width=8)
        t.add_column("Artifact", width=28)
        t.add_column("Detail",   ratio=1)
        t.add_column("Evasion",  ratio=1)
        for item in items:
            typ = item.get("type","")
            col = TYPE_COLOR.get(typ, "white")
            t.add_row(
                f"[{col}]{typ}[/{col}]",
                item.get("os","—"),
                f"[bold]{item.get('artifact','—')}[/bold]",
                item.get("detail","—"),
                f"[dim]{item.get('evasion_tip','—')}[/dim]",
            )
        console.print(t)

    iocs = analysis.get("iocs", [])
    if iocs:
        t2 = Table(title="[bold red]INDICATORS OF COMPROMISE[/bold red]",
                   box=box.SIMPLE_HEAD, expand=True)
        t2.add_column("IOC")
        for ioc in iocs:
            t2.add_row(ioc)
        console.print(t2)

    tools = analysis.get("detection_tools", [])
    if tools:
        console.print(f"\n[bold white]Detection tools:[/bold white] "
                      + "  ".join(f"[cyan]{t}[/cyan]" for t in tools))

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    console.print(Panel(
        "[bold white]Post-exploitation artifact awareness[/bold white]\n"
        "[dim]Looks up a CVE and prints the forensic artifacts that betray its use[/dim]",
        title="[bold red]◈ DC ARTIFACTS ◈[/bold red]",
        border_style="red",
    ))

    cve_id = input("\nEnter CVE ID (e.g. CVE-2021-44228): ").strip().upper()
    if not cve_id.startswith("CVE-"):
        cve_id = "CVE-" + cve_id

    with console.status(f"[bold cyan]Fetching {cve_id} from NVD…[/bold cyan]"):
        cve_data = fetch_cve(cve_id)

    if not cve_data:
        console.print(f"[red]Could not retrieve data for {cve_id}. "
                       "Check the ID and try again.[/red]")
        return

    print_cve_header(cve_data)

    analysis = analyze_artifacts(cve_data)
    if not analysis:
        console.print("[red]Artifact analysis failed.[/red]")
        return

    print_artifacts(analysis, cve_id)

if __name__ == "__main__":
    main()
