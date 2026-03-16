#!/usr/bin/env python3
"""
dc_vulnreport.py — Windows host companion to dig_champs_mini
Reads a .json report from the Kali VM shared folder, queries NVD, CVE Program,
CVE Details, OSV, and Go Vuln DB for each finding, then outputs a ranked top-10.

Requirements:
    pip install requests rich
"""

import argparse, json, os, sys, time
from pathlib import Path

try:
    import requests
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
except ImportError:
    sys.exit("[!] Missing deps — run: pip install requests rich")

console = Console()

# ── Severity → numeric score (for sorting) ──────────────────────────────────
SEV_SCORE = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}

# ── Ease-of-exploitation heuristics from CVSS fields ─────────────────────────
def ease_score(cvss: dict) -> int:
    """
    Returns 0-3 (higher = easier to exploit).
    Uses attackVector, attackComplexity, privilegesRequired, userInteraction
    from CVSS v3.x metrics where available.
    """
    score = 0
    av  = cvss.get("attackVector", "")
    ac  = cvss.get("attackComplexity", "")
    pr  = cvss.get("privilegesRequired", "")
    ui  = cvss.get("userInteraction", "")
    if av  in ("NETWORK",):          score += 1
    if ac  in ("LOW",):              score += 1
    if pr  in ("NONE", "LOW"):       score += 1
    if ui  in ("NONE",):             score += 0  # already baked into CVSS base
    return score

# ── Helpers ──────────────────────────────────────────────────────────────────
def get(url, params=None, retries=3, delay=1.5) -> dict | list | None:
    for attempt in range(retries):
        try:
            r = requests.get(url, params=params, timeout=12,
                             headers={"User-Agent": "dc_vulnreport/1.0"})
            if r.status_code == 429:
                time.sleep(delay * (attempt + 1))
                continue
            r.raise_for_status()
            return r.json()
        except Exception as e:
            if attempt == retries - 1:
                console.print(f"[dim]  ↳ request failed ({url}): {e}[/dim]")
    return None

def cvss_fields(metrics: dict) -> dict:
    """Pull the highest-version CVSS v3 metrics available."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            return {
                "baseScore":         data.get("baseScore"),
                "baseSeverity":      data.get("baseSeverity", "UNKNOWN").upper(),
                "attackVector":      data.get("attackVector", ""),
                "attackComplexity":  data.get("attackComplexity", ""),
                "privilegesRequired":data.get("privilegesRequired", ""),
                "userInteraction":   data.get("userInteraction", ""),
            }
    # fallback to v2
    for entry in metrics.get("cvssMetricV2", []):
        data = entry.get("cvssData", {})
        sev = entry.get("baseSeverity", "UNKNOWN").upper()
        return {"baseScore": data.get("baseScore"), "baseSeverity": sev,
                "attackVector": data.get("accessVector",""),
                "attackComplexity": data.get("accessComplexity",""),
                "privilegesRequired": data.get("authentication",""),
                "userInteraction": ""}
    return {"baseScore": None, "baseSeverity": "UNKNOWN",
            "attackVector":"","attackComplexity":"","privilegesRequired":"","userInteraction":""}

# ── Source queries ────────────────────────────────────────────────────────────

def query_nvd(keyword: str) -> list[dict]:
    data = get("https://services.nvd.nist.gov/rest/json/cves/2.0",
               params={"keywordSearch": keyword, "resultsPerPage": 5})
    if not data:
        return []
    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        desc = next((d["value"] for d in cve.get("descriptions", [])
                     if d.get("lang") == "en"), "")
        fields = cvss_fields(cve.get("metrics", {}))
        results.append({**fields, "cve_id": cve_id, "desc": desc[:200],
                         "source": "NVD", "keyword": keyword})
    return results

def query_cve_program(cve_id: str) -> dict | None:
    """Direct CVE Program API lookup for a known CVE ID."""
    data = get(f"https://cveawg.mitre.org/api/cve/{cve_id}")
    if not data:
        return None
    containers = data.get("containers", {}).get("cna", {})
    desc = next((d["value"] for d in containers.get("descriptions", [])
                 if d.get("lang", "").startswith("en")), "")
    return {"cve_id": cve_id, "desc": desc[:200], "source": "CVE Program",
            "keyword": cve_id, "baseScore": None, "baseSeverity": "UNKNOWN",
            "attackVector":"","attackComplexity":"","privilegesRequired":"","userInteraction":""}

def query_cve_details(keyword: str) -> list[dict]:
    """
    CVE Details doesn't have an open JSON API, so we use NVD with a keyword
    filter that mimics what CVE Details surfaces, then tag the source.
    (A full scrape would require Selenium and violates ToS in bulk.)
    """
    results = query_nvd(keyword)
    for r in results:
        r["source"] = "CVE Details (via NVD)"
    return results

def query_osv(keyword: str) -> list[dict]:
    payload = {"query": keyword, "pageSize": 5}
    data = get("https://api.osv.dev/v1/querybatch",
               # OSV query endpoint uses POST; fall back to GET search
               )
    # OSV v1 search is POST-based; do it properly:
    try:
        r = requests.post("https://api.osv.dev/v1/query",
                          json={"query": {"package": {"name": keyword}}},
                          timeout=10,
                          headers={"User-Agent": "dc_vulnreport/1.0"})
        r.raise_for_status()
        vulns = r.json().get("vulns", [])
    except Exception:
        vulns = []
    results = []
    for v in vulns[:5]:
        sev_list = v.get("severity", [])
        score_str = sev_list[0].get("score", "") if sev_list else ""
        # OSV severity scores may be CVSS strings like "CVSS:3.1/AV:N/..."
        base_score = None
        sev_label = "UNKNOWN"
        if score_str.startswith("CVSS"):
            parts = {kv.split(":")[0]: kv.split(":")[1]
                     for kv in score_str.split("/")[1:] if ":" in kv}
            try:
                # Not always present; skip gracefully
                pass
            except Exception:
                pass
        results.append({
            "cve_id": v.get("id", ""),
            "desc": (v.get("summary") or v.get("details", ""))[:200],
            "source": "OSV",
            "keyword": keyword,
            "baseScore": base_score,
            "baseSeverity": sev_label,
            "attackVector": "",
            "attackComplexity": "",
            "privilegesRequired": "",
            "userInteraction": "",
        })
    return results

def query_govuln(keyword: str) -> list[dict]:
    """Go Vulnerability Database — only useful for Go-related services."""
    try:
        r = requests.get("https://vuln.go.dev/index/vulns.json", timeout=10,
                         headers={"User-Agent": "dc_vulnreport/1.0"})
        r.raise_for_status()
        all_vulns = r.json()
    except Exception:
        return []
    kw = keyword.lower()
    results = []
    for v in all_vulns:
        vid = v.get("id","")
        if kw in vid.lower() or kw in v.get("aliases",[""])[0].lower() if v.get("aliases") else False:
            results.append({
                "cve_id": vid,
                "desc": "",
                "source": "Go Vuln DB",
                "keyword": keyword,
                "baseScore": None,
                "baseSeverity": "UNKNOWN",
                "attackVector": "",
                "attackComplexity": "",
                "privilegesRequired": "",
                "userInteraction": "",
            })
            if len(results) >= 3:
                break
    return results

# ── Dedup + rank ──────────────────────────────────────────────────────────────

def dedup(vulns: list[dict]) -> list[dict]:
    seen = {}
    for v in vulns:
        key = v["cve_id"] or f"{v['source']}:{v['keyword']}"
        if key not in seen:
            seen[key] = v
        else:
            # Prefer entry with actual score data
            if seen[key]["baseScore"] is None and v["baseScore"] is not None:
                seen[key] = v
    return list(seen.values())

def rank(vulns: list[dict]) -> list[dict]:
    def sort_key(v):
        sev  = SEV_SCORE.get(v.get("baseSeverity","UNKNOWN"), 0)
        ease = ease_score(v)
        score = float(v["baseScore"]) if v.get("baseScore") else 0.0
        return (sev, ease, score)
    return sorted(vulns, key=sort_key, reverse=True)

# ── Main ──────────────────────────────────────────────────────────────────────

def load_report(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        sys.exit(f"[!] File not found: {path}")
    return json.loads(p.read_text(encoding="utf-8"))

def extract_keywords(findings: list[dict]) -> list[str]:
    kws = set()
    for f in findings:
        if "cve"     in f: kws.add(f["cve"])
        if "service" in f: kws.add(f["service"])
        if "tech"    in f: kws.add(f["tech"])
        if "issue"   in f: kws.add(f["issue"])
    return [k for k in kws if k]

def query_all(keywords: list[str], known_cves: list[str]) -> list[dict]:
    all_vulns = []
    sources = [
        ("NVD",          lambda kw: query_nvd(kw)),
        ("CVE Details",  lambda kw: query_cve_details(kw)),
        ("OSV",          lambda kw: query_osv(kw)),
        ("Go Vuln DB",   lambda kw: query_govuln(kw)),
    ]

    with console.status("[bold cyan]Querying vulnerability databases…"):
        # Direct CVE lookups via CVE Program API
        for cve_id in known_cves:
            result = query_cve_program(cve_id)
            if result:
                all_vulns.append(result)
                # Also enrich via NVD
                all_vulns.extend(query_nvd(cve_id))
            time.sleep(0.4)   # respect rate limits

        # Keyword-based lookups
        for kw in keywords:
            for src_name, fn in sources:
                console.print(f"  [dim]→ {src_name}: {kw}[/dim]")
                all_vulns.extend(fn(kw))
                time.sleep(0.3)

    return all_vulns

def print_report(top10: list[dict], target: str, output_path: str | None):
    sev_color = {"CRITICAL":"bold red","HIGH":"red","MEDIUM":"yellow",
                 "LOW":"green","UNKNOWN":"dim","NONE":"dim"}

    console.print(Panel(
        f"[bold white]TARGET:[/bold white] [cyan]{target}[/cyan]\n"
        f"[bold white]TOP-10 VULNERABILITIES[/bold white] — ranked by severity then exploitability",
        title="[bold red]◈ DC VULN REPORT ◈[/bold red]",
        border_style="red",
    ))

    table = Table(box=box.SIMPLE_HEAD, show_lines=True, expand=True)
    table.add_column("#",       style="bold", width=3)
    table.add_column("CVE / ID",             width=20)
    table.add_column("Severity",             width=10)
    table.add_column("CVSS",                 width=6)
    table.add_column("Ease",                 width=6)
    table.add_column("Source",               width=14)
    table.add_column("Description",          ratio=1)

    for i, v in enumerate(top10, 1):
        sev   = v.get("baseSeverity","UNKNOWN")
        score = f"{v['baseScore']:.1f}" if v.get("baseScore") else "—"
        ease  = "★" * ease_score(v) or "—"
        col   = sev_color.get(sev, "white")
        table.add_row(
            str(i),
            v.get("cve_id","—"),
            f"[{col}]{sev}[/{col}]",
            score,
            ease,
            v.get("source","—"),
            v.get("desc","—"),
        )

    console.print(table)

    if output_path:
        out = [
            {k: v[k] for k in ("cve_id","baseSeverity","baseScore","source","keyword","desc")}
            for v in top10
        ]
        Path(output_path).write_text(json.dumps({"target": target, "top10": out}, indent=2))
        console.print(f"\n[green]✓ JSON report saved → {output_path}[/green]")

def main():
    ap = argparse.ArgumentParser(
        description="Windows host vuln lookup companion for dig_champs_mini")
    ap.add_argument("report",         help="Path to dig_champs_mini JSON report")
    ap.add_argument("-o","--output",  help="Save top-10 as JSON to this path", default=None)
    args = ap.parse_args()

    data     = load_report(args.report)
    target   = data.get("target", "unknown")
    findings = data.get("findings", [])

    if not findings:
        sys.exit("[!] No findings in report.")

    known_cves = [f["cve"] for f in findings if "cve" in f]
    keywords   = extract_keywords(findings)

    console.print(f"[bold]Loaded report for[/bold] [cyan]{target}[/cyan] "
                  f"— {len(findings)} findings, {len(known_cves)} CVEs, {len(keywords)} keywords")

    raw_vulns = query_all(keywords, known_cves)
    unique    = dedup(raw_vulns)
    ranked    = rank(unique)
    top10     = ranked[:10]

    if not top10:
        console.print("[yellow]No vulnerabilities found across all sources.[/yellow]")
        return

    print_report(top10, target, args.output)

if __name__ == "__main__":
    main()
