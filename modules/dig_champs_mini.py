#!/usr/bin/env python3
import subprocess, shutil, ipaddress, socket, os, json, re, tempfile, shlex
from datetime import datetime

BLOCKED = {"127.0.0.1","0.0.0.0","255.255.255.255","::1","localhost"}
def ok(t):
    if t in BLOCKED: print("[!] Refusing to scan loopback/broadcast."); return None
    try:
        a = ipaddress.ip_address(t)
        if a.is_loopback or a.is_unspecified or a.is_multicast: print("[!] Refusing to scan loopback/broadcast."); return None
        return t
    except ValueError: pass
    try:
        resolved = socket.gethostbyname(t)
        a = ipaddress.ip_address(resolved)
        if a.is_loopback or a.is_unspecified or a.is_multicast: print("[!] Refusing to scan loopback/broadcast."); return None
        if a.is_private: print(f"[!] Warning: {t} resolves to private IP {resolved} — proceeding with IP.")
        return resolved
    except socket.error: return None
def need(tool):
    if not shutil.which(tool): print(f"[!] {tool} missing"); exit(1)
def read(path):
    if not os.path.exists(path): print(f"[!] No output: {path}"); return ""
    if os.path.getsize(path) > 10 * 1024 * 1024: print(f"[!] Output suspiciously large, truncating: {path}")
    return open(path, errors="ignore").read(10 * 1024 * 1024)
def sanitize(s): return re.sub(r"[^\w\s\-\./]", "", str(s))[:80]
def run(args, out, timeout=3600):
    print(f"[+] {' '.join(args)}")
    with open(out,"w") as f:
        r = subprocess.run(args, stdout=f, stderr=subprocess.DEVNULL, text=True, timeout=timeout)
    return r.returncode == 0

def nmap_scan(target, mode, tmpdir):
    flags = {1:["-T1","-f","--data-length","25"], 2:["-T2","-f"], 3:["-T4"], 4:["-T5","--min-rate","1000"]}[mode]
    out = os.path.join(tmpdir,"nmap.txt")
    run(["nmap","-sV","-O"]+flags+["-oN",out,target])
    return read(out)

def nikto_scan(target, mode, tmpdir):
    flags = {1:["-Delay","5","-evasion","1"], 2:["-Delay","2"], 3:[], 4:["-Delay","0"]}[mode]
    out = os.path.join(tmpdir,"nikto.txt")
    run(["nikto","-h",target]+flags, out)
    return read(out)

def enum_scan(target, tmpdir):
    out = os.path.join(tmpdir,"enum.txt")
    run(["enum4linux","-a",target], out, timeout=900)
    return read(out)

def whatweb_scan(target, tmpdir):
    out = os.path.join(tmpdir,"whatweb.txt")
    run(["whatweb","--no-errors","-a","3",target], out)
    return read(out)

def dnsrecon_scan(target, tmpdir):
    out = os.path.join(tmpdir,"dnsrecon.txt")
    run(["dnsrecon","-d",target,"-t","std"], out)
    return read(out)

def parse(nmap, nikto, enum4, whatweb='', dns=''):
    findings = []
    for line in nmap.splitlines():
        m = re.search(r"(\d+)/(tcp|udp)\s+open\s+(\S+)", line)
        if m: findings.append({"port":m[1],"proto":m[2],"service":m[3],"src":"nmap"})
    for line in nikto.splitlines():
        c = re.search(r"(CVE-\d+-\d+)", line)
        if c: findings.append({"cve":c[1],"evidence":line.strip(),"src":"nikto"})
        if "outdated" in line.lower(): findings.append({"issue":"outdated software","evidence":line.strip(),"src":"nikto"})
        for s in [".env",".git","id_rsa",".bak","backup","admin","wp-admin"]:
            if s in line.lower(): findings.append({"juicy":s,"evidence":line.strip(),"src":"nikto"}); break
    for line in whatweb.splitlines():
        for kw in ["cms","wordpress","joomla","drupal","jquery","bootstrap","php","apache","nginx","iis"]:
            if kw in line.lower(): findings.append({"tech":kw,"evidence":line.strip(),"src":"whatweb"}); break
    for line in dns.splitlines():
        for kw in ["zone transfer","axfr","a ","cname","mx ","txt "]:
            if kw in line.lower(): findings.append({"dns":kw.strip(),"evidence":line.strip(),"src":"dnsrecon"}); break
    if "anonymous login successful" in enum4.lower():
        findings.append({"issue":"SMB null session","src":"enum4linux"})
    for u in re.findall(r"user:\[(.*?)\]", enum4):
        findings.append({"user":u,"src":"enum4linux"})
    return findings

def run_searchsploit(findings):
    queries = set()
    for f in findings:
        if "cve"     in f: queries.add(sanitize(f["cve"]))
        if "service" in f: queries.add(sanitize(f["service"]))
        if "issue"   in f: queries.add(sanitize(f["issue"]))
    if not queries: return print("[~] No searchsploit queries found.")
    for q in queries:
        print(f"\n[+] searchsploit {q}")
        r = subprocess.run(["searchsploit", q], capture_output=True, text=True)
        print(r.stdout if r.stdout.strip() else "  (no results)")

def report(findings, target):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fn = os.path.join(os.path.expanduser("~"), f"report_{target}_{ts}.json")
    with open(fn,"w") as f: json.dump({"target":target,"findings":findings}, f, indent=2)
    print(f"[+] {len(findings)} findings → {fn}")

def main():
    raw = input("Target IP/domain: ").strip()
    target = ok(raw)
    if not target: return print("[!] Invalid target")
    use_ss = input("Run searchsploit on findings? (y/n): ").strip().lower() == "y"
    if use_ss: need("searchsploit")
    for t in ["nmap","nikto","enum4linux","whatweb","dnsrecon"]: need(t)
    print("\n1=Ghost  2=Sneaky  3=YOLO  4=BOSS")
    try: mode = int(input("Mode [1-4]: ").strip())
    except ValueError: return print("[!] Invalid mode")
    if mode not in range(1,5): return print("[!] Invalid mode")
    if mode == 4 and input("Type CONFIRM to use BOSS mode: ") != "CONFIRM": return print("Cancelled.")
    with tempfile.TemporaryDirectory() as tmp:
        os.chmod(tmp, 0o700)
        print("\n[+] Nmap..."); nmap   = nmap_scan(target, mode, tmp)
        http = any(s in nmap for s in ["http","https","nginx","apache","iis"])
        smb  = any(s in nmap for s in ["microsoft-ds","netbios","445","139"])
        nikto   = nikto_scan(target, mode, tmp) if http else (print("[~] No HTTP, skipping Nikto") or "")
        whatweb = whatweb_scan(target, tmp)     if http else (print("[~] No HTTP, skipping WhatWeb") or "")
        enum4   = enum_scan(target, tmp)        if smb  else (print("[~] No SMB, skipping enum4linux") or "")
        dns     = dnsrecon_scan(target, tmp)
        findings = parse(nmap, nikto, enum4, whatweb, dns)
        report(findings, target)

if __name__ == "__main__": main()
