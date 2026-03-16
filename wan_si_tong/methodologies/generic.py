"""
methodologies/generic.py — OS-agnostic attack methodologies.

These 24 entries cover recon, credential attacks, web exploitation, SMB,
post-exploitation, privilege escalation, and network service probing.
They are registered with os_tags=["any"] so they surface regardless of
which OS the router detects.

All entries are migrated verbatim from the original wan_si_tong.py monolith.
"""

from wan_si_tong.registry import MethodologyRegistry
from wan_si_tong.schema import Methodology

_R = MethodologyRegistry.get()

# ── Recon ─────────────────────────────────────────────────────────────────────

_R.register(Methodology(
    id="wsit_port_enum",
    name="Port & Service Enumeration",
    category="recon",
    phase="looking",
    triggers=["always"],
    mitre=["T1046"],
    prerequisites=["network_access"],
    tools=["nmap"],
    description=(
        "Full TCP/UDP port scan to enumerate running services, versions, "
        "and OS fingerprint. Foundation for all subsequent phases. "
        "Version detection (-sV) reveals exact daemon versions for CVE matching."
    ),
    opsec_level=2,
    expected_findings=["port", "service", "version", "os_guess"],
    next_ids=["wsit_web_recon", "wsit_smb_enum", "wsit_ssh_spray", "wsit_ftp_anon"],
), os_tags=["any"])

_R.register(Methodology(
    id="wsit_web_recon",
    name="Web Technology Fingerprinting",
    category="recon",
    phase="looking",
    triggers=["port:80", "port:443", "port:8080", "port:8443", "service:http", "service:https"],
    mitre=["T1592.002", "T1595.003"],
    prerequisites=["port:http_or_https"],
    tools=["whatweb", "nikto", "curl"],
    description=(
        "Identify web framework, CMS, server software, and juicy paths. "
        "WhatWeb fingerprints headers and HTML. Nikto probes for misconfigurations, "
        "exposed admin panels, outdated software, and default files. "
        "Juicy paths (.env, .git, /admin) indicate deeper attack surface."
    ),
    opsec_level=2,
    expected_findings=["tech", "issue", "juicy", "cve"],
    next_ids=["wsit_web_fuzz", "wsit_cms_attack", "wsit_sqli_probe"],
    detection_notes="Nikto is extremely noisy. WhatWeb is passive but detectable via user-agent.",
), os_tags=["any"])

_R.register(Methodology(
    id="wsit_smb_enum",
    name="SMB Null Session Enumeration",
    category="smb",
    phase="looking",
    triggers=["port:445", "port:139", "service:microsoft-ds", "service:netbios"],
    mitre=["T1135", "T1087.002"],
    prerequisites=["port:smb"],
    tools=["enum4linux", "smbclient", "crackmapexec"],
    description=(
        "Enumerate SMB shares, users, groups, and policies via null session. "
        "Null sessions (unauthenticated) can expose share listings, user accounts, "
        "password policies, and domain info. Cracked credentials expand access "
        "to admin shares (C$, ADMIN$, IPC$) and full file system enumeration."
    ),
    opsec_level=2,
    expected_findings=["user", "issue"],
    next_ids=["wsit_smb_filehunt", "wsit_smb_spray", "wsit_smb_vuln_probe"],
    detection_notes="Null session attempts logged in Windows Event ID 4624 (anonymous logon).",
), os_tags=["any"])

_R.register(Methodology(
    id="wsit_dns_recon",
    name="DNS Enumeration & Zone Transfer",
    category="recon",
    phase="looking",
    triggers=["port:53", "service:dns", "always"],
    mitre=["T1590.002"],
    prerequisites=["network_access"],
    tools=["dnsrecon", "dig", "nmap"],
    description=(
        "Enumerate DNS records (A, MX, TXT, SRV, NS), attempt zone transfers, "
        "and brute-force subdomains. TXT records often leak internal hostnames, "
        "mail server config, and SPF/DKIM data. Zone transfers expose full "
        "internal DNS topology when misconfigured."
    ),
    opsec_level=3,
    expected_findings=["dns"],
    next_ids=["wsit_vhost_fuzz", "wsit_web_recon"],
), os_tags=["any"])

# ── Credential Attacks ────────────────────────────────────────────────────────

_R.register(Methodology(
    id="wsit_ssh_spray",
    name="SSH Credential Spraying",
    category="credential",
    phase="looking_deeper",
    triggers=["port:22", "service:ssh"],
    mitre=["T1110.003"],
    prerequisites=["port:22"],
    tools=["hydra", "crackmapexec", "medusa"],
    description=(
        "Low-rate credential spray against SSH using common username/password "
        "combinations. Lockout detection essential — rate-limit to 1 attempt/5s. "
        "If successful, postauth SSH enumeration reveals privilege level, "
        "shadow file, sudo config, and SUID binaries."
    ),
    opsec_level=2,
    expected_findings=["cred"],
    next_ids=["wsit_ssh_postauth", "wsit_privesc_sudo", "wsit_privesc_suid"],
    detection_notes=(
        "Failed SSH logins: /var/log/auth.log, Event ID 4625. "
        "Rapid failures trigger fail2ban."
    ),
), os_tags=["any"])

_R.register(Methodology(
    id="wsit_ftp_anon",
    name="FTP Anonymous + Credential Access",
    category="credential",
    phase="looking_deeper",
    triggers=["port:21", "service:ftp"],
    mitre=["T1078.001", "T1110"],
    prerequisites=["port:21"],
    tools=["hydra", "ftp", "nmap-nse"],
    description=(
        "Probe FTP for anonymous login first (ftp-anon NSE). If blocked, "
        "spray common FTP credentials. Anonymous access may expose config files, "
        "backups, and web root content depending on server configuration. "
        "Cracked credentials should be reused against SMB and HTTP."
    ),
    opsec_level=3,
    expected_findings=["cred", "hvf_path"],
    next_ids=["wsit_ftp_filehunt", "wsit_cred_reuse"],
    detection_notes="Anonymous FTP logged at info level; brute force triggers ProFTPD/vsftpd rate limits.",
), os_tags=["any"])

_R.register(Methodology(
    id="wsit_smb_spray",
    name="SMB Credential Spraying (CrackMapExec)",
    category="credential",
    phase="looking_deeper",
    triggers=["port:445", "issue:SMB null session", "user:*"],
    mitre=["T1110.003", "T1021.002"],
    prerequisites=["port:445"],
    tools=["crackmapexec", "hydra"],
    description=(
        "Spray enumerated usernames (from null session or enum4linux) against "
        "SMB with common passwords. A single valid credential grants share access "
        "and can enable Pass-the-Hash or lateral movement. "
        "Password policy from null session guides attempt count before lockout."
    ),
    opsec_level=2,
    expected_findings=["cred"],
    next_ids=["wsit_smb_filehunt", "wsit_cred_reuse"],
    detection_notes=(
        "Event ID 4625 per failed attempt; 4648 for explicit credential use. "
        "High volume triggers ATA/Defender Identity alerts."
    ),
), os_tags=["any"])

_R.register(Methodology(
    id="wsit_rdp_spray",
    name="RDP Credential Spraying",
    category="credential",
    phase="looking_deeper",
    triggers=["port:3389", "service:rdp", "service:ms-wbt-server"],
    mitre=["T1110.003"],
    prerequisites=["port:3389"],
    tools=["hydra", "crowbar", "ncrack"],
    description=(
        "Spray RDP (port 3389) with common credentials. RDP access gives "
        "full graphical session as the compromised user. Network Level Auth (NLA) "
        "must be bypassed or pre-auth exploitation attempted if present. "
        "CVE-2019-0708 (BlueKeep) exploitable pre-auth on unpatched systems."
    ),
    opsec_level=1,
    expected_findings=["cred"],
    next_ids=["wsit_win_token_impersonate"],
    detection_notes=(
        "RDP failed logins: Event ID 4625 + 4624 (logon type 10). "
        "Extremely visible — triggers SIEM alerts at low volume."
    ),
), os_tags=["any"])

_R.register(Methodology(
    id="wsit_http_form_spray",
    name="HTTP Form / Basic Auth Spraying",
    category="credential",
    phase="looking_deeper",
    triggers=["fuzz_status:401", "fuzz_status:403", "juicy:/admin", "juicy:/login",
              "issue:HTTP basic auth", "tech:wordpress", "tech:joomla", "tech:drupal"],
    mitre=["T1110.003", "T1078"],
    prerequisites=["port:http_or_https"],
    tools=["hydra", "ffuf", "burpsuite"],
    description=(
        "Spray discovered login endpoints (from web fuzz results) with common "
        "credentials. WordPress admin (/wp-login.php), Joomla admin, cPanel, "
        "and HTTP basic-auth endpoints are prime targets. "
        "Reuse credentials already cracked from other services first."
    ),
    opsec_level=2,
    expected_findings=["cred"],
    next_ids=["wsit_ssh_postauth"],
    detection_notes="Web server logs; ModSecurity rules; CMS lockout plugins.",
), os_tags=["any"])

_R.register(Methodology(
    id="wsit_cred_reuse",
    name="Cross-Service Credential Reuse",
    category="credential",
    phase="looking_deeper",
    triggers=["finding:cred"],
    mitre=["T1078", "T1110.004"],
    prerequisites=["cred_exists"],
    tools=["crackmapexec", "hydra"],
    description=(
        "Systematically test cracked credentials across all other discovered services. "
        "Users frequently reuse passwords across SSH, FTP, SMB, RDP, and web apps. "
        "CrackMapExec can spray a single credential across all SMB hosts in one command. "
        "Successful reuse dramatically expands the attack surface."
    ),
    opsec_level=3,
    expected_findings=["cred"],
    next_ids=["wsit_ssh_postauth", "wsit_smb_filehunt"],
), os_tags=["any"])

# ── Web Exploitation ──────────────────────────────────────────────────────────

_R.register(Methodology(
    id="wsit_web_fuzz",
    name="Web Directory & Endpoint Fuzzing",
    category="web",
    phase="looking_deeper",
    triggers=["port:80", "port:443", "service:http", "service:https"],
    mitre=["T1595.003"],
    prerequisites=["port:http_or_https"],
    tools=["ffuf", "gobuster", "feroxbuster"],
    description=(
        "Brute-force hidden directories, files, and API endpoints. "
        "Target .env, .git, backup files (.bak, .sql), admin panels, "
        "and API paths (/api/v1/, /swagger). "
        "200/301 responses indicate accessible content; "
        "401/403 indicate content that exists but requires auth."
    ),
    opsec_level=2,
    expected_findings=["fuzz_url", "fuzz_status"],
    next_ids=["wsit_http_form_spray", "wsit_sqli_probe"],
    detection_notes="High request rate in access logs; WAF rate limiting.",
), os_tags=["any"])

_R.register(Methodology(
    id="wsit_vhost_fuzz",
    name="Virtual Host / Subdomain Fuzzing",
    category="web",
    phase="looking_deeper",
    triggers=["dns:*", "port:80", "port:443"],
    mitre=["T1590.001"],
    prerequisites=["target_is_domain"],
    tools=["ffuf", "gobuster"],
    description=(
        "Fuzz the Host header to discover virtual hosts serving different content "
        "on the same IP. Internal apps, admin panels, and dev/staging environments "
        "are often accessible only via specific hostnames but share the same IP. "
        "Combines with DNS zone data for smarter wordlist generation."
    ),
    opsec_level=3,
    expected_findings=["fuzz_url"],
    next_ids=["wsit_web_recon", "wsit_web_fuzz"],
), os_tags=["any"])

_R.register(Methodology(
    id="wsit_sqli_probe",
    name="SQL Injection Probe",
    category="web",
    phase="looking_deeper",
    triggers=["tech:php", "tech:asp", "tech:aspx", "fuzz_url:*", "issue:SQL"],
    mitre=["T1190"],
    prerequisites=["web_input_identified"],
    tools=["sqlmap", "ffuf"],
    description=(
        "Automated SQL injection testing against discovered endpoints and parameters. "
        "Error-based, blind boolean, and time-based techniques. "
        "Successful SQLi can lead to data exfiltration, auth bypass, "
        "file read/write (INTO OUTFILE → webshell), and OS command execution."
    ),
    opsec_level=2,
    expected_findings=["issue", "cve"],
    next_ids=["wsit_db_enum"],
    detection_notes="SQLi signatures in WAF/IDS; error responses in app logs.",
), os_tags=["any"])

_R.register(Methodology(
    id="wsit_cms_attack",
    name="CMS Vulnerability Exploitation",
    category="web",
    phase="looking_deeper",
    triggers=["tech:wordpress", "tech:joomla", "tech:drupal", "tech:magento"],
    mitre=["T1190", "T1059.006"],
    prerequisites=["cms_identified"],
    tools=["wpscan", "joomscan", "nikto"],
    description=(
        "Enumerate CMS version, installed plugins/themes, and known CVEs. "
        "WordPress: unauthenticated RCE via vulnerable plugins is extremely common. "
        "Joomla: SQLi in com_fields (CVE-2017-8917). Drupal: Drupalgeddon2 (CVE-2018-7600). "
        "WPScan with API key provides real-time vulnerability database."
    ),
    opsec_level=2,
    expected_findings=["cve", "issue"],
    next_ids=["wsit_http_form_spray"],
), os_tags=["any"])

# ── SMB / File Hunt ───────────────────────────────────────────────────────────

_R.register(Methodology(
    id="wsit_smb_filehunt",
    name="SMB Share File Hunt (Authenticated & Null)",
    category="smb",
    phase="looking_deeper",
    triggers=["port:445", "issue:SMB null session", "finding:cred"],
    mitre=["T1039", "T1083"],
    prerequisites=["port:445"],
    tools=["smbclient", "crackmapexec", "nmap-nse"],
    description=(
        "Enumerate accessible SMB shares and recursively list file contents. "
        "Target: credentials (.env, id_rsa, .kdbx), config files (web.config, "
        "database.yml), backups (.bak, .sql), and scripts with hardcoded passwords. "
        "Authenticated access (with cracked creds) expands to C$ and ADMIN$ shares."
    ),
    opsec_level=3,
    expected_findings=["hvf_path", "hvf_category"],
    next_ids=["wsit_cred_extract", "wsit_privesc_sudo"],
    detection_notes=(
        "Share access logged: Event ID 5140/5145. Recursive enumeration "
        "generates high 5145 volume."
    ),
), os_tags=["any"])

_R.register(Methodology(
    id="wsit_ftp_filehunt",
    name="FTP File Hunt (Authenticated)",
    category="credential",
    phase="looking_deeper",
    triggers=["port:21", "finding:cred", "service:ftp"],
    mitre=["T1039"],
    prerequisites=["ftp_cred_exists"],
    tools=["ftp", "ncftp", "lftp"],
    description=(
        "Authenticated FTP traversal to enumerate and download high-value files. "
        "FTP roots often overlap with web roots — config files here may contain "
        "DB credentials. Recursive download of the full FTP tree for offline analysis."
    ),
    opsec_level=4,
    expected_findings=["hvf_path"],
    next_ids=["wsit_cred_extract"],
    detection_notes="FTP access logged per-command in server logs.",
), os_tags=["any"])

# ── Post-Exploitation ─────────────────────────────────────────────────────────

_R.register(Methodology(
    id="wsit_ssh_postauth",
    name="SSH Post-Auth System Enumeration",
    category="post_exploit",
    phase="looking_deeper",
    triggers=["finding:cred", "service:ssh"],
    mitre=["T1087", "T1057", "T1082", "T1069"],
    prerequisites=["ssh_cred_exists"],
    tools=["ssh"],
    description=(
        "Full passive enumeration after SSH access: identity (id, whoami), "
        "OS details, sudo permissions, SUID/SGID binaries, crontab entries, "
        "/etc/passwd + /etc/shadow readability, running processes, "
        "environment variables, bash history, and network listeners. "
        "Identifies privilege escalation vectors without running any exploit code."
    ),
    opsec_level=4,
    expected_findings=["post_auth_data", "issue"],
    next_ids=["wsit_privesc_sudo", "wsit_privesc_suid", "wsit_privesc_kernel",
              "wsit_lin_suid_search", "wsit_lin_sudo_enum"],
    detection_notes="/var/log/auth.log records login; command history if shell monitoring active.",
), os_tags=["any"])

_R.register(Methodology(
    id="wsit_cred_extract",
    name="Credential Extraction from Files",
    category="post_exploit",
    phase="looking_deeper",
    triggers=["hvf_category:credentials", "hvf_category:configs", "hvf_path:*"],
    mitre=["T1552.001"],
    prerequisites=["hvf_findings_exist"],
    tools=["grep", "cat", "strings"],
    description=(
        "Parse discovered high-value files for embedded credentials: "
        "DB connection strings in config files, API keys in .env files, "
        "private keys in .pem/.key files, password hashes in shadow/passwd, "
        "hardcoded passwords in scripts and source code. "
        "Extracted creds feed directly into credential reuse phase."
    ),
    opsec_level=5,
    expected_findings=["cred"],
    next_ids=["wsit_cred_reuse", "wsit_ssh_spray"],
), os_tags=["any"])

# ── Privilege Escalation ──────────────────────────────────────────────────────

_R.register(Methodology(
    id="wsit_privesc_sudo",
    name="Sudo Misconfiguration Exploitation",
    category="privilege_esc",
    phase="predicting",
    triggers=["issue:sudo NOPASSWD", "issue:sudo ALL", "post_auth_data:sudo"],
    mitre=["T1548.003"],
    prerequisites=["ssh_access", "sudo_config_visible"],
    tools=["gtfobins", "ssh"],
    description=(
        "Exploit overly permissive sudo rules. NOPASSWD rules on editors, "
        "scripting interpreters (python, perl, ruby), file utilities (find, cp), "
        "or network tools (nmap --interactive) all enable trivial root escalation. "
        "GTFOBins documents escape techniques for every common binary."
    ),
    opsec_level=4,
    expected_findings=["issue"],
    next_ids=[],
    detection_notes="sudo executions logged to /var/log/auth.log and syslog.",
), os_tags=["any"])

_R.register(Methodology(
    id="wsit_privesc_suid",
    name="SUID Binary Abuse",
    category="privilege_esc",
    phase="predicting",
    triggers=["issue:SUID binaries", "post_auth_data:suid"],
    mitre=["T1548.001"],
    prerequisites=["ssh_access", "suid_binaries_identified"],
    tools=["gtfobins", "ssh"],
    description=(
        "Exploit SUID binaries that allow shell escapes or file reads as root. "
        "Common exploitable SUIDs: find, vim, nmap (--interactive), python, "
        "perl, cp (can overwrite /etc/passwd), bash (-p flag for privileged shell). "
        "Custom SUID binaries with path injection or buffer overflow vulnerabilities "
        "are higher-value targets."
    ),
    opsec_level=4,
    expected_findings=["issue"],
    next_ids=[],
    detection_notes="SUID execution logged by auditd (if configured) with key=privilege_esc.",
), os_tags=["any"])

_R.register(Methodology(
    id="wsit_privesc_kernel",
    name="Kernel Exploit (CVE-based)",
    category="privilege_esc",
    phase="predicting",
    triggers=["os:linux", "cve:CVE-*-kernel*", "vuln_confirmed:true"],
    mitre=["T1068"],
    prerequisites=["ssh_access", "kernel_version_known"],
    tools=["searchsploit", "gcc", "python3"],
    description=(
        "Identify kernel version from uname -a, cross-reference against known "
        "LPE (local privilege escalation) CVEs. Dirty COW (CVE-2016-5195), "
        "Dirty Pipe (CVE-2022-0847), and PwnKit (CVE-2021-4034) cover a wide "
        "range of kernel versions. Compile and execute PoC only when other "
        "escalation paths are exhausted — kernel exploits can crash the system."
    ),
    opsec_level=1,
    expected_findings=["issue"],
    next_ids=[],
    detection_notes=(
        "Kernel exploit execution may trigger kernel ring buffer warnings; "
        "SELinux/AppArmor may block execution."
    ),
), os_tags=["any"])

# ── Vulnerability Probing ─────────────────────────────────────────────────────

_R.register(Methodology(
    id="wsit_smb_vuln_probe",
    name="SMB Vulnerability Probing (EternalBlue, etc.)",
    category="network_service",
    phase="predicting",
    triggers=["port:445", "cve:CVE-2017-0144", "cve:CVE-2020-0796"],
    mitre=["T1210"],
    prerequisites=["port:445"],
    tools=["nmap-nse", "metasploit"],
    description=(
        "Probe for critical SMB CVEs: EternalBlue (CVE-2017-0144, MS17-010) "
        "enables unauthenticated RCE on unpatched Windows systems. "
        "SMBGhost (CVE-2020-0796) targets SMBv3. Both are weaponised and "
        "widely available. nmap smb-vuln-ms17-010 confirms without exploitation."
    ),
    opsec_level=1,
    expected_findings=["vuln_confirmed", "cve"],
    next_ids=[],
    detection_notes=(
        "SMB exploit attempts generate high-volume event log noise; "
        "detected by AV/EDR on the host."
    ),
), os_tags=["any"])

_R.register(Methodology(
    id="wsit_ssl_probe",
    name="SSL/TLS Vulnerability Probing",
    category="network_service",
    phase="predicting",
    triggers=["port:443", "port:8443", "service:https"],
    mitre=["T1557"],
    prerequisites=["port:https"],
    tools=["nmap-nse", "sslscan", "testssl.sh"],
    description=(
        "Test for Heartbleed (CVE-2014-0160), POODLE (CVE-2014-3566), "
        "CCS injection (CVE-2014-0224), BEAST, CRIME, ROBOT, and weak cipher suites. "
        "Heartbleed leaks server memory including private keys and session tokens. "
        "Outdated TLS versions (1.0, 1.1) indicate unmaintained infrastructure."
    ),
    opsec_level=4,
    expected_findings=["vuln_confirmed", "cve"],
    next_ids=[],
    detection_notes="TLS probes are largely passive and difficult to detect.",
), os_tags=["any"])

_R.register(Methodology(
    id="wsit_db_enum",
    name="Database Service Enumeration",
    category="network_service",
    phase="looking_deeper",
    triggers=["port:3306", "port:5432", "port:1433", "port:1521",
              "service:mysql", "service:postgresql", "service:mssql"],
    mitre=["T1046", "T1110"],
    prerequisites=["port:db"],
    tools=["nmap-nse", "hydra", "sqlmap"],
    description=(
        "Enumerate exposed database services. MySQL (3306), PostgreSQL (5432), "
        "MSSQL (1433), Oracle (1521). Test for default credentials "
        "(root/root, sa/sa, postgres/postgres). "
        "MSSQL xp_cmdshell enables OS command execution as the DB service account."
    ),
    opsec_level=2,
    expected_findings=["cred", "issue"],
    next_ids=["wsit_cred_reuse"],
), os_tags=["any"])
