"""
methodologies/linux.py — Linux-specific attack methodologies.

17 entries covering privilege escalation, credential extraction, and
post-exploitation vectors specific to Linux/Unix targets.

Registered with os_tags=["linux"] so they only surface when the router
detects a Linux target (or when collate_findings() is called with os_tag="linux").
"""

from wan_si_tong.registry import MethodologyRegistry
from wan_si_tong.schema import Methodology

_R = MethodologyRegistry.get()

_R.register(Methodology(
    id="wsit_lin_suid_search",
    name="SUID/SGID Binary Discovery",
    category="privilege_esc",
    phase="predicting",
    triggers=["os:linux", "post_auth_data:*"],
    mitre=["T1548.001"],
    prerequisites=["ssh_access"],
    tools=["find", "gtfobins"],
    description=(
        "Enumerate SUID and SGID binaries on the filesystem. "
        "find / -perm -4000 -type f reveals every SUID binary. "
        "Non-standard SUIDs (binaries outside /bin, /usr/bin) are highest priority; "
        "check GTFOBins for exploit techniques against common binaries. "
        "Custom SUID binaries may have path injection or buffer overflow vulnerabilities."
    ),
    opsec_level=4,
    expected_findings=["issue"],
    next_ids=["wsit_privesc_suid"],
    detection_notes="find execution logged by auditd if configured with filesystem watches.",
), os_tags=["linux"])

_R.register(Methodology(
    id="wsit_lin_sudo_enum",
    name="Sudo Rule Enumeration",
    category="privilege_esc",
    phase="predicting",
    triggers=["os:linux", "finding:cred", "service:ssh"],
    mitre=["T1548.003"],
    prerequisites=["ssh_access"],
    tools=["ssh", "sudo", "gtfobins"],
    description=(
        "Run `sudo -l` to enumerate allowed sudo rules for the current user. "
        "NOPASSWD entries on interpreters (python, perl, ruby, node), editors (vim, nano, less), "
        "file utilities (find, cp, mv, tee), or network tools (nmap) enable trivial root. "
        "Even password-required rules may be exploitable via NOPASSWD on obscure binaries. "
        "Cross-reference every allowed binary against GTFOBins."
    ),
    opsec_level=5,
    expected_findings=["issue"],
    next_ids=["wsit_privesc_sudo"],
    detection_notes="sudo -l is a read operation; logged in /var/log/auth.log on some distros.",
), os_tags=["linux"])

_R.register(Methodology(
    id="wsit_lin_cron_abuse",
    name="Cron Job & PATH Hijack",
    category="privilege_esc",
    phase="predicting",
    triggers=["os:linux", "post_auth_data:crontab_sys", "issue:cron_jobs_found"],
    mitre=["T1053.003"],
    prerequisites=["ssh_access"],
    tools=["crontab", "ls", "pspy"],
    description=(
        "Enumerate cron jobs for all users (/etc/cron*, /var/spool/cron). "
        "Look for: scripts writable by the current user, scripts that invoke "
        "binaries by relative path (PATH hijack possible), or scripts that "
        "source writable files. pspy monitors process execution without root "
        "to catch transient cron/systemd timer jobs."
    ),
    opsec_level=4,
    expected_findings=["issue"],
    next_ids=[],
    detection_notes="pspy itself is detectable via /proc monitoring. Cron job modification "
                    "logged if auditd is watching /etc/cron*.",
), os_tags=["linux"])

_R.register(Methodology(
    id="wsit_lin_lxd_esc",
    name="LXD / Docker Group Escalation",
    category="privilege_esc",
    phase="predicting",
    triggers=["os:linux", "post_auth_data:lxd"],
    mitre=["T1611"],
    prerequisites=["ssh_access", "lxd_or_docker_group_membership"],
    tools=["lxc", "docker"],
    description=(
        "Membership in the lxd or docker group provides an unprivileged path to root. "
        "LXD: initialize a privileged container, mount the host root filesystem, "
        "chroot in and read/write /etc/shadow or add an SSH key. "
        "Docker: `docker run -v /:/mnt --rm alpine chroot /mnt` gives root on the host. "
        "Both are well-documented and reliable on misconfigured systems."
    ),
    opsec_level=3,
    expected_findings=["issue"],
    next_ids=[],
    detection_notes="Container creation logged in audit log; Docker daemon logs group membership.",
), os_tags=["linux"])

_R.register(Methodology(
    id="wsit_lin_passwd_hash",
    name="/etc/shadow Extraction",
    category="credential",
    phase="predicting",
    triggers=["os:linux", "post_auth_data:shadow_readable"],
    mitre=["T1003.008"],
    prerequisites=["ssh_access", "shadow_readable"],
    tools=["cat", "john", "hashcat"],
    description=(
        "If /etc/shadow is readable (world-readable or owned by a group the user belongs to), "
        "extract all password hashes. Feed to john/hashcat for offline cracking. "
        "Common hash types: $6$ (sha-512crypt), $y$ (yescrypt), $1$ (md5crypt). "
        "Cracked passwords from shadow often reuse across services."
    ),
    opsec_level=5,
    expected_findings=["cred"],
    next_ids=["wsit_lin_hash_crack"],
    detection_notes="File access logged by auditd if inode watch configured on /etc/shadow.",
), os_tags=["linux"])

_R.register(Methodology(
    id="wsit_lin_hash_crack",
    name="Offline Password Hash Cracking",
    category="credential",
    phase="predicting",
    triggers=["hvf_category:credentials", "os:linux"],
    mitre=["T1110.002"],
    prerequisites=["hash_file_obtained"],
    tools=["hashcat", "john", "rockyou.txt"],
    description=(
        "Offline cracking of extracted Linux password hashes. "
        "Hashcat with GPU acceleration is ~100x faster than CPU-based john. "
        "Wordlist + rules attack (rockyou + best64.rule) covers ~60-70% of real passwords. "
        "sha-512crypt ($6$): use hashcat mode 1800. "
        "yescrypt ($y$): use hashcat mode 7400 or john --format=crypt."
    ),
    opsec_level=5,
    expected_findings=["cred"],
    next_ids=["wsit_cred_reuse"],
    detection_notes="Offline operation — zero detection risk on target.",
), os_tags=["linux"])

_R.register(Methodology(
    id="wsit_lin_ssh_key_harvest",
    name="SSH Private Key & Authorized Keys Harvest",
    category="post_exploit",
    phase="looking_deeper",
    triggers=["os:linux", "finding:cred", "service:ssh"],
    mitre=["T1552.004"],
    prerequisites=["ssh_access"],
    tools=["find", "cat", "ssh"],
    description=(
        "Enumerate ~/.ssh/ for private keys (id_rsa, id_ed25519, id_ecdsa) "
        "and authorized_keys files. Check /root/.ssh/ and other users' home dirs "
        "if readable. Unencrypted private keys can be used directly for lateral movement. "
        "Authorized_keys reveal which other machines trust this user's keys."
    ),
    opsec_level=5,
    expected_findings=["hvf_path", "cred"],
    next_ids=["wsit_cred_reuse"],
    detection_notes="File read logged by auditd if inode watches configured on .ssh/.",
), os_tags=["linux"])

_R.register(Methodology(
    id="wsit_lin_env_var_leak",
    name="Environment Variable & Process Env Credential Leak",
    category="post_exploit",
    phase="looking_deeper",
    triggers=["os:linux", "post_auth_data:*"],
    mitre=["T1552.007"],
    prerequisites=["ssh_access"],
    tools=["env", "cat", "strings"],
    description=(
        "Dump the current environment (env, printenv) and check /proc/*/environ "
        "for other processes' environment variables. "
        "Database passwords (DB_PASS, DATABASE_URL), API keys (AWS_SECRET_ACCESS_KEY, "
        "API_KEY), and service tokens are commonly stored in environment variables "
        "on Linux application servers."
    ),
    opsec_level=5,
    expected_findings=["cred"],
    next_ids=["wsit_cred_extract"],
    detection_notes="Process env reads via /proc are generally invisible; env command is benign.",
), os_tags=["linux"])

_R.register(Methodology(
    id="wsit_lin_nfs_misconfig",
    name="NFS Export Misconfiguration",
    category="network_service",
    phase="looking_deeper",
    triggers=["port:2049", "service:nfs"],
    mitre=["T1135"],
    prerequisites=["port:2049"],
    tools=["showmount", "nfsstat", "mount"],
    description=(
        "Enumerate NFS exports (showmount -e <target>). "
        "Exports with no_root_squash allow a remote attacker with uid=0 to read/write "
        "any file on the exported filesystem — including /etc/shadow or SSH keys. "
        "Exports with rw permissions allow placing a reverse shell or modifying /etc/passwd. "
        "Check for exports of / or /home."
    ),
    opsec_level=3,
    expected_findings=["issue"],
    next_ids=["wsit_lin_passwd_hash"],
    detection_notes="showmount queries logged in NFS server logs; mount operations visible.",
), os_tags=["linux"])

_R.register(Methodology(
    id="wsit_lin_writable_service",
    name="Writable systemd Service File Abuse",
    category="privilege_esc",
    phase="predicting",
    triggers=["os:linux", "post_auth_data:systemd"],
    mitre=["T1543.002"],
    prerequisites=["ssh_access"],
    tools=["find", "systemctl", "ss"],
    description=(
        "Find writable systemd service files or ExecStart scripts: "
        "find /etc/systemd/system /lib/systemd/system -writable. "
        "If a service runs as root and its ExecStart script is writable by the user, "
        "modify it to execute a reverse shell or add an SSH key. "
        "Reload and restart the service to trigger execution as root."
    ),
    opsec_level=3,
    expected_findings=["issue"],
    next_ids=[],
    detection_notes="systemctl daemon-reload and service restart logged in journald.",
), os_tags=["linux"])

_R.register(Methodology(
    id="wsit_lin_path_hijack",
    name="PATH Injection in SUID / sudo Scripts",
    category="privilege_esc",
    phase="predicting",
    triggers=["os:linux", "post_auth_data:suid_bins", "issue:suid_bins_present"],
    mitre=["T1574.007"],
    prerequisites=["ssh_access", "suid_script_or_writable_path"],
    tools=["strings", "strace", "ltrace"],
    description=(
        "Identify SUID scripts or sudo-allowed scripts that call external programs "
        "without absolute paths. Use strings or strace to find relative binary invocations. "
        "Create a malicious binary with the same name in a directory earlier in PATH, "
        "or modify the PATH environment variable if the sudo rule doesn't sanitize it. "
        "The called binary executes as root when the SUID program runs."
    ),
    opsec_level=4,
    expected_findings=["issue"],
    next_ids=[],
    detection_notes="strace on SUID programs requires careful execution; "
                    "auditd syscall watches catch execve calls.",
), os_tags=["linux"])

_R.register(Methodology(
    id="wsit_lin_capabilities",
    name="Linux Capability Abuse",
    category="privilege_esc",
    phase="predicting",
    triggers=["os:linux", "post_auth_data:capabilities"],
    mitre=["T1548.001"],
    prerequisites=["ssh_access"],
    tools=["getcap", "python3", "perl"],
    description=(
        "Enumerate files with Linux capabilities: getcap -r / 2>/dev/null. "
        "cap_setuid+ep allows a binary to setuid(0) — any interpreter with this "
        "capability (python3, perl, ruby) provides trivial root via "
        "os.setuid(0) + os.system('/bin/bash'). "
        "cap_dac_read_search allows reading any file regardless of permissions (shadow file). "
        "cap_net_raw + cap_net_admin allow raw packet injection."
    ),
    opsec_level=4,
    expected_findings=["issue"],
    next_ids=[],
    detection_notes="getcap is a read operation; capability abuse logged by auditd "
                    "if priv_esc watches configured.",
), os_tags=["linux"])

_R.register(Methodology(
    id="wsit_lin_sudo_all",
    name="NOPASSWD Sudo Root Shell",
    category="privilege_esc",
    phase="live_adapt",
    triggers=["os:linux", "issue:sudo_nopasswd", "post_auth_data:sudo_privs"],
    mitre=["T1548.003"],
    prerequisites=["ssh_access"],
    tools=["ssh", "sudo"],
    description=(
        "User has (ALL:ALL) NOPASSWD:ALL sudo rights — direct root shell with `sudo su` "
        "or `sudo /bin/bash`. No password required. Immediate full system compromise. "
        "Also usable for reading /etc/shadow, adding SSH keys to root's authorized_keys, "
        "installing persistence (cron, systemd unit, PAM backdoor), "
        "and pivoting to other hosts via root's SSH keys."
    ),
    opsec_level=5,
    expected_findings=["issue"],
    next_ids=["wsit_lin_passwd_hash", "wsit_lin_ssh_key_harvest"],
    detection_notes="sudo invocations logged in /var/log/auth.log. "
                    "NOPASSWD means no password prompt — less human-visible but still logged.",
), os_tags=["linux"])

_R.register(Methodology(
    id="wsit_lin_docker_escape",
    name="Docker Daemon Container Escape",
    category="privilege_esc",
    phase="live_adapt",
    triggers=["os:linux", "issue:docker_running", "service:docker",
              "post_auth_data:lxd", "issue:container_group"],
    mitre=["T1611"],
    prerequisites=["ssh_access"],
    tools=["docker"],
    description=(
        "Docker daemon is running and accessible. If the current user is in the docker group "
        "or the socket is world-accessible: "
        "`docker run -v /:/mnt --rm -it alpine chroot /mnt` mounts the host root and gives "
        "a root shell on the host filesystem. Write an SSH key to /root/.ssh/authorized_keys "
        "or add a cron job at /etc/cron.d/. "
        "Alternatively: `docker run --privileged` + nsenter into host namespaces."
    ),
    opsec_level=3,
    expected_findings=["issue"],
    next_ids=["wsit_lin_passwd_hash"],
    detection_notes="Docker API calls logged by the daemon. Container creation visible in "
                    "`docker ps` and audit log if dockerd has audit plugin enabled.",
), os_tags=["linux"])

_R.register(Methodology(
    id="wsit_lin_lateral_pivot",
    name="Multi-Homed Host Lateral Pivot",
    category="lateral",
    phase="live_adapt",
    triggers=["os:linux", "issue:multi_homed"],
    mitre=["T1021.004", "T1090"],
    prerequisites=["ssh_access"],
    tools=["ssh", "nmap", "proxychains", "sshuttle"],
    description=(
        "Host has multiple network interfaces — it bridges two or more subnets. "
        "Enumerate the secondary interface range with nmap from within the host "
        "(avoids network-level filtering that blocks the attacker's machine). "
        "Use the compromised host as a pivot: SSH -L/-D for dynamic SOCKS proxy, "
        "or sshuttle to route a full subnet through the session. "
        "Check /etc/hosts and ARP cache for known neighbors on the internal subnet."
    ),
    opsec_level=3,
    expected_findings=["issue"],
    next_ids=["wsit_port_enum"],
    detection_notes="Port scans from the pivot host appear as internal traffic — "
                    "may evade perimeter IDS but visible to host-based monitoring.",
), os_tags=["linux"])

_R.register(Methodology(
    id="wsit_lin_kernel_exploit",
    name="Linux Kernel Local Privilege Escalation",
    category="privilege_esc",
    phase="predicting",
    triggers=["os:linux", "issue:kernel_old", "post_auth_data:kernel"],
    mitre=["T1068"],
    prerequisites=["ssh_access"],
    tools=["gcc", "searchsploit", "linux-exploit-suggester"],
    description=(
        "Kernel version is below 4.x — a wide range of local privilege escalation exploits "
        "apply. Run linux-exploit-suggester against the kernel version string to get a ranked "
        "list. High-value targets for kernels in the 3.x range: "
        "Dirty COW (CVE-2016-5195, 3.x/2.6.x, reliable write-anywhere), "
        "overlayfs privesc (CVE-2015-1328, Ubuntu 12.04–15.10), "
        "perf_swevent_init (CVE-2013-2094). "
        "Compile exploit on a matching architecture; transfer via SCP or wget."
    ),
    opsec_level=2,
    expected_findings=["issue"],
    next_ids=[],
    detection_notes="Exploit compilation and execution produce unusual CPU spikes and "
                    "syscall patterns detectable by auditd or EDR.",
), os_tags=["linux"])

_R.register(Methodology(
    id="wsit_lin_unrealircd_backdoor",
    name="UnrealIRCd 3.2.8.1 Backdoor",
    category="network_service",
    phase="live_adapt",
    triggers=["service:unrealircd", "port:6667", "port:6697"],
    mitre=["T1190"],
    prerequisites=["network_access"],
    tools=["netcat", "ncat", "metasploit"],
    description=(
        "UnrealIRCd 3.2.8.1 contains a compiled-in backdoor (CVE-2010-2075). "
        "Sending 'AB;' followed by a shell command on the IRC port triggers remote "
        "code execution as the ircd process owner. "
        "Metasploit: use exploit/unix/irc/unreal_ircd_3281_backdoor. "
        "Manual: echo 'AB; id' | nc <target> 6667 — look for uid= in response. "
        "The backdoor runs the command and returns output directly over the TCP connection."
    ),
    opsec_level=2,
    expected_findings=["issue", "cred"],
    next_ids=["wsit_lin_sudo_enum", "wsit_lin_sudo_all"],
    detection_notes="Connection to IRC port from non-IRC client is anomalous. "
                    "AB; pattern easily signatured in NIDS.",
), os_tags=["linux"])
