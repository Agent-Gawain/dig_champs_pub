"""
methodologies/macos.py — macOS-specific attack methodologies.

10 entries covering macOS privilege escalation, credential extraction,
TCC bypass, persistence, and post-exploitation techniques.

Registered with os_tags=["macos"].
"""

from wan_shi_tong.registry import MethodologyRegistry
from wan_shi_tong.schema import Methodology

_R = MethodologyRegistry.get()

_R.register(Methodology(
    id="wsit_mac_tcc_bypass",
    name="TCC Database Bypass",
    category="privilege_esc",
    phase="predicting",
    triggers=["os:macos", "post_auth_data:tcc"],
    mitre=["T1548"],
    prerequisites=["macos_shell_access"],
    tools=["sqlite3", "tccutil"],
    description=(
        "TCC (Transparency, Consent and Control) controls access to sensitive resources "
        "(camera, microphone, Full Disk Access, Contacts, Calendar). "
        "Bypass techniques: exploit TCC database at "
        "~/Library/Application Support/com.apple.TCC/TCC.db (writable by user in older macOS), "
        "abuse apps with existing TCC permissions via Apple Events injection (T1631), "
        "or exploit CVEs that grant TCC bypass (CVE-2023-26818 and similar). "
        "Full Disk Access grants unrestricted filesystem read including mail, messages, and ssh keys."
    ),
    opsec_level=2,
    expected_findings=["issue"],
    next_ids=[],
    detection_notes="TCC database modifications logged in Unified Log; "
                    "Apple Endpoint Security Framework monitors TCC changes.",
), os_tags=["macos"])

_R.register(Methodology(
    id="wsit_mac_dylib_hijack",
    name="Dylib Hijacking in Elevated Binaries",
    category="privilege_esc",
    phase="predicting",
    triggers=["os:macos", "post_auth_data:suid"],
    mitre=["T1574.004"],
    prerequisites=["macos_shell_access"],
    tools=["otool", "install_name_tool", "dyld_print_libraries"],
    description=(
        "Enumerate dylib load paths for SUID binaries or apps with elevated entitlements. "
        "otool -L <binary> shows linked libraries. If a library is loaded from a "
        "user-writable path (common with @rpath, @loader_path), place a malicious dylib "
        "there to hijack execution in the elevated context. "
        "DYLD_INSERT_LIBRARIES is blocked on SIP-protected binaries, "
        "but @rpath hijacks bypass this on non-hardened apps."
    ),
    opsec_level=3,
    expected_findings=["issue"],
    next_ids=[],
    detection_notes="dylib loading events monitored by Endpoint Security Framework. "
                    "Gatekeeper checks code signatures on loaded dylibs.",
), os_tags=["macos"])

_R.register(Methodology(
    id="wsit_mac_keychain_extract",
    name="Keychain Credential Extraction",
    category="credential",
    phase="predicting",
    triggers=["os:macos", "finding:cred"],
    mitre=["T1555.001"],
    prerequisites=["macos_user_access"],
    tools=["security", "chainbreaker", "keychaineditor"],
    description=(
        "macOS Keychain stores passwords, certificates, and private keys. "
        "The user's login keychain unlocks automatically at login. "
        "`security dump-keychain -d` dumps all unlocked keychain items in plaintext "
        "(triggers user prompt on modern macOS). "
        "chainbreaker can extract from keychain files offline if the master password is known. "
        "Target: login.keychain-db, iCloud keychain sync data, "
        "system.keychain (requires root), and app-specific keychains."
    ),
    opsec_level=4,
    expected_findings=["cred"],
    next_ids=["wsit_cred_reuse"],
    detection_notes="security command logged via Unified Log; TCC prompt shown to user.",
), os_tags=["macos"])

_R.register(Methodology(
    id="wsit_mac_launch_agent",
    name="LaunchAgent / LaunchDaemon Persistence",
    category="persistence",
    phase="predicting",
    triggers=["os:macos", "finding:cred"],
    mitre=["T1543.001"],
    prerequisites=["macos_user_access"],
    tools=["launchctl", "plutil"],
    description=(
        "Create a plist in ~/Library/LaunchAgents/ (user-level, no root required) "
        "or /Library/LaunchDaemons/ (system-level, requires root) to persist a payload. "
        "LaunchAgents run as the user at login; LaunchDaemons run as root at boot. "
        "Use KeepAlive=true for automatic restart. "
        "Disguise plist as a legitimate-looking service name to evade casual inspection."
    ),
    opsec_level=4,
    expected_findings=["issue"],
    next_ids=[],
    detection_notes="LaunchAgent installation detected by most macOS EDR solutions. "
                    "Unified Log records launchctl load events.",
), os_tags=["macos"])

_R.register(Methodology(
    id="wsit_mac_sudo_tty",
    name="Sudo TTY Ticket Abuse",
    category="privilege_esc",
    phase="predicting",
    triggers=["os:macos", "finding:cred", "service:ssh"],
    mitre=["T1548.003"],
    prerequisites=["macos_shell_access"],
    tools=["sudo", "gtfobins", "ssh"],
    description=(
        "macOS sudo retains a TTY ticket (~5 minute window after password entry). "
        "If another process can inject into a terminal where sudo was recently used, "
        "the ticket may still be valid. "
        "sudo -l enumerates allowed commands — check for NOPASSWD rules or "
        "overly broad permissions. /etc/sudoers on macOS often allows wheel group "
        "members to run all commands; check group membership."
    ),
    opsec_level=4,
    expected_findings=["issue"],
    next_ids=["wsit_privesc_sudo"],
    detection_notes="sudo usage logged to /var/log/auth.log equivalent (Unified Log). "
                    "Shell history captures sudo commands.",
), os_tags=["macos"])

_R.register(Methodology(
    id="wsit_mac_osascript_priv",
    name="osascript Privilege Dialog Phishing",
    category="privilege_esc",
    phase="predicting",
    triggers=["os:macos", "post_auth_data:*"],
    mitre=["T1056.002"],
    prerequisites=["macos_shell_access"],
    tools=["osascript", "AppleScript"],
    description=(
        "Display a fake system authentication dialog via osascript AppleScript. "
        "A convincing dialog asking for the user's password harvests credentials directly. "
        "Example: osascript -e 'display dialog \"macOS needs your password\" "
        "with hidden answer default answer \"\" buttons {\"OK\"} default button 1'. "
        "Captured password can unlock the login keychain and provide sudo escalation. "
        "Effective against users who expect routine macOS authentication prompts."
    ),
    opsec_level=2,
    expected_findings=["cred"],
    next_ids=["wsit_mac_keychain_extract", "wsit_mac_sudo_tty"],
    detection_notes="osascript execution and dialog prompts logged in Unified Log. "
                    "XProtect may flag malicious scripts.",
), os_tags=["macos"])

_R.register(Methodology(
    id="wsit_mac_mdm_enroll",
    name="MDM Profile Enumeration & Abuse",
    category="recon",
    phase="looking_deeper",
    triggers=["os:macos", "post_auth_data:mdm"],
    mitre=["T1580"],
    prerequisites=["macos_shell_access"],
    tools=["profiles", "mdmclient"],
    description=(
        "Enumerate installed MDM profiles: profiles list -all, profiles show -all. "
        "MDM profiles may reveal: organisation name, MDM server URL, certificate authorities, "
        "and installed configuration (VPN, Wi-Fi credentials, email settings). "
        "If the MDM server is internet-accessible, enumerate its API for device management "
        "capabilities. Some MDM solutions allow remote command execution on enrolled devices."
    ),
    opsec_level=5,
    expected_findings=["issue"],
    next_ids=[],
    detection_notes="profiles command legitimate; MDM server queries logged server-side.",
), os_tags=["macos"])

_R.register(Methodology(
    id="wsit_mac_disk_arb",
    name="Disk Arbitration / FUSE Mount Abuse",
    category="privilege_esc",
    phase="predicting",
    triggers=["os:macos", "post_auth_data:*"],
    mitre=["T1548"],
    prerequisites=["macos_shell_access"],
    tools=["diskutil", "hdiutil", "macFUSE"],
    description=(
        "Exploit disk mount race conditions or misconfigured mount points. "
        "hdiutil mount with setuid payloads (before Gatekeeper checks). "
        "macFUSE filesystem implementations with privilege escalation bugs. "
        "diskutil list enumerates all volumes; look for network-mounted volumes "
        "with permissive options. "
        "May combine with Disk Arbitration daemon exploitation on older macOS versions."
    ),
    opsec_level=3,
    expected_findings=["issue"],
    next_ids=[],
    detection_notes="Disk mount events logged in Unified Log; Endpoint Security Framework "
                    "monitors filesystem mount events.",
), os_tags=["macos"])

_R.register(Methodology(
    id="wsit_mac_ssh_agent",
    name="SSH Agent Forwarding Hijack",
    category="post_exploit",
    phase="looking_deeper",
    triggers=["os:macos", "service:ssh", "finding:cred"],
    mitre=["T1563.001"],
    prerequisites=["macos_shell_access", "ssh_agent_running"],
    tools=["ssh-add", "SSH_AUTH_SOCK"],
    description=(
        "If SSH agent forwarding is enabled and an agent socket exists "
        "(SSH_AUTH_SOCK env var), any process with access to the socket can "
        "use it to authenticate to remote hosts as the agent's key owner. "
        "List available keys: ssh-add -l. Connect to remote hosts: ssh -A <host>. "
        "On macOS, the keychain-integrated ssh-agent stores passphrase-protected keys "
        "unlocked at login — socket hijack gives persistent access."
    ),
    opsec_level=4,
    expected_findings=["cred"],
    next_ids=["wsit_cred_reuse"],
    detection_notes="SSH connections logged in /var/log/auth.log and remote host auth.log. "
                    "Agent socket access is not separately logged.",
), os_tags=["macos"])

_R.register(Methodology(
    id="wsit_mac_spotlight_meta",
    name="Spotlight Metadata Credential Mining",
    category="post_exploit",
    phase="looking_deeper",
    triggers=["os:macos", "post_auth_data:*"],
    mitre=["T1083"],
    prerequisites=["macos_user_access"],
    tools=["mdfind", "mdls"],
    description=(
        "Query Spotlight metadata for sensitive files without browsing the filesystem. "
        "mdfind 'kMDItemDisplayName == \"*.pem\"' finds all certificate files. "
        "mdfind 'kMDItemTextContent == \"password\"' searches file content. "
        "Target queries: *.pem, *.key, id_rsa, .env, password, secret, token, api_key. "
        "Spotlight searches inside files — finds credentials in documents, "
        "emails, and notes that normal filesystem traversal would miss."
    ),
    opsec_level=5,
    expected_findings=["hvf_path"],
    next_ids=["wsit_cred_extract"],
    detection_notes="mdfind queries are lightweight and typically unlogged. "
                    "High-volume mdfind may appear in activity monitor.",
), os_tags=["macos"])
