"""
methodologies/android.py — Android-specific attack methodologies.

8 entries covering ADB access, application data extraction, dynamic
instrumentation, certificate pinning bypass, and Android privilege escalation.

Registered with os_tags=["android"].
"""

from wan_si_tong.registry import MethodologyRegistry
from wan_si_tong.schema import Methodology

_R = MethodologyRegistry.get()

_R.register(Methodology(
    id="wsit_and_adb_shell",
    name="ADB Shell Access (USB / Network)",
    category="post_exploit",
    phase="looking_deeper",
    triggers=["os:android", "port:5555", "service:adb"],
    mitre=["T1219"],
    prerequisites=["adb_reachable"],
    tools=["adb"],
    description=(
        "ADB (Android Debug Bridge) provides shell access to the device. "
        "Network ADB (port 5555) is exposed when developer mode + network debugging is on. "
        "adb connect <ip>:5555 — if no auth required (older Android / developer builds), "
        "immediate shell access. "
        "adb shell id reveals privilege level; root ADB = full device access. "
        "First step: enumerate apps, check backup settings, inspect logcat."
    ),
    opsec_level=2,
    expected_findings=["post_auth_data"],
    next_ids=["wsit_and_app_data_extract", "wsit_and_logcat_harvest"],
    detection_notes="ADB connections visible in developer options. "
                    "Network ADB creates a visible notification on many Android versions.",
), os_tags=["android"])

_R.register(Methodology(
    id="wsit_and_app_data_extract",
    name="Application Private Data Extraction via ADB",
    category="post_exploit",
    phase="looking_deeper",
    triggers=["os:android", "post_auth_data:adb"],
    mitre=["T1005"],
    prerequisites=["adb_shell_access"],
    tools=["adb", "run-as", "sqlite3"],
    description=(
        "Extract application private data from /data/data/<package_name>/. "
        "On non-rooted devices, use run-as <package_name> if the app is debuggable "
        "(common in debug builds and poorly configured apps). "
        "On rooted devices: adb shell 'su -c \"cp -r /data/data/<package> /sdcard/dump\"'. "
        "Targets: SQLite databases (credentials, tokens), SharedPreferences XML "
        "(API keys, session tokens), files/, cache/ directories."
    ),
    opsec_level=4,
    expected_findings=["hvf_path", "cred"],
    next_ids=["wsit_cred_extract"],
    detection_notes="run-as requires debuggable app flag; generates filesystem access events.",
), os_tags=["android"])

_R.register(Methodology(
    id="wsit_and_frida_hook",
    name="Frida Dynamic Instrumentation",
    category="post_exploit",
    phase="looking_deeper",
    triggers=["os:android", "post_auth_data:adb"],
    mitre=["T1179"],
    prerequisites=["adb_shell_access"],
    tools=["frida", "frida-server", "objection"],
    description=(
        "Deploy frida-server via ADB and use Frida to hook application methods at runtime. "
        "Intercept: cryptographic functions (expose plaintext before encryption), "
        "authentication checks (bypass login validation), "
        "network calls (dump request/response bodies), "
        "and sensitive API calls (keystore access, biometric authentication). "
        "objection provides a Frida-powered interactive exploration shell with "
        "built-in commands for common Android testing tasks."
    ),
    opsec_level=3,
    expected_findings=["cred", "issue"],
    next_ids=["wsit_and_cert_pin_bypass"],
    detection_notes="Frida server process visible in ps output. "
                    "Some apps include Frida detection (anti-tampering checks).",
), os_tags=["android"])

_R.register(Methodology(
    id="wsit_and_cert_pin_bypass",
    name="Certificate Pinning Bypass",
    category="web",
    phase="looking_deeper",
    triggers=["os:android", "post_auth_data:frida"],
    mitre=["T1557"],
    prerequisites=["adb_shell_access", "frida_deployed"],
    tools=["objection", "frida", "burpsuite", "apktool"],
    description=(
        "Bypass SSL/TLS certificate pinning to intercept HTTPS traffic in Burp Suite. "
        "Methods: objection android sslpinning disable (hooks common SSL libraries), "
        "Frida scripts targeting OkHttp/TrustManager, "
        "or static patching with apktool + smali modification. "
        "Once pinning is bypassed, set the device proxy to Burp Suite and "
        "inspect all API traffic including auth tokens, session management, and PII."
    ),
    opsec_level=3,
    expected_findings=["cred", "issue"],
    next_ids=["wsit_sqli_probe"],
    detection_notes="SSL pinning bypass via Frida requires frida-server running on device. "
                    "Static patching changes the APK signature.",
), os_tags=["android"])

_R.register(Methodology(
    id="wsit_and_backup_extract",
    name="ADB Backup Credential Extraction",
    category="credential",
    phase="looking_deeper",
    triggers=["os:android", "post_auth_data:adb"],
    mitre=["T1005"],
    prerequisites=["adb_connected", "backup_allowed"],
    tools=["adb", "android-backup-extractor", "java"],
    description=(
        "Use adb backup to extract application data without root: "
        "adb backup -apk -shared -all -f backup.ab. "
        "Decrypt with android-backup-extractor: "
        "java -jar abe.jar unpack backup.ab backup.tar [password]. "
        "Unpack tar and browse /apps/<package>/db/, sp/, f/ for credentials. "
        "Individual app backup: adb backup -f <pkg>.ab <package_name>. "
        "Many apps set allowBackup=false, but not all — test each target app."
    ),
    opsec_level=4,
    expected_findings=["cred", "hvf_path"],
    next_ids=["wsit_cred_reuse"],
    detection_notes="adb backup creates a device notification. "
                    "Android 12+ requires physical confirmation on the device.",
), os_tags=["android"])

_R.register(Methodology(
    id="wsit_and_root_detect",
    name="Root Detection Bypass & Root Escalation",
    category="privilege_esc",
    phase="predicting",
    triggers=["os:android", "post_auth_data:adb", "issue:rooted"],
    mitre=["T1548"],
    prerequisites=["adb_shell_access"],
    tools=["Magisk", "frida", "objection"],
    description=(
        "If the device is rooted (Magisk, KingRoot, etc.): "
        "adb shell 'su -c id' confirms root access. "
        "Root enables full filesystem access, extraction of all app data, "
        "and modification of system files. "
        "If root detection prevents app from running: use Magisk Hide (now Zygisk + DenyList) "
        "or Frida hooks on RootBeer/SafetyNet checks. "
        "Google Play Integrity API (replacement for SafetyNet) is harder to bypass."
    ),
    opsec_level=2,
    expected_findings=["post_auth_data"],
    next_ids=["wsit_and_app_data_extract"],
    detection_notes="su execution visible to parent process. "
                    "Root detection libraries check for su binary, superuser apps, and build tags.",
), os_tags=["android"])

_R.register(Methodology(
    id="wsit_and_broadcast_recv",
    name="Broadcast Receiver / Exported Component Exploitation",
    category="web",
    phase="looking_deeper",
    triggers=["os:android", "post_auth_data:adb", "issue:exported component"],
    mitre=["T1406"],
    prerequisites=["adb_shell_access"],
    tools=["adb", "drozer", "apktool", "jadx"],
    description=(
        "Enumerate exported Activities, Services, Content Providers, and Broadcast Receivers "
        "in the target app's AndroidManifest.xml (apktool d <apk>). "
        "Exploit exported components: "
        "Activities: adb shell am start -n <package>/<activity> (bypass auth screens), "
        "Content Providers: adb shell content query --uri content://<authority>/ "
        "(may expose SQLite DB via URI), "
        "Services: adb shell am startservice with crafted Intent extras. "
        "Drozer provides an interactive exploitation console for all component types."
    ),
    opsec_level=3,
    expected_findings=["issue", "cred"],
    next_ids=[],
    detection_notes="Intent-based attacks leave traces in device logs. "
                    "Content provider queries visible in app logs if debug logging enabled.",
), os_tags=["android"])

_R.register(Methodology(
    id="wsit_and_logcat_harvest",
    name="Logcat Credential & Session Token Harvest",
    category="post_exploit",
    phase="looking_deeper",
    triggers=["os:android", "post_auth_data:adb"],
    mitre=["T1005"],
    prerequisites=["adb_shell_access"],
    tools=["adb logcat", "grep"],
    description=(
        "Capture Android logcat output to harvest credentials and tokens logged by apps. "
        "Many Android apps log sensitive data during development and fail to disable "
        "it in production builds: passwords in login error messages, "
        "auth tokens in network request logs, API responses with PII. "
        "adb logcat -v time | grep -iE 'token|password|auth|secret|key' "
        "filters relevant output. Capture during app login/use for best results. "
        "Some apps log Base64-encoded credentials: pipe through base64 -d."
    ),
    opsec_level=5,
    expected_findings=["cred"],
    next_ids=["wsit_cred_reuse"],
    detection_notes="logcat is a standard Android debugging tool; its use is not anomalous.",
), os_tags=["android"])
