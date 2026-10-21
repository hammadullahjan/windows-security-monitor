"""
╔══════════════════════════════════════════════════════════════════╗
║       WINDOWS SECURITY MONITOR v3.0 - STEALTH EDITION          ║
║                                                                  ║
║  • Real threat detection (no noise)                              ║
║  • Suspicious process & malware detection                        ║
║  • Software install monitoring                                   ║
║  • Protected file access alerts                                  ║
║  • Brute force attack detection                                  ║
║  • Runs silently in background (no visible window)               ║
╚══════════════════════════════════════════════════════════════════╝
"""

import json
import time
import logging
import hashlib
import os
import sys
import signal
import argparse
import smtplib
import threading
import subprocess
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

if sys.platform != "win32":
    print("[!] Windows only. You can still test notifications with --test")

try:
    import requests
except ImportError:
    sys.exit("[!] Run: pip install requests")

if sys.platform == "win32":
    try:
        import win32evtlog
        import win32con
        import wmi
    except ImportError:
        sys.exit("[!] Run: pip install pywin32 wmi\nThen: python -m pywin32_postinstall -install")

# ═══════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════

CONFIG_FILE = Path(__file__).parent / "config.json"

DEFAULT_CONFIG = {
    "notification_method": "email",

    "email": {
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "sender_email": "YOUR_GMAIL@gmail.com",
        "sender_password": "YOUR_APP_PASSWORD",
        "receiver_email": "YOUR_GMAIL@gmail.com"
    },

    "telegram": {
        "bot_token": "YOUR_TELEGRAM_BOT_TOKEN",
        "chat_id": "YOUR_TELEGRAM_CHAT_ID"
    },

    "monitor_settings": {
        "poll_interval_seconds": 5,
        "log_file": "security_events.log",
        "alert_cooldown_seconds": 30,
        "max_alerts_per_hour": 50
    },

    "threat_detection": {
        "failed_login_threshold": 3,
        "failed_login_window_seconds": 300
    },

    "protected_files": [
        # Add files/folders you want to monitor
        # Example: "C:\\Users\\haier\\Desktop\\secret_folder",
        # Example: "C:\\Users\\haier\\Documents\\passwords.xlsx"
    ],

    "protected_file_extensions": [
        # Alert when these file types are accessed in protected folders
        ".xlsx", ".docx", ".pdf", ".txt", ".csv",
        ".jpg", ".png", ".zip", ".rar", ".7z",
        ".pptx", ".key", ".wallet", ".kdbx"
    ]
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM ACCOUNTS TO IGNORE
# ═══════════════════════════════════════════════════════════════════

SYSTEM_ACCOUNTS = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
    "DWM-1", "DWM-2", "DWM-3", "UMFD-0", "UMFD-1", "UMFD-2",
    "ANONYMOUS LOGON", "IUSR", "DefaultAppPool",
    "Font Driver Host", "Window Manager", "-", "", "N/A"
}

# ═══════════════════════════════════════════════════════════════════
# SUSPICIOUS PROCESSES (Malware, Hacking Tools, Viruses)
# ═══════════════════════════════════════════════════════════════════

MALWARE_PROCESSES = {
    # ── Hacking Tools ──
    "mimikatz.exe": ("CRITICAL", "Credential stealing tool (Mimikatz)"),
    "lazagne.exe": ("CRITICAL", "Password dumping tool"),
    "psexec.exe": ("CRITICAL", "Remote execution tool (PsExec)"),
    "psexesvc.exe": ("CRITICAL", "PsExec service"),
    "wce.exe": ("CRITICAL", "Windows Credential Editor"),
    "procdump.exe": ("HIGH", "Memory dumping tool"),
    "bloodhound.exe": ("CRITICAL", "Active Directory recon tool"),
    "sharphound.exe": ("CRITICAL", "AD data collector"),
    "rubeus.exe": ("CRITICAL", "Kerberos attack tool"),
    "covenant.exe": ("CRITICAL", "C2 framework agent"),
    "cobalt*.exe": ("CRITICAL", "Cobalt Strike beacon"),

    # ── Reverse Shells ──
    "nc.exe": ("CRITICAL", "Netcat - reverse shell tool"),
    "nc64.exe": ("CRITICAL", "Netcat 64-bit"),
    "ncat.exe": ("CRITICAL", "Ncat - reverse shell"),
    "chisel.exe": ("HIGH", "Network tunneling tool"),
    "plink.exe": ("HIGH", "PuTTY tunneling tool"),
    "socat.exe": ("HIGH", "Socket relay tool"),

    # ── Ransomware Indicators ──
    "vssadmin.exe": ("CRITICAL", "Shadow copy deletion (ransomware indicator!)"),
    "wbadmin.exe": ("HIGH", "Backup deletion tool"),
    "bcdedit.exe": ("HIGH", "Boot config editor (ransomware may disable recovery)"),

    # ── Living-off-the-Land (LoLBins) ──
    "mshta.exe": ("HIGH", "MSHTA - script execution bypass"),
    "wscript.exe": ("MEDIUM", "Windows Script Host"),
    "cscript.exe": ("MEDIUM", "Console Script Host"),
    "regsvr32.exe": ("MEDIUM", "DLL registration (can bypass security)"),
    "certutil.exe": ("HIGH", "CertUtil - often abused to download malware"),
    "bitsadmin.exe": ("HIGH", "BitsAdmin - background file downloader"),
    "msiexec.exe": ("MEDIUM", "MSI installer (can install malware remotely)"),
    "rundll32.exe": ("MEDIUM", "DLL executor"),

    # ── Reconnaissance ──
    "whoami.exe": ("LOW", "User enumeration"),
    "systeminfo.exe": ("LOW", "System info gathering"),
    "net.exe": ("LOW", "Network enumeration"),
    "net1.exe": ("LOW", "Network enumeration"),

    # ── Persistence ──
    "schtasks.exe": ("MEDIUM", "Scheduled task (persistence mechanism)"),
    "at.exe": ("MEDIUM", "Task scheduling"),
    "reg.exe": ("MEDIUM", "Registry modification"),

    # ── Data Exfiltration ──
    "rar.exe": ("MEDIUM", "RAR archiver (possible data exfil)"),
    "7z.exe": ("MEDIUM", "7-Zip (possible data exfil)"),
}

SUSPICIOUS_POWERSHELL_ARGS = [
    "-encodedcommand", "-enc ", "-e ",
    "-executionpolicy bypass", "-ep bypass",
    "-windowstyle hidden", "-w hidden",
    "invoke-expression", "iex(", "iex ",
    "invoke-webrequest", "downloadstring",
    "downloadfile", "net.webclient",
    "frombase64string", "reflection.assembly",
    "invoke-mimikatz", "invoke-shellcode",
    "amsibypass", "disable-realtimemonitoring",
]


# ═══════════════════════════════════════════════════════════════════
# NOTIFICATION SYSTEM
# ═══════════════════════════════════════════════════════════════════

class NotificationManager:
    def __init__(self, config):
        self.config = config
        self.method = config.get("notification_method", "email")
        self.alert_history = []
        self.cooldown_cache = {}
        self.settings = config.get("monitor_settings", {})

    def _is_rate_limited(self):
        max_alerts = self.settings.get("max_alerts_per_hour", 50)
        cutoff = datetime.now() - timedelta(hours=1)
        self.alert_history = [t for t in self.alert_history if t > cutoff]
        return len(self.alert_history) >= max_alerts

    def _is_cooldown(self, event_hash):
        cooldown = self.settings.get("alert_cooldown_seconds", 30)
        if event_hash in self.cooldown_cache:
            if (datetime.now() - self.cooldown_cache[event_hash]).total_seconds() < cooldown:
                return True
        self.cooldown_cache[event_hash] = datetime.now()
        return False

    def send_alert(self, title, message, severity="HIGH", force=False):
        h = hashlib.md5(f"{title}{message[:100]}".encode()).hexdigest()
        if not force:
            if self._is_cooldown(h) or self._is_rate_limited():
                return False
        self.alert_history.append(datetime.now())

        if self.method == "email":
            return self._send_email(title, message, severity)
        elif self.method == "telegram":
            return self._send_telegram(title, message, severity)
        return False

    def _send_email(self, title, message, severity):
        cfg = self.config.get("email", {})
        sender = cfg.get("sender_email", "")
        password = cfg.get("sender_password", "")
        receiver = cfg.get("receiver_email", sender)

        if "YOUR_" in sender or "YOUR_" in password:
            return False

        colors = {"CRITICAL": "#dc3545", "HIGH": "#fd7e14", "MEDIUM": "#ffc107", "LOW": "#28a745", "INFO": "#17a2b8"}
        color = colors.get(severity, "#6c757d")
        labels = {"CRITICAL": "🚨 IMMEDIATE ACTION", "HIGH": "⚠️ INVESTIGATE NOW", "MEDIUM": "📋 REVIEW SOON"}
        label = labels.get(severity, "")

        html = f"""<html><body style="font-family:'Segoe UI',Arial;margin:0;padding:20px;background:#0a0a1a;">
<div style="max-width:520px;margin:0 auto;background:#111827;border-radius:12px;overflow:hidden;border-left:4px solid {color};">
<div style="background:{color};padding:14px 20px;text-align:center;">
<h2 style="margin:0;color:#fff;font-size:16px;">🚨 THREAT DETECTED</h2>
<p style="margin:3px 0 0;color:rgba(255,255,255,.85);font-size:11px;">{label}</p></div>
<div style="padding:14px 20px;border-bottom:1px solid #1f2937;">
<table style="width:100%"><tr><td style="color:#6b7280;font-size:11px">SEVERITY</td>
<td style="color:{color};font-size:13px;font-weight:bold;text-align:right">{severity}</td></tr>
<tr><td style="color:#6b7280;font-size:11px">TIME</td>
<td style="color:#d1d5db;font-size:12px;text-align:right">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr></table></div>
<div style="padding:12px 20px;border-bottom:1px solid #1f2937;">
<h3 style="margin:0;color:#f87171;font-size:14px;">{title}</h3></div>
<div style="padding:12px 20px;">
<pre style="color:#d1d5db;font-size:11px;line-height:1.7;white-space:pre-wrap;margin:0;font-family:Consolas,monospace;background:#0d1117;padding:12px;border-radius:8px;">{message}</pre></div>
<div style="padding:8px 20px;background:#0d1117;text-align:center;">
<small style="color:#4b5563;">Security Monitor v3.0 | Stealth Edition</small></div></div></body></html>"""

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 [{severity}] {title}"
        msg["From"] = sender
        msg["To"] = receiver
        msg.attach(MIMEText(f"{title}\n{message}", "plain"))
        msg.attach(MIMEText(html, "html"))

        try:
            with smtplib.SMTP(cfg.get("smtp_server", "smtp.gmail.com"), cfg.get("smtp_port", 587), timeout=15) as s:
                s.starttls()
                s.login(sender, password)
                s.send_message(msg)
            return True
        except Exception as e:
            logging.error(f"Email failed: {e}")
            return False

    def _send_telegram(self, title, message, severity):
        cfg = self.config.get("telegram", {})
        token = cfg.get("bot_token", "")
        chat = cfg.get("chat_id", "")
        if "YOUR_" in token:
            return False
        emojis = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡"}
        e = emojis.get(severity, "⚠️")
        text = f"{e} <b>{title}</b>\n<b>Severity:</b> {severity}\n<b>Time:</b> {datetime.now().strftime('%H:%M:%S')}\n\n<pre>{message}</pre>"
        try:
            r = requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
                              json={"chat_id": chat, "text": text, "parse_mode": "HTML"}, timeout=10)
            return r.status_code == 200
        except:
            return False

    def send_test(self):
        return self.send_alert("🧪 Test - Stealth Monitor Active",
            "✅ Security Monitor v3.0 is running silently!\n\n"
            "Active protections:\n"
            "  • Brute force detection\n"
            "  • Malware/hacking tool detection\n"
            "  • Software install monitoring\n"
            "  • Protected file access alerts\n"
            "  • USB device monitoring\n"
            "  • Firewall change detection\n"
            "  • RDP connection alerts\n"
            "  • Runs silently in background\n\n"
            "System noise: FILTERED OUT", "INFO", force=True)


# ═══════════════════════════════════════════════════════════════════
# FILE WATCHDOG - Monitor protected files/folders
# ═══════════════════════════════════════════════════════════════════

class FileWatchdog(threading.Thread):
    """Watches protected files - detects access, deletion, modification, and new files."""

    def __init__(self, config, notifier):
        super().__init__(daemon=True)
        self.config = config
        self.notifier = notifier
        self.running = True
        self.protected_paths = config.get("protected_files", [])
        self.extensions = set(config.get("protected_file_extensions", []))
        self.tracked_files = {}  # {path: {"atime": x, "mtime": y, "size": z}}
        self._scan_initial()

    def _get_file_info(self, f):
        """Get file stats for tracking."""
        try:
            stat = f.stat()
            return {"atime": stat.st_atime, "mtime": stat.st_mtime, "size": stat.st_size}
        except:
            return None

    def _get_all_files(self):
        """Get all files currently in protected paths."""
        current_files = {}
        for path in self.protected_paths:
            p = Path(path)
            if p.is_file():
                info = self._get_file_info(p)
                if info:
                    current_files[str(p)] = info
            elif p.is_dir():
                try:
                    for f in p.rglob("*"):
                        if f.is_file():
                            # Monitor all files in protected folders, not just certain extensions
                            info = self._get_file_info(f)
                            if info:
                                current_files[str(f)] = info
                except:
                    pass
        return current_files

    def _scan_initial(self):
        """Record initial state of all protected files."""
        self.tracked_files = self._get_all_files()

    def run(self):
        if not self.protected_paths:
            return

        logging.info(f"  📂 File Watchdog: Monitoring {len(self.protected_paths)} paths ({len(self.tracked_files)} files)")

        while self.running:
            try:
                current_files = self._get_all_files()
                current_paths = set(current_files.keys())
                tracked_paths = set(self.tracked_files.keys())

                # ── Detect DELETED files ──
                deleted = tracked_paths - current_paths
                for fpath in deleted:
                    fname = os.path.basename(fpath)
                    old_size = self.tracked_files[fpath]["size"]
                    self.notifier.send_alert(
                        title="🗑️ PROTECTED FILE DELETED",
                        message=(
                            f"🚨 A protected file was DELETED!\n\n"
                            f"📄 File: {fname}\n"
                            f"📂 Path: {fpath}\n"
                            f"📏 Size was: {old_size / 1024:.1f} KB\n"
                            f"🕐 Detected: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                            f"🔍 ACTION: Check who deleted this file!\n"
                            f"   Check Recycle Bin to recover it."
                        ),
                        severity="CRITICAL"
                    )
                    logging.info(f"  🗑️ DELETED: {fpath}")

                # ── Detect NEW files added ──
                new_files = current_paths - tracked_paths
                for fpath in new_files:
                    fname = os.path.basename(fpath)
                    size = current_files[fpath]["size"]
                    self.notifier.send_alert(
                        title="📄 NEW FILE IN PROTECTED FOLDER",
                        message=(
                            f"A new file appeared in a protected folder.\n\n"
                            f"📄 File: {fname}\n"
                            f"📂 Path: {fpath}\n"
                            f"📏 Size: {size / 1024:.1f} KB\n"
                            f"🕐 Detected: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                            f"🔍 Could be legitimate or dropped by malware."
                        ),
                        severity="MEDIUM"
                    )

                # ── Detect ACCESSED or MODIFIED files ──
                for fpath in current_paths & tracked_paths:
                    old = self.tracked_files[fpath]
                    new = current_files[fpath]
                    fname = os.path.basename(fpath)

                    # File was MODIFIED (content changed)
                    if new["mtime"] > old["mtime"]:
                        size_change = new["size"] - old["size"]
                        change_str = f"+{size_change/1024:.1f}" if size_change >= 0 else f"{size_change/1024:.1f}"
                        self.notifier.send_alert(
                            title="✏️ PROTECTED FILE MODIFIED",
                            message=(
                                f"⚠️ A protected file was edited!\n\n"
                                f"📄 File: {fname}\n"
                                f"📂 Path: {fpath}\n"
                                f"📏 Size: {old['size']/1024:.1f} KB → {new['size']/1024:.1f} KB ({change_str} KB)\n"
                                f"🕐 Modified: {datetime.fromtimestamp(new['mtime']).strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                                f"🔍 ACTION: Verify this change was authorized."
                            ),
                            severity="HIGH"
                        )

                    # File was OPENED (accessed but not modified)
                    elif new["atime"] > old["atime"]:
                        self.notifier.send_alert(
                            title="📂 PROTECTED FILE ACCESSED",
                            message=(
                                f"⚠️ Someone opened a protected file!\n\n"
                                f"📄 File: {fname}\n"
                                f"📂 Path: {fpath}\n"
                                f"📏 Size: {new['size']/1024:.1f} KB\n"
                                f"🕐 Accessed: {datetime.fromtimestamp(new['atime']).strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                                f"🔍 ACTION: Check who accessed this file."
                            ),
                            severity="HIGH"
                        )

                # Update tracked state
                self.tracked_files = current_files

                time.sleep(3)
            except Exception as e:
                logging.debug(f"Watchdog error: {e}")
                time.sleep(5)


# ═══════════════════════════════════════════════════════════════════
# SOFTWARE INSTALL MONITOR
# ═══════════════════════════════════════════════════════════════════

class SoftwareMonitor(threading.Thread):
    """Monitors for new software installations."""

    def __init__(self, notifier):
        super().__init__(daemon=True)
        self.notifier = notifier
        self.running = True
        self.known_software = set()
        self._scan_initial()

    def _get_installed_software(self):
        """Get list of installed software from registry."""
        software = set()
        if sys.platform != "win32":
            return software

        try:
            import winreg
            paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            ]
            for reg_path in paths:
                for hive in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                    try:
                        key = winreg.OpenKey(hive, reg_path)
                        i = 0
                        while True:
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                subkey = winreg.OpenKey(key, subkey_name)
                                try:
                                    name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                    if name:
                                        software.add(name)
                                except:
                                    pass
                                winreg.CloseKey(subkey)
                                i += 1
                            except OSError:
                                break
                        winreg.CloseKey(key)
                    except:
                        continue
        except:
            pass
        return software

    def _scan_initial(self):
        self.known_software = self._get_installed_software()
        logging.info(f"  📦 Software Monitor: Tracking {len(self.known_software)} installed programs")

    def run(self):
        while self.running:
            try:
                time.sleep(30)  # Check every 30 seconds
                current = self._get_installed_software()
                new_software = current - self.known_software
                removed_software = self.known_software - current

                for sw in new_software:
                    self.notifier.send_alert(
                        title="📦 NEW SOFTWARE INSTALLED",
                        message=(
                            f"⚠️ New software was installed on this computer!\n\n"
                            f"📦 Software: {sw}\n"
                            f"🕐 Detected: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                            f"🔍 ACTION: Verify this installation was authorized.\n"
                            f"   Malware often disguises itself as legitimate software."
                        ),
                        severity="HIGH"
                    )

                for sw in removed_software:
                    self.notifier.send_alert(
                        title="🗑️ SOFTWARE REMOVED",
                        message=(
                            f"📋 Software was uninstalled from this computer.\n\n"
                            f"🗑️ Software: {sw}\n"
                            f"🕐 Detected: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                        ),
                        severity="MEDIUM"
                    )

                self.known_software = current
            except Exception as e:
                logging.debug(f"Software monitor error: {e}")
                time.sleep(30)


# ═══════════════════════════════════════════════════════════════════
# THREAT ENGINE - Smart analysis
# ═══════════════════════════════════════════════════════════════════

class ThreatEngine:
    def __init__(self, config):
        self.config = config.get("threat_detection", {})
        self.failed_logins = defaultdict(list)

    def is_system_account(self, name):
        if not name:
            return True
        return name.strip().upper() in {a.upper() for a in SYSTEM_ACCOUNTS} or name.endswith("$")

    def check_brute_force(self, account, source_ip):
        now = datetime.now()
        window = self.config.get("failed_login_window_seconds", 300)
        threshold = self.config.get("failed_login_threshold", 3)

        key = f"{account}_{source_ip}"
        self.failed_logins[key].append(now)
        self.failed_logins[key] = [t for t in self.failed_logins[key] if (now - t).total_seconds() < window]

        count = len(self.failed_logins[key])
        return {"is_attack": count >= threshold, "count": count}

    def check_process(self, process_path, command_line=""):
        if not process_path:
            return None

        proc_name = os.path.basename(process_path).lower()

        # Check known malware/hacking tools
        for pattern, (severity, desc) in MALWARE_PROCESSES.items():
            if pattern.endswith("*"):
                if proc_name.startswith(pattern[:-1]):
                    return {"severity": severity, "reason": desc, "process": proc_name}
            elif proc_name == pattern:
                return {"severity": severity, "reason": desc, "process": proc_name}

        # Check suspicious PowerShell
        if proc_name in ("powershell.exe", "pwsh.exe") and command_line:
            cmd_lower = command_line.lower()
            for flag in SUSPICIOUS_POWERSHELL_ARGS:
                if flag in cmd_lower:
                    return {
                        "severity": "CRITICAL",
                        "reason": f"Suspicious PowerShell: {flag.strip()}",
                        "process": proc_name,
                        "command": command_line[:300]
                    }

        return None

    def analyze(self, event_id, data):
        strings = data.get("strings", [])
        computer = data.get("computer", "?")
        etime = data.get("time", "?")

        # ── FAILED LOGIN → Brute Force ──
        if event_id == 4625:
            account = strings[5] if len(strings) > 5 else "?"
            source_ip = strings[19] if len(strings) > 19 else "-"
            reason = strings[8] if len(strings) > 8 else "?"

            if self.is_system_account(account):
                return None

            bf = self.check_brute_force(account, source_ip)
            if bf["is_attack"]:
                return {
                    "severity": "CRITICAL",
                    "title": "🚨 BRUTE FORCE ATTACK",
                    "message": (
                        f"⚠️ {bf['count']} failed logins detected!\n\n"
                        f"👤 Target: {account}\n"
                        f"🌐 Source IP: {source_ip}\n"
                        f"❌ Reason: {reason}\n"
                        f"🖥️ Computer: {computer}\n"
                        f"🕐 Time: {etime}\n\n"
                        f"🔍 ACTION: Block IP {source_ip} if unknown."
                    )
                }
            return None

        # ── SUCCESSFUL LOGIN (RDP/Network only) ──
        if event_id == 4624:
            account = strings[5] if len(strings) > 5 else "?"
            logon_type = strings[8] if len(strings) > 8 else "0"
            source_ip = strings[18] if len(strings) > 18 else "-"

            if self.is_system_account(account):
                return None
            if logon_type in ("0", "5"):  # System/Service
                return None

            if logon_type == "10":  # RDP
                return {
                    "severity": "CRITICAL",
                    "title": "🚨 REMOTE DESKTOP LOGIN",
                    "message": (
                        f"Someone connected via Remote Desktop!\n\n"
                        f"👤 Account: {account}\n"
                        f"🌐 Source IP: {source_ip}\n"
                        f"🖥️ Computer: {computer}\n"
                        f"🕐 Time: {etime}\n\n"
                        f"🔍 If this wasn't you, someone has remote access!"
                    )
                }
            if logon_type == "3":  # Network
                return {
                    "severity": "HIGH",
                    "title": "🔴 NETWORK LOGIN",
                    "message": (
                        f"Network login detected.\n\n"
                        f"👤 Account: {account}\n"
                        f"🌐 Source IP: {source_ip}\n"
                        f"🖥️ Computer: {computer}\n"
                        f"🕐 Time: {etime}"
                    )
                }
            return None

        # ── ADMIN PRIVILEGES (Human only) ──
        if event_id == 4672:
            account = strings[1] if len(strings) > 1 else "?"
            if self.is_system_account(account):
                return None
            return {
                "severity": "HIGH",
                "title": "🔴 ADMIN PRIVILEGES GRANTED",
                "message": f"👤 Account: {account}\n🖥️ Computer: {computer}\n🕐 Time: {etime}"
            }

        # ── NEW USER CREATED ──
        if event_id == 4720:
            account = strings[0] if strings else "?"
            by = strings[4] if len(strings) > 4 else "?"
            return {
                "severity": "CRITICAL",
                "title": "🚨 NEW USER ACCOUNT CREATED",
                "message": f"👤 New Account: {account}\n🔧 Created By: {by}\n🖥️ Computer: {computer}\n🕐 Time: {etime}\n\n🔍 Attackers create accounts for persistence!"
            }

        # ── ACCOUNT DELETED ──
        if event_id == 4726:
            account = strings[0] if strings else "?"
            return {
                "severity": "HIGH",
                "title": "🔴 USER ACCOUNT DELETED",
                "message": f"👤 Deleted Account: {account}\n🖥️ Computer: {computer}\n🕐 Time: {etime}"
            }

        # ── PASSWORD RESET ──
        if event_id == 4724:
            account = strings[0] if strings else "?"
            return {
                "severity": "HIGH",
                "title": "🔴 PASSWORD RESET",
                "message": f"👤 Account: {account}\n🖥️ Computer: {computer}\n🕐 Time: {etime}"
            }

        # ── USER ADDED TO ADMIN GROUP ──
        if event_id == 4732:
            return {
                "severity": "CRITICAL",
                "title": "🚨 USER ADDED TO ADMIN GROUP",
                "message": f"⚠️ Someone was added to a privileged group!\n🖥️ Computer: {computer}\n🕐 Time: {etime}\n\n🔍 This is a common privilege escalation technique!"
            }

        # ── AUDIT LOG CLEARED ──
        if event_id == 1102:
            return {
                "severity": "CRITICAL",
                "title": "🚨 SECURITY LOGS CLEARED",
                "message": f"⚠️ Someone cleared the security audit logs!\n🖥️ Computer: {computer}\n🕐 Time: {etime}\n\n🔍 This is a sign of evidence tampering. Investigate immediately!"
            }

        # ── AUDIT POLICY CHANGED ──
        if event_id == 4719:
            return {
                "severity": "HIGH",
                "title": "🔴 AUDIT POLICY CHANGED",
                "message": f"Security audit policy was modified.\n🖥️ Computer: {computer}\n🕐 Time: {etime}"
            }

        # ── NEW SERVICE INSTALLED ──
        if event_id == 7045:
            svc = strings[0] if strings else "?"
            path = strings[1] if len(strings) > 1 else "?"
            return {
                "severity": "HIGH",
                "title": "🔴 NEW SERVICE INSTALLED",
                "message": f"⚙️ Service: {svc}\n📂 Path: {path}\n🖥️ Computer: {computer}\n🕐 Time: {etime}\n\n🔍 Malware installs services for persistence."
            }

        # ── FIREWALL CHANGES ──
        if event_id == 2004:
            return {
                "severity": "HIGH",
                "title": "🔴 FIREWALL RULE ADDED",
                "message": f"A new firewall rule was added.\n🖥️ Computer: {computer}\n🕐 Time: {etime}"
            }
        if event_id == 2006:
            return {
                "severity": "MEDIUM",
                "title": "🟡 FIREWALL RULE DELETED",
                "message": f"A firewall rule was deleted.\n🖥️ Computer: {computer}\n🕐 Time: {etime}"
            }

        # ── RDP SESSION ──
        if event_id == 4778:
            account = strings[0] if strings else "?"
            source = strings[4] if len(strings) > 4 else "?"
            return {
                "severity": "CRITICAL",
                "title": "🚨 REMOTE DESKTOP CONNECTION",
                "message": f"👤 Account: {account}\n🌐 Source: {source}\n🖥️ Computer: {computer}\n🕐 Time: {etime}\n\n🔍 If unexpected, someone has remote access!"
            }

        # ── PROCESS CREATION (suspicious only) ──
        if event_id == 4688:
            proc = strings[5] if len(strings) > 5 else ""
            cmd = strings[8] if len(strings) > 8 else ""

            result = self.check_process(proc, cmd)
            if result:
                return {
                    "severity": result["severity"],
                    "title": f"🚨 MALICIOUS PROCESS DETECTED",
                    "message": (
                        f"⚠️ {result['reason']}\n\n"
                        f"⚙️ Process: {result['process']}\n"
                        f"💻 Command: {result.get('command', proc)}\n"
                        f"🖥️ Computer: {computer}\n"
                        f"🕐 Time: {etime}\n\n"
                        f"🔍 ACTION: Kill this process and investigate!"
                    )
                }
            return None

        # ── WINDOWS DEFENDER ALERTS ──
        if event_id == 1116:  # Defender detected malware
            return {
                "severity": "CRITICAL",
                "title": "🦠 VIRUS/MALWARE DETECTED",
                "message": f"⚠️ Windows Defender detected a threat!\n🖥️ Computer: {computer}\n🕐 Time: {etime}\n\n🔍 Check Windows Security for details and quarantine the threat!"
            }
        if event_id == 1117:  # Defender took action
            return {
                "severity": "HIGH",
                "title": "🛡️ DEFENDER ACTION TAKEN",
                "message": f"Windows Defender took action against a threat.\n🖥️ Computer: {computer}\n🕐 Time: {etime}"
            }

        return None


# ═══════════════════════════════════════════════════════════════════
# MAIN MONITOR
# ═══════════════════════════════════════════════════════════════════

MONITORED_IDS = {4625, 4624, 4672, 4720, 4724, 4726, 4732, 1102, 4719, 7045, 2004, 2006, 4778, 4688, 4648, 1116, 1117}

class SecurityMonitor:
    def __init__(self, config, silent=False):
        self.config = config
        self.silent = silent
        self.notifier = NotificationManager(config)
        self.engine = ThreatEngine(config)
        self.running = False
        self.stats = {"events": 0, "threats": 0, "filtered": 0}
        self.start_time = None
        self.last_check = datetime.now()

        log_file = config.get("monitor_settings", {}).get("log_file", "security_events.log")
        handlers = [logging.FileHandler(log_file, encoding="utf-8")]
        if not silent:
            handlers.append(logging.StreamHandler())

        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                           handlers=handlers, force=True)

    def _parse_time(self, time_str):
        for fmt in ["%a %b %d %H:%M:%S %Y", "%m/%d/%y %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"]:
            try:
                return datetime.strptime(time_str, fmt)
            except:
                continue
        return None

    def _scan_logs(self):
        for log_name in ["Security", "System", "Microsoft-Windows-Windows Defender/Operational"]:
            try:
                hand = win32evtlog.OpenEventLog(None, log_name)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

                while True:
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    if not events:
                        break
                    for event in events:
                        et = self._parse_time(event.TimeGenerated.Format())
                        if et is None or et <= self.last_check:
                            win32evtlog.CloseEventLog(hand)
                            return

                        eid = event.EventID & 0xFFFF
                        if eid not in MONITORED_IDS:
                            continue

                        self.stats["events"] += 1
                        data = {
                            "event_id": eid,
                            "time": event.TimeGenerated.Format(),
                            "source": event.SourceName,
                            "computer": event.ComputerName,
                            "strings": list(event.StringInserts) if event.StringInserts else []
                        }

                        result = self.engine.analyze(eid, data)
                        if result:
                            self.stats["threats"] += 1
                            logging.info(f"🚨 [{result['severity']}] {result['title']}")
                            self.notifier.send_alert(result["title"], result["message"], result["severity"])
                        else:
                            self.stats["filtered"] += 1

                win32evtlog.CloseEventLog(hand)
            except Exception as e:
                if "The specified channel" not in str(e) and "does not exist" not in str(e):
                    logging.debug(f"Log read error ({log_name}): {e}")

    def _check_usb(self):
        try:
            c = wmi.WMI()
            w = c.Win32_DeviceChangeEvent.watch_for(notification_type="Creation", delay_secs=1)
            event = w(timeout_ms=100)
            if event:
                for usb in c.Win32_USBControllerDevice():
                    d = usb.Dependent
                    self.notifier.send_alert(
                        "🔌 USB DEVICE CONNECTED",
                        f"🔌 Device: {d.Caption}\n🆔 ID: {d.DeviceID}\n🕐 Time: {datetime.now().strftime('%H:%M:%S')}\n\n🔍 USB devices can carry malware or steal data.",
                        "MEDIUM"
                    )
        except:
            pass

    def start(self):
        if sys.platform != "win32":
            print("[!] Use --test to test notifications.")
            return

        self.running = True
        self.start_time = datetime.now()
        poll = self.config.get("monitor_settings", {}).get("poll_interval_seconds", 5)

        # Start background threads
        file_watchdog = FileWatchdog(self.config, self.notifier)
        file_watchdog.start()

        sw_monitor = SoftwareMonitor(self.notifier)
        sw_monitor.start()

        if not self.silent:
            print("\n" + "=" * 55)
            print("  🛡️  SECURITY MONITOR v3.0 - STEALTH EDITION")
            print("=" * 55)
            print(f"  📱  Alerts via  : {self.config.get('notification_method', 'email').upper()}")
            print(f"  🔇  Noise Filter: ON")
            print(f"  📂  File Watch  : {len(self.config.get('protected_files', []))} paths")
            print(f"  📦  Software Mon: ON")
            print(f"  🕐  Started     : {self.start_time.strftime('%H:%M:%S')}")
            print("=" * 55)
            print("  Ctrl+C to stop\n")

        def stop(sig, frame):
            self.running = False
        signal.signal(signal.SIGINT, stop)

        while self.running:
            try:
                self._scan_logs()
                self._check_usb()
                self.last_check = datetime.now()
                if not self.silent:
                    u = datetime.now() - self.start_time
                    h, r = divmod(int(u.total_seconds()), 3600)
                    m, s = divmod(r, 60)
                    print(f"\r  🛡️ {h:02d}:{m:02d}:{s:02d} | Scanned: {self.stats['events']} | Threats: {self.stats['threats']} | Filtered: {self.stats['filtered']}  ", end="", flush=True)
                time.sleep(poll)
            except Exception as e:
                logging.error(f"Error: {e}")
                time.sleep(poll)

        file_watchdog.running = False
        sw_monitor.running = False


# ═══════════════════════════════════════════════════════════════════
# STEALTH MODE - Run silently with no window
# ═══════════════════════════════════════════════════════════════════

def install_stealth(script_path):
    """Create a VBS launcher that runs the monitor with no visible window."""
    vbs_content = f'''Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "pythonw ""{script_path}"" --silent", 0, False
'''
    vbs_path = Path(script_path).parent / "stealth_launcher.vbs"
    with open(vbs_path, "w") as f:
        f.write(vbs_content)

    # Create startup shortcut
    startup_dir = Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup"
    startup_vbs = startup_dir / "SecurityMonitor.vbs"

    try:
        with open(startup_vbs, "w") as f:
            f.write(vbs_content)
        print(f"  ✅ Stealth launcher created!")
        print(f"  ✅ Auto-start added to: {startup_vbs}")
        print(f"\n  The monitor will now:")
        print(f"    • Start automatically when Windows boots")
        print(f"    • Run completely hidden (no window)")
        print(f"    • Send alerts silently to your email/phone")
        print(f"\n  To stop: Open Task Manager → find 'pythonw' → End Task")
        print(f"  To remove auto-start: delete {startup_vbs}")
    except Exception as e:
        print(f"  ⚠️ Could not create startup entry: {e}")
        print(f"  Manual setup: Copy {vbs_path} to your Startup folder")


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
        # Add new v3 fields if missing
        changed = False
        for key in ["protected_files", "protected_file_extensions", "threat_detection"]:
            if key not in config:
                config[key] = DEFAULT_CONFIG[key]
                changed = True
        if changed:
            with open(CONFIG_FILE, "w") as f:
                json.dump(config, f, indent=4)
        return config
    else:
        with open(CONFIG_FILE, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        return DEFAULT_CONFIG

def setup_wizard():
    print("\n" + "=" * 55)
    print("  🧙 SECURITY MONITOR v3.0 - SETUP")
    print("=" * 55)

    config = DEFAULT_CONFIG.copy()

    print("\n  [1] Gmail Email (recommended)")
    print("  [2] Telegram Bot (needs VPN in PK)")
    choice = input("\n  Choice (1/2): ").strip()

    if choice == "2":
        config["notification_method"] = "telegram"
        config["telegram"]["bot_token"] = input("  Bot Token: ").strip()
        config["telegram"]["chat_id"] = input("  Chat ID: ").strip()
    else:
        config["notification_method"] = "email"
        print("\n  📧 Get App Password: myaccount.google.com/apppasswords")
        config["email"]["sender_email"] = input("  Gmail: ").strip()
        config["email"]["sender_password"] = input("  App Password: ").strip()
        r = input("  Receiver email (Enter=same): ").strip()
        config["email"]["receiver_email"] = r if r else config["email"]["sender_email"]

    # Protected files setup
    print("\n  📂 PROTECTED FILES SETUP:")
    print("  Add files/folders to monitor (Enter to skip):")
    print("  Example: C:\\Users\\haier\\Desktop\\secret_folder")
    paths = []
    while True:
        p = input("  Path (Enter to finish): ").strip()
        if not p:
            break
        paths.append(p)
    config["protected_files"] = paths

    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)
    print("\n  ✅ Saved!")

    if input("\n  Send test? (y/n): ").strip().lower() == "y":
        n = NotificationManager(config)
        if n.send_test():
            print("  ✅ Test sent! Check your phone/email.")
        else:
            print("  ❌ Failed. Check config.json")

def main():
    parser = argparse.ArgumentParser(description="🛡️ Security Monitor v3.0")
    parser.add_argument("--setup", action="store_true")
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--start", action="store_true")
    parser.add_argument("--silent", action="store_true", help="Run with no console output")
    parser.add_argument("--stealth", action="store_true", help="Install stealth mode (auto-start, no window)")
    parser.add_argument("--protect", nargs="+", help="Add protected file/folder paths")
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args()

    if args.setup:
        setup_wizard()
        return

    config = load_config()

    if args.test:
        print("\n  📱 Sending test...")
        n = NotificationManager(config)
        print("  ✅ Sent!" if n.send_test() else "  ❌ Failed. Run --setup")
        return

    if args.protect:
        paths = config.get("protected_files", [])
        for p in args.protect:
            if p not in paths:
                paths.append(p)
                print(f"  ✅ Protected: {p}")
        config["protected_files"] = paths
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
        return

    if args.stealth:
        script = str(Path(__file__).resolve())
        install_stealth(script)
        return

    if args.status:
        print(f"\n  📋 Method: {config.get('notification_method')}")
        print(f"  📂 Protected files: {len(config.get('protected_files', []))}")
        for p in config.get("protected_files", []):
            print(f"     → {p}")
        td = config.get("threat_detection", {})
        print(f"  🎯 Brute force: {td.get('failed_login_threshold', 3)} fails in {td.get('failed_login_window_seconds', 300)}s")
        return

    method = config.get("notification_method", "email")
    if "YOUR_" in json.dumps(config.get(method, {})):
        print(f"\n  ⚠️ Not configured! Run: python {Path(__file__).name} --setup\n")
        return

    monitor = SecurityMonitor(config, silent=args.silent)
    monitor.start()

if __name__ == "__main__":
    main()
