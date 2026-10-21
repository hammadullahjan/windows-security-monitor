# 🛡️ Windows Security Monitor v3.0 — Stealth Edition

A real-time Windows endpoint security monitoring tool that detects threats, malware, brute force attacks, file tampering, and suspicious activity — and sends instant alerts to your phone via Email or Telegram.

Built as a cybersecurity portfolio project demonstrating endpoint detection & response (EDR) capabilities.

---

## 🎯 Features

### 🧠 Smart Threat Detection
- **Brute Force Detection** — Alerts when multiple failed logins occur within a time window (configurable threshold)
- **Malware & Hacking Tool Detection** — Identifies 40+ known attack tools (Mimikatz, PsExec, Netcat, Cobalt Strike, etc.)
- **Suspicious PowerShell Monitoring** — Catches encoded commands, hidden windows, download cradles, AMSI bypasses
- **Ransomware Indicators** — Detects shadow copy deletion, backup tampering, boot config changes
- **Windows Defender Integration** — Alerts when Defender detects or quarantines malware

### 📂 File Protection
- **Access Alerts** — Know when someone opens your protected files
- **Deletion Alerts** — Instant CRITICAL alert when protected files are deleted
- **Modification Alerts** — Detects edits with before/after file size comparison
- **New File Detection** — Alerts when unknown files appear in protected folders

### 📦 Software Monitoring
- **Install Detection** — Alerts when new software is installed on the system
- **Uninstall Detection** — Alerts when software is removed
- Scans Windows Registry every 30 seconds for changes

### 🔐 Security Event Monitoring
- Failed & successful logins (human only, system noise filtered)
- RDP (Remote Desktop) connection alerts
- New user account creation
- Password resets & account deletions
- Privilege escalation detection
- Firewall rule changes
- New service installations
- Audit log clearing (anti-forensics)
- USB device connections

### 🥷 Stealth Mode
- Runs completely hidden with no visible window
- Auto-starts on Windows boot
- No taskbar icon, no console — fully invisible
- All activity logged silently to file

### 🔇 Noise Filtering
- System accounts (SYSTEM, LOCAL SERVICE, NETWORK SERVICE) are ignored
- Background Windows service logons are filtered
- Only real human actions and genuine threats trigger alerts
- Single failed login won't alert — brute force pattern required

---

## 📸 Alert Examples

### Email Alert
```
🚨 [CRITICAL] BRUTE FORCE ATTACK
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️ 5 failed login attempts detected!

👤 Target: Administrator
🌐 Source IP: 192.168.1.105
❌ Reason: Bad password
🖥️ Computer: DESKTOP-ABC123
🕐 Time: 2026-05-15 14:30:22

🔍 ACTION: Block IP 192.168.1.105 if unknown.
```

### File Deletion Alert
```
🚨 [CRITICAL] PROTECTED FILE DELETED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚨 A protected file was DELETED!

📄 File: passwords.xlsx
📂 Path: C:\Users\haier\Documents\passwords.xlsx
📏 Size was: 24.5 KB
🕐 Detected: 2026-05-15 18:45:10

🔍 ACTION: Check who deleted this file!
   Check Recycle Bin to recover it.
```

---

## 🚀 Quick Start

### Prerequisites
- Windows 10/11
- Python 3.8+
- Admin privileges (to read Security event logs)

### Installation

```bash
# Clone the repository
git clone https://github.com/hammadullahjan/windows-security-monitor.git
cd windows-security-monitor

# Install dependencies
pip install -r requirements.txt
python -m pywin32_postinstall -install
```

### Setup Notifications

```bash
python windows_security_monitor.py --setup
```

Choose **Gmail Email** (recommended) or **Telegram Bot** and follow the prompts.

> **Gmail Setup:** You need an App Password, not your regular password.
> Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords) (requires 2-Step Verification enabled).

### Start Monitoring

```bash
# Run as Administrator
python windows_security_monitor.py --start
```

---

## 📖 Usage

```bash
# First-time setup
python windows_security_monitor.py --setup

# Start monitoring (visible mode)
python windows_security_monitor.py --start

# Send test notification
python windows_security_monitor.py --test

# Add protected files/folders
python windows_security_monitor.py --protect "C:\path\to\secret" "C:\path\to\file.pdf"

# Install stealth mode (hidden + auto-start on boot)
python windows_security_monitor.py --stealth

# Run silently (no console output)
python windows_security_monitor.py --silent

# View current configuration
python windows_security_monitor.py --status
```

---

## ⚙️ Configuration

After running `--setup`, a `config.json` is created:

```json
{
    "notification_method": "email",
    "email": {
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "sender_email": "you@gmail.com",
        "sender_password": "xxxx xxxx xxxx xxxx",
        "receiver_email": "you@gmail.com"
    },
    "monitor_settings": {
        "poll_interval_seconds": 5,
        "alert_cooldown_seconds": 30,
        "max_alerts_per_hour": 50
    },
    "threat_detection": {
        "failed_login_threshold": 3,
        "failed_login_window_seconds": 300
    },
    "protected_files": [
        "C:\\Users\\you\\Desktop\\secret_folder",
        "C:\\Users\\you\\Documents\\passwords.xlsx"
    ]
}
```

### Tunable Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `poll_interval_seconds` | 5 | How often to scan event logs |
| `alert_cooldown_seconds` | 30 | Minimum gap between duplicate alerts |
| `max_alerts_per_hour` | 50 | Rate limit to prevent email spam |
| `failed_login_threshold` | 3 | Failed logins before brute force alert |
| `failed_login_window_seconds` | 300 | Time window for brute force detection |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────┐
│           Security Monitor v3.0             │
├─────────────────────────────────────────────┤
│                                             │
│  ┌───────────┐  ┌───────────┐  ┌─────────┐ │
│  │  Event     │  │  File     │  │Software │ │
│  │  Log       │  │  Watchdog │  │Monitor  │ │
│  │  Scanner   │  │  Thread   │  │Thread   │ │
│  └─────┬─────┘  └─────┬─────┘  └────┬────┘ │
│        │              │              │      │
│        ▼              ▼              ▼      │
│  ┌─────────────────────────────────────────┐│
│  │         Threat Analysis Engine          ││
│  │  • System account filtering            ││
│  │  • Brute force correlation             ││
│  │  • Suspicious process matching         ││
│  │  • Severity classification             ││
│  └──────────────────┬──────────────────────┘│
│                     │                       │
│                     ▼                       │
│  ┌─────────────────────────────────────────┐│
│  │        Notification Manager             ││
│  │  • Rate limiting & cooldown             ││
│  │  • Gmail SMTP / Telegram Bot            ││
│  │  • HTML formatted alerts                ││
│  └──────────────────┬──────────────────────┘│
│                     │                       │
│                     ▼                       │
│              📱 Your Phone                  │
└─────────────────────────────────────────────┘
```

---

## 🔍 Detected Threats

### Critical Severity
| Threat | Event ID | Description |
|--------|----------|-------------|
| Brute Force Attack | 4625 (×3+) | Multiple failed logins in time window |
| RDP Connection | 4778 | Remote desktop session connected |
| New User Created | 4720 | Attacker creating persistence account |
| Admin Group Change | 4732 | Privilege escalation |
| Audit Log Cleared | 1102 | Evidence tampering |
| Mimikatz / Credential Dump | 4688 | Known hacking tool executed |
| Ransomware Indicators | 4688 | Shadow copy deletion detected |
| Virus Detected | 1116 | Windows Defender found malware |
| Protected File Deleted | — | File watchdog detection |

### High Severity
| Threat | Event ID | Description |
|--------|----------|-------------|
| Network Login | 4624 (type 3) | Login from network |
| Password Reset | 4724 | Account password changed |
| New Service Installed | 7045 | Possible malware persistence |
| Firewall Rule Added | 2004 | Firewall tampering |
| Suspicious PowerShell | 4688 | Encoded/hidden/download commands |
| Protected File Modified | — | File content changed |
| Protected File Accessed | — | File opened/viewed |
| New Software Installed | — | Registry change detected |

### Medium Severity
| Threat | Event ID | Description |
|--------|----------|-------------|
| USB Device Connected | — | WMI device event |
| Firewall Rule Deleted | 2006 | Rule removed |
| New File in Protected Folder | — | Unknown file appeared |
| Software Removed | — | Program uninstalled |

---

## 🛡️ Stealth Mode

Install stealth mode to run the monitor completely hidden:

```bash
python windows_security_monitor.py --stealth
```

This creates:
- A VBS launcher script (runs Python with no window)
- A Windows Startup entry (auto-runs on boot)

**To stop stealth mode:**
- Open Task Manager → find `pythonw.exe` → End Task
- Delete `SecurityMonitor.vbs` from your Startup folder

---

## 📁 Project Structure

```
windows-security-monitor/
├── windows_security_monitor.py   # Main application
├── config.json                   # Configuration (auto-generated, gitignored)
├── security_events.log           # Event log file (auto-generated, gitignored)
├── requirements.txt              # Python dependencies
├── .gitignore                    # Git ignore rules
└── README.md                     # Documentation
```

---

## 🛠️ Tech Stack

- **Python 3.8+** — Core language
- **pywin32** — Windows Event Log API access
- **WMI** — USB device monitoring
- **smtplib** — Gmail SMTP email alerts
- **threading** — Concurrent file & software monitoring
- **Windows Event Log API** — Security, System, and Defender logs

---

## 🎓 Skills Demonstrated

This project demonstrates competency in:

- **Endpoint Detection & Response (EDR)** — Real-time threat monitoring
- **Security Event Analysis** — Windows Event Log parsing and correlation
- **Threat Intelligence** — Known malware/tool signature matching
- **Incident Alerting** — Multi-channel notification system
- **Digital Forensics** — File integrity monitoring and logging
- **Python Security Tooling** — System-level Windows programming
- **Anti-Forensics Detection** — Audit log tampering alerts
- **Brute Force Detection** — Login attempt correlation
- **Stealth Operations** — Silent background execution

Relevant for: **SOC Analyst**, **Security Engineer**, **Incident Response**, **Threat Analyst**, **Penetration Tester** roles.

---

## ⚠️ Disclaimer

This tool is designed for **monitoring your own systems** for security purposes. Always ensure you have proper authorization before monitoring any computer. Use responsibly and in accordance with applicable laws.

---

## 📄 License

MIT License — Free to use, modify, and distribute.

---

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.
