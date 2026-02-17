
# 🛡️ N-Guard v1.0 Advanced EDR-Ready Malware Defense Toolkit

**CyberGuard Pro** is an enterprise-grade **Endpoint Detection and Response (EDR)** toolkit designed to protect Windows systems from modern cyber threats. It combines **static analysis**, **behavioral monitoring**, **machine learning**, **cloud intelligence**, and **real‑time response** to detect, analyze, and neutralize malware, ransomware, and network attacks.

> **⚠️ Important**  
> This tool is intended for **security professionals**, **system administrators**, and **researchers**. It requires **administrator privileges** for full functionality (ETW, registry monitoring, firewall blocking).

---

## ✨ Key Features

| Category | Features |
|----------|----------|
| **🔍 Static Analysis** | – Hash calculation (MD5, SHA1, SHA256)<br>– File type detection via magic bytes<br>– Deep PE analysis (suspicious imports, entropy, packers, entry point anomalies, timestamp checks)<br>– String extraction (with size limits) & heuristic pattern matching (URLs, PowerShell, base64, ransomware keywords)<br>– **YARA rule scanning** (hot‑reload support) |
| **🧠 Machine Learning** | – Random Forest classifier trained on file features (size, entropy, suspicious imports, packed status, digital signature)<br>– Real‑time probability scoring integrated into threat scoring engine |
| **☁️ Cloud Intelligence** | – **VirusTotal** hash lookup (with optional file upload, size‑limited to 32 MB)<br>– **AbuseIPDB** IP reputation check for outbound connections |
| **📊 Behavioral Monitoring** | – **File system** (watchdog) – monitors file creation/modification in watched directories<br>– **Process** (psutil) – detects new processes, network connections, file access, suspicious command lines<br>– **Network** – detects port scans (SYN‑sent tracking) and automatically blocks offending IPs via Windows Firewall<br>– **ETW (Windows)** – monitors security events (process creation) – needs admin<br>– **Registry** – monitors persistence locations (Run, RunOnce, Services) |
| **⚖️ Threat Scoring** | Weighted scoring from all detectors, producing a verdict:<br>– **CLEAN** (0‑4)<br>– **SUSPICIOUS** (5‑9)<br>– **MALICIOUS** (10‑14)<br>– **CRITICAL** (15+) |
| **🚨 Response Actions** | – Automatic **quarantine** (AES‑256 encrypted ZIP with password)<br>– **Sandbox execution** via Sandboxie‑Plus (if installed)<br>– **Process termination** (whitelist‑protected)<br>– Interactive prompts for user decisions<br>– All events logged to **SQLite** database and shown in **real‑time web dashboard** |
| **🌐 Web Dashboard** | Built with **Flask** – live alerts, system stats, easy monitoring at `http://localhost:5000` |

---

## 📦 Requirements

- **Python 3.8+**
- **Windows** (for full EDR capabilities; some features work on Linux, but ETW, registry, and firewall blocking are Windows‑only)
- **Administrator privileges** (for ETW, firewall blocking, and some registry monitoring)

### Python Libraries

Install all dependencies with `pip` (see [Installation](#installation)):

```
yara-python, requests, pefile, psutil, watchdog, python-magic, python-dotenv,
pyzipper, joblib, scikit-learn, numpy, flask, pywin32
 ```


---

## 🔧 Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/cyberguard-pro.git
cd cyberguard-pro

python -m venv venv
venv\Scripts\activate   # On Windows
pip install -r requirements.txt
