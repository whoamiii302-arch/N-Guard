# 🛡️ N-Guard v3.0 — Advanced EDR Security Toolkit

<div align="center">

![Version](https://img.shields.io/badge/version-3.0-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8%2B-yellow?style=for-the-badge&logo=python)
![Platform](https://img.shields.io/badge/Windows-10%2F11-0078D6?style=for-the-badge&logo=windows)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Tests](https://img.shields.io/badge/tests-33%2F33%20passing-brightgreen?style=for-the-badge)

**Enterprise-grade Endpoint Detection & Response toolkit for security teams**  
*Real ML · Online + Offline · Centralized Management · Windows Service*

[Installation](#-installation) • [Usage](#-usage) • [What's New](#-whats-new-in-v30) • [Architecture](#-architecture) • [FAQ](#-faq)

</div>

---

## 📋 Changelog

| Version | Date | Highlights |
|:---:|:---:|:---|
| **v3.0** | 2026 | Real ML training data, central server, Windows Service, online/offline auto-switch |
| v2.0 | 2026 | Statistical ML dataset, secured dashboard, extended monitoring, production server |
| v1.0 | 2026 | Initial release — YARA, file scanning, basic dashboard |

---

## ✨ What's New in v3.0

### 🧠 Real Malware Training Data (Major Change)
Previous versions trained the ML model on random statistical data. v3.0 uses **real malware samples**:

- **MalwareBazaar API** (free, no key required) — latest real-world malware metadata
- **GitHub IOC Feeds** — verified malicious hashes from Maltrail & PAN Unit42
- **Auto-update every 24 hours** — model retrains automatically with fresh data
- **Ensemble model**: GradientBoosting + RandomForest (Voting) — AUC > 0.95

### 🌐 Automatic Online / Offline Switching
```
Internet available  →  MalwareBazaar + VirusTotal + AbuseIPDB + ML model
No internet         →  Offline Hash DB + pre-trained ML model (local only)
```
The system detects connectivity automatically — no manual configuration needed.

### 🏢 Central Server (New)
- **One server + multiple agents** over a local network (LAN)
- **WebSocket dashboard** — alerts appear in real time without page refresh
- **Offline queue** — agents buffer alerts locally and flush when reconnected
- Separate authentication: `X-Agent-Secret` for agents, `X-Auth-Token` for dashboard

### 🖥️ Windows Service (New)
```bat
install_service.bat    ← one click, done
```
- Starts automatically with Windows
- Runs silently in the background
- Controlled via `sc start/stop NGuardAgent`

### 🔒 Security Hardening
- Quarantine passwords stored in **database only** — never in plain-text files
- Dashboard bound to `127.0.0.1` by default — not exposed to the network
- All secrets live in `.env` — never hardcoded

---

## 📊 Comparison

| Feature | N-Guard v3 | Malwarebytes | Bitdefender | Windows Defender |
|:---|:---:|:---:|:---:|:---:|
| Open source | ✅ | ❌ | ❌ | ❌ |
| Real ML training data | ✅ | ✅ | ✅ | ✅ |
| Offline detection | ✅ | ⚠️ | ⚠️ | ⚠️ |
| Centralized management | ✅ | ❌ | ✅ (paid) | ❌ |
| Windows Service | ✅ | ✅ | ✅ | ✅ |
| YARA rules | ✅ | ❌ | ❌ | ❌ |
| Firewall auto-block | ✅ | ❌ | ✅ | ⚠️ |
| Cost | 🆓 Free | 💰 Annual | 💰 Annual | 🆓 Free |

---

## 🏗️ Architecture

```
N-Guard v3.0
│
├── Central Server (one per network)
│   ├── Receives alerts from all agents via REST API
│   ├── WebSocket dashboard (real-time)
│   └── SQLite central database
│
└── Agent (one per endpoint)
    ├── File Monitor     — watchdog (create / modify events)
    ├── Process Monitor  — psutil (new processes, suspicious commands)
    ├── Network Monitor  — connection tracking, port scan detection
    ├── Registry Monitor — Run/RunOnce/Services persistence keys (Windows)
    ├── Static Analyzer  — hashes, PE analysis, YARA, string heuristics
    └── ML Engine        — offline hash DB + ensemble classifier
```

---

## 📁 Project Structure

```
N-Guard/
├── agent/
│   └── agent.py              ← Main agent (monitors + scanner + Windows Service)
├── ml/
│   └── engine.py             ← ML engine + offline hash DB + auto-update
├── server/
│   └── central_server.py     ← Central server + WebSocket dashboard
├── rules/                    ← YARA rules directory (hot-reload)
│   └── basic.yar
├── db/                       ← SQLite databases (auto-created)
│   ├── reputation.db         ← Local scan cache
│   ├── hash.db               ← Offline malware hash database
│   └── central.db            ← Central server database
├── models/                   ← ML model (auto-trained on first run)
│   └── nguard_ensemble.pkl
├── quarantine/               ← AES-256 encrypted quarantine ZIPs
├── logs/                     ← Rotating log files
├── tests/
│   └── test_v3.py            ← 33 automated tests
├── requirements.txt
├── .env.example
└── install_service.bat       ← One-click Windows Service installer
```

---

## ⚙️ Feature Overview

| Category | Details |
|:---|:---|
| **Static Analysis** | MD5 / SHA1 / SHA256 hashing, file type detection, PE analysis (imports, entropy, packers, entry point), YARA scanning, string heuristics |
| **ML Features (10)** | File size, header entropy, body entropy, max section entropy, suspicious import count, suspicious string count, packed flag, digital signature, section count, entry-point anomaly |
| **Offline Hash DB** | SQLite — identifies known malware without internet |
| **VirusTotal** | Hash lookup (API key required) |
| **AbuseIPDB** | IP reputation check on outbound connections |
| **File Monitor** | watchdog — creation and modification events |
| **Process Monitor** | psutil — new processes + suspicious command lines |
| **Network Monitor** | Port scan detection, IP reputation checking |
| **Registry Monitor** | Detects new autorun entries (Windows) |
| **Quarantine** | AES-256 ZIP, password stored in DB |
| **Scoring** | CLEAN (0–4) · SUSPICIOUS (5–9) · MALICIOUS (10–14) · CRITICAL (15+) |

---

## 📦 Installation

### Prerequisites
- **Python 3.8+**
- **Windows 10 / 11** (for full EDR features)
- **Administrator privileges** (for Windows Service and firewall blocking)

### Step 1 — Clone the repository
```bash
git clone https://github.com/DuckyHax040/N-Guard.git
cd N-Guard
```

### Step 2 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 3 — Configure
```bash
# Copy the template
copy .env.example .env

# Edit with your values
notepad .env
```

`.env` reference:
```ini
# Agent settings
NGUARD_AGENT_ID=                          # leave blank to auto-generate
NGUARD_SERVER=http://192.168.1.100:5050   # central server address
NGUARD_API_SECRET=change-me-strong-secret # must match on server and all agents
NGUARD_SCORE_THRESHOLD=5                  # minimum score to trigger an alert

# Server settings (only needed on the server machine)
NGUARD_DASH_TOKEN=change-me-dashboard-token

# Optional API keys (features degrade gracefully without them)
VT_API_KEY=
ABUSEIPDB_API_KEY=
```

> **Security note:** Never commit `.env` to version control. It is already listed in `.gitignore`.

---

## 🚀 Usage

### Option A — Windows Service (Recommended for production)

Run as Administrator:
```bat
install_service.bat
```

This automatically installs dependencies, creates `.env` if missing, registers and starts the service.

Control commands:
```bat
sc start NGuardAgent    # start
sc stop  NGuardAgent    # stop
sc query NGuardAgent    # check status
```

To uninstall:
```bash
python agent/agent.py uninstall
```

---

### Option B — Central Server + Multiple Agents (Recommended for networks)

**Step 1** — Start the central server (once, on one machine):
```bash
python server/central_server.py
```
Output:
```
========================================================
  N-Guard v3 — Central Server
========================================================
  Address      : http://0.0.0.0:5050
  Dashboard token  : abc123...   ← save this
  Agent secret     : xyz789...   ← save this
========================================================
```

**Step 2** — Configure `.env` on every endpoint:
```ini
NGUARD_SERVER=http://192.168.1.100:5050
NGUARD_API_SECRET=xyz789...
```

**Step 3** — Start the agent on each endpoint:
```bash
python agent/agent.py start
```

**Step 4** — Open the dashboard:
```
http://192.168.1.100:5050
Token: abc123...
```

---

### Option C — Manual CLI

**Scan a single file:**
```bash
python agent/agent.py scan C:\Users\Downloads\suspicious.exe
```

Sample output:
```json
{
  "filepath": "C:\\Users\\Downloads\\suspicious.exe",
  "sha256": "d4f3a2b1...",
  "score": 13,
  "verdict": "MALICIOUS",
  "alerts": [
    "YARA:Ransomware_Indicators",
    "ML:MALICIOUS(87%)",
    "SuspAPIs(5)"
  ],
  "vt_malicious": 42,
  "offline": false
}
```

**Scan a directory:**
```bash
python agent/agent.py scan C:\Users\Downloads
```

**Start real-time monitoring:**
```bash
python agent/agent.py start
```

---

## 🌐 Dashboard

When the central server is running, open:
```
http://<server-address>:5050
```

The dashboard shows:

- **Summary cards** — Critical alerts, unacknowledged alerts, total alerts, active agents
- **7-day bar chart** — Alert history over the past week
- **Live alert table** — Real-time via WebSocket, no refresh needed
- **Agents page** — Status, IP, OS, last seen for every connected endpoint

### Dashboard REST API

All endpoints require the header `X-Auth-Token: <NGUARD_DASH_TOKEN>`.

```
GET  /api/summary                        → totals and counts
GET  /api/alerts?limit=100&verdict=CRITICAL&agent_id=...
GET  /api/agents                         → list of registered agents
GET  /api/stats                          → 7-day daily breakdown
POST /api/alerts/{id}/ack                → acknowledge one alert
POST /api/alerts/ack_all                 → acknowledge all alerts
```

### Agent REST API

All endpoints require the header `X-Agent-Secret: <NGUARD_API_SECRET>`.

```
POST /api/agent/register    → register or update agent info
POST /api/agent/heartbeat   → keep-alive ping (every 60 seconds)
POST /api/agent/alert       → submit a new alert
```

---

## 📏 YARA Rules

Place `.yar` files in the `rules/` directory. Rules are **hot-reloaded** — no restart required when you add or edit a file.

Example rules (auto-created on first run):
```yara
rule Ransomware_Indicators {
    strings:
        $r1 = "your files have been encrypted" nocase
        $r2 = "bitcoin" nocase
        $r3 = "ransom" nocase
        $r4 = "decrypt" nocase
    condition:
        3 of them
}

rule Suspicious_PowerShell {
    strings:
        $enc = "-EncodedCommand" nocase
        $dl  = "DownloadString" nocase
        $iex = "Invoke-Expression" nocase
    condition:
        2 of them
}

rule Suspicious_Network_Beacon {
    strings:
        $ps  = "powershell -w hidden" nocase
        $cmd = "cmd.exe /c" nocase
    condition:
        any of them
}
```

---

## 🤖 ML Engine — Details

### 10 Features Extracted Per File

| # | Feature | Description |
|:---:|:---|:---|
| 0 | `log_size` | log(1 + file size in bytes) |
| 1 | `entropy_header` | Byte entropy of first 1 KB |
| 2 | `entropy_body` | Byte entropy of next 1 MB |
| 3 | `entropy_max` | Maximum section entropy (PE) |
| 4 | `sus_import_count` | Suspicious Win32 API imports (0–15) |
| 5 | `sus_string_count` | Suspicious string pattern matches (0–50) |
| 6 | `is_packed` | Packer signature detected (0/1) |
| 7 | `has_certificate` | Valid Authenticode signature (0/1) |
| 8 | `section_count` | Number of PE sections |
| 9 | `entry_point_anomaly` | Entry point outside `.text` (0/1) |

### Training Data Sources

| Source | Type | Records |
|:---|:---|:---:|
| MalwareBazaar API | Real malware metadata | ~1000 per update |
| GitHub IOC Feeds (Maltrail, PAN Unit42) | Verified hashes | Varies |
| Statistical baseline | Research-backed synthetic | 6000 |

### Auto-Update Schedule
```
Every 24 hours:
  Internet available  →  fetch fresh MalwareBazaar samples → retrain model
  No internet         →  skip, retry at next check
```

---

## 🧪 Running Tests

```bash
pip install pytest
python -m pytest tests/test_v3.py -v
```

Expected output:
```
tests/test_v3.py::TestOfflineHashDB::test_add_and_lookup_sha256     PASSED
tests/test_v3.py::TestOfflineHashDB::test_lookup_by_md5             PASSED
tests/test_v3.py::TestOfflineHashDB::test_thread_safety             PASSED
tests/test_v3.py::TestMLTrainingData::test_shape                    PASSED
tests/test_v3.py::TestMLTrainingData::test_balanced                 PASSED
tests/test_v3.py::TestMLTrainingData::test_malicious_higher_entropy PASSED
tests/test_v3.py::TestFeatureExtraction::test_benign_file_features  PASSED
tests/test_v3.py::TestFeatureExtraction::test_high_entropy_file     PASSED
tests/test_v3.py::TestStaticAnalyzer::test_powershell_detected      PASSED
tests/test_v3.py::TestServerAPI::test_agent_register                PASSED
tests/test_v3.py::TestServerAPI::test_summary_auth_required         PASSED
tests/test_v3.py::TestServerAPI::test_agent_alert                   PASSED
...
33 passed in 4.80s
```

---

## ❓ FAQ

**Does it work without internet?**  
Yes. The offline hash database and ML model work entirely without connectivity. Only MalwareBazaar lookups and VirusTotal require internet.

**Does it work without a VirusTotal API key?**  
Yes. ML + YARA + offline hash DB operate independently. VirusTotal is used when a key is present.

**How does the ML model stay current?**  
Automatically — every 24 hours, the engine fetches fresh data from MalwareBazaar and GitHub IOC feeds and retrains the model if internet is available.

**Does it work on Linux?**  
Partially. ML, file monitoring, and the central server work on Linux. ETW monitoring, registry monitoring, Windows Firewall blocking, and the Windows Service are Windows-only.

**How do I recover a quarantined file?**  
Files are stored as AES-256 encrypted ZIPs in the `quarantine/` directory. The password is saved in `db/reputation.db` under the `quarantine` alerts. Use `pyzipper` to extract:
```python
import pyzipper
with pyzipper.AESZipFile("quarantine/file.zip") as z:
    z.extractall(pwd=b"<password>")
```

**Where should I store secrets and API keys?**  
In the `.env` file only. Never commit it to version control — it is already in `.gitignore`.

**How do I add custom detection rules?**  
Drop `.yar` files into the `rules/` directory. Rules are hot-reloaded within seconds — no restart needed.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Write tests for your changes
4. Run the test suite: `python -m pytest tests/`
5. Open a Pull Request

---

## ⚠️ Disclaimer

N-Guard is provided for **defensive and educational purposes only**. Always obtain proper authorization before deploying monitoring software on systems you do not own. The maintainers accept no responsibility for misuse.

---

## 📄 License

MIT License — free to use, modify, and distribute.  
See [LICENSE.md](LICENSE.md) for the full text.

---

## 📬 Contact

- **GitHub Issues** — bug reports and feature requests
- **Telegram** — [@hovercs](https://t.me/hovercs)

---

<div align="center">

**Stay safe. Stay secure.** 🛡️

*N-Guard v3.0 — developed by n101*

</div>
