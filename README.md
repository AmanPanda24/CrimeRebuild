# 🔎 CrimeRebuild

> Digital Crime Scene Reconstruction System<br>
>  Collect ➡️ Correlate ➡️ Reconstruct.

**Created by: Aman Kumar Panda**

```
   ██████╗██████╗ ██╗███╗   ███╗███████╗██████╗ ███████╗██████╗ ██╗   ██╗██╗██╗     ██████╗
  ██╔════╝██╔══██╗██║████╗ ████║██╔════╝██╔══██╗██╔════╝██╔══██╗██║   ██║██║██║     ██╔══██╗
  ██║     ██████╔╝██║██╔████╔██║█████╗  ██████╔╝█████╗  ██████╔╝██║   ██║██║██║     ██║  ██║
  ██║     ██╔══██╗██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══╝  ██╔══██╗██║   ██║██║██║     ██║  ██║
  ╚██████╗██║  ██║██║██║ ╚═╝ ██║███████╗██║  ██║███████╗██████╔╝╚██████╔╝██║███████╗██████╔╝
   ╚═════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚═╝╚══════╝╚═════╝
```

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-cyan.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/framework-Flask-lightgrey.svg)](https://flask.palletsprojects.com/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-purple.svg)](#-installation)
[![Offline](https://img.shields.io/badge/network-100%25%20offline-blue.svg)](#-features)
[![Tests](https://img.shields.io/badge/tests-31%20passing-brightgreen.svg)](#-testing)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

CrimeRebuild rebuilds the timeline of a cyber incident from scattered digital evidence. It merges **event logs, browser
history, USB records, file activity and login records** into **one chronological timeline**, flags **five kinds of
suspicious behaviour**, scores the risk, and exports a **PDF forensic report** with hashes and chain of custody.



---

## 📑 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
- [Supported Evidence Formats](#-supported-evidence-formats)
- [Live Collection on Windows](#-live-collection-on-windows)
- [Detection Rules & Risk Score](#-detection-rules--risk-score)
- [How It Works](#-how-it-works)
- [Project Structure](#-project-structure)
- [Testing](#-testing)
- [FAQ](#-faq)
- [Limitations](#-limitations)
- [Legal Disclaimer](#-legal-disclaimer)
- [Contributing](#-contributing)
- [Author](#-author)
- [License](#-license)

---

## ✨ Features

| Module | Capability |
|--------|-----------|
| 📥 Evidence Intake | Read-only copy of every file, **SHA-256 hash at intake**, append-only chain-of-custody log |
| 🔄 Format Converter | Upload one ZIP or any mix of CSV / Excel / JSON / `.evtx` / browser history / FTK Imager and Autopsy exports |
| 🧩 Parsers | Every format normalised to one schema: `ts, source, category, action, user, target, dest, details` |
| 🕒 Timeline Engine | Pandas merge, sort and de-duplicate; gap detection, activity bursts, per-file "life stories" across sources |
| 🚨 Detection | Five explainable, rule-based detectors mapped to **MITRE ATT&CK**; each alert links to the exact events behind it |
| 📊 Dashboard | Flask + Bootstrap + Chart.js: reconstructed sequence, risk gauge, alerts, evidence, timeline filter and CSV export |
| 📄 Forensic Report | One-click **PDF** (ReportLab): findings, timeline, hashes and chain of custody |
| 🖥️ Live Collection | Collect artifacts straight from a Windows machine (event logs, USB history, Recycle Bin, browser history ...) |
| ⚙️ Tunable Settings | Detection thresholds are visible and editable; changing one re-analyses every case |
| 🧾 Plain-language Summary | Narrative generated from the findings by rules, **no AI, no ML** |
| 🔒 Offline by design | No cloud and no external calls. Bootstrap and Chart.js are bundled in `static/vendor/` |

**Tech stack:** Python · Flask · SQLite · Pandas · psutil · pywin32 · Bootstrap · Chart.js · ReportLab

---

## 🚀 Installation

### Requirements

- Python **3.9+**
- `pip`
- Windows is only needed for **live collection**; uploading evidence works on Windows, Linux and macOS

### Install

```bash
git clone https://github.com/AmanPanda24/CrimeRebuild.git
cd CrimeRebuild

python -m venv venv
```

Activate the virtual environment:

```bash
# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `Flask >= 3.0` | Web application |
| `pandas >= 2.0` | Timeline merge, sort and de-duplication |
| `reportlab >= 4.0` | PDF forensic report |
| `psutil >= 5.9` | Sessions and mounted removable drives |
| `pywin32 >= 306` | Windows event log access (installed on Windows only) |
| `openpyxl >= 3.1` | Reading `.xlsx` evidence |
| `evtx >= 0.8` | Reading Windows `.evtx` logs |
| `pytest >= 8.0` | Test suite |

---

## ⚡ Quick Start

```bash
python run.py
```

Open **http://127.0.0.1:5000** in your browser.

The app starts **empty**: there is no built-in demo data. Open a case, then upload your evidence. Until you upload,
the case page stays blank.

```bash
python run.py --host 127.0.0.1 --port 5000   # defaults shown
python run.py --debug                        # Flask debug mode (development only)
```

> By default the server binds to your own machine only. Do not expose it to a network without adding authentication.

---

## 📖 Usage

### 1. Web workflow

| Step | Where | What happens |
|------|-------|--------------|
| 1 | **Cases → Open a new case** | Creates an empty case |
| 2 | **Evidence → upload** | Each file is hashed, converted to JSON, then parsed by the same pipeline |
| 3 | **Dashboard** | Reconstructed sequence: every source, one story, in time order |
| 4 | **Risk gauge + Alerts** | Each alert stores the exact events that triggered it |
| 5 | **Evidence → Verify integrity** | Re-checks SHA-256 of every file. Change one byte and verification fails |
| 6 | **Forensic report (PDF)** | Findings, timeline, hashes and chain of custody |
| 7 | **Detection settings** | Tune thresholds; every case is re-analysed |

Other pages: **Timeline** (filter + CSV export) and **About**.

### 2. Command-line helper

```bash
# Load a built-in synthetic case (developer tool, not used by the web app)
python cli.py demo insider        # insider data theft
python cli.py demo intrusion      # full attack chain, triggers all five rules

# Write sample evidence files to sample_evidence/
python cli.py samples

# Collect from this Windows machine into a new case (run as Administrator)
python cli.py collect --name "PC-01" --days 14

# Export the PDF report for case 1
python cli.py report 1 out.pdf
```

| Demo scenario | Story | Detects |
|---------------|-------|---------|
| `insider` | A confidential PDF is opened, copied to a USB stick and deleted within nine minutes | USB exfiltration, evidence destruction |
| `intrusion` | Password guessing, a 00:03 login, USB theft, mass deletion and a cleared audit log | All five detection rules |

---

## 📂 Supported Evidence Formats

Choose **Auto-detect** on upload, or pick the type manually. Column names are matched loosely (case and spacing ignored).

### Upload types

| Input | How it is handled |
|-------|-------------------|
| `.zip` | Unpacked (path-traversal and zip-bomb safe); every file inside is converted |
| `.csv` `.tsv` `.txt` `.json` `.jsonl` `.xlsx` | Read as tables / records |
| `.evtx` | Windows event log → JSON (`evtx` package) |
| Chrome / Edge / Firefox history, Autopsy `autopsy.db` | SQLite → JSON |
| FTK Imager / Autopsy file lists | Each Created / Modified / Accessed timestamp becomes one event |
| `.E01` `.AD1` `.dd` `.raw` `.mem` `.pcap` `.pcapng` | Rejected with a message: export from the forensic tool first |

The original file is kept untouched and hashed; the converted JSON is hashed and logged in the chain of custody too
(`data/cases/<id>/converted/`).

### Evidence schemas

| Type | Accepted input | Key columns |
|------|----------------|-------------|
| Event log | CSV/JSON from `Get-WinEvent \| Export-Csv`, Event Viewer "Save as CSV", or CrimeRebuild's collector | `TimeCreated, EventID, Account, ObjectName, AccessMask, LogonType, IpAddress, ProcessName, CommandLine, Message` |
| Browser history | Chrome / Edge / Brave `History`, Firefox `places.sqlite`, or CSV | SQLite tables `urls` + `visits` (+ `downloads`) / CSV `timestamp, url, title` |
| USB log | CSV/JSON | `Timestamp, Event (Connected/Disconnected), DeviceName, Serial, Vendor, DriveLetter` |
| File log | CSV/JSON | `Timestamp, Action (Accessed/Copied/Deleted/Modified), Path, User, Process, Destination` |
| Login log | CSV/JSON | `Timestamp, User, Result (Success/Failed/Logoff), SourceIP, LogonType` |

**Windows Event IDs understood:** 4624 / 4625 / 4634 / 4647 / 4648 (logons), 4663 / 4660 (file access / delete, decoded
from `AccessMask`), 4688 (process), 4698, 4720, 4726, 4732, 7045, 1102 / 104 (log cleared), 6005 / 6006.

**Timestamps:** values with a time zone are converted to **UTC**; values **without** one are assumed to be UTC. Use ISO
format (`2026-09-14 10:05:00`) to avoid day/month ambiguity. Unreadable rows are skipped and counted, never fatal.

---

## 🖥️ Live Collection on Windows

Evidence tab → **Collect from this machine**, or `python cli.py collect --name "PC-01" --days 14`.
Run the terminal **as Administrator** and only on machines you are **authorised** to examine.

| Artifact | Source | Notes |
|----------|--------|-------|
| Logons, processes, accounts, log clearing | Security + System event logs via `win32evtlog` | Needs Administrator |
| File open / delete events (4663 / 4660) | Security log | **Only exist if auditing is on:** `auditpol /set /subcategory:"File System" /success:enable`, plus an auditing entry (SACL) on the folders to watch |
| Process command lines | Event 4688 | Enable "Include command line in process creation events" in Group Policy |
| USB history | `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`, `setupapi.dev.log`, mounted removable drives (`psutil`) | Registry time is *approximately* the last connection |
| Deleted files | Recycle Bin `$I` records (original path + deletion time) | Only files deleted via Explorer; emptied bins are gone |
| Opened files | Recent Items shortcuts (last-opened time) | File name only, no full path |
| Sessions | `psutil.users()`, boot time | Active sessions at collection time |
| Browser history | Chrome / Edge / Brave / Firefox databases (copied, never opened live) | Close the browser if the copy fails |

> **Note:** the Windows-API parts (`win32evtlog`, registry, `esentutl` fallback) could not be executed in the Linux
> environment this project was built in. The parsing helpers they depend on (Recycle Bin `$I`, `setupapi.dev.log`,
> event XML) are unit-tested. Run `python cli.py collect` once on your Windows machine before relying on it, and keep a
> sample ZIP as a safe path.

---

## 🚨 Detection Rules & Risk Score

Defaults are editable under **Detection settings**.

| Rule | Fires when | Severity | MITRE ATT&CK |
|------|-----------|----------|--------------|
| Mass file deletion | ≥ 10 files deleted by one user in 5 min (temp/cache paths ignored) | high; critical at 3× | T1485 Data Destruction |
| USB data exfiltration | Files written to a drive during a USB session | critical if a name looks sensitive; high if ≥ 5 files; else medium/low | T1052.001 Exfiltration over USB |
| Off-hours login | Successful login 00:00-05:00 | medium; high if ≥ 3 actions follow within an hour | T1078 Valid Accounts |
| Repeated failed logins | ≥ 5 failures in 10 min per account, or ≥ 5 from one address across ≥ 3 accounts (password spraying) | medium; high at 3× or spraying; critical if a success follows within 10 min | T1110 Brute Force |
| File tampering | Protected path changed; audit log cleared; sensitive file deleted within 60 min of being copied | high / critical (log cleared) | T1070 Indicator Removal |

**Risk score** = sum of alert points (low 10 · medium 20 · high 35 · critical 50), capped at **100**.

| Score | Label |
|-------|-------|
| < 25 | Low |
| < 50 | Medium |
| < 75 | High |
| ≥ 75 | Critical |

It is a triage aid: every point is traceable to an alert.

---

## 🧠 How It Works

Six-stage design:

| Stage | File | What it does |
|-------|------|--------------|
| 1. Evidence collection | `crimerebuild/collector.py`, `evidence.py` | Live Windows collection or upload. Copies each file read-only, SHA-256 hashes it, logs chain of custody |
| 2. Evidence parsing | `crimerebuild/parsers.py`, `converter.py` | Converts every format into one schema |
| 3. Timeline reconstruction | `crimerebuild/timeline.py` | Pandas merge + sort + de-duplicate; gaps, bursts, per-file stories |
| 4. Suspicious-activity detection | `crimerebuild/detector.py` | Five rule-based detectors, alerts linked to exact events, risk score |
| 5. Dashboard | `crimerebuild/views.py`, `templates/`, `static/` | Flask + Bootstrap + Chart.js |
| 6. Forensic report | `crimerebuild/report.py` | ReportLab PDF |

Supporting modules: `db.py` (SQLite schema + settings), `summary.py` (plain-language narrative), `demo.py` (scenarios),
`analysis.py` (shared by dashboard and report), `cli.py` (command line).

### Data flow

```
 evidence files ──► intake (copy, hash, custody) ──► parser ──► events table (SQLite)
                                                                      │
                          timeline engine (pandas: merge, sort, de-duplicate)
                                                                      │
                           detectors ──► alerts + risk score ──► dashboard / PDF
```

---

## 🏗️ Project Structure

```
CrimeRebuild/
├── run.py                  # Start the web app
├── cli.py                  # Command-line helper (demo, samples, collect, report)
├── config.py               # Paths, upload limit, project metadata
├── requirements.txt
├── LICENSE
├── crimerebuild/
│   ├── __init__.py         # Flask app factory
│   ├── collector.py        # Live Windows collection
│   ├── evidence.py         # Intake, SHA-256 hashing, chain of custody, verification
│   ├── converter.py        # Mixed-format upload → JSON
│   ├── parsers.py          # Per-format parsers → common event schema
│   ├── timeline.py         # Merge, sort, de-duplicate, gaps, bursts
│   ├── detector.py         # Five detection rules + risk score
│   ├── summary.py          # Plain-language narrative
│   ├── report.py           # PDF forensic report
│   ├── analysis.py         # Shared analysis for dashboard and report
│   ├── demo.py             # Synthetic demo scenarios
│   ├── db.py               # SQLite schema + settings
│   ├── views.py            # Flask routes
│   └── constants.py        # Actions, event IDs, rule catalogue
├── templates/              # base, cases, dashboard, timeline, alerts, evidence, settings, about
├── static/                 # css/app.css, js/, vendor/ (Bootstrap, Chart.js, icons: offline)
├── tests/                  # test_pipeline.py, test_converter.py
└── data/                   # Created at first run (SQLite DB + read-only evidence copies)
```

### Configuration

Settings live in `config.py`; environment variables override them:

| Variable | Default | Purpose |
|----------|---------|---------|
| `CRIMEREBUILD_DATA` | `./data` | Where the database, evidence copies and reports are stored |
| `CRIMEREBUILD_SECRET` | dev key | Flask secret key. **Set your own** for any real use |

Maximum upload size is `MAX_UPLOAD_MB = 500`. The `PROJECT_META` block controls the title, institute and author shown
on the About page and in the PDF report footer.

---

## 🧪 Testing

```bash
python -m pytest tests -q
```

31 tests cover the full pipeline, the converter, hash verification and tamper detection, and the sliding-window
detector.

---

## ❓ FAQ

**Why not machine learning?**
Forensics needs explainable results. Each alert shows the rule, the threshold and the exact events; a model would not.

**How do you know the evidence was not altered?**
SHA-256 at intake, a verified read-only copy, the hash re-checked on demand and before every report, and an
append-only chain-of-custody log. Tests prove tampering is detected.

**What if two sources report the same event?**
Exact duplicates (same time, source, action, account, target, details) are merged and counted.

**How are different time zones handled?**
Converted to UTC; untagged timestamps are assumed UTC (stated in the report).

**How does the sliding-window detector work?**
Two pointers over the sorted timestamps; overlapping windows with enough events merge into one alert
(`detector.burst_groups`, covered by tests).

---

## ⚠️ Limitations

- Windows evidence sources only
- Rule-based, so it finds known patterns rather than unknown ones
- An attacker can delete logs (the tool flags log clearing when it sees it)
- Not intended as court-admissible evidence

### 🔮 Future work

User login and roles (investigator / admin / evaluator), Linux log sources (`auth.log`, `journald`), memory and disk
artifacts, correlation across multiple hosts, and a rule editor in the UI.

---

## ⚠️ Legal Disclaimer

**CrimeRebuild is designed for authorised digital forensics, incident response, education and research only.**

- Only analyse systems and evidence you **own or have explicit permission** to investigate
- Comply with all applicable laws in your jurisdiction
- The author is not responsible for misuse of this tool
- Live collection must only be run on machines you are authorised to examine

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a branch: `git checkout -b feature/my-feature`
3. Run the tests: `python -m pytest tests -q`
4. Commit and open a pull request

To add a new **detection rule**, add a `rule_*` function in `crimerebuild/detector.py`, call it from `run_rules`, and register its title and
ATT&CK reference in `RULE_INFO` in `crimerebuild/constants.py`. To support a new **evidence format**, add a parser in
`crimerebuild/parsers.py` that outputs the common event schema.

---

## 👨‍💻 Author

**Created by: Aman Kumar Panda**
MCA (Cybersecurity & Forensics Science) 
GitHub: [@AmanPanda24](https://github.com/AmanPanda24)

---

## 📄 License

MIT License. Copyright (c) 2026 Aman Kumar Panda. See [LICENSE](LICENSE) for details.

---

<p align="center"><b>CrimeRebuild</b> Created by: Aman Kumar Panda</p>
