# Python-Port-Scanner 🔍

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Category](https://img.shields.io/badge/Category-Cybersecurity%20%2F%20Networking-red.svg)]()

A fast, multi-threaded TCP port scanner built in Python for learning network security fundamentals, network mapping, and security auditing on authorized systems.

---

## 📌 Features

- **Multi-threaded Performance:** Powered by Python's `concurrent.futures.ThreadPoolExecutor` for lightning-fast port checks.
- **Service Detection:** Automatically maps common open ports to well-known services (HTTP, HTTPS, SSH, FTP, SMB, MySQL, RDP, DNS, etc.).
- **Banner Grabbing:** Safely probes open ports to retrieve server headers and service banners.
- **Flexible Port Ranges:** Supports individual ports, comma-separated lists, and continuous ranges (e.g. `1-1024`, `21,22,80,443`, `20-100`).
- **Interactive & CLI Modes:** Run with command-line flags or enter intuitive interactive prompts.
- **Automated Report Generation:** Exports scan summary, open port status, response latency, and banner info to `results/scan_report.txt`.
- **Zero Mandatory Dependencies:** Runs out of the box using Python's standard library (`socket`, `sys`, `concurrent.futures`, `argparse`).

---

## 📁 Project Structure

```text
Python-Port-Scanner/
├── README.md
├── scanner.py
├── requirements.txt
├── results/
│   └── scan_report.txt
└── screenshots/
    └── README.md
```

---

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR-USERNAME/Python-Port-Scanner.git
cd Python-Port-Scanner
```

### 2. (Optional) Install Styling Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Scanner

#### Option A: Interactive Mode (Recommended for Beginners)
Simply run the script without any parameters:
```bash
python scanner.py
```
You will be prompted to enter:
1. Target IP or hostname (e.g., `127.0.0.1` or `scanme.nmap.org`)
2. Port range (e.g., `1-1024` or `20-100`)
3. Thread count (e.g., `50` or `100`)
4. Banner grabbing enable/disable (`y`/`n`)

#### Option B: Command-Line Interface (CLI Mode)
```bash
# Scan localhost top 1024 ports
python scanner.py -t 127.0.0.1

# Scan custom port range with 100 threads
python scanner.py -t scanme.nmap.org -p 20-100 -th 100

# Scan specific ports with banner grabbing and custom report output
python scanner.py -t 127.0.0.1 -p 21,22,80,443,3306 -b -o results/scan_report.txt
```

---

## ⚙️ CLI Options & Arguments

| Flag | Long Flag | Description | Default |
|------|-----------|-------------|---------|
| `-t` | `--target` | Target IP address or hostname | *Required (in CLI mode)* |
| `-p` | `--ports` | Port range or comma-separated list | `1-1024` |
| `-th`| `--threads` | Number of concurrent worker threads | `50` |
| `-to`| `--timeout` | Socket connection timeout in seconds | `1.0` |
| `-b` | `--banner` | Enable service banner grabbing | `Disabled` |
| `-o` | `--output` | Destination file for the scan report | `results/scan_report.txt` |

---

## 📊 Sample Terminal Output

```text
======================================================================
  Tool: Multi-threaded Python Port Scanner
  Purpose: Ethical Security Auditing & Network Discovery
======================================================================

[*] Target Host       : 127.0.0.1
[*] Target IP         : 127.0.0.1
[*] Total Ports       : 1024
[*] Concurrent Threads: 50
[*] Connection Timeout: 1.0s
[*] Banner Grabbing   : Enabled
[*] Scan Started At   : 2026-11-02 22:00:00
----------------------------------------------------------------------
[+] Port 80    OPEN  -> HTTP                 (0.85 ms) | Banner: HTTP/1.1 200 OK
[+] Port 135   OPEN  -> MS-RPC               (1.12 ms)
[+] Port 445   OPEN  -> SMB                  (0.94 ms)
----------------------------------------------------------------------
[*] Scan Completed in 1.42 seconds.
[*] Open Ports Found : 3 / 1024

======================================================================
PORT     STATE    SERVICE                LATENCY    BANNER
======================================================================
80       OPEN     HTTP                   0.85 ms    HTTP/1.1 200 OK
135      OPEN     MS-RPC                 1.12 ms    -
445      OPEN     SMB                    0.94 ms    -
======================================================================
[+] Detailed scan report saved to: results/scan_report.txt
```

---

## 🛡️ Ethical Disclaimer

> **Important**: This tool is designed strictly for **educational purposes** and **authorized security assessments**. Scanning targets without prior explicit permission from the network/system owner is illegal in many jurisdictions and violates network service terms. Always test against your own local machine (`127.0.0.1` / `localhost`) or systems designated for authorized scanning practice (such as [scanme.nmap.org](http://scanme.nmap.org)).

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
