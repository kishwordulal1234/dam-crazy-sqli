<div align="center">

```
██████╗  █████╗ ███╗   ███╗     ██████╗██████╗  █████╗ ███████╗██╗   ██╗    ███████╗ ██████╗ ██╗     ██╗
██╔══██╗██╔══██╗████╗ ████║    ██╔════╝██╔══██╗██╔══██╗╚════██║╚██╗ ██╔╝    ██╔════╝██╔═══██╗██║     ██║
██║  ██║███████║██╔████╔██║    ██║     ██████╔╝███████║    ██╔╝ ╚████╔╝     ███████╗██║   ██║██║     ██║
██║  ██║██╔══██║██║╚██╔╝██║    ██║     ██╔══██╗██╔══██║   ██╔╝   ╚██╔╝      ╚════██║██║▄▄ ██║██║     ██║
██████╔╝██║  ██║██║ ╚═╝ ██║    ╚██████╗██║  ██║██║  ██║   ██║     ██║       ███████║╚██████╔╝███████╗██║
╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝     ╚═╝       ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝
```

<img src="https://img.shields.io/badge/Version-v2.0%20%E2%80%94%20Reborn-red?style=for-the-badge&logo=mysql&logoColor=white"/>
<img src="https://img.shields.io/badge/Language-Bash%20%2B%20Python3-blue?style=for-the-badge&logo=gnu-bash&logoColor=white"/>
<img src="https://img.shields.io/badge/OS-Linux%20%7C%20Termux-blueviolet?style=for-the-badge&logo=linux&logoColor=white"/>
<img src="https://img.shields.io/badge/License-Educational%20Use%20Only-orange?style=for-the-badge"/>

### 🦇 Dam Crazy SQLi — The Ultimate SQL Injection & Database Hijacker Toolkit
*Fast Automatic SQL Injection · SQLi Dumper · URL Fuzzer · Dork Tools · Hash Cracking*

> **"SQli Never Die."**

---

</div>

## 📖 Table of Contents

- [Overview](#-overview)
- [Version History & Changelog](#-version-history--changelog)
  - [v1 — Original Bash Engine](#v1--original-bash-engine)
  - [v2 — Reborn Edition (Bash + Python3)](#v2--reborn-edition-bash--python3)
  - [Side-by-Side Comparison](#-side-by-side-comparison-v1-vs-v2)
- [Features](#-features)
- [Requirements](#-requirements)
- [Installation Guide](#-installation-guide)
  - [Linux (Kali / Parrot / Ubuntu)](#-linux-kali--parrot--ubuntu)
  - [Android (Termux)](#-android-termux)
  - [Running v1 vs v2](#-choosing-which-version-to-run)
- [How It Works](#-how-it-works)
- [Tool Menu Reference](#-tool-menu-reference)
- [Disclaimer](#%EF%B8%8F-disclaimer)

---

## 🔍 Overview

**Dam Crazy SQLi** is a powerful, automated SQL Injection framework built for penetration testers and bug bounty hunters. It is a heavily extended and bug-fixed evolution of the original **PSQLI** tool (by Kedjaw3n), combining a battle-hardened Bash injection engine with a modern multi-threaded Python3 module for clean, WAF-free exploitation.

The toolkit supports everything from single-site union injection to mass dorking and auto-exploitation across thousands of targets — with 16+ modules covering nearly every SQLi scenario in the wild.

---

## 📋 Version History & Changelog

### `v1` — Original Bash Engine

**File:** `dcsqli_v1/psqli.sh`

The v1 engine is the foundational Bash script authored by **Kedjaw3n** (originally released 17 January 2020, last updated 21 April 2020). It is a pure Bash implementation that handles SQL injection end-to-end using `curl`, `sed`, `awk`, and `grep`.

**What v1 does well:**
- Solid WAF bypass payloads — 10+ whitespace bypass styles (URL-encoded comment injection, `%23%0a`, buffer-of-A techniques, etc.)
- Full DIOS (Dump In One Shot) method with 5 query variants (basic WAF, Madblood WAF, Zen WAF, Madblood no-WAF, dynamic `${by}` method)
- 16-module menu system covering dorking, mass exploitation, hash tools, and admin finders
- SQLi login bypass payload library (`' or 1=1 limit 1-- -+`, `'=''or'`, etc.)

**Known issues in v1 (inherited from the original PSQLI source):**
- `.angka` file race condition: `cat .angka | sed ... > .angka` writes and reads the same file simultaneously, corrupting it to 0 bytes mid-extraction
- Silent menu exits when column extraction reaches the DIOS phase due to the above bug
- `sed` `unterminated 's'` errors when multi-column vulnerable sites are processed, caused by unescaped special characters in `sed` pattern variables
- Empty `curl` arguments constructed from broken `sed` output, causing noisy `curl` errors with no recovery logic

---

### `v2` — Reborn Edition (Bash + Python3)

**Files:** `dcsqli_v2/psqliv2.sh` + `dcsqli_v2/plain_inject.py`

v2 is a complete rework of the extraction pipeline. The core Bash shell loop is retained and improved, and a brand-new Python3 module (`plain_inject.py`) is introduced as a dedicated **plain/clean injection engine** — no WAF bypass, pure `UNION SELECT`, designed for targets that have no firewall in place.

**Key improvements in v2:**

- All `.angka` file handling now uses an atomic `.tmp` write-then-rename pattern to eliminate the race condition
- `sed` pattern inputs are sanitized with `head -1` and strict integer casting before being passed to `sed`, eliminating the `unterminated 's'` crash class
- `curl` invocations are guarded with empty-argument checks; the script skips gracefully instead of erroring out
- Menu validation gates added across all sub-menus so the script never silently drops back to the main menu
- **New `plain_inject.py` module** (Python3): autonomous ORDER BY column counter, reflected column scanner via `BeautifulSoup`-cleaned text, concurrent multi-threaded table and column enumeration with `ThreadPoolExecutor` (10 workers), hex-encoded DB name injection to avoid quoting issues, and structured stdout output parseable by the Bash wrapper
- Main menu expanded to 9 options (v1 had 8 active options) — option 5/6 now routes to the Python3 plain inject runner

---

### 📊 Side-by-Side Comparison: v1 vs v2

| Category | v1 (Original Bash) | v2 (Reborn — Bash + Python3) |
|---|---|---|
| **Engine language** | Pure Bash | Bash + Python3 |
| **Column count detection** | ORDER BY in Bash loop | ORDER BY in Python3 with error-keyword detection |
| **Reflected column scan** | Bash `curl` + `grep` | Python3 with BeautifulSoup HTML stripping |
| **DIOS extraction** | 5 variants (may crash on buggy `.angka`) | 5 variants + fixed `.tmp` atomic write |
| **Plain injection mode** | ❌ Not available | ✅ `plain_inject.py` — clean UNION SELECT, no WAF bypass |
| **Table enumeration** | Sequential Bash loop | Concurrent (10 threads via `ThreadPoolExecutor`) |
| **`.angka` race condition** | ❌ Present — data loss | ✅ Fixed with `.angka.tmp` pattern |
| **`sed` crash on multi-col** | ❌ Present — script exits | ✅ Fixed with `head -1` + integer guard |
| **`curl` empty-arg errors** | ❌ Noisy errors, no recovery | ✅ Guards skip gracefully |
| **Menu exit on crash** | ❌ Silent drop to main menu | ✅ Informative echo + validated returns |
| **HTML-contaminated output** | Sometimes — raw `grep` | Cleaned via `BeautifulSoup` + `lxml` parser |
| **Boot screen** | Standard console | Custom ASCII animation |
| **Menu options** | 8 | 9 |
| **Dependencies** | `curl grep gawk sed diff awk` | Above + `python3 requests bs4 lxml` |

---

## ✨ Features

1. **Single Site Injection** — TARGET a single URL and fully dump its database  
2. **Mass Exploit SQL Injection** — Feed a list of URLs and auto-exploit all vulnerable targets  
3. **Auto Dorking + Auto Exploit** — Generate dorks, scrape Google/Bing/DuckDuckGo, then auto-inject results  
4. **SQLi Base64 Injection** — Encode payloads in Base64 for filter bypass  
5. **SQLi POST Method** — Inject via HTTP POST parameters, not just GET  
6. **SQLi ERROR Based Method** — Extract data via database error messages  
7. **Scan Site + Auto Inject (Web Crawler)** — Crawl a site and auto-test all discovered parameters  
8. **Reverse IP Vuln SQLi + Auto Inject** — Find all sites on a shared IP and test them all  
9. **Query Email:Pass Dumper + Auto Filter Mail** — Dump credentials and sort by mail provider  
10. **Hash Tools** — Crack MD5/SHA hashes via online APIs  
11. **Dork Generator** — Generate custom dorks by keyword, country, and parameter  
12. **New Admin Finder** — Scan for common admin panel paths  
13. **PSQLi Scanner** — Unified SQLi / XSS / LFI / AdminFinder scanner  
14. **SQLi Dork Dumper** — Dump from dork-discovered sites in bulk  
15. **Auto Bypass SQL Login** — Attempt common SQLi login bypass payloads automatically  
16. **Dr. Dork Generator** — Advanced dork generation with multiple search engine support  

---

## 🧰 Requirements

### For v1 (Bash only)

| Tool | Purpose |
|---|---|
| `bash` | Shell interpreter |
| `curl` | HTTP requests |
| `grep` / `egrep` | Response parsing |
| `gawk` / `awk` | Text field extraction |
| `sed` | Pattern substitution |
| `diff` | Comparison operations |

### For v2 (Bash + Python3)

Everything above, **plus:**

| Tool | Purpose |
|---|---|
| `python3` | Runtime for `plain_inject.py` |
| `pip3` / `pip` | Python package manager |
| `requests` | HTTP session management in Python |
| `beautifulsoup4` | HTML-clean text extraction |
| `lxml` | Fast HTML parser (used by BS4) |
| `urllib3` | SSL warning suppression |

---

## 🚀 Installation Guide

### 🐧 Linux (Kali / Parrot / Ubuntu)

**Step 1 — Install system dependencies**

```bash
sudo apt update && sudo apt install -y git curl gawk sed diffutils python3 python3-pip
```

**Step 2 — Clone the repository**

```bash
git clone https://github.com/kishwordulal1234/dam-crazy-sqli.git
cd dam-crazy-sqli
```

**Step 3 — Install Python3 dependencies (required for v2 only)**

```bash
pip3 install requests beautifulsoup4 lxml urllib3
```

> **Tip:** If you get a "externally managed environment" error on newer Ubuntu/Debian, use:
> ```bash
> pip3 install requests beautifulsoup4 lxml urllib3 --break-system-packages
> ```
> Or use a virtual environment:
> ```bash
> python3 -m venv sqli-env && source sqli-env/bin/activate
> pip install requests beautifulsoup4 lxml urllib3
> ```

**Step 4 — Set executable permissions**

```bash
# For v1:
chmod +x dcsqli_v1/psqli.sh

# For v2:
chmod +x dcsqli_v2/psqliv2.sh
```

**Step 5 — Launch**

```bash
# Run v1:
bash dcsqli_v1/psqli.sh

# Run v2 (recommended):
bash dcsqli_v2/psqliv2.sh
```

---

### 📱 Android (Termux) — Full Setup Guide

> **Before you begin:** Install **Termux** from [F-Droid](https://f-droid.org/packages/com.termux/) only.
> The Google Play Store version is outdated and will cause package failures.
> Do **not** use Termux from the Play Store.

---

#### 📦 Step 1 — Bootstrap Termux & Fix Repositories

When you open Termux for the first time, run this to sync and upgrade everything:

```bash
pkg update -y && pkg upgrade -y
```

If you get a prompt asking `"Do you want to replace the modified configuration file?"`, press **`Y`** and hit Enter.

---

#### 🔧 Step 2 — Install All Required Bash / System Tools

These are every system-level tool the scripts depend on, mapped to their exact Termux package names:

```bash
pkg install -y \
  git \
  curl \
  wget \
  grep \
  gawk \
  sed \
  diffutils \
  coreutils \
  util-linux \
  ncurses-utils \
  python \
  openssl-tool \
  libxml2 \
  libxslt
```

**What each package provides:**

| Termux Package | Tools Provided | Used For |
|---|---|---|
| `git` | `git` | Cloning the repository |
| `curl` | `curl` | All HTTP requests (injection, dorking, hash cracking) |
| `wget` | `wget` | File downloads in some modules |
| `grep` | `grep`, `egrep` | Response parsing — finding SQLi errors & reflected columns |
| `gawk` | `gawk`, `awk` | Text field extraction from injection responses |
| `sed` | `sed` | Pattern substitution in URL/payload construction |
| `diffutils` | `diff` | Comparison operations in injection detection |
| `coreutils` | `base64`, `cat`, `cut`, `sort`, `uniq`, `wc`, `head`, `tail`, `tr`, `mktemp` | Core text and file processing utilities |
| `util-linux` | `column` | Formatted table output in menus |
| `ncurses-utils` | `tput` | Terminal color/cursor control for the UI |
| `python` | `python3`, `pip3` | Runtime for `plain_inject.py` (v2 only) |
| `openssl-tool` | `openssl` | SSL/TLS support for `curl` HTTPS requests |
| `libxml2` | `libxml2` libraries | Required by `lxml` Python parser |
| `libxslt` | `libxslt` libraries | Required by `lxml` Python parser |

---

#### 🐍 Step 3 — Install All Python3 Libraries (v2 only)

First, upgrade `pip` itself to the latest version:

```bash
pip install --upgrade pip
```

Then install every required Python library:

```bash
pip install \
  requests \
  beautifulsoup4 \
  lxml \
  urllib3 \
  certifi \
  charset-normalizer \
  idna \
  soupsieve
```

**What each library does:**

| Python Package | Import Name | Purpose in `plain_inject.py` |
|---|---|---|
| `requests` | `import requests` | HTTP session management — sends all injection requests with custom headers, redirects, SSL skip |
| `beautifulsoup4` | `from bs4 import BeautifulSoup` | Strips HTML tags from server responses to extract clean reflected text without false positives |
| `lxml` | *(used by bs4)* | Fast C-based HTML/XML parser backend for BeautifulSoup — required for `BeautifulSoup(html, "lxml")` |
| `urllib3` | `import urllib3` | SSL InsecureRequestWarning suppression (`urllib3.disable_warnings(...)`) |
| `certifi` | *(urllib3 dependency)* | CA certificate bundle — required by `requests` for HTTPS |
| `charset-normalizer` | *(requests dependency)* | Automatic encoding detection for non-UTF-8 server responses |
| `idna` | *(requests dependency)* | Internationalised domain name support in URLs |
| `soupsieve` | *(bs4 dependency)* | CSS selector engine used internally by BeautifulSoup |

**Standard library modules** (already built into Python3 — no installation needed):

| Module | Used For |
|---|---|
| `sys` | Command-line argument parsing, stderr output |
| `os` | File path operations, environment access |
| `re` | Regex extraction of reflected column markers from responses |
| `json` | JSON parsing of structured API responses |
| `concurrent.futures` | `ThreadPoolExecutor` — 10-worker concurrent table/column enumeration |
| `hashlib` | Hash computation (conditional use) |
| `urllib.parse` | URL parsing and encoding (conditional use) |

---

#### 🛠️ Step 4 — Fix Common Termux Build Issues

If `lxml` fails to install with a **compilation error**, install the build tools first:

```bash
pkg install -y clang python-dev libxml2-dev libxslt-dev
pip install lxml
```

If you get **`CERTIFICATE_VERIFY_FAILED`** errors when running the tool:

```bash
pip install --upgrade certifi
```

If `pip install` gives **`externally-managed-environment`** error:

```bash
pip install requests beautifulsoup4 lxml urllib3 certifi charset-normalizer idna soupsieve --break-system-packages
```

If any `pkg install` step fails due to a **broken repo mirror**, force-refresh the mirrors:

```bash
termux-change-repo
```
Select "Mirror group" → "Albatross / BFSU" (or any working mirror), then re-run `pkg update -y`.

---

#### 📂 Step 5 — Clone the Repository

```bash
git clone https://github.com/kishwordulal1234/dam-crazy-sqli.git
cd dam-crazy-sqli
```

---

#### 🔑 Step 6 — Set Permissions

```bash
# For v1 (Bash only — no Python needed):
chmod +x dcsqli_v1/psqli.sh

# For v2 (Bash + Python3):
chmod +x dcsqli_v2/psqliv2.sh
chmod +x dcsqli_v2/plain_inject.py
```

---

#### ✅ Step 7 — Verify Your Installation

Run this quick check to confirm all tools are available before launching:

```bash
echo "=== Bash Tools ===" && \
for tool in git curl wget grep gawk sed diff base64 column tput python3 pip3; do
  if command -v $tool &>/dev/null; then
    echo "  ✅ $tool → $(command -v $tool)"
  else
    echo "  ❌ $tool → NOT FOUND"
  fi
done && \
echo "" && echo "=== Python Libraries ===" && \
python3 -c "
import importlib
libs = ['requests','bs4','lxml','urllib3','certifi']
for lib in libs:
    try:
        m = importlib.import_module(lib)
        print(f'  ✅ {lib}')
    except ImportError:
        print(f'  ❌ {lib} → NOT INSTALLED')
"
```

All items should show ✅ before running v2.

---

#### 🚀 Step 8 — Launch

```bash
# Run v1 (pure Bash, no Python required):
bash dcsqli_v1/psqli.sh

# Run v2 (recommended — Bash + Python3 plain inject):
bash dcsqli_v2/psqliv2.sh
```

---

#### 🗺️ Full One-Liner Setup (Copy & Paste)

If you want to do the entire Termux setup in one shot, paste this complete block:

```bash
pkg update -y && pkg upgrade -y && \
pkg install -y git curl wget grep gawk sed diffutils coreutils util-linux ncurses-utils python openssl-tool libxml2 libxslt && \
pip install --upgrade pip && \
pip install requests beautifulsoup4 lxml urllib3 certifi charset-normalizer idna soupsieve && \
git clone https://github.com/kishwordulal1234/dam-crazy-sqli.git && \
cd dam-crazy-sqli && \
chmod +x dcsqli_v1/psqli.sh dcsqli_v2/psqliv2.sh dcsqli_v2/plain_inject.py && \
echo "✅ Setup complete! Run: bash dcsqli_v2/psqliv2.sh"
```

---

### 🔀 Choosing Which Version to Run

| Situation | Recommended Version |
|---|---|
| Target has a WAF / mod_security | **v1 or v2** — both have full WAF bypass payloads |
| Target has NO WAF (plain site) | **v2** — use the new Python3 Plain Inject mode (option 5/6) |
| Running on Android / low-resource device | **v1** — no Python3 needed |
| Mass exploitation / bulk list | **v2** — faster, more stable extraction |
| Learning / studying the code | **v1** — simpler single-file structure |

---

## ⚙️ How It Works

**Bash Engine (both versions):**
The main Bash script constructs crafted `curl` requests with encoded UNION SELECT payloads. It tries multiple whitespace bypass techniques and DIOS query variants, parses the HTTP response with `grep`/`sed`/`awk` to find reflected columns, then dumps table names and column data via iterative DIOS or `GROUP_CONCAT` queries.

**Python3 Plain Inject Engine (v2 only — `plain_inject.py`):**
When the user selects Plain Mode, `psqliv2.sh` spawns `plain_inject.py` as a subprocess. The Python module:
1. Sends `ORDER BY N --+` requests incrementally until a "unknown column" error is detected — determining column count
2. Sends a single `UNION SELECT concat(~~,N,~~) --+` request across all columns to find which ones reflect in the page body (HTML-stripped via BeautifulSoup)
3. Extracts `database()`, `version()`, `user()` in a single request using the identified reflected column
4. Concurrently enumerates all tables from `information_schema.tables` using 10 parallel threads
5. Concurrently fetches all columns for the selected table
6. Dumps rows and outputs structured `KEY=VALUE` lines to stdout for the Bash wrapper to parse and display

---

## 📋 Tool Menu Reference

```
╔══════════════════════════════════════════════════╗
║          DAM CRAZY SQLI — MAIN MENU              ║
╠══════════════════════════════════════════════════╣
║  [1]  Single Site Injection                      ║
║  [2]  Mass Exploit SQL Injection                 ║
║  [3]  Auto Dorking + Auto Exploit                ║
║  [4]  SQLi Base64 / POST / ERROR Method          ║
║  [5]  Plain Inject — No WAF (v2: Python3 mode)   ║
║  [6]  Scan Site + Auto Inject (Web Crawler)      ║
║  [7]  Reverse IP Vuln SQLi                       ║
║  [8]  Email:Pass Dumper + Mail Filter            ║
║  [9]  Hash Tools / Dork Generator / Admin Finder ║
╚══════════════════════════════════════════════════╝
```

---

## ⚠️ Disclaimer

> This toolkit is developed and published **strictly for educational purposes, bug bounty hunting, and authorized penetration testing only.**
>
> You **must** have explicit written permission from the target system owner before using this tool against any website, server, or application.
>
> The original author (Kedjaw3n) and all contributors to this repository bear **zero responsibility** for any illegal, unauthorized, or malicious use of this software.
>
> By cloning or using this tool, you agree to use it **lawfully and ethically**, in full compliance with the laws and regulations of your jurisdiction.
>
> **Unauthorized access to computer systems is a criminal offense in most countries.**

---

<div align="center">

*Original engine by Kedjaw3n (2019–2020) · v2 reborn by kishwordulal1234*

**Dam Crazy SQLi** — For the ethical hacker in you.

</div>

