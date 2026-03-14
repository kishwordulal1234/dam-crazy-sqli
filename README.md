<div align="center">
  <img src="https://img.shields.io/badge/Version-v.3%20Modded%20By%20Unknone%20Hart-red?style=for-the-badge&logo=mysql&logoColor=white" />
  <img src="https://img.shields.io/badge/Language-Bash-blue?style=for-the-badge&logo=gnu-bash&logoColor=white" />
  <img src="https://img.shields.io/badge/OS-Linux%20%7C%20Termux-blueviolet?style=for-the-badge&logo=linux&logoColor=white" />

  # 🦇 PSQL-I v.3 (Modded by Unknone Hart) 
  
  **Ultimate SQL Injection & Database Hijacker Tool**
  
  <p><i>Fast Automatic SQL Injection, SQLi Dumper, URL Fuzzer, Dork Tools & Cracking Tools.<br><strong>SQli Never Die!</strong></i></p>

---
</div>

## ✨ What's New? (Original vs. Modded Version)

The **Original PSQL-I v.3** tool is incredibly powerful but contained fatal shell-scripting bugs during column extraction (DIOS phase). When users reached the crucial step of actually dumping the database, the script would frequently trace-crash natively and silently exit to the main menu. 

**Unknone Hart's Modded Version fixes all of these extraction crashes natively.**

| Feature / Issue | ❌ Original Version | ✅ Modded Version (Unknone Hart) |
| --- | --- | --- |
| **`.angka` Truncation Bug** | `cat .angka | sed ... > .angka` caused the file to race-condition itself into 0 bytes. | Handled safely using `.tmp` files (`mv .angka.tmp .angka`), ensuring no data deletion! |
| **Silent Menu Exits** | The script would abruptly crash and return you to the main menu when attempting to dump DB tables. | Added proper validation gates with informative `echo` handling instead of breaking the entire script loop. |
| **`sed` Unterminated 's' Error** | When SQLi found multiple vulnerable columns, variable escaping broke `sed`, throwing syntax errors (`char 22 unterminated 's'`). | Appended precise `head -1` parameter matching to guarantee `sed` receives strict integer values. |
| **`curl` Blank Argument Error** | Because `sed` previously crashed, it constructed empty URLs, causing `curl` to error out. | Fixed implicitly by the `sed` fixes! Custom `curl` argument guards have been added so the script skips gracefully. |
| **Loading Screen** | Standard console start. | Added a custom **Unknone Hart ASCII Animation** boot loader for a sleek aesthetic! |

## 🛠 Features List

1. Single Site Injection
2. Mass Xploit SQL-Injection
3. Auto Dorking + Auto Xploit
4. SQLi Base64 Injection
5. SQLi POST Method
6. SQLi ERROR Based Method
7. Scan Site + Auto Inject (Web Crawler)
8. Reverse IP Vuln SQLi + Auto Inject
9. Query Email Pass Dumper + Auto Filter Mail
10. Hash Tools
11. Dork Generator
12. New Admin Finder
13. PSQLi SQli/Xss/LFI/AdminFinder Scanner
14. SQLi Dork Dumper  
15. Auto Bypass SQL Login Tools
16. Dr.Dork Generator

---

## 🚀 Installation & Usage

**Prerequisites required:** `curl`, `grep`, `gawk`, `sed`, `diff`, `awk`

### 🐧 Linux (Kali/Parrot/Ubuntu)

Open your terminal and execute:

```bash
# Clone the repository (Replace with actual repo link if pushing to GitHub)
# git clone https://github.com/kishwordulal1234/dam-crazy-sqli.git

# Enter the directory
cd dam-crazy-sqli/dcsqli_v2

# close the version u like

# Make the script executable
chmod +x ./psqliv2.sh

# Run the hijacker
bash ./psqliv2.sh
```

### 📱 Android (Termux)

To use this effortlessly on your phone via Termux, you need to configure your package manager first:

```bash
# Update repositories and upgrade packages
pkg update && pkg upgrade -y

# Install required core binaries
pkg install git curl gawk sed ncurses-utils wget diffutils -y

# Clone the repository
# git clone https://github.com/kishwordulal1234/dam-crazy-sqli.git

# Navigate into the tool directory
cd dam-crazy-sqli/dcsqli_v2

# Grant executable permissions
chmod +x ./psqliv2.sh

# Launch the tool!
bash ./psqliv2.sh
```

---

<div align="center">
  <h3>🔥 Warning & Disclaimer 🔥</h3>
  <p>This tool is designed for <b>Bug Bounty Hunting, Educational Purposes, and Authorized Penetration Testing ONLY</b>. Do not use this tool on targets you do not explicitly have permission to test. The developers/modders will not be held responsible for illegal abuse.</p>
</div>
