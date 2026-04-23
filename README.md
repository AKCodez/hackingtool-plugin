<div align="center">

<img src="images/logo.svg" alt="HackingTool" width="600">

# hackingtool — Claude Code plugin

**183 pentesting & OSINT tools at Claude's fingertips.** Plugin-skill wrapper around [Z4nzu/hackingtool](https://github.com/Z4nzu/hackingtool). Claude Code runs locally — tries every tool first via native Bash, WSL, or Docker with purpose-built images. Only hands off on actual failure (hardware missing, stdin prompts, unavailable backend).

![Plugin](https://img.shields.io/badge/Claude_Code-Plugin-7B61FF?style=for-the-badge)
![Tools](https://img.shields.io/badge/183_Tools-00FF88?style=for-the-badge)
![Categories](https://img.shields.io/badge/20+_Categories-FF61DC?style=for-the-badge)
![OS](https://img.shields.io/badge/Linux_%7C_macOS_%7C_Windows-FFA116?style=for-the-badge&logo=linux&logoColor=white)

Built by [ariacodez](https://github.com/AKCODEZ) · wraps [Z4nzu/hackingtool](https://github.com/Z4nzu/hackingtool) (MIT)

</div>

---

## Install

```
/plugin marketplace add AKCODEZ/hackingtool-plugin
/plugin install hackingtool@hackingtool-marketplace
```

Then ask Claude something like *"recon example.com"* or *"investigate the username johndoe"* — the skill auto-activates.

---

## Screenshots

<div align="center">

<img src="images/A.png" alt="HackingTool main menu" width="720">
<br><sub>Main menu — 20 categories, ~185 tools</sub>

<br><br>

<img src="images/AA.png" alt="Category listing" width="720">
<br><sub>Category view with install status per tool</sub>

<br><br>

<img src="images/AAA.png" alt="Tool run view" width="720">
<br><sub>Tool detail — install / run / update / open folder</sub>

<br><br>

<img src="images/AAAA.png" alt="Search and filter" width="720">
<br><sub>Search, tag filter, and recommend</sub>

<br><br>

<img src="images/AAAAA.png" alt="Help overlay" width="720">
<br><sub>Inline help + quick commands</sub>

</div>

Screenshots from the upstream [Z4nzu/hackingtool](https://github.com/Z4nzu/hackingtool) repo — the plugin gives Claude the same coverage without the menu.

---

## How it works (try-first)

Claude Code runs on your machine. So does this plugin. Every tool invocation goes through `ht_run.py`, which:

1. Picks a backend: **native** (Linux/macOS), **WSL** (Windows + real distro), or **Docker** (anywhere with Docker Desktop).
2. Maps known tools to **purpose-built Docker images** (`instrumentisto/nmap`, `projectdiscovery/nuclei`, `caffix/amass`, etc.) for fast pulls and clean ENTRYPOINTs. Falls back to `kalilinux/kali-rolling` for anything not mapped.
3. **Tries the command first.** Permission denied? Retries with `sudo -n`. Binary missing? Suggests `--install`. Hardware not visible? *That's* when it hands off, with the actual error message.
4. Only one pre-block: tools flagged `interactive` (they read stdin mid-run and can't be answered through Bash pipes). Bypass with `--force` + `--command` if you have non-interactive args.

Capability flags in the index are hints — not veto votes. The old 🟢/🟡 split is a rough proxy for "how likely is this to run cleanly on the first attempt":

| Icon | Meaning |
|---|---|
| 🟢 | High confidence — no sudo, no hardware, no GUI, no stdin prompts. Usually just works. |
| 🟡 | May need `sudo -n` retry, GUI launch on desktop, or handoff on real failure (missing hardware, install needed). The plugin will try first and tell you what actually happened. |

Current breakdown: **56 high-confidence runs · 127 may-need-fallback**.

---

## OS support

The plugin picks a backend automatically via `ht_env.py`:

| Host | Backend |
|---|---|
| Linux / macOS native | `bash -lc <cmd>` |
| Windows + real WSL distro (Ubuntu, Kali, etc.) | `wsl -d <distro> -- bash -lc <cmd>` |
| Windows + Docker Desktop (no WSL) | `docker run --rm kalilinux/kali-rolling bash -lc <cmd>` |
| Windows without either | Handoff with install hints |

Tools still need to be installed in the chosen backend. `ht_run.py <tool_id> --install` runs the install commands (which may itself be a handoff if install needs sudo).

---

## Master tool inventory

Legend: 🟢 Claude runs it directly · 🟡 handoff (sudo / GUI / interactive / hardware)

**183 tools total** — 🟢 56 Claude-runnable · 🟡 127 handoff


### 🛡 Anonymously Hiding (2)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [Anonymously Surf](https://github.com/Und3rf10w/kali-anonsurf) | It automatically overwrites the RAM when the system shuts down | 🟡 | `sudo` |
| [Multitor](https://github.com/trimstray/multitor) | How to stay in multi places at the same time. | 🟡 | `sudo` |

### 🔍 Information Gathering (26)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [Amass (Attack Surface Mapping)](https://github.com/owasp-amass/amass) | In-depth subdomain enumeration and attack surface mapping. | 🟢 | — |
| [Breacher](https://github.com/s0md3v/Breacher) | An advanced multithreaded admin panel finder written in python. | 🟡 | `interactive` |
| [Dracnmap](https://github.com/Screetsec/Dracnmap) | Open source program using nmap to exploit the network and gather information. | 🟡 | `sudo` |
| [Find Info Using Shodan](https://github.com/m4ll0k/Shodanfy.py) | Get ports, vulnerabilities, information, banners. | 🟡 | — |
| [Gitleaks (Git Secret Scanner)](https://github.com/gitleaks/gitleaks) | Fast secret scanner for git repos — detects hardcoded passwords, API keys, tokens. | 🟢 | — |
| [Holehe (Email → Social Accounts)](https://github.com/megadose/holehe) | Check if an email address is registered on 120+ websites. | 🟢 | — |
| Host to IP | Resolve hostname to IP. | 🟡 | `interactive` |
| [httpx (HTTP Toolkit)](https://github.com/projectdiscovery/httpx) | Fast multi-purpose HTTP probing tool. | 🟢 | — |
| [Infoga - Email OSINT](https://github.com/m4ll0k/Infoga) | Gathers email account information (ip, hostname, country) from public sources. | 🟢 | — |
| IsItDown (Check Website Down/Up) | Check Website Is Online or Not. | 🟡 | — |
| [Maigret (Username OSINT)](https://github.com/soxoj/maigret) | Collect a dossier on a person by username across 3000+ sites. | 🟢 | — |
| [Masscan (Fast Port Scanner)](https://github.com/robertdavidgraham/masscan) | Fastest internet port scanner — 10 million packets/sec. | 🟡 | `sudo` |
| [Network Map (nmap)](https://github.com/nmap/nmap) | Free utility for network discovery and security auditing. | 🟡 | `sudo` |
| [Port Scanner - rang3r](https://github.com/floriankunushevci/rang3r) | Python script for multi-threaded port scanning. | 🟡 | `interactive` |
| Port scanning | Basic port scan wrapper. | 🟡 | `interactive` |
| [ReconDog](https://github.com/s0md3v/ReconDog) | ReconDog Information Gathering Suite. | 🟡 | `sudo` |
| [ReconSpider (For All Scanning)](https://github.com/bhavsec/reconspider) | Advanced OSINT Framework for IPs, Emails, Websites, Organizations. | 🟡 | `sudo` |
| [RED HAWK (All In One Scanning)](https://github.com/Tuhinshubhra/RED_HAWK) | All in one tool for Information Gathering and Vulnerability Scanning. | 🟢 | — |
| [RustScan (Modern Port Scanner)](https://github.com/RustScan/RustScan) | Scans all 65k ports in 3 seconds, passes results to nmap automatically. | 🟡 | `sudo` |
| [SecretFinder (like API & etc)](https://github.com/m4ll0k/SecretFinder) | Python script for finding sensitive data like API keys. | 🟡 | `sudo` |
| [SpiderFoot (OSINT Automation)](https://github.com/smicallef/spiderfoot) | Automates OSINT collection for threat intelligence and attack surface mapping. | 🟢 | — |
| [Striker](https://github.com/s0md3v/Striker) | Recon & Vulnerability Scanning Suite. | 🟡 | `interactive` |
| [Subfinder (Subdomain Enumeration)](https://github.com/projectdiscovery/subfinder) | Fast passive subdomain enumeration using multiple sources. | 🟢 | — |
| [theHarvester (OSINT)](https://github.com/laramies/theHarvester) | Gather emails, names, subdomains, IPs and URLs from public sources. | 🟢 | — |
| [TruffleHog (Secret Scanner)](https://github.com/trufflesecurity/trufflehog) | Find, verify, and analyze leaked credentials across git repos, S3 buckets, filesystems. | 🟢 | — |
| [Xerosploit](https://github.com/LionSec/xerosploit) | Penetration testing toolkit to perform MITM attacks. | 🟡 | `sudo` |

### 📚 Wordlist Generator (7)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [Cupp](https://github.com/Mebus/cupp) | Common User Passwords Profiler — generates personalized wordlists. | 🟡 | `interactive` `long` |
| [Goblin WordGenerator](https://github.com/UndeadSec/GoblinWordGenerator.git) | Goblin WordGenerator. | 🟢 | `long` |
| [haiti (Hash Type Identifier)](https://github.com/noraj/haiti) | Identify hash types — supports 300+ algorithms. | 🟢 | `long` |
| [Hashcat (Password Cracker)](https://github.com/hashcat/hashcat) | World's fastest GPU/CPU password recovery tool — 300+ hash types. | 🟡 | `sudo` `long` |
| [John the Ripper](https://github.com/openwall/john) | Open-source password security auditing and recovery tool. | 🟡 | `sudo` `long` |
| [Password list (1.4B Clear Text)](https://github.com/Viralmaniar/SMWYG-Show-Me-What-You-Got) | Search 1.4 Billion clear text credentials from BreachCompilation leak. | 🟢 | `long` |
| [WordlistCreator](https://github.com/Z4nzu/wlcreator) | C program that generates all possibilities of passwords. | 🟡 | `sudo` `long` |

### 📶 Wireless Attack (13)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [Airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon) | Multi-use bash script for auditing wireless networks. | 🟡 | `sudo` `hw` |
| [Bettercap](https://github.com/bettercap/bettercap) | Swiss army knife for WiFi, BLE, HID, and Ethernet recon and MITM. | 🟡 | `sudo` `hw` |
| [Bluetooth Honeypot (bluepot)](https://github.com/andrewmichaelsmith/bluepot) | Bluetooth receiver honeypot. | 🟡 | `sudo` `hw` |
| [EvilTwin](https://github.com/Z4nzu/fakeap) | Evil Twin attack via fake page and fake Access Point. | 🟡 | `sudo` `hw` |
| [Fastssh](https://github.com/Z4nzu/fastssh) | Multi-threaded scan and brute force against SSH. | 🟡 | `sudo` `hw` |
| [Fluxion](https://github.com/FluxionNetwork/fluxion) | Remake of linset — automated MITM wifi attack. | 🟡 | `interactive` `sudo` `hw` |
| [hcxdumptool](https://github.com/ZerBea/hcxdumptool) | Capture packets and PMKID hashes from WLAN devices. | 🟡 | `sudo` `hw` |
| [hcxtools](https://github.com/ZerBea/hcxtools) | Convert captured WLAN packets to hashcat/JtR-compatible format. | 🟡 | `sudo` `hw` |
| Howmanypeople | Count people around you by monitoring wifi signals. | 🟡 | `sudo` `hw` |
| [pixiewps](https://github.com/wiire/pixiewps) | Brute force offline WPS pin (pixie-dust attack). | 🟡 | `sudo` `hw` `long` |
| [WiFi-Pumpkin](https://github.com/P0cL4bs/wifipumpkin3) | Rogue AP framework for creating fake networks. | 🟡 | `sudo` `hw` |
| [Wifiphisher](https://github.com/wifiphisher/wifiphisher) | Rogue Access Point framework for red team engagements. | 🟡 | `sudo` `hw` |
| [Wifite](https://github.com/derv82/wifite2) | Automated wireless attack tool. | 🟡 | `sudo` `hw` |

### 🧩 SQL Injection (7)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [Blisqy](https://github.com/JohnTroony/Blisqy) | Find time-based blind SQL injections on HTTP headers. | 🟡 | — |
| [DSSS](https://github.com/stamparm/DSSS) | Damn Small SQLi Scanner — GET and POST parameters. | 🟡 | — |
| [Explo](https://github.com/dtag-dev-sec/explo) | Describe web security issues in human and machine readable format. | 🟡 | — |
| [Leviathan](https://github.com/leviathan-framework/leviathan) | Mass audit toolkit — service discovery, brute force, SQLi detection. | 🟢 | — |
| [NoSqlMap](https://github.com/codingo/NoSQLMap) | Audit and automate injection attacks on NoSQL databases. | 🟢 | — |
| [Sqlmap](https://github.com/sqlmapproject/sqlmap) | Automate detection and exploitation of SQL injection flaws. | 🟡 | `interactive` |
| [SQLScan](https://github.com/Cvar1984/sqlscan) | Quick web scanner to find SQL injection points. | 🟡 | `sudo` |

### 🎣 Phishing Attack (17)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [AdvPhishing](https://github.com/Ignitetch/AdvPhishing) | Advance Phishing Tool — OTP phishing. | 🟡 | `sudo` |
| [Autophisher](https://github.com/CodingRanjith/autophisher) | Automated Phishing Toolkit. | 🟡 | `sudo` |
| [BlackEye](https://github.com/An0nUD4Y/blackeye) | Phishing tool with 38 website templates. | 🟡 | `sudo` |
| [BlackPhish](https://github.com/iinc0gnit0/BlackPhish) | Phishing toolkit. | 🟡 | `sudo` |
| [dnstwist](https://github.com/elceef/dnstwist) | Domain name permutation engine — typosquatting and brand impersonation. | 🟢 | — |
| [Evilginx3](https://github.com/kgretzky/evilginx2) | MITM attack framework for phishing login credentials. | 🟡 | `sudo` |
| [HiddenEye](https://github.com/Morsmalleo/HiddenEye) | Modern phishing tool with multi-tunnelling. | 🟡 | `sudo` |
| [I-See-You](https://github.com/Viralmaniar/I-See-You) | Find the exact location of a target via social engineering. | 🟡 | `sudo` |
| [Maskphish](https://github.com/jaykali/maskphish) | Hide phishing URL under a normal looking URL. | 🟡 | `sudo` |
| [Pyphisher](https://github.com/KasRoudra/PyPhisher) | Easy to use phishing tool with 77 website templates. | 🟡 | `sudo` |
| [QR Code Jacking](https://github.com/cryptedwolf/ohmyqr) | QR Code Jacking (Any Website). | 🟡 | `sudo` |
| [QRLJacking](https://github.com/OWASP/QRLJacking) | Session hijacking against QR-code-based login. | 🟡 | `sudo` |
| [SayCheese](https://github.com/hangetzzu/saycheese) | Grab webcam shots from target via malicious link. | 🟡 | `sudo` |
| [Setoolkit](https://github.com/trustedsec/social-engineer-toolkit) | Social-Engineer Toolkit. | 🟡 | `sudo` |
| [ShellPhish](https://github.com/An0nUD4Y/shellphish) | Phishing tool for 18 social media. | 🟡 | `sudo` |
| [SocialFish](https://github.com/UndeadSec/SocialFish) | Automated Phishing Tool & Information Collector. | 🟡 | `sudo` |
| [Thanos](https://github.com/TridevReddy/Thanos) | Browser to Browser Phishing toolkit. | 🟡 | `sudo` |

### 🌐 Web Attack (20)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [Arjun](https://github.com/s0md3v/Arjun) | HTTP parameter discovery — finds hidden GET/POST parameters. | 🟢 | — |
| [Blazy](https://github.com/UltimateHackers/Blazy) | Modern login page bruteforcer (also clickjacking). | 🟡 | `archived` |
| [Caido](https://github.com/caido/caido) | Lightweight web security auditing toolkit — Burp alternative in Rust. | 🟡 | `sudo` |
| [CheckURL](https://github.com/UndeadSec/checkURL) | Detect evil URLs that use IDN Homograph Attack. | 🟢 | — |
| [Dirb](https://gitlab.com/kalilinux/packages/dirb) | Web Content Scanner — existing and hidden Web Objects. | 🟡 | `interactive` `sudo` |
| [Dirsearch](https://github.com/maurosoria/dirsearch) | Web path brute-forcing — directories and files on web servers. | 🟢 | — |
| [Feroxbuster](https://github.com/epi052/feroxbuster) | Fast, recursive content discovery tool in Rust. | 🟡 | `sudo` `long` |
| [ffuf](https://github.com/ffuf/ffuf) | Fast web fuzzer — content, parameter, vhost discovery. | 🟢 | `long` |
| [Gobuster](https://github.com/OJ/gobuster) | Directory/file, DNS, and vhost brute-forcing in Go. | 🟢 | — |
| [Katana](https://github.com/projectdiscovery/katana) | Next-generation crawling and spidering framework. | 🟢 | — |
| [mitmproxy](https://github.com/mitmproxy/mitmproxy) | Interactive TLS-capable intercepting HTTP proxy. | 🟢 | — |
| [Nikto](https://github.com/sullo/nikto) | Scan web servers for dangerous files, outdated software, misconfig. | 🟡 | `sudo` |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Fast, template-based vulnerability scanner used by 50k+ teams. | 🟢 | — |
| [OWASP ZAP](https://github.com/zaproxy/zaproxy) | Full-featured web application security scanner. | 🟡 | `sudo` `gui` |
| Skipfish | Automated active web application security reconnaissance. | 🟡 | `sudo` |
| [Sub-Domain TakeOver](https://github.com/edoardottt/takeover) | Sub-domain takeover scanner. | 🟡 | — |
| [Sublist3r](https://github.com/aboul3la/Sublist3r) | Enumerate subdomains of websites using OSINT. | 🟡 | `sudo` |
| [testssl.sh](https://github.com/drwetter/testssl.sh) | Check TLS/SSL ciphers, protocols, and cryptographic flaws. | 🟢 | — |
| [wafw00f](https://github.com/EnableSecurity/wafw00f) | Fingerprint and identify Web Application Firewalls (WAF). | 🟢 | — |
| [Web2Attack](https://github.com/santatic/web2attack) | Web hacking framework with tools and exploits. | 🟡 | `sudo` |

### 🔧 Post Exploitation (10)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [Chisel](https://github.com/jpillora/chisel) | Fast TCP/UDP tunnel over HTTP — pivoting and port forwarding. | 🟢 | — |
| [Chrome Keylogger](https://github.com/UndeadSec/HeraKeylogger) | Hera Chrome Keylogger. | 🟡 | `sudo` |
| [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) | Ultimate WinRM shell for Windows pentesting. | 🟢 | — |
| [Havoc](https://github.com/HavocFramework/Havoc) | Modern post-exploitation C2 framework with EDR evasion. | 🟢 | — |
| [Ligolo-ng](https://github.com/nicocha30/ligolo-ng) | Advanced tunneling/pivoting via TUN interfaces. | 🟢 | — |
| [Mythic](https://github.com/its-a-feature/Mythic) | Collaborative multi-payload C2 platform for red team ops. | 🟡 | `sudo` |
| [PEASS-ng (LinPEAS/WinPEAS)](https://github.com/peass-ng/PEASS-ng) | Privilege escalation enumeration for Linux and Windows. | 🟢 | — |
| [pwncat-cs](https://github.com/calebstewart/pwncat) | Post-exploitation platform — manages reverse/bind shells. | 🟢 | — |
| [Sliver](https://github.com/BishopFox/sliver) | Cross-platform adversary emulation / red team C2. | 🟡 | `sudo` |
| [Vegile (Ghost In The Shell)](https://github.com/Screetsec/Vegile) | Set up backdoor/rootkits when a backdoor is already set up. | 🟡 | `sudo` |

### 🕵 Forensics (8)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| Autopsy | Forensic investigation platform. | 🟡 | `sudo` `gui` |
| [Binwalk](https://github.com/ReFirmLabs/binwalk) | Analyze, reverse engineer, and extract firmware images. | 🟢 | — |
| [Bulk extractor](https://github.com/simsong/bulk_extractor) | Extract useful information without parsing the file system. | 🟡 | — |
| [Guymager (Disk Clone / ISO)](https://guymager.sourceforge.io/) | Free forensic imager for media acquisition. | 🟡 | `sudo` |
| [pspy](https://github.com/DominicBreuker/pspy) | Monitor Linux processes without root — cron jobs, scheduled tasks. | 🟢 | — |
| [Toolsley](https://www.toolsley.com/) | Ten-plus useful tools for investigation. | 🟡 | — |
| [Volatility 3](https://github.com/volatilityfoundation/volatility3) | World's most widely used memory forensics framework. | 🟡 | `interactive` |
| Wireshark | Network capture and analyzer. | 🟡 | `sudo` `gui` |

### 📦 Payload Creation (8)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [Brutal](https://github.com/Screetsec/Brutal) | Toolkit for payloads, powershell attacks, HID attacks. | 🟡 | `sudo` |
| [Enigma](https://github.com/UndeadSec/Enigma) | Multiplatform payload dropper. | 🟡 | `sudo` |
| [Mob-Droid](https://github.com/kinghacker0/Mob-Droid) | Generate metasploit payloads easily. | 🟡 | `sudo` |
| [MSFvenom Payload Creator](https://github.com/g0tmi1k/msfpc) | Wrapper to generate multiple types of payloads. | 🟡 | `sudo` |
| [Spycam](https://github.com/indexnotfound404/spycam) | Win32 payload that captures webcam images every minute. | 🟢 | — |
| [Stitch](https://nathanlopez.github.io/Stitch) | Cross Platform Python Remote Administrator Tool. | 🟡 | `sudo` |
| [The FatRat](https://github.com/Screetsec/TheFatRat) | Backdoor/payload generation that can bypass most AV. | 🟡 | `sudo` |
| [Venom Shellcode Generator](https://github.com/r00t-3xp10it/venom) | Exploits apache2 to deliver LAN payloads via fake webpages. | 🟡 | `sudo` |

### 🧰 Exploit Framework (3)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [Commix](https://github.com/commixproject/commix) | Automated OS command injection and exploitation tool. | 🟡 | `interactive` `sudo` |
| [RouterSploit](https://github.com/threat9/routersploit) | Exploitation framework dedicated to embedded devices. | 🟡 | `sudo` |
| [WebSploit](https://github.com/The404Hacking/websploit) | Advanced MITM framework. | 🟡 | `sudo` |

### 🔁 Reverse Engineering (5)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [Androguard](https://github.com/androguard/androguard) | Reverse engineering and malware analysis of Android apps. | 🟡 | `sudo` |
| [Apk2Gold](https://github.com/lxdvs/apk2gold) | CLI tool for decompiling Android apps to Java. | 🟡 | `interactive` `sudo` |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | NSA's software reverse engineering framework. | 🟡 | `sudo` `gui` |
| [JadX](https://github.com/skylot/jadx) | Dex to Java decompiler. | 🟡 | `sudo` |
| [Radare2](https://github.com/radareorg/radare2) | Portable UNIX-like reverse engineering framework. | 🟢 | — |

### ⚡ DDOS (6)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [Asyncrone (SYN Flood)](https://github.com/fatihsnsy/aSYNcrone) | C-based multifunction SYN Flood weapon. | 🟡 | `interactive` `sudo` `long` |
| [DDoS Script](https://github.com/the-deepnet/ddos) | DDoS attack script — 36+ methods. | 🟡 | `interactive` `sudo` `long` |
| [GoldenEye](https://github.com/jseidl/GoldenEye) | Python3 stress testing app. | 🟡 | `interactive` `long` |
| [SaphyraDDoS](https://github.com/anonymous24x7/Saphyra-DDoS) | Python DDoS script. | 🟡 | `interactive` `long` |
| SlowLoris | HTTP Denial of Service attack. | 🟡 | `interactive` `sudo` `long` |
| [UFOnet](https://github.com/epsylon/ufonet) | P2P cryptographic disruptive toolkit for DoS/DDoS. | 🟡 | `gui` `long` |

### 🖥 RAT (1)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [Pyshell](https://github.com/knassar702/pyshell) | RAT with file upload/download. | 🟢 | — |

### 💥 XSS (9)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [XSStrike](https://github.com/UltimateHackers/XSStrike) | Python-based XSS detection and exploitation tool. | 🟡 | `sudo` |
| [DalFox](https://github.com/hahwul/dalfox) | XSS scanning and parameter analysis tool. | 🟡 | `sudo` |
| [Extended XSS Searcher](https://github.com/Damian89/extended-xss-search) | Extended XSS searcher and finder. | 🟡 | `interactive` |
| [RVuln](https://github.com/iinc0gnit0/RVuln) | Multi-threaded web vulnerability scanner in Rust. | 🟡 | `sudo` |
| [XanXSS](https://github.com/Ekultek/XanXSS) | Reflected XSS searching tool with template-based payloads. | 🟡 | — |
| [XSpear](https://github.com/hahwul/XSpear) | XSS scanner built on Ruby Gems. | 🟢 | — |
| [XSS Payload Generator](https://github.com/capture0x/XSS-LOADER.git) | XSS payload generator, scanner, and dork finder. | 🟡 | `sudo` |
| [XSS-Freak](https://github.com/PR0PH3CY33/XSS-Freak) | XSS scanner written in Python 3. | 🟡 | `sudo` |
| [XSSCon](https://github.com/menkrep1337/XSSCon) | XSS scanner. | 🟡 | `interactive` `sudo` |

### 🖼 Steganography (4)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| SteganoHide | Hide/retrieve data in image or audio files. | 🟡 | `interactive` `sudo` |
| StegnoCracker | Brute force hidden data inside files. | 🟡 | `interactive` `long` |
| [StegoCracker](https://github.com/W1LDN16H7/StegoCracker) | Hide and retrieve data in image or audio files. | 🟡 | `sudo` |
| [Whitespace](https://github.com/beardog108/snow10) | Steganography via whitespace and unicode. | 🟡 | `sudo` |

### 🏢 Active Directory (6)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [BloodHound](https://github.com/BloodHoundAD/BloodHound) | Graph theory to reveal hidden attack paths in AD/Azure. | 🟡 | `sudo` |
| [Certipy](https://github.com/ly4k/Certipy) | Active Directory Certificate Services enumeration and abuse. | 🟢 | — |
| [Impacket](https://github.com/fortra/impacket) | Python classes for SMB, MSRPC, Kerberos, LDAP. | 🟢 | — |
| [Kerbrute](https://github.com/ropnop/kerbrute) | Kerberos pre-auth brute-forcer — enumeration and spraying. | 🟢 | — |
| [NetExec (nxc)](https://github.com/Pennyw0rth/NetExec) | Swiss army knife for Windows/AD pentesting — CrackMapExec successor. | 🟢 | — |
| [Responder](https://github.com/lgandx/Responder) | LLMNR/NBT-NS/MDNS poisoner for credential capture. | 🟡 | `sudo` |

### ☁ Cloud Security (4)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [Pacu](https://github.com/RhinoSecurityLabs/pacu) | AWS exploitation framework for offensive security testing. | 🟢 | — |
| [Prowler](https://github.com/prowler-cloud/prowler) | Security tool for AWS, Azure, GCP, Kubernetes. | 🟢 | — |
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | Multi-cloud security auditing tool. | 🟢 | — |
| [Trivy](https://github.com/aquasecurity/trivy) | Vulnerability scanner for containers, Kubernetes, IaC. | 🟡 | `sudo` |

### 📱 Mobile Security (3)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [Frida](https://github.com/frida/frida) | Dynamic instrumentation toolkit for runtime hooking. | 🟢 | — |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | All-in-one mobile app pentesting and malware analysis. | 🟢 | — |
| [Objection](https://github.com/sensepost/objection) | Runtime mobile exploration powered by Frida. | 🟢 | — |

### ✨ Other (1)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [HatCloud](https://github.com/HatBashBR/HatCloud) | Ruby tool to bypass CloudFlare and discover real IP. | 🟡 | `interactive` |

### 📱 Android Attack (5)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [DroidCam (Capture Image)](https://github.com/kinghacker0/WishFish) | Grab front camera snap using a link. | 🟡 | `sudo` |
| [EvilApp](https://github.com/crypticterminal/EvilApp) | Android App that hijacks authenticated sessions in cookies. | 🟢 | — |
| [Keydroid](https://github.com/F4dl0/keydroid) | Android Keylogger + Reverse Shell. | 🟢 | — |
| [Lockphish](https://github.com/JasonJerry/lockphish) | Lock-screen phishing. | 🟢 | — |
| [MySMS](https://github.com/papusingh2sms/mysms) | Android App that hacks SMS through WAN. | 🟢 | — |

### 📧 Email Verifier (1)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [Knockmail](https://github.com/heywoodlh/KnockMail) | Verify if an email exists. | 🟡 | `sudo` |

### 🔑 Hash Crack (1)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [Hash Buster](https://github.com/s0md3v/Hash-Buster) | Hash cracking via public hash databases. | 🟢 | — |

### 🎭 Homograph (1)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [EvilURL](https://github.com/UndeadSec/EvilURL) | Unicode evil domains for IDN Homograph Attack. | 🟢 | — |

### 🧪 Mix Tools (2)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [Crivo](https://github.com/GMDSantana/crivo) | Extract and filter URLs, IPs, domains, and subdomains. | 🟡 | — |
| Terminal Multiplexer | Tilix — tiling terminal emulator. | 🟡 | `sudo` |

### 💉 Payload Injection (2)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [Debinject](https://github.com/UndeadSec/Debinject) | Inject malicious code into *.debs. | 🟢 | — |
| [Pixload](https://github.com/chinarulezzz/pixload) | Image Payload Creating tools. | 🟡 | `sudo` |

### 📱 Social Media (4)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [AllinOne SocialMedia Attack](https://github.com/Matrix07ksa/Brute_Force) | Brute-force Gmail, Hotmail, Twitter, Facebook, Netflix. | 🟡 | `sudo` |
| [Application Checker](https://github.com/jakuta-tech/underhanded) | Check if an app is installed on the target via link. | 🟡 | `sudo` |
| [Facebook Attack](https://github.com/Matrix07ksa/Brute_Force) | Facebook BruteForcer. | 🟡 | `interactive` `sudo` |
| [Instagram Attack](https://github.com/chinoogawa/instaBrute) | Brute force attack against Instagram. | 🟡 | `archived` |

### 🔎 Social Media Finder (4)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [Find SocialMedia By Facial Recognition](https://github.com/Greenwolf/social_mapper) | Social Media Mapping Tool that correlates profiles. | 🟡 | `sudo` |
| [Find SocialMedia By UserName](https://github.com/xHak9x/finduser) | Find usernames across 75+ social networks. | 🟡 | `sudo` |
| [Sherlock](https://github.com/sherlock-project/sherlock) | Hunt down social media accounts by username. | 🟡 | `interactive` `sudo` |
| [SocialScan](https://github.com/iojw/socialscan) | Check email and username availability on online platforms. | 🟡 | `interactive` |

### 🕸 Web Crawling (1)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [Gospider](https://github.com/jaeles-project/gospider) | Fast web spider written in Go. | 🟡 | `sudo` |

### 📡 Wifi Jamming (2)

| Tool | What it does | Claude | Flags |
|---|---|:---:|---|
| [KawaiiDeauther](https://github.com/aryanrtm/KawaiiDeauther) | Pentest toolkit for wifi deauthentication. | 🟡 | `sudo` `hw` |
| [WifiJammer-NG](https://github.com/MisterBianco/wifijammer-ng) | Continuously jam all wifi clients and APs within range. | 🟡 | `sudo` `hw` |

---

## Refreshing the tool index

When upstream hackingtool adds tools, regenerate `data/tools.json` and the README table:

```
python ${CLAUDE_PLUGIN_ROOT}/scripts/ht_index.py --hackingtool-path /path/to/hackingtool
python ${CLAUDE_PLUGIN_ROOT}/scripts/build_readme_table.py > new_table.md
```

If hackingtool is a sibling directory of this repo, `--hackingtool-path` isn't needed — the script auto-detects.

---

## Directory layout

```
hackingtool-plugin/
├── .claude-plugin/
│   └── marketplace.json          # marketplace entry
├── images/                       # screenshots + logo
├── README.md                     # this file
└── plugins/hackingtool/
    ├── .claude-plugin/plugin.json
    ├── data/tools.json           # generated index
    ├── scripts/
    │   ├── ht_index.py           # (dev) regenerate tools.json
    │   ├── build_readme_table.py # (dev) regenerate the table above
    │   ├── ht_search.py          # query index
    │   ├── ht_env.py             # detect backend
    │   └── ht_run.py             # run or hand off
    └── skills/pentest/
        ├── SKILL.md
        └── reference/
            ├── workflows.md
            └── handoff-patterns.md
```

---

## Limitations

- **Python 3.10+** required.
- **No async tool streaming.** Long-running tools block until they finish or timeout.
- **Docker backend** pulls `kalilinux/kali-rolling` on first use.
- **Capability flags are heuristics.** If you find a mis-tagged tool, fix it in `data/tools.json` or open an issue.

---

## Credits

- Upstream toolkit: [Z4nzu/hackingtool](https://github.com/Z4nzu/hackingtool) — all tool metadata, categorization, and screenshots originate from this project.
- Plugin wrapper: [ariacodez](https://github.com/AKCODEZ) (AKCodez on GitHub).

## License

MIT. Upstream Z4nzu/hackingtool is also MIT-licensed.

> **For authorized security testing, bug bounty, CTFs, and research only.**
