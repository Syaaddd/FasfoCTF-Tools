# FASFO — Forensics Analysis Suite For Operations

> **CTF Forensics Tool** — All-in-one forensics analysis suite designed for Capture The Flag competitions.

<p align="center">
  <strong>v5.0.0</strong> · 
  Built for <strong>Kali Linux / Parrot OS</strong> · 
  Bash-based CLI Tool · 14 Analysis Modules + Decode Engine + DNS Analysis Engine + Crypto Analysis
</p>

---

## 🔍 Overview

**FASFO** is a comprehensive Bash-based forensics toolkit that automates the analysis of files commonly encountered in CTF forensics challenges. It integrates multiple open-source forensics tools into a single command-line interface with **interactive menus**, **multi-file batch scanning**, a **17-type Decode Engine**, an advanced **DNS Analysis Engine** for tunneling detection, **4 Advanced Modules** for deep forensics (file carving, DFIR memory analysis, network C2 detection, statistical steganography), a **Crypto Analysis module** (RSA, AES, hash cracking, length extension, SageMath integration), **AWK/GREP/SORT log analysis**, **intelligent flag detection**, and **modular analysis pipelines**.

### Key Features

✅ **14 forensics modules** — File, Stego, Network, Memory, Archive, Log, OSINT, Registry, Windows Artifacts, Crypto, + 4 Advanced modules  
✅ **Crypto Analysis** — RSA factoring, AES/DES/ChaCha20 analysis, hash cracking (MD5/SHA/bcrypt), length extension attacks, SageMath integration  
✅ **Advanced File Analysis** — Polyglot detection, XOR brute force, malware static triage, scalpel carving, entropy analysis  
✅ **Advanced Memory/DFIR** — Hidden process detection, DLL injection, SSDT hooks, credential dumping, NTFS timeline, slack space  
✅ **Advanced Network Forensics** — C2 beacon detection, covert channel analysis, TLS/SNI extraction, Zeek integration, ICMP exfil  
✅ **Advanced Steganography** — Chi-square test, entropy analysis, Pillow channel extraction, DCT frequency domain, audio LSB  
✅ **Windows Registry Analysis** — SAM/SYSTEM/NTUSER/SOFTWARE/SECURITY hive parsing + .reg export hex decode  
✅ **Windows Artifact Analysis** — LNK shortcuts, Prefetch files, Event Logs (.evtx)  
✅ **Standalone decode mode** — `fasfo --decode "string"` for instant decoding  
✅ **Auto-decode integration** — Automatically decodes suspicious strings during scans  
✅ **Interactive menu system** — No need to memorize flags, just pick options  
✅ **Multi-file batch scanning** — Scan multiple files in one command  
✅ **AWK/GREP/SORT log analysis** — Column-level precision parsing for auth, HTTP, syslog  
✅ **Auto file-type detection** — Suggests relevant modules based on file type  
✅ **Smart archive bruteforce** — 3-phase attack with CTF common passwords  
✅ **Reversed flag detection** — Auto-detects `}...{PREFIX` patterns and decodes them  
✅ **Log attack detection** — Brute force, SQLi, XSS, port scanning, scanner tools  
✅ **Smart dependency checker** — Auto-detects tools and suggests fixes  
✅ **WSL-aware** — Gracefully handles Windows Subsystem for Linux limitations  
✅ **Report generation** — Structured text reports with built-in report viewer  

---

## 📦 Installation

### Quick Install

```bash
# Clone or download fasfo.sh
chmod +x fasfo.sh

# Install to /usr/local/bin (optional)
./fasfo.sh --install
# Then run from anywhere:
fasfo --help
```

### Dependencies

FASFO auto-checks for these tools on first run (`fasfo --deps`):

| Category | Tool | Package (apt) | Purpose |
|----------|------|---------------|---------|
| **Core** | `file`, `strings`, `xxd` | `file`, `binutils` | File identification & string extraction |
| **Decode Engine** | `python3`, `base64`, `xxd` | `python3`, `binutils` | Multi-encoding decode (17 types) |
| **File Analysis** | `binwalk`, `foremost`, `exiftool` | `binwalk`, `foremost`, `libimage-exiftool-perl` | Embedded file detection & metadata |
| **Steganography** | `zsteg`, `steghide`, `pngcheck`, `outguess` | `zsteg`, `steghide`, `pngcheck` | LSB analysis & hidden data extraction |
| **Network** | `tshark`, `capinfos` | `tshark` | PCAP & DNS analysis |
| **Memory** | `volatility3` | `pip3 install volatility3` | Memory dump forensics |
| **Archive** | `unzip`, `unrar`, `7z`, `fcrackzip`, `john` | `unzip`, `unrar`, `p7zip-full`, `fcrackzip`, `john` | Archive extraction & bruteforce |
| **Log Analysis** | `last`, `lastb`, `lastlog`, `journalctl`, `awk` | `coreutils`, `systemd`, `gawk` | Binary login log & journal analysis |
| **Registry Analysis** | `reglookup`, `regripper` (rip.pl) | `reglookup` | Windows registry hive parsing |
| **Windows Artifacts** | `evtx_dump` / `python-evtx` | `libevtx-utils` / `pip3 install python-evtx` | Event Log (.evtx) parsing |
| **OSINT** | `whois`, `dig` | `whois`, `bind9-dnsutils` | Domain & DNS lookups |
| **Advanced: scalpel** | `scalpel` | `scalpel` | Advanced file carving |
| **Advanced: sleuthkit** | `fls`, `mactime` | `sleuthkit` | NTFS/EXT4 forensics, timeline |
| **Advanced: Python** | `Pillow`, `numpy` | `pip3 install Pillow numpy` | Image analysis, DCT stego |
| **Advanced: zeek** | `zeek` | `zeek` | Advanced network analysis |
| **Advanced: objdump** | `objdump` | `binutils` | ELF/PE malware triage |
| **Crypto: openssl** | `openssl` | `openssl` | RSA/cert analysis, AES encrypt/decrypt |
| **Crypto: hashcat** | `hashcat` | `hashcat` | GPU hash cracking (MD5/SHA/bcrypt) |
| **Crypto: pycryptodome** | `pycryptodome` | `pip3 install pycryptodome` | Python crypto: AES, RSA, DES, ChaCha20 |
| **Crypto: hashpumpy** | `hashpumpy` | `pip3 install hashpumpy` | Hash length extension attacks |
| **Crypto: z3-solver** | `z3-solver` | `pip3 install z3-solver` | SMT solver for reverse crypto |
| **Crypto: SageMath** | `sage` | `sagemath` | RSA factoring, elliptic curves, DLP |
| **Crypto: RsaCtfTool** | `RsaCtfTool` | Manual install | RSA multi-attack auto-solver |
| **Stego: stegcrack** | `stegcrack` | `pip3 install stegcrack` | Steghide brute-force password cracker (Python) |
| **Stego: stegseek** | `stegseek` | `sudo apt install stegseek` | **RECOMMENDED** — C++ native steghide cracker, much faster than stegcrack |
| **Extras** | `stegsolve.jar` | Manual download | GUI steganalysis tool |

#### Install All Common Dependencies

```bash
sudo apt update
sudo apt install file binutils binwalk foremost libimage-exiftool-perl \
                 zsteg steghide pngcheck tshark unrar p7zip-full \
                 fcrackzip john whois bind9-dnsutils perl ffmpeg gawk \
                 reglookup libevtx-utils scalpel sleuthkit zeek \
                 bsdmainutils sonic-visualiser openssl hashcat sagemath stegseek

# Python tools
pip3 install volatility3 Pillow numpy pycryptodome hashpumpy z3-solver stegcrack

# Stegsolve (GUI tool)
wget http://www.caesum.com/handbook/Stegsolve.jar -O ~/bin/stegsolve.jar

# Wordlist for bruteforce
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

#### Check Dependencies

```bash
fasfo --deps
```

This will show which tools are installed and provide install commands for missing ones.

---

## 🚀 Usage

### Three Ways to Use FASFO

FASFO supports three interaction modes:

| Mode | Syntax | Best For |
|------|--------|----------|
| **Interactive** | `fasfo` (no args) | Beginners, exploring files |
| **Interactive + file** | `fasfo image.png` | Quick start with menu guidance |
| **CLI (scriptable)** | `fasfo image.png --Forensics --stego` | Automation, experienced users |

### Interactive Mode (Recommended for Beginners)

Just run `fasfo` with no arguments — it will prompt you to enter a file path:

```bash
fasfo
```

Or provide a file directly — you'll get a guided menu:

```bash
fasfo image.png
```

The interactive mode features:
- **Main menu** — Choose Forensics, Dependency Check, Help, or View Reports
- **Module selector** — Pick specific modules or run Full Scan
- **Auto-hints** — Suggests relevant modules based on file type (e.g., "PNG detected → try Steganography")
- **Report viewer** — Browse and read previously saved scan reports
- **Re-run prompt** — After a scan, ask if you want to run additional modules

### CLI Mode (Scriptable)

```bash
# Full scan (all applicable modules)
fasfo image.png --Forensics

# Specific modules only
fasfo capture.pcap --Forensics --net      # Network forensics only
fasfo photo.jpg --Forensics --stego       # Steganography only
fasfo memory.raw --Forensics --mem        # Memory forensics only
fasfo domain.com --Forensics --osint      # OSINT only
fasfo secret.zip --Forensics --archive    # Archive analysis only
fasfo auth.log --Forensics --log           # Log analysis only
fasfo NTUSER.DAT --Forensics --registry    # Registry hive analysis
fasfo SYSTEM --Forensics --registry         # System hive analysis
fasfo memdump.raw --Forensics --registry    # Memory registry extraction
fasfo shortcut.lnk --Forensics --windows    # LNK/Prefetch/EVTX analysis
```

### Multi-File Batch Scanning

Scan multiple files in a single command:

```bash
# Interactive multi-file mode (drag & drop friendly)
fasfo image.png photo.jpg capture.pcap

# CLI multi-file mode
fasfo file1.png file2.jpg secret.zip --Forensics --stego
```

Features:
- **Progress bar** with ASCII art
- **Per-file reports** — Each file gets its own report
- **Smart module suggestions** — Detects mixed file types and suggests modules
- **Pause between files** — Option to skip remaining files
- **Unified summary** — Aggregates flag candidates from all files

### Standalone Decode Mode — NEW in v1.7.0

Decode any string instantly without running a full scan:

```bash
# Decode a base64 string
fasfo --decode "RlRDe3R1cjBfMW5fNHJ0MTRmY3R9"

# Decode a reversed flag
fasfo --decode "}tc4f1tr4_fn1_nur0tu4{FTC"

# Decode a hex string
fasfo --decode "4654437b6865785f666c61677d"

# Interactive decode mode (prompts for input)
fasfo --decode
```

The decode engine tries **17 encoding types** automatically and reports all successful decodes.

### Available Options

| Flag | Description |
|------|-------------|
| `--Forensics` | **Required for CLI mode.** Activates forensics analysis mode |
| `--decode` | Decode string directly (base64, hex, rot13, reversed, morse, binary, XOR, atbash, l33t, etc.) |
| `--file` | File analysis module only |
| `--stego` | Steganography module only |
| `--net` | Network forensics module only (PCAP + DNS analysis) |
| `--mem` | Memory forensics module only |
| `--osint` | OSINT module only |
| `--archive` | Archive analysis module only (ZIP/RAR/7Z/TAR) |
| `--log` | Log analysis module only |
| `--registry` | Registry analysis module only (SAM/SYSTEM/NTUSER/SOFTWARE/SECURITY/memory) |
| `--windows` | Windows artifact module only (LNK/Prefetch/EVTX) |
| `--adv-file` | Advanced file analysis (polyglot, XOR, malware triage, scalpel) |
| `--adv-mem` | Advanced memory/DFIR (hidden proc, DLL injection, SSDT, timeline) |
| `--adv-net` | Advanced network forensics (C2 detection, covert channels, Zeek) |
| `--adv-stego` | Advanced steganography (chi-square, DCT, Pillow channels, audio LSB) |
| `--crypto` | Crypto analysis (RSA, AES, hash cracking, length extension, SageMath) |
| `--deps` | Check all dependencies |
| `--help`, `-h` | Show help message |
| `--install` | Install fasfo to `/usr/local/bin` |
| `--version` | Show version |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `FASFO_WORDLIST=/path/to/wordlist.txt` | Custom wordlist for archive bruteforce (default: rockyou.txt) |

---

## 📋 Modules

### 1. 📁 File Analysis (`--file`)

Analyzes file structure, content, and metadata.

**Features:**
- **Magic bytes** detection — Identifies true file type vs. extension
- **Extension mismatch** detection — Flags suspicious file type mismatches (e.g., `.png` that's actually a `.jpg`)
- **Strings extraction** — Extracts printable strings (≥6 chars) with flag pattern matching
- **Hex dump** — Shows first 32 bytes in hexadecimal
- **Binwalk** — Scans for embedded files and signatures
- **File carving** — Uses `foremost` to extract embedded files
- **Metadata extraction** — Full `exiftool` dump with suspicious field detection (comment, author, password, key, etc.)

#### Auto-Decode Integration — NEW in v1.7.0

During file analysis, FASFO automatically detects and decodes:

| Pattern | Auto-Decode Action |
|---------|-------------------|
| Normal flags `CTF{...}`, `flag{...}` | Logged as `STRINGS_FLAGS` |
| **Reversed flags** `}...{PREFIX` | Extracted, decoded via full decode engine |
| Base64 strings (24+ chars) | Decoded, checked for nested flags |
| Hex strings (32+ chars, with or without `0x`) | Decoded to text |
| URL-encoded strings (`%xx`) | Decoded |

All decoded results are saved to the report for reference.

**Supported formats:** All file types (PNG, JPEG, PDF, etc.)

---

### 2. 🖼️ Steganography (`--stego`)

Detects and extracts hidden data from images and audio.

**Features by file type:**

#### PNG Files
- **pngcheck** — Validates PNG structure and chunks
- **zsteg** — LSB (Least Significant Bit) and channel analysis
- **Stegsolve** — GUI-based bit-plane analysis (auto-launches if available)

#### JPEG Files
- **steghide** — Extracts hidden data (tries empty passphrase first)
- **stegseek** — **RECOMMENDED** — C++ native steghide cracker, significantly faster than stegcrack. Uses rockyou.txt wordlist with rapid GPU-like speed. Supports `--seed` mode for steghide file detection without wordlist.
- **stegcrack** — Python-based steghide brute-force password cracker using wordlists (rockyou.txt), with progress display and auto-extraction on success
- **outguess** — Alternative steganography extraction

#### Audio Files
- **ffmpeg** audio info — Duration, codec, stream details
- Hints for spectrogram analysis (Audacity/Sonic Visualiser)
- **steghide** support for audio files

**Flag detection:** All modules scan for embedded CTF flag patterns.

---

### 3. 🌐 Network Forensics (`--net`)

Analyzes PCAP files for hidden data, credentials, and **DNS tunneling/data exfiltration**.

#### Standard PCAP Analysis
- **PCAP summary** — Protocol statistics and overview (via `capinfos` or `tshark`)
- **Protocol breakdown** — Tree view of protocol distribution
- **Top IP conversations** — Most active IP pairs
- **HTTP analysis** — Host + URI extraction for all HTTP requests
- **Credential harvesting** — Detects cleartext credentials (FTP, Telnet, HTTP Basic Auth)
- **Payload flag scanning** — Searches network payload for CTF flags

#### DNS Analysis Engine — NEW in v2.0.0

A comprehensive 7-step DNS analysis pipeline designed to detect and reconstruct data exfiltration via DNS tunneling — a common CTF challenge pattern.

##### Step 1: DNS Query Extraction
- Extracts all DNS queries (request-only, filtering out responses)
- Counts total queries and unique domains
- Displays top 30 unique domains queried

##### Step 2: DNS Tunneling & Anomaly Detection
Automatically detects four tunneling indicators:

| Indicator | Detection Method |
|-----------|-----------------|
| **Sequential subdomains** | Pattern `NN-<data>.<domain>` (e.g., `01-abc.`, `02-def.`) |
| **Abnormally long subdomains** | Subdomains >30 characters before first dot |
| **High-entropy subdomains** | Character diversity ratio ≥0.6 with length ≥8 (data encoded) |
| **Repeated parent domains** | Same parent domain queried ≥4 times with different subdomains |

Each finding increments a **suspicion score** (max 8 points).

##### Step 3: C2 Domain Identification & Chunk Extraction
- Identifies Command & Control (C2) candidate domains by frequency analysis
- For each C2 candidate:
  - Lists all unique queries to that domain
  - Detects sequential chunk patterns (`NN-<data>.<c2dom>`)
  - Displays ordered chunk table with sequence number, full domain, and extracted data

##### Step 4: Data Exfiltration Decoding
Reconstructs and decodes exfiltrated data from DNS subdomain chunks:

| Method | Description |
|--------|-------------|
| **Base32** | Auto-padded, case-normalized Base32 decode of combined chunks |
| **Base64** | Standard Base64 decode of combined chunks |
| **Hex** | Hex decode if chunk data is hex-formatted |
| **FASFO Decode Engine** | All 17 encoding types tried on combined data |

Flags found in decoded DNS tunnel data are highlighted with `[FLAG?]` markers.

##### Step 5: DNS Record Type Analysis
- Categorizes all DNS record types (A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, ANY)
- **TXT record detection** — TXT records are commonly used for C2 responses
- Auto-decodes TXT record content using the decode engine

##### Step 6: IOC Summary
- Aggregates all suspicious indicators into a **tunneling suspicion score** (0-8):
  - Sequential subdomains: +3
  - Long subdomains: +2
  - High-entropy subdomains: +2
  - TXT records present: +1
- Lists all external domains queried (excluding internal/local domains)

##### Step 7: Export Commands
Provides manual `tshark` commands for further investigation:
- `tshark -r <pcap> --export-objects http,/tmp/pcap_http_export`
- `tshark -r <pcap> -Y 'dns' -T fields -e dns.qry.name -e dns.resp.name > dns_full.txt`

#### Supported PCAP Formats
Wireshark/tshark compatible captures (.pcap, .pcapng)

---

### 4. 🧠 Memory Forensics (`--mem`)

Analyzes memory dumps and disk images.

**Features:**
- **OS profile detection** — Auto-detects Windows/Linux memory dumps
- **Process listing** — Running processes at time of dump
- **Network connections** — Active connections from memory
- **Command history** — Executed commands (Windows)
- **Clipboard content** — Clipboard data extraction
- **Quick strings scan** — Flag pattern matching in raw memory

**Fallback:** If `volatility3` is not installed, performs strings-based flag detection.

**Tools:** `volatility3`, `strings`

---

### 5. 📦 Archive Analysis (`--archive`)

Extracts and analyzes archive files (ZIP, RAR, 7Z, TAR, GZ, BZ2, XZ).

**Features:**
- **Auto format detection** — Identifies archive type via magic bytes and extension
- **Metadata & listing** — Detailed file listing with timestamps
- **Encryption detection** — Identifies password-protected archives
- **ZIP/RAR/7Z comment extraction** — Often contains hints or flags
- **ZIP internal detail** — Extra fields, encryption methods via `zipdetails`
- **ZIP bomb detection** — Warns about high compression ratios (>100x)
- **Nested archive detection** — Finds archives within archives
- **String scanning** — Searches archive body for flags and suspicious filenames
- **Automatic extraction** — Extracts unencrypted archives
- **Post-extraction scanning** — Recursively scans extracted files for flags
- **Text file preview** — Displays content of flag/hint/note files

**Supported formats:** ZIP, RAR, 7Z, TAR, GZ, BZ2, XZ

---

### 6. 🔐 Archive Bruteforce — Smart 3-Phase Attack

*Auto-triggered when an encrypted archive is detected.*

Cracks password-protected archives using an intelligent multi-phase approach, designed for speed during competitions.

#### Phase 1 — Smart Password Attack (seconds)

Tests **50+ common CTF passwords** instantly, including:
- Empty password, `password`, `123456`, `admin`, `qwerty`
- **Filename-based** — The archive filename without extension (classic CTF trick: `flag.zip` → password `flag`)
- CTF classics: `flag`, `secret`, `hacker`, `ctf`, `openme`, `challenge`
- Competition-specific: `redlimit`, `lks`, `lks2026`, `cyber`, `forensics`
- Keyboard walks: `qwerty123`, `asdf`, `zxcvbn`, `1q2w3e`
- Years: `2024`, `2025`, `2026`

> ✅ Most CTF archive passwords are found in Phase 1!

#### Phase 2 — John the Ripper (GPU-accelerated)

- Extracts hash via `zip2john` / `rar2john` / `7z2john`
- Runs `john --wordlist=rockyou.txt` with forked processes
- **5-minute timeout** with live progress display
- Falls back to `john --single` mode if rockyou.txt is unavailable
- Can be **Ctrl+C'd** to skip to Phase 3 without killing the script

#### Phase 3 — fcrackzip (ZIP only, 60-second timeout)

- Last resort for ZIP files
- Limited to 60 seconds to avoid wasting competition time

#### If All Phases Fail

FASFO provides actionable hints:
1. Check challenge description for hidden password hints
2. Try the filename itself as password
3. Set custom wordlist: `FASFO_WORDLIST=/path/wordlist.txt`
4. Use hashcat for GPU cracking: `hashcat -m 17200 hash.txt rockyou.txt`
5. Check metadata of other files in the same challenge

**Post-crack:** Auto-extracts and scans all files for flags, displaying text file contents directly.

---

### 7. 🗒️ Log Analysis (`--log`)

Analyzes system, authentication, HTTP, and binary login logs for security events and hidden data.

#### Auto-Detection of Log Type

FASFO automatically detects the log type based on filename and content:

| Log Type | Detection | Analysis |
|----------|-----------|----------|
| **Binary Login** | `wtmp`, `btmp`, `lastlog`, `faillog` | `last`/`lastb`/`lastlog` + strings fallback |
| **Auth/SSH** | `auth.log`, `secure` | Failed logins, brute force, privilege escalation |
| **HTTP Access** | `access.log`, `access_log` | Status codes, attack patterns, scanner detection |
| **HTTP Error** | `error.log`, `error_log` | Error analysis |
| **Syslog** | `syslog`, `messages`, `kern.log` | Service crashes, cron, kernel events |
| **Systemd Journal** | `.journal` files | `journalctl --file` analysis |
| **Generic** | Any `.log` file | Universal checks applied |

#### Auth/SSH Log Analysis

- **SSH failed logins** — Extracts failed password and invalid user attempts
- **Brute force detection** — Alerts when >10 failed login attempts found
- **Top attacker IPs** — Ranks source IPs by failed attempt count
- **Successful logins** — Lists accepted password/publickey sessions
- **Privilege escalation** — Detects suspicious sudo commands (bash, python, nc, wget, curl, chmod, passwd)
- **New user/group creation** — Flags account creation events
- **PAM session events** — Tracks session open/close events

#### HTTP Access Log Analysis

- **HTTP status code summary** — Counts requests by response code
- **Top 10 IP addresses** — Most active clients
- **Attack pattern detection** — SQL injection, LFI, RCE, XSS, path traversal, command injection
- **Scanner/tool detection** — Identifies Nikto, sqlmap, Nmap, Nuclei, DirBuster, Gobuster, Hydra in User-Agent strings
- **POST/PUT requests** — File upload and form submission analysis
- **404/403 enumeration** — Detects directory/path bruteforce (>50 requests)
- **Flag patterns in URLs** — Scans for CTF flags embedded in HTTP requests

#### Syslog Analysis

- **Service crashes** — Detects errors, segfaults, OOM-killer events
- **Cron job analysis** — Lists scheduled tasks
- **Kernel/hardware events** — USB, device mount, kernel messages
- **Firewall events** — iptables, UFW, nftables, dropped packets

#### AWK/GREP/SORT Analysis Engine — NEW in v1.8.0

Per-log-type precision column analysis using `awk`, `grep`, and `sort | uniq -c`:

**AUTH Logs:**
- Service distribution (column 5 extraction)
- Username frequency in failed logins
- Top IP sources (all connections, including successful)
- Event distribution by hour and date
- **Port scanning detection** — Alerts when >5 unique ports appear in auth log

**HTTP Logs:**
- Top URIs accessed (column 7)
- HTTP method distribution (GET/POST/PUT/DELETE)
- Status code distribution with severity labels (`[SERVER ERROR]`, `[CLIENT ERROR]`, `[REDIRECT]`, `[SUCCESS]`)
- Response size statistics (min/max/avg/total)
- 5xx server error analysis
- Top referers (traffic source)
- Traffic timeline per hour (ASCII bar chart)
- Suspicious query strings (SQLi, XSS, encoding patterns)

**Syslog:**
- Top processes/services generating logs
- Severity level distribution (emergency/alert/critical/error/warning/info/debug)
- Event timeline per hour (ASCII bar chart)
- Hostname/node analysis
- **Anomaly detection** — Finds abnormally high PIDs (>99999)

**Generic Logs:**
- First-field token frequency
- Error/warning/fatal keyword counts
- Line length distribution (detects anomalously long lines)

#### Universal Checks (All Log Types)

- **Flag pattern scan** — Searches for all CTF flag formats including **reversed flags** (`}...{PREFIX`) which are auto-decoded
- **Sensitive keyword detection** — Finds passwords, tokens, API keys, secrets, hints
- **Base64 detection & decode** — Automatically finds and decodes base64 strings, checks decoded content for flags
- **Hex string detection** — Identifies and decodes hex-encoded strings with frequency counts
- **IP address extraction** — Lists all unique IPs labeled as `[LOOPBACK]`, `[PRIVATE]`, or `[PUBLIC]`
- **Domain/hostname extraction** — Finds all domains in log content
- **Email address detection** — Extracts all email addresses found
- **URL/endpoint extraction** — Finds all URLs in log content
- **Timeline analysis** — ASCII bar chart showing busiest hours
- **File statistics** — Line count, word count, file size, log period
- **Auto column format detection** — Analyzes sample line structure and column count

---

### 8. 🕵️ OSINT (`--osint`)

Performs open-source intelligence gathering on domains, URLs, and files.

#### For URLs/Domains
- **Whois lookup** — Domain registration information
- **DNS enumeration** — All record types (A, MX, TXT, etc.)
- **Wayback Machine** — Hints for archived web page analysis

#### For Files
- **Full exiftool dump** — Complete metadata extraction
- **GPS coordinate extraction** — Location data from images
- **Hidden metadata detection** — Unusual or suspicious metadata fields (comment, user comment, description, tags, keywords, author, creator, flag, secret, note, hint)

**Tools:** `whois`, `dig`, `exiftool`

---

### 9. 🪟 Registry Analysis (`--registry`) — NEW in v3.0.0

Analyzes Windows registry hive files (SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT, UsrClass.dat) and memory dumps for CTF-relevant artifacts.

#### Supported Input Types

| Input Type | Detection Method | Analysis Engine |
|------------|-----------------|-----------------|
| **.reg export** | Extension `.reg` or header `Windows Registry Editor` | Text parsing + hex decode |
| **SAM hive** | Filename starts with `sam` | reglookup + RegRipper |
| **SYSTEM hive** | Filename starts with `system` | reglookup + RegRipper |
| **SOFTWARE hive** | Filename starts with `software` | reglookup + RegRipper |
| **SECURITY hive** | Filename starts with `security` | reglookup + RegRipper |
| **NTUSER.DAT** | Filename starts with `ntuser` | reglookup + RegRipper |
| **UsrClass.dat** | Filename starts with `usrclass` | reglookup + RegRipper |
| **Memory dump** | File type contains `memory`/`dump`/`crash` | Volatility3 registry plugins |

#### Registry Export File (.reg) Analysis

When a `.reg` text export file is provided (exported from Windows Registry Editor), FASFO performs a specialized 6-step text-based analysis:

**Step 1: Read & Display File Content**
- Displays the full `.reg` file content (first 100 lines)
- Counts total lines and identifies all registry key paths (`[HKEY_...]`)

**Step 2: Identify Suspicious Values**
- Scans for persistence keys: `Run`, `RunOnce`, `RunServices`, `Winlogon\Userinit`
- Flags any startup/persistence mechanisms found

**Step 3: Extract & Decode Hex Data**
- Extracts all `hex:` encoded values (e.g., `"SystemCheck"=hex:43,54,46,7b,...`)
- Handles multi-line hex values (continuation lines with `\`)
- Merges all hex data and decodes to ASCII using `xxd`
- Displays hex → ASCII breakdown table
- **Auto-detects flags** in decoded hex data (e.g., `CTF{r3g1stry_4rt1f4ct_f0und}`)

**Step 4: String Values**
- Extracts all string (`"key"="value"`) entries
- Detects flags and reversed flags in string values

**Step 5: Dword Values**
- Lists all `dword:` entries

**Step 6: Full File Flag Pattern Scan**
- Scans entire `.reg` file for CTF flag patterns
- Detects and auto-decodes reversed flags (`}...{PREFIX`)

**Example .reg flag pattern:**
```reg
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce]
"SystemCheck"=hex:43,54,46,7b,72,33,67,31,73,74,72,79,5f,34,72,74,31,66,34,63,74,5f,66,30,75,6e,64,7d
```
→ Decodes to: `CTF{r3g1stry_4rt1f4ct_f0und}`

#### Offline Hive Analysis (11-Step Pipeline)

**Step 1: Hive Structure Scan**
- Validates hive readability via `reglookup`
- Identifies hive type (SAM/SYSTEM/SOFTWARE/SECURITY/NTUSER/UsrClass)

**Step 2: Registry Key Extraction**
Per-hive key extraction targeting CTF-relevant artifacts:

| Hive | Key Paths Analyzed |
|------|-------------------|
| **SAM** | `SAM\Domains\Account\Users`, `SAM\Domains\Account\Users\Names` |
| **SYSTEM** | `ComputerName`, `TimeZoneInformation`, `Windows`, `USB\Enum`, `USBSTOR\Enum`, `MountedDevices` |
| **SOFTWARE** | `Uninstall`, `Run`, `RunOnce`, `Shell Folders`, `Windows NT\CurrentVersion`, `TaskCache\Tasks` |
| **SECURITY** | `Policy\PolAdtEv`, `Policy\PolAudit` |
| **NTUSER.DAT** | `UserAssist`, `RecentDocs`, `RunMRU`, `TypedURLs`, `Shell Folders`, `IE\TypedURLs`, `Run`, `RunOnce`, `Shell\Bags`, `Regedit`, `OpenSaveMRU`, `LastVisitedMRU` |
| **UsrClass.dat** | `BagMRU`, `Bags`, `MuiCache` |

**Step 3: UserAssist ROT13 Decoding**
- Extracts UserAssist entries from NTUSER.DAT
- Automatically decodes ROT13-encoded program names
- Flags found in decoded UserAssist entries are highlighted

**Step 4: Run Keys Analysis (Persistence Detection)**
- Scans all Run/RunOnce/RunServices/Winlogon keys
- Detects persistence mechanisms
- Flags found in Run key values are highlighted

**Step 5: USB Device History**
- Extracts `CurrentControlSet\Enum\USB` entries
- Counts unique USB devices
- Extracts `USBSTOR` entries for connected storage devices
- Flags found in USB history are highlighted

**Step 6: Recent Documents & MRU Lists**
- RecentDocs, RunMRU, OpenSaveMRU, LastVisitedMRU
- TypedURLs (browser history from registry)
- Flags found in MRU entries are highlighted

**Step 7: Installed Programs**
- Enumerates `Uninstall` keys
- Counts total installed programs
- **Detects suspicious programs**: ncat, netcat, meterpreter, cobalt strike, sliver, mimikatz, bloodhound, psexec, etc.

**Step 8: System Information**
- Computer name
- Timezone information
- Last shutdown time

**Step 9: SAM User Accounts**
- Lists user accounts from SAM hive
- Useful for identifying local users

**Step 10: RegRipper Full Analysis**
- Runs RegRipper (`rip.pl`) with hive-specific plugins
- Comprehensive artifact extraction and timeline reconstruction

**Step 11: Full Hive Flag Pattern Scan**
- Scans entire hive for CTF flag patterns
- Detects reversed flags (`}...{PREFIX`) and auto-decodes
- Detects encoded strings (Base64, Hex) and auto-decodes

#### Memory-Based Registry Extraction

When a memory dump is provided instead of a hive file:
- Uses **Volatility3** `windows.registry.hivelist` to enumerate hives in memory
- Uses `windows.registry.printkey` to dump specific registry keys
- Uses `windows.registry.userassist` with automatic ROT13 decoding
- Key paths extracted: Run, RunOnce, UserAssist, RecentDocs, USB, ComputerName, TimeZone

#### Integration with Decode Engine
- All reversed flags found in registry values are auto-decoded
- All Base64/Hex encoded strings are auto-decoded
- UserAssist ROT13 decoding is automatic

**Tools:** `reglookup`, `regripper` (rip.pl), `volatility3`

---

### 10. 💻 Windows Artifact Analysis (`--windows`) — NEW in v3.0.0

Analyzes Windows forensic artifact files commonly found in CTF challenges.

#### Supported Artifact Types

| Artifact Type | Extension | Analysis |
|--------------|-----------|----------|
| **LNK Shortcut** | `.lnk` | Target path, arguments, flag detection |
| **Prefetch** | `.pf` | Executable name, DLLs/paths, flag detection |
| **Event Log** | `.evtx` | Event parsing with `evtx_dump`, flag detection |

#### LNK File Analysis
- **Target path extraction** via `strings` (detects `C:\...` paths, `.exe`, `.bat`, `.ps1`, `.vbs`, `.cmd`, `.msi`)
- **Raw flag detection** in LNK content
- **Hex dump** of LNK header
- **File info** via `file -v`

#### Prefetch File Analysis
- **Executable name extraction** from filename (e.g., `CMD.EXE-A1B2C3D4.pf` → `CMD.EXE`)
- **DLL and path extraction** via `strings` (detects `C:\...`, `.dll`, `.exe`, `.sys`, `Program Files`, `System32`)
- **Flag detection** in raw strings
- **Reversed flag detection** with auto-decode
- **Hex dump** of prefetch header

#### Event Log (.evtx) Analysis
- **Structured parsing** via `evtx_dump` / `python-evtx` / `evtxinfo`
- **Fallback strings analysis** — detects Logon/Logoff/Error/Warning/Audit events and Windows event IDs (4624, 4625, 4688, 4698, 4699)
- **Flag detection** in both structured output and raw strings

**Tools:** `evtx_dump` / `python-evtx` / `libevtx-utils`

---

### 10. 🔐 Crypto Analysis (`--crypto`) — NEW in v5.0.0

Comprehensive cryptography analysis for CTF crypto challenges. Supports RSA, AES, DES, ChaCha20, hash cracking, length extension attacks, and advanced mathematical cryptanalysis via SageMath.

**Supported Cipher Types:**

| Cipher | Analysis Capabilities |
|--------|----------------------|
| **RSA** | Public key extraction, modulus factoring, common attack detection (small e, Wiener, Hastad, common factor, Fermat), RsaCtfTool multi-attack auto-solver |
| **AES** | Mode detection (ECB/CBC/CTR/GCM), padding analysis (PKCS#7, zero padding), key/IV extraction, pycryptodome-based decrypt |
| **DES/3DES** | ECB/CBC mode detection, weak key detection, pycryptodome-based decrypt |
| **ChaCha20** | Stream cipher analysis, nonce/key extraction |
| **Hash Functions** | Auto-detection of hash type (MD5, SHA1, SHA256, SHA512, bcrypt, NTLM), GPU-accelerated cracking via hashcat |
| **Length Extension** | MD5/SHA1/SHA256 hash length extension attacks via hashpumpy |

**Analysis Pipeline:**

1. **Input Detection** — Auto-detects RSA keys (PEM/DER), encrypted files, hash strings, certificates
2. **RSA Analysis** — Extracts public key parameters (n, e), checks for common vulnerabilities:
   - Small public exponent (e=3, e=5)
   - Wiener's attack (small private exponent)
   - Hastad's broadcast attack
   - Common modulus attack
   - Fermat factoring (close primes)
   - RsaCtfTool integration for automated multi-attack solving
3. **Hash Analysis** — Identifies hash type by length/format, attempts hashcat cracking with rockyou.txt
4. **Symmetric Cipher Analysis** — Detects cipher mode, extracts key/IV if available, attempts decryption
5. **Certificate Analysis** — OpenSSL-based X.509 certificate inspection, key extraction
6. **SageMath Integration** — Elliptic curve cryptography (ECC), discrete logarithm problems, advanced RSA factoring
7. **Z3 SMT Solver** — Symbolic execution for reverse crypto challenges, constraint solving

**Tools:** `openssl`, `hashcat`, `pycryptodome` (Python), `hashpumpy` (Python), `z3-solver` (Python), `SageMath`, `RsaCtfTool`

---

### 11. 🔬 Advanced File Analysis (`--adv-file`) — NEW in v4.0.0

Deep file inspection beyond basic magic bytes and strings. Designed for complex CTF challenges involving polyglot files, XOR obfuscation, and embedded malware.

**8 Sub-Analysis Modules:**

| # | Analysis | Description |
|---|----------|-------------|
| 1 | **PNG/JPEG/PDF/ZIP Chunk Parsers** | Python-based structured file format parsing with flag detection in chunk data |
| 2 | **Polyglot Detection** | Detects multiple magic byte signatures within a single file (file-within-a-file) |
| 3 | **Binwalk Entropy Analysis** | Detects encrypted/compressed regions via entropy scoring (>0.95) |
| 4 | **Binwalk Deep Extraction** | `--dd='.*'` extracts ALL embedded signatures, not just common ones |
| 5 | **Scalpel File Carving** | Complements existing `foremost` with config-based carving for additional file types |
| 6 | **XOR Obfuscation Brute Force** | Scans XOR keys 0x01–0xFF against flag patterns (`flag{`, `ctf{`, `picoctf{`, `htb{`, `thm{`) |
| 7 | **Malware Static Triage** | Suspicious strings (network IOCs, shellcode), `objdump` disassembly for dangerous API calls (`socket`, `connect`, `execve`, `system`, `ptrace`, `dlopen`), packer detection (UPX, Themida, VMProtect) |
| 8 | **Annotated Hexdump** | `hexdump -C` with 32-line preview for visual inspection |

**Tools:** `scalpel`, `objdump` (binutils), `hexdump` (bsdmainutils), Python3

---

### 12. 🧬 Advanced Memory/DFIR (`--adv-mem`) — NEW in v4.0.0

Advanced digital forensics and incident response analysis for memory dumps, going beyond basic Volatility3 plugins.

**10 Sub-Analysis Modules:**

| # | Analysis | Description |
|---|----------|-------------|
| 1 | **Hidden Process Detection** | Compares `pslist` vs `psscan` via Volatility3 to find rootkit-hidden processes |
| 2 | **DLL Injection Detection** | Runs `windows.malfind` for injected code in process memory |
| 3 | **Suspicious Process Scanning** | Matches against malware names (mimikatz, meterpreter, cobalt, beacon, RAT, trojan) |
| 4 | **Credential Dumping** | Finds lsass.exe PID, runs `windows.hashdump`, suggests `lsadump`/`cachedump` |
| 5 | **Network Connections from Memory** | `windows.netstat` with suspicious outbound connection filtering |
| 6 | **Command History + PowerShell** | `windows.cmdline` + PowerShell command extraction via strings (`encodedcommand`, `bypass`, `hidden`, `base64`) |
| 7 | **Rootkit Hook Detection** | `windows.ssdt` for non-standard SSDT hook entries |
| 8 | **NTFS Alternate Data Streams (ADS)** | Uses `fls` from sleuthkit for ADS detection |
| 9 | **Timeline Reconstruction** | `fls + mactime` bodyfile timeline generation for event reconstruction |
| 10 | **Slack Space Analysis** | Python-based detection of data beyond EOF, anti-forensics tool string detection (`timestomp`, `shred`, `sdelete`, `BCWipe`) |

**Tools:** `volatility3`, `fls` (sleuthkit), `mactime` (sleuthkit), Python3

---

### 13. 🌐 Advanced Network Forensics (`--adv-net`) — NEW in v4.0.0

Advanced network traffic analysis for C2 detection, covert channels, and file reconstruction from PCAP files.

**7 Sub-Analysis Modules:**

| # | Analysis | Description |
|---|----------|-------------|
| 1 | **File Reconstruction** | HTTP object extraction (`--export-objects`), FTP data reconstruction, SMB detection |
| 2 | **Manual Protocol Decoding** | Non-standard port detection, raw TCP stream extraction (streams 0–5) with flag scanning |
| 3 | **TLS/Encrypted Traffic Analysis** | TLS version distribution (flags deprecated TLS 1.0/1.1), SNI extraction, certificate CN analysis |
| 4 | **C2 (Command & Control) Detection** | Beacon interval analysis (periodic connections with average interval calculation), payload keyword scanning (`cmd=`, `task=`, `meterpreter`, `getsystem`, `hashdump`) |
| 5 | **DNS Tunneling (Enhanced)** | iodine pattern (hex subdomains), dnscat2 pattern (numeric subdomains), large DNS response detection |
| 6 | **Covert Channel Detection** | ICMP data exfiltration, DNS base32 exfil reconstruction, HTTP cookie/header exfiltration |
| 7 | **Zeek Integration** | Runs `zeek -r` in background with log output directory, NetworkMiner hint |

**Tools:** `tshark`, `zeek`, Python3

---

### 14. 🎨 Advanced Steganography (`--adv-stego`) — NEW in v4.0.0

Advanced steganography analysis using statistical methods, frequency domain analysis, and multi-channel extraction.

**7 Sub-Analysis Modules:**

| # | Analysis | Description |
|---|----------|-------------|
| 1 | **zsteg Deep Scan** | Runs `zsteg --all` with comprehensive flag pattern matching |
| 2 | **Statistical Analysis** | Entropy calculation, LSB ratio analysis (0.5 = stego indicator), Chi-square test for uniform distribution detection, byte frequency histogram |
| 3 | **Stegsolve Channel Analysis (CLI)** | Python/Pillow-based RGB+Alpha channel bit-plane extraction (LSB, bit1, bit2) for all 4 channels, alpha channel unique value detection |
| 4 | **Audio Steganography** | WAV LSB extraction (16-bit samples), ffmpeg metadata, video frame extraction (`fps=1`), steghide on audio |
| 5 | **Frequency Domain (DCT)** | numpy-based 8×8 block variance analysis for JPEG, detects jsteg/outguess patterns in frequency coefficients |
| 6 | **Noise Pattern Analysis** | LSB transition ratio per channel, visual artifact/banding detection |
| 7 | **Advanced Tool References** | Hints for openstego, silenteye, snow, stegoveritas |

**Tools:** `zsteg`, `Pillow` (Python), `numpy` (Python), `ffmpeg`, `sonic-visualiser`

---

## 🔓 Decode Engine — NEW in v1.7.0

FASFO includes a comprehensive **17-type encoding decoder** that automatically attempts to decode any suspicious string found during scans. It can also be used standalone via `fasfo --decode "string"`.

### Supported Encoding Types

| # | Encoding | Description | Example |
|---|----------|-------------|---------|
| 1 | **REVERSED** | String reversal | `}tc4f1tr4_fn1_nur0tu4{FTC` → `FTC{ut0run_1nf_4rt1f4ct}` |
| 2 | **BASE64** | Standard Base64 | `RlRDe3R1cjBfMW5fNHJ0MTRmY3R9` → `FTC{tur0_1n_4rt14fct}` |
| 3 | **BASE64URL** | URL-safe Base64 (`-` and `_`) | Handles URL-safe encoding variants |
| 4 | **HEX** | Pure hex or `0x` prefixed | `4654437b...` → text |
| 5 | **HEX_SPACED** | Hex with spaces | `46 54 43 7b ...` → text |
| 6 | **ROT13** | Caesar cipher shift 13 | Standard ROT13 |
| 7 | **CAESAR (ROT 1-25)** | Brute force all 25 shifts | Checks each shift for flag patterns |
| 8 | **URL_DECODE** | Percent-encoded (`%xx`) | `%46%54%43%7b...` → text |
| 9 | **BINARY** | Binary strings (01010011) | `0100011001010100...` → text |
| 10 | **MORSE** | Morse code (`. - /`) | `.-. . -..` → `RED` |
| 11 | **ATBASH** | A↔Z, B↔Y substitution | Classical cipher |
| 12 | **OCTAL** | Octal values (3-digit groups) | `106 124 103 ...` → text |
| 13 | **HTML_ENTITY** | HTML entities (`&amp;`, `&#65;`) | Decodes HTML entities |
| 14 | **REV+BASE64** | Reversed then Base64 decoded | Combines reversal + Base64 |
| 15 | **XOR (0x01-0xFF)** | Single-byte XOR brute force | Tries all 255 keys, stops on flag match |
| 16 | **L33T** | Leetspeak normalization | `l33t` → `leet`, `p@ssw0rd` → `password` |
| 17 | **REVERSED_FLAG** | Bracket reversal (`}...{XTC` → `CTF{...}`) | Fixes reversed flag brackets |

### Recursive Decoding

The decode engine supports **recursive decoding** — if a Base64 decode reveals another encoded string, it automatically attempts to decode that too. This handles multi-layer encoding challenges common in CTFs.

### Integration Points

The decode engine is triggered at multiple points:

1. **File Analysis** — When suspicious strings (base64, hex, URL-encoded, reversed flags) are found in file content
2. **Log Analysis** — When reversed flags or encoded strings are found in logs
3. **DNS Analysis** — When DNS tunnel data chunks are reconstructed (Step 4)
4. **Scan Summary** — `decode_flag_candidates()` runs at the end of every scan, gathering ALL candidates from:
   - Report file entries (STRINGS_FLAGS, ZSTEG, STEGHIDE, B64_FLAG, LOG_FLAG, HTTP_FLAG, CRACKED_FLAG, etc.)
   - Raw strings from the target file
   - All 17 encoding types are tried on each candidate
5. **Standalone mode** — `fasfo --decode "string"` for instant decoding

### Output Format

```
  [DECODE] BASE64: RlRDe3R1cjBfMW5fNHJ0MTRmY3R9 → FTC{tur0_1n_4rt14fct}
  [DECODE] REVERSED: }tc4f1tr4_fn1_nur0tu4{FTC → FTC{ut0run_1nf_4rt1f4ct}
  [DECODE] REVERSED_FLAG: }tc4f1tr4_fn1_nur0tu4{FTC → FTC{ut0run_1nf_4rt1f4ct}
  [DECODE] XOR(0x42): 24362115... → FTC{decoded_xor_flag}
```

All decode hits are saved to the report file as `DECODE_HIT:` entries.

---

## 🎯 Interactive Menu System — NEW in v1.6.0

FASFO v1.6.0+ introduces a **full interactive menu system** — no need to memorize CLI flags.

### Main Menu

```
┌─────────────────────────────────────────┐
│  Pilih Mode Analisis                    │
├─────────────────────────────────────────┤
│  [1] 🔍  Forensics — Analisis file / CTF│
│  [2] 🔧  Dependency Check — Cek tools   │
│  [3] ℹ️   Info & Help                    │
│  [4] 🗑️   Lihat Laporan Tersimpan       │
│  [0] Keluar / Batal                     │
└─────────────────────────────────────────┘
```

### Forensics Module Menu

```
┌─────────────────────────────────────────┐
│  Pilih Modul Forensics                  │
│  (pilih beberapa, pisah spasi)          │
├─────────────────────────────────────────┤
│  [1] 📁  File Analysis                  │
│  [2] 🖼️   Steganography                 │
│  [3] 🌐  Network Forensics              │
│  [4] 🧠  Memory Forensics               │
│  [5] 📦  Archive Analysis               │
│  [6] 🗒️   Log Analysis                  │
│  [7] 🕵️   OSINT                         │
│  [8] 🪟  Registry Analysis              │
│  [9] 💻  Windows Artifacts              │
│  [10] 🔐 Crypto Analysis                │
│  [11] 🔬 Advanced File                  │
│  [12] 🧬 Advanced Memory/DFIR           │
│  [13] 🌐 Advanced Network               │
│  [14] 🎨 Advanced Steganography         │
│  [a] Pilih SEMUA modul                  │
│  [0] Keluar / Batal                     │
└─────────────────────────────────────────┘
```

### Smart Module Suggestions

When you select a file, FASFO auto-detects its type and suggests relevant modules:

```
[!] Saran modul berdasarkan tipe file:
    → File Gambar terdeteksi — disarankan: [1] File Analysis + [2] Steganography
    → PCAP terdeteksi — disarankan: [3] Network Forensics
    → Archive terdeteksi — disarankan: [5] Archive Analysis
    → Log file terdeteksi — disarankan: [6] Log Analysis
    → Registry hive terdeteksi — disarankan: [8] Registry Analysis
    → LNK/Prefetch terdeteksi — disarankan: [9] Windows Artifacts
    → RSA key / hash / encrypted file — disarankan: [10] Crypto Analysis
```

### Report Viewer

Browse and read previously saved scan reports directly from the menu — no need to navigate the filesystem.

---

##  Output

### Terminal Output

FASFO uses color-coded output for easy scanning:

| Color | Symbol | Meaning |
|-------|--------|---------|
| 🟢 `[+]` | Green | Success / Info |
| 🔵 `[*]` | Cyan | Processing |
| 🟡 `[!]` | Yellow | Warning / Hint |
| 🔴 `[-]` | Red | Failure |
| 🟣 `[FLAG?]` | Magenta | **Potential flag detected!** |
| 🟣 `[DECODE]` | Magenta | **Decoded string result** |

### Reports

All scans generate a report file saved to:

```
~/.fasfo/reports/<filename>_YYYYMMDD_HHMMSS.txt
```

Reports include:
- Scan timestamp and target information
- All extracted metadata
- Detected flag candidates (normal and reversed)
- All decode hits (encoding type → decoded result)
- Suspicious findings (brute force attempts, suspicious commands, etc.)
- Raw string samples for further decode analysis
- DNS analysis results (tunneling indicators, decoded chunks, IOC scores)

### Decode Report

Standalone decode mode generates its own report:
```
~/.fasfo/reports/decode_YYYYMMDD_HHMMSS.txt
```

### Scan Summary

At the end of each scan, FASFO displays:
- Target file and scan time
- Report file location
- All detected flag candidates
- **Auto-decode results** — All candidates decoded with all 17 encoding types

---

## 🎯 CTF Use Cases

### Common Scenarios

| Challenge Type | Command |
|----------------|---------|
| **Mystery file** | `fasfo unknown_file --Forensics` |
| **PNG steganography** | `fasfo challenge.png --Forensics --stego` |
| **JPEG with hidden data** | `fasfo photo.jpg --Forensics --stego` |
| **Network capture** | `fasfo traffic.pcap --Forensics --net` |
| **DNS tunneling challenge** | `fasfo capture.pcap --Forensics --net` |
| **Memory dump** | `fasfo memdump.raw --Forensics --mem` |
| **Encrypted ZIP** | `fasfo secret.zip --Forensics --archive` |
| **Nested archives** | `fasfo puzzle.zip --Forensics --archive` |
| **Auth log analysis** | `fasfo auth.log --Forensics --log` |
| **HTTP access log** | `fasfo access.log --Forensics --log` |
| **Syslog investigation** | `fasfo syslog --Forensics --log` |
| **Binary login log** | `fasfo wtmp --Forensics --log` |
| **Registry hive (NTUSER)** | `fasfo NTUSER.DAT --Forensics --registry` |
| **Registry export (.reg)** | `fasfo artifact.reg --Forensics --registry` |
| **Memory registry extraction** | `fasfo memdump.raw --Forensics --registry` |
| **LNK shortcut analysis** | `fasfo shortcut.lnk --Forensics --windows` |
| **Prefetch file analysis** | `fasfo CMD.EXE-ABC123.pf --Forensics --windows` |
| **Event Log analysis** | `fasfo Security.evtx --Forensics --windows` |
| **Advanced file (polyglot/XOR)** | `fasfo suspicious.exe --Forensics --adv-file` |
| **Advanced memory DFIR** | `fasfo memdump.raw --Forensics --adv-mem` |
| **Advanced network (C2)** | `fasfo traffic.pcap --Forensics --adv-net` |
| **Advanced steganography** | `fasfo challenge.png --Forensics --adv-stego` |
| **Crypto analysis (RSA/hashes)** | `fasfo encrypted.txt --Forensics --crypto` |
| **Domain investigation** | `fasfo suspicious.com --Forensics --osint` |
| **Image with GPS** | `fasfo photo.jpg --Forensics --osint` |
| **Batch scan (CLI)** | `fasfo file1.png file2.jpg secret.zip --Forensics` |
| **Batch scan (interactive)** | `fasfo file1.png file2.jpg` |
| **Decode a string** | `fasfo --decode "RlRDe3R1cjBfMW5fNHJ0MTRmY3R9"` |
| **Decode reversed flag** | `fasfo --decode "}tc4f1tr4_fn1_nur0tu4{FTC"` |
| **Decode hex** | `fasfo --decode "4654437b6865785f666c61677d"` |

### Tips for CTF Players

1. **Start with interactive mode** — `fasfo file.png` lets you pick modules visually
2. **Auto-decode catches hidden flags** — Reversed flags (`}...{PREFIX`), base64, hex are all auto-decoded during scans
3. **Use standalone decode** — `fasfo --decode "string"` for quick string decoding
4. **DNS tunneling detection** — PCAP scans now include 7-step DNS analysis for data exfiltration challenges
5. **Check log files** — AWK/GREP/SORT engine provides column-level precision analysis
6. **Review reports** — All findings and decode hits are saved for later reference
7. **Use `--deps` first** — Ensure all tools are installed before competitions
8. **Custom wordlists** — Set `FASFO_WORDLIST` for targeted bruteforce attacks
9. **Multi-file scan** — Drag & drop multiple files for batch analysis
10. **Base64 auto-decode** — Log analysis and file analysis automatically decode base64/hex strings
11. **XOR brute force** — Decode engine tries all 255 XOR keys on hex strings
12. **DNS chunk reconstruction** — Sequential subdomain chunks are automatically reassembled and decoded
13. **Registry artifact analysis** — Auto-detects SAM/SYSTEM/NTUSER hives and extracts Run keys, UserAssist, USB history
14. **UserAssist ROT13** — Registry UserAssist entries are automatically ROT13-decoded
15. **Registry export (.reg)** — Hex-encoded values in .reg files are automatically decoded to reveal flags
16. **Suspicious program detection** — Registry analysis flags known CTF tools (mimikatz, bloodhound, cobalt strike, etc.)
17. **Windows artifacts** — LNK, Prefetch, and EVTX files are auto-detected and analyzed for flag patterns
18. **Advanced file analysis** — Polyglot detection, XOR brute force (0x01–0xFF), malware static triage with objdump
19. **Advanced memory DFIR** — Hidden process detection, DLL injection, SSDT hooks, credential dumping, NTFS timeline
20. **Advanced network forensics** — C2 beacon interval analysis, covert channel detection, Zeek integration
21. **Advanced steganography** — Chi-square test, DCT frequency domain analysis, Pillow RGB channel extraction
22. **File carving** — Both `foremost` and `scalpel` for comprehensive carved file recovery
23. **Crypto analysis** — RSA factoring, AES/DES/ChaCha20, hash cracking (MD5/SHA/bcrypt), length extension attacks, SageMath for elliptic curves/DLP
24. **Hash cracking** — GPU-accelerated hashcat integration with auto-detection of hash types
25. **RsaCtfTool integration** — Multi-attack RSA solver (small e, Wiener, Hastad, common factor, etc.)
26. **Stegcrack integration** — Automated steghide password brute-forcing with rockyou.txt wordlist, progress display, and auto-extraction
27. **Stegseek integration** — C++ native steghide cracker (MUCH faster than stegcrack), with --seed mode for steghide detection without wordlist
28. **Decode engine optimization** — Caesar brute force now uses single python3 spawn for all 24 ROT shifts (instead of 24 separate spawns)

---

## 🗂️ Project Structure

```
fasfo.sh              # Main script (single-file tool, 7100+ lines)
plan.txt              # Development roadmap
Pl4n.png              # Architecture diagram
README.md             # This file
```

**Reports directory:** `~/.fasfo/reports/`

---

## ⚙️ Configuration

### Custom Wordlist

```bash
# Set environment variable
export FASFO_WORDLIST=/path/to/custom_wordlist.txt

# Or inline
FASFO_WORDLIST=./rockyou.txt fasfo encrypted.zip --Forensics --archive
```

### WSL Users

FASFO automatically detects WSL and adjusts behavior:
- **Stegsolve GUI** will not auto-launch (no display server)
- Manual launch instructions provided
- All CLI features fully functional

To enable GUI tools on WSL:
```bash
# Install VcXsrv or X410 on Windows
export DISPLAY=:0
```

---

## 🛠️ Development

### Current Version: `5.0.0`

**Changelog v5.0.0:**
- 🆕 **Crypto Analysis Module (`--crypto`)** — Comprehensive cryptography analysis for CTF crypto challenges
- 🆕 **RSA Analysis** — Public key extraction, modulus factoring, common attack detection (small e, Wiener, Hastad, common factor)
- 🆕 **Hash Cracking** — GPU-accelerated hashcat integration with auto-detection of hash types (MD5, SHA1, SHA256, SHA512, bcrypt, NTLM)
- 🆕 **AES/DES/ChaCha20 Analysis** — pycryptodome-based cipher analysis, mode detection (ECB/CBC/CTR/GCM), padding analysis
- 🆕 **Length Extension Attacks** — hashpumpy integration for MD5/SHA1/SHA256 hash length extension
- 🆕 **SageMath Integration** — RSA factoring, elliptic curve cryptography, discrete logarithm problems
- 🆕 **RsaCtfTool Integration** — Multi-attack RSA solver (auto-detects and applies best attack)
- 🆕 **Z3 SMT Solver** — Symbolic execution for reverse crypto challenges
- 🆕 **OpenSSL Integration** — Certificate analysis, RSA key inspection, AES encrypt/decrypt utilities
- 🆕 **Crypto tool dependency check** — New "Crypto Tools (v5.0.0)" section in `--deps`
- 🆕 **Stegseek integration** — C++ native steghide cracker (much faster than stegcrack), with --seed mode for detection without wordlist
- 🆕 **Decode engine optimization** — Caesar brute force uses single python3 spawn for all 24 ROT shifts
- 🆕 **Total codebase** — 7100+ lines of Bash

**Changelog v4.0.0:**
- 🆕 **4 Advanced Modules** — Deep forensics analysis for complex CTF challenges
- 🆕 **Advanced File Analysis (`--adv-file`)** — 8 sub-analyses: PNG/JPEG/PDF/ZIP chunk parsers, polyglot detection, binwalk entropy analysis, binwalk deep extraction, scalpel file carving, XOR obfuscation brute force (0x01–0xFF), malware static triage (objdump disassembly, suspicious API detection, packer detection), annotated hexdump
- 🆕 **Advanced Memory/DFIR (`--adv-mem`)** — 10 sub-analyses: hidden process detection (pslist vs psscan), DLL injection (malfind), suspicious process scanning, credential dumping (hashdump/lsadump/cachedump), network connections, PowerShell command extraction, rootkit hook detection (SSDT), NTFS ADS detection, timeline reconstruction (fls + mactime), slack space analysis (anti-forensics tool detection)
- 🆕 **Advanced Network Forensics (`--adv-net`)** — 7 sub-analyses: file reconstruction (HTTP/FTP/SMB), manual protocol decoding, TLS/SNI/certificate analysis, C2 beacon interval detection, enhanced DNS tunneling (iodine/dnscat2 patterns), covert channel detection (ICMP/DNS/HTTP exfiltration), Zeek integration
- 🆕 **Advanced Steganography (`--adv-stego`)** — 7 sub-analyses: zsteg deep scan, statistical analysis (entropy, LSB ratio, chi-square test), Pillow RGB+Alpha channel bit-plane extraction, audio steganography (WAV LSB, video frame extraction), frequency domain DCT analysis (8×8 block variance), noise pattern analysis, advanced tool references (openstego, silenteye, snow, stegoveritas)
- 🆕 **9 new tool integrations** — scalpel, objdump (binutils), hexdump (bsdmainutils), sleuthkit (fls, mactime), Pillow (Python), numpy (Python), zeek, sonic-visualiser, ffmpeg
- 🆕 **Enhanced dependency check** — "Advanced Tools (v4.0.0)" section with optional tool recommendations
- 🆕 **Interactive menu expanded** — 13 module options (0-12) including all 4 advanced modules
- 🆕 **Auto-decode moved before summary** — Flag candidates decoded and displayed before the FASFO SCAN SUMMARY box
- 🆕 **Total codebase** — 5800+ lines of Bash

**Changelog v3.0.0:**
- 🆕 **Module 8: Windows Registry Analysis** — Full offline hive parsing for SAM/SYSTEM/SOFTWARE/SECURITY/NTUSER.DAT/UsrClass.dat
- 🆕 **Registry Export (.reg) Support** — Text-based .reg file parsing with hex value extraction and auto-decode
- 🆕 **Hex Decode for .reg files** — Extracts `hex:XX,XX,...` values, merges multi-line continuations, decodes to ASCII
- 🆕 **11-Step Registry Pipeline** — Structure scan, key extraction, UserAssist ROT13, Run keys, USB history, MRU, installed programs, system info, SAM users, RegRipper, full hive flag scan
- 🆕 **Memory Registry Extraction** — Volatility3 hivelist, printkey, and userassist plugins for memory dumps
- 🆕 **UserAssist ROT13 Decoding** — Automatic ROT13 decode of UserAssist registry entries from both offline hives and memory
- 🆕 **Run Keys Persistence Detection** — Scans all Run/RunOnce/RunServices/Winlogon keys for persistence mechanisms
- 🆕 **USB Device History** — Extracts USB and USBSTOR enum entries with device counts
- 🆕 **MRU List Analysis** — RecentDocs, RunMRU, OpenSaveMRU, LastVisitedMRU, TypedURLs
- 🆕 **Installed Program Enumeration** — Lists all installed programs from Uninstall keys
- 🆕 **Suspicious Program Detection** — Flags known CTF tools (mimikatz, bloodhound, cobalt strike, meterpreter, sliver, ncat, psexec, etc.)
- 🆕 **RegRipper Integration** — Runs RegRipper (rip.pl) with hive-specific plugins for comprehensive analysis
- 🆕 **Full Hive Flag Pattern Scan** — Scans entire registry hive for CTF flags, reversed flags, and encoded strings
- 🆕 **Module 9: Windows Artifact Analysis** — LNK shortcut, Prefetch, and Event Log (.evtx) analysis
- 🆕 **LNK File Analysis** — Target path and argument extraction, flag detection
- 🆕 **Prefetch File Analysis** — Executable name extraction, DLL/path enumeration, flag detection
- 🆕 **Event Log (.evtx) Parsing** — Structured parsing via evtx_dump/python-evtx with strings fallback
- 🆕 **Auto-detect registry hives** — Full scan auto-detects SAM/SYSTEM/NTUSER/registry files and memory dumps
- 🆕 **Auto-detect Windows artifacts** — Full scan auto-detects LNK/Prefetch/EVTX files
- 🆕 **Interactive menu updated** — 10 module options including Registry and Windows Artifacts
- 🆕 **New CLI flags** — `--registry` and `--windows` for targeted analysis
- 🆕 **Smart module hints** — Auto-suggests Registry module for hive files, Windows module for LNK/Prefetch/EVTX

**Changelog v2.0.0:**
- 🆕 **DNS Analysis Engine** — 7-step DNS tunneling and data exfiltration detection pipeline
- 🆕 **Step 1: DNS Query Extraction** — Full query extraction with unique domain counting
- 🆕 **Step 2: Tunneling Detection** — Sequential subdomains, long subdomains (>30 chars), high-entropy subdomains, repeated parent domains
- 🆕 **Step 3: C2 Domain Identification** — Frequency-based C2 candidate detection with chunk extraction tables
- 🆕 **Step 4: Data Exfiltration Decoding** — Base32, Base64, Hex decode of reconstructed DNS chunks
- 🆕 **Step 5: DNS Record Type Analysis** — Record type categorization, TXT record detection and decoding
- 🆕 **Step 6: IOC Summary** — Suspicion scoring (0-8) based on tunneling indicators
- 🆕 **Step 7: Export Commands** — Manual tshark commands for further investigation
- 🆕 **DNS chunk table visualization** — Ordered chunk display with sequence number, full domain, and data column
- 🆕 **capinfos integration** — PCAP summary via capinfos when available
- 🆕 **Improved PCAP output formatting** — Section headers, credential detection feedback

**Changelog v1.8.0:**
- 🆕 **AWK/GREP/SORT Analysis Engine** — Column-level precision log parsing
- 🆕 **AUTH log deep analysis** — Service distribution, username frequency, port scanning detection
- 🆕 **HTTP log deep analysis** — URI ranking, method distribution, status codes with severity labels, response size stats, traffic timeline
- 🆕 **Syslog deep analysis** — Process frequency, severity levels, anomaly detection (abnormal PIDs)
- 🆕 **Generic log analysis** — Token frequency, keyword counts, line length distribution
- 🆕 **IP address labeling** — Auto-tags IPs as `[LOOPBACK]`, `[PRIVATE]`, or `[PUBLIC]`
- 🆕 **Domain/hostname extraction** — Finds all domains in log content
- 🆕 **Email address detection** — Extracts all email addresses from logs
- 🆕 **ASCII timeline charts** — Bar chart visualization of event distribution
- 🆕 **Auto column format detection** — Analyzes log structure and column count

**Changelog v1.7.0:**
- 🆕 **17-type Decode Engine** — Base64, Base64URL, Hex, ROT1-25, Morse, Binary, XOR, Atbash, L33t, Octal, HTML Entities, Reversed Base64, Reversed Flag, Reversed String
- 🆕 **Standalone decode mode** — `fasfo --decode "string"` for instant decoding
- 🆕 **Auto-decode integration** — Automatically decodes suspicious strings during file and log analysis
- 🆕 **Reversed flag detection** — Auto-detects `}...{PREFIX` pattern and decodes it
- 🆕 **Recursive decoding** — Decodes multi-layer encoded strings (e.g., base64 → hex → flag)
- 🆕 **Decode report** — All decode hits saved to report file
- 🆕 **Flag candidate aggregation** — Gathers all candidates from report and target file

**Changelog v1.6.0:**
- 🆕 **Module 7: Log Analysis** — Auth, HTTP, syslog, binary login logs, systemd journal
- 🆕 **Interactive menu system** — Single-select and multi-select menus
- 🆕 **Multi-file batch scanning** — CLI and interactive mode with progress bar
- 🆕 **Smart module suggestions** — Auto-suggests modules based on file type

**Previous Versions:**
- **v1.3.0** — Smart 3-Phase Archive Bruteforce (filename-based + John + fcrackzip)
- **v1.2.0** — Archive analysis with ZIP bomb detection

**Planned Features:**
- [ ] PDF forensics module
- [ ] NTFS artifact analysis ($MFT, $LogFile, timeline generation)
- [ ] SQLite database analysis (browser history, chat logs)
- [ ] JSON/HTML report export
- [ ] Plugin system for custom modules
- [ ] Web dashboard (FastAPI-based)
- [ ] YARA rule scanning for malware/IOC detection

---

## 📜 License

Built for the CTF community. Use responsibly.

---

## 🙏 Acknowledgments

Tools integrated in FASFO:
- [binwalk](https://github.com/ReFirmLabs/binwalk)
- [volatility3](https://github.com/volatilityfoundation/volatility3)
- [stegsolve](http://www.caesum.com/handbook/)
- [zsteg](https://github.com/zed-0xff/zsteg)
- [steghide](https://github.com/StefanoDeVuono/steghide)
- [tshark](https://www.wireshark.org/docs/man-pages/tshark.html)
- [exiftool](https://exiftool.org/)
- [foremost](https://foremost.sourceforge.io/)
- [John the Ripper](https://www.openwall.com/john/)

---

## 🚩 Happy CTF Hunting!

> *"The flag is always in the details."*

For issues or feature requests, check the architecture diagram (`Pl4n.png`) and development plan (`plan.txt`).
