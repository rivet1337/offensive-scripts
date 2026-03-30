# offensive-scripts

A collection of Python-based offensive security tools for Red Teaming, penetration testing, and security awareness. Written for full cross-platform compatibility — runs on Linux, macOS, and iOS (Pythonista).

> **Legal notice:** These tools are intended for authorised testing only. Do not scan systems or networks without explicit written permission. Misuse may be illegal.

---

## Quick Start

```bash
pip install -r requirements.txt
python3 port_scanner.py -h
```

---

## Tool Overview

| Script | What it does |
|---|---|
| `port_scanner.py` | Multi-threaded port scanner with service fingerprinting, CVE matching, and auto-enrichment |
| `ssh_scanner.py` | SSH banner grabber, CVE fingerprinter, credential sprayer, and honeypot detector |
| `ftp_scanner.py` | FTP/FTPS scanner with anonymous login detection, directory enumeration, and CVE matching |
| `dns_scanner.py` | Extended DNS reconnaissance — AXFR, crt.sh, SPF/DMARC analysis, subdomain permutation |
| `nuclei_scanner.py` | Wrapper around Nuclei for templated vulnerability scanning with curated options |
| `random_scanner.py` | **[NEW]** Threat-actor simulation — scans random internet targets with live dashboard and scoring |
| `ipmagic.py` | IP → ASN/WHOIS lookup library and CLI; ASN → subnet expansion |
| `prettyprint.py` | Thread-safe console output and file logging library used by all tools |
| `bg_nmap.sh` | Shell helper to run nmap in background tmux sessions |

---

## prettyprint.py

Central output library used by every tool in the suite. All `pp.*` calls are thread-safe and automatically strip ANSI codes when writing to log files.

```python
import prettyprint as pp

pp.status('Starting scan...')       # [*] blue
pp.info('Host is up')               # [+] green
pp.warning('Port 23 open (Telnet)') # [!] yellow
pp.error('Connection refused')      # [-] red
pp.critical('Redis — NO AUTH')      # [CRITICAL] red bold
pp.debug('Raw banner: ...')         # [DBG] grey  (--verbose only)
pp.log_status('msg', 'scan.log')    # append ANSI-stripped line to file
```

**v5 changes:**
- Rewritten as a proper library (no `if __name__ == '__main__'` guard needed, safe to import anywhere)
- `critical()` and `debug()` log levels added
- `bcolors` palette exported for direct ANSI use in calling scripts
- `log_status()` automatically strips ANSI escape codes so log files are clean plain text
- Thread-safe: internal lock protects all stdout writes

---

## ipmagic.py

IP → ASN / WHOIS lookup library backed by [ipwhois](https://ipwhois.readthedocs.io/) RDAP. All lookups are cached per-IP in a thread-safe dict — subsequent calls for the same IP are instant.

### Library API (used by other scripts)

```python
import ipmagic

info = ipmagic.get_full_info('8.8.8.8')
# {'asn': '15169', 'asn_cidr': '8.8.8.0/24', 'asn_description': 'GOOGLE',
#  'nets_cidr': '8.8.8.0/24', 'nets_name': 'GOGL', 'country': 'US',
#  'abuse_email': 'network-abuse@google.com', ...}

ipmagic.get_asn_info('1.1.1.1')    # → 'CLOUDFLARENET'
ipmagic.get_country('1.1.1.1')     # → 'AU'
ipmagic.asn2IP('13335')            # → {cidr: description, ...}
```

### CLI

```bash
# Single IP lookup
python3 ipmagic.py -a 8.8.8.8

# Batch lookup from file, output CSV
python3 ipmagic.py -l ips.txt -o results.csv --geo --abuse

# CIDR expansion lookup
python3 ipmagic.py -a 1.1.1.0/24 --json

# ASN → all announced prefixes
python3 ipmagic.py --asn2ip 13335

# Pipe-friendly single-field output
python3 ipmagic.py -a 8.8.8.8 --asn-number   # → 15169
python3 ipmagic.py -a 8.8.8.8 --asn-cidr     # → 8.8.8.0/24
```

**v5 changes:**
- Caching layer with thread lock (imported by other scripts without repeated lookups)
- `get_full_info()`, `get_country()`, `get_abuse_email()` convenience wrappers added
- `--geo` and `--abuse` flags added to CLI
- `--json` output mode added
- Console output now uses `pp.*` functions (consistent with rest of suite)
- Stdout/stderr routing fixed for `-o -` pipe mode
- `datetime.utcnow()` deprecation resolved

---

## port_scanner.py

Multi-threaded TCP port scanner with deep service fingerprinting.

```bash
# Scan top 20 ports on a single host
python3 port_scanner.py -t 192.168.1.1

# Scan a CIDR range, specific ports, with ASN info and HTML report
python3 port_scanner.py -t 10.0.0.0/24 -p 22,80,443,8080 --asn --html-report -o results/

# Scan from a list, top 100 ports, verbose
python3 port_scanner.py -l hosts.txt -p top100 -v

# Generate Nuclei targets file
python3 port_scanner.py -t target.com --nuclei
```

**Features:**
- Service fingerprinting via banner grabbing and regex signatures (`SERVICE_SIGNATURES`)
- CVE matching from banner strings (`BANNER_CVE_MAP`) — SSH, FTP, Apache, nginx, OpenSSL, etc.
- `quick_check()` for unauthenticated access detection — Redis, MongoDB, Memcached, Elasticsearch, ZooKeeper
- OS hint via TTL ping (`--os-hint`)
- Per-port timing and open/closed/filtered state
- Output: JSON findings, CSV all-hosts, HTML report, Nuclei targets file
- `TOP_100_PORTS`, `TOP_20_PORTS`, and custom port specs (`22,80,443` or `1-1024`)

---

## ssh_scanner.py

SSH reconnaissance, credential spraying, and post-exploitation chaining.

```bash
# Banner grab and CVE fingerprint a single host
python3 ssh_scanner.py -t 192.168.1.1

# Spray a credential list against a CIDR range
python3 ssh_scanner.py -t 10.0.0.0/24 -U users.txt -P passwords.txt --spray

# Scan a list with rate limiting and jitter (stealth)
python3 ssh_scanner.py -l targets.txt --rate 5 --stealth -o results/
```

**Features:**
- Banner extraction with `paramiko` transport (no full auth required)
- CVE map for common OpenSSH versions
- Honeypot detection heuristics (abnormal banner, fake version strings, timing anomalies)
- Credential spray mode with configurable rate limiter and jitter delay
- Post-exploit command execution on successful login (`--cmd`)
- Dashboard output with live stats
- Output: JSON findings, CSV, text log

**v5 changes:**
- Duplicate `_log_lock` removed (prettyprint owns the lock)
- `write_text_log()` delegates to `pp.log_status()` — consistent log format
- `datetime.utcnow()` deprecation resolved

---

## ftp_scanner.py

FTP/FTPS scanner with anonymous login detection, directory enumeration, and CVE fingerprinting.

```bash
# Scan a single host for anonymous access
python3 ftp_scanner.py -t 192.168.1.1

# Scan a CIDR range with enumeration on hits
python3 ftp_scanner.py -t 10.0.0.0/24 --enumerate --html-report

# Scan from list with FTPS support
python3 ftp_scanner.py -l targets.txt --ftps -o results/
```

**Features:**
- Anonymous login detection and directory listing via `MLSD` / `LIST`
- FTPS (FTP-over-TLS) support with implicit and explicit modes
- Banner fingerprinting with CVE matching (`CVEEntry` dataclass)
- File download capability on anonymous hits
- Rate limiter and jitter delay for stealth scanning
- Output: JSON findings, CSV, HTML report

**v5 changes:**
- Inline `from prettyprint import log_status` inside `main()` removed; now uses `pp.log_status()`
- `datetime.utcnow()` deprecation resolved

---

## dns_scanner.py

Extended DNS reconnaissance tool going well beyond a basic lookup.

```bash
# Full recon on a domain
python3 dns_scanner.py -d example.com

# Include crt.sh certificate transparency and subdomain permutation
python3 dns_scanner.py -d example.com --crt --permute -o results/

# Attempt zone transfer
python3 dns_scanner.py -d example.com --axfr

# Scan a list of domains
python3 dns_scanner.py -l domains.txt --html-report
```

**Features:**
- A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV record enumeration
- Zone transfer (AXFR) attempt
- Certificate transparency via [crt.sh](https://crt.sh) API
- SPF, DMARC, DKIM policy extraction and analysis
- Subdomain permutation wordlist generation
- Wildcard DNS detection
- Output: JSON, CSV, HTML report

**v5 changes:**
- `datetime.utcnow()` deprecation resolved

---

## nuclei_scanner.py

Wrapper around [Nuclei](https://github.com/projectdiscovery/nuclei) that applies curated options and integrates with the rest of the suite.

```bash
# Run against a target file produced by port_scanner --nuclei
python3 nuclei_scanner.py -l results/nuclei_hosts.txt

# Run with specific severity and template tags
python3 nuclei_scanner.py -l targets.txt --severity critical,high --tags cve,rce

# Stealth mode (slower, lower traffic)
python3 nuclei_scanner.py -l targets.txt --stealth
```

**v5 fixes applied:**
- Stealth timeout correctly applied (was being overridden)
- HTML injection in report output neutralised
- `stderr` output cap to prevent log overflow on large runs
- Template path validation (warns instead of silently skipping missing paths)
- Exit code propagation fixed (Nuclei exit codes now surfaced correctly)
- `datetime.utcnow()` deprecation resolved

---

## random_scanner.py *(new)*

Standalone threat-actor simulation for security awareness presentations. Scans random internet targets, scores them by attack surface, and displays a live ANSI dashboard. **Actually works** — not a demo script.

```bash
# Pure random internet scan, 50 hosts
python3 random_scanner.py --count 50 --asn --html-report

# Target a specific country
python3 random_scanner.py --country DE --count 100 --rate 20

# Target a specific ASN
python3 random_scanner.py --mode asn --asn-target AS13335 --count 20 --seed 42

# Target an org by name (resolves via RIR data)
python3 random_scanner.py --mode org --org-name "Cloudflare" --count 10

# Explicit CIDR range
python3 random_scanner.py --cidr 1.1.1.0/24 --count 10 -v

# Presentation mode — dramatic typing effect, "FOUND!" banners, pacing
python3 random_scanner.py --count 20 --seed 1337 --presentation

# Stop after finding 3 interesting hosts
python3 random_scanner.py --stop-at 3 --rate 20
```

### Targeting modes

| Flag | Mode | How IPs are selected |
|---|---|---|
| *(default)* | `random` | Pure random across all public IPv4 space |
| `--country DE` | `country` | Random IPs from RIR-allocated CIDRs for those countries |
| `--asn-target AS13335` | `asn` | Random IPs within ASN-announced subnets |
| `--org-name "Acme"` | `org` | Resolve org → ASNs via RIR data, then scan their subnets |
| `--cidr 1.1.1.0/24` | `cidr` | Random IPs within explicit CIDR(s) |

`--mode` is auto-inferred from whichever target flag is used — you don't need to specify it explicitly.

RIR delegation files (ARIN, RIPE, APNIC, LACNIC, AFRINIC) are downloaded once and cached in `~/.cache/random_scanner/` for 24 hours. Use `--refresh-rir` to force re-download.

### Scoring

Each host is scored after scanning and labelled:

| Label | Score threshold | Colour |
|---|---|---|
| Critical | ≥ 25 | Red |
| High | ≥ 15 | Orange |
| Medium | ≥ 6 | Yellow |
| Low | < 6 | Blue |

Score contributions:

| Finding | Points |
|---|---|
| Each open port | +2 |
| Each CVE matched | +3 |
| CRITICAL severity CVE bonus | +5 |
| HIGH severity CVE bonus | +3 |
| Unauthenticated DB/cache access | +10 |
| Telnet (port 23) open | +5 |
| RDP (port 3389) open | +5 |
| SMB (port 445) open | +3 |
| FTP anonymous login | +2 |

### Enrichment pipeline (per host)

1. **Port scan** — parallel inner `ThreadPoolExecutor`, configurable port list (top20 / top100 / custom)
2. **SSH enrichment** — banner grab → `parse_banner()` → CVE matching
3. **FTP enrichment** — banner grab → `fingerprint_ftp()` → CVE matching; anonymous login check
4. **HTTP enrichment** — `HEAD / HTTP/1.0` request → `Server:` header → CVE re-matching
5. **Quick checks** — unauthenticated Redis, MongoDB, Elasticsearch, Memcached, MySQL, PostgreSQL, ZooKeeper
6. **ASN lookup** — `ipmagic.get_full_info()` for country, ASN, abuse contact (with `--asn`)
7. **OS hint** — TTL-based OS detection (with `--os-hint`)
8. **Scoring** — `score_target()` → `AttackScore` dataclass

### Live dashboard

```
╔═════════════════════════════════════════════════════════╗
║    THREAT ACTOR SIMULATION  —  Internet Exposure Scan   ║
╠═════════════════════════════════════════════════════════╣
║  Scanned: 1,234    Open Ports: 456    Rate: 12.3/s      ║
║  Critical Hosts: 3  High: 12  Medium: 45  CVEs: 27      ║
╠══════════════════ LIVE FEED ════════════════════════════╣
║  [!!] 1.2.3.4    Redis EXPOSED (no auth) — AS12345 US  ║
║  [!]  5.6.7.8    Apache/2.4.49 CVE-2021-41773 CRIT     ║
║  [+]  9.10.11.12  SSH OpenSSH 7.4 — 2 CVEs  DE         ║
╚═════════════════════════════════════════════════════════╝
```

Dashboard is a daemon thread redrawing every 0.5s. It pauses and clears itself before printing permanent findings so nothing is lost or overwritten.

### Output files

All written to `--output DIR` (default: `random_scan_YYYYMMDD_HHMMSS/`):

| File | Content |
|---|---|
| `findings.json` | JSONL — one JSON object per host with open ports (score > Low) |
| `all_scan.csv` | Every IP scanned — IP, score, label, CVE count, country, ASN, duration |
| `report.html` | Dark-theme summary — all hosts with open ports, CVE table, scoring cards |
| `targets.txt` | All IPs with open ports — feed to other tools |
| `ssh_targets.txt` | IPs with port 22 open — feed to `ssh_scanner.py -l` |
| `ftp_targets.txt` | IPs with port 21 open — feed to `ftp_scanner.py -l` |
| `nuclei_hosts.txt` | `http://ip:port` format — feed to `nuclei_scanner.py -l` |

### Full CLI reference

```
Target Selection:
  --mode MODE           random (default) | asn | country | org | cidr
  --asn-target ASN      ASN(s): "AS13335" or "AS13335,AS15169"
  --country CC          ISO country codes: "US" or "US,DE,GB"
  --org-name NAME       Organisation name substring: "Cloudflare"
  --cidr CIDR           CIDR(s): "1.2.3.0/24" or "1.2.3.0/24,5.6.0.0/16"
  --refresh-rir         Force re-download of RIR delegation files

Target Generation:
  --count N             IPs to scan before stopping (default: unlimited)
  --stop-at N           Stop after N hosts with score > Low
  --seed N              RNG seed for reproducible demo sequences
  --exclude FILE        CIDRs/IPs to never scan (one per line, # comments OK)

Scan Configuration:
  -p / --ports SPEC     top20 (default) | top100 | "22,80,443"
  -m / --maxthread N    Concurrent host threads (default: 20)
  -t / --timeout N      Per-connection timeout seconds (default: 3)
  --rate N              Max host scans per second (default: 10)
  --stealth             Add jitter 0.5–3s between hosts; halve rate

Enrichment:
  --asn                 ASN/geo lookup on all hits (ipmagic.get_full_info)
  --os-hint             OS detection via TTL ping

Presentation:
  --presentation        Dramatic mode: typing effect, FOUND! banners, pacing

Output:
  -o / --output DIR     Results directory (default: random_scan_YYYYMMDD_HHMMSS)
  --no-json             Disable JSONL findings output
  --html-report         Generate HTML report at end of run
  -v / --verbose        Show all banners and closed-port debug info
```

---

## Pipeline Integration

The tools are designed to chain together. Here's a typical workflow:

```bash
# 1. Port scan a target range
python3 port_scanner.py -t 10.0.0.0/24 -p top100 --asn --nuclei -o results/

# 2. Feed SSH hits to ssh_scanner
python3 ssh_scanner.py -l results/ssh_targets.txt -U users.txt -P passwords.txt

# 3. Feed FTP hits to ftp_scanner
python3 ftp_scanner.py -l results/ftp_targets.txt --enumerate

# 4. Feed HTTP/HTTPS to nuclei
python3 nuclei_scanner.py -l results/nuclei_hosts.txt --severity critical,high

# 5. Enrich IPs with ASN data
python3 ipmagic.py -l results/open_hosts.txt --geo --abuse -o enriched.csv
```

From `random_scanner.py`, pipeline files are written automatically into the output directory and can be fed directly to the other tools.

---

## Requirements

```bash
pip install -r requirements.txt
```

| Package | Version | Used by |
|---|---|---|
| `paramiko` | ≥ 2.12.0 | `ssh_scanner.py` — SSH transport |
| `dnspython` | ≥ 2.6.1 | `dns_scanner.py` — DNS resolver |
| `ipwhois` | ≥ 1.3.0 | `ipmagic.py` — WHOIS / ASN lookups |
| `requests` | ≥ 2.31.0 | `dns_scanner.py` — crt.sh API; `random_scanner.py` — RIR downloads |

**External tools (not pip-installable):**
- `nuclei` — required by `nuclei_scanner.py`; install from [projectdiscovery.io](https://github.com/projectdiscovery/nuclei)

---

## iOS / Pythonista Compatibility

All tools use only stdlib + the packages listed above. No C extensions that require compilation. Works in [Pythonista](http://omz-software.com/pythonista/) and [a-Shell](https://holzschu.github.io/a-Shell_iOS/).

On iOS, ANSI dashboard (`random_scanner.py`) will detect a non-TTY and disable itself gracefully.

---

## Legal Notice

These tools are provided for **authorised security testing only**. You are responsible for ensuring you have explicit written permission before scanning any system or network not owned by you. Unauthorised scanning may violate computer fraud laws in your jurisdiction.
