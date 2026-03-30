#!/usr/bin/env python3

"""Port Scanner v5 — Authorized Penetration Testing Tool.
Multi-threaded TCP connect scanner with service fingerprinting, banner grabbing,
CVE correlation, and auto-invocation of FTP/SSH credential scanners.
"""

import os
import sys
import csv
import html
import json
import re
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

import ftp_scanner
import ssh_scanner
import prettyprint as pp

# ─── Constants ────────────────────────────────────────────────────────────────

VERSION = '5.0'
DEFAULT_TIMEOUT = 5.0
DEFAULT_THREADS = 10

# nmap-style top port frequency list (top 100)
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080,
    8, 20, 26, 37, 79, 81, 82, 83, 84, 85, 88, 89, 90, 99, 106, 109, 113,
    119, 125, 137, 138, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255,
    256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417,
    425, 427, 444, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 524,
    541, 543, 544, 548, 554, 587, 593, 616, 617, 625, 631, 636, 646, 648,
    666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720,
]

TOP_1000_PORTS = list(range(1, 1001))

# Service signature matching — banner substring → service name
SERVICE_SIGNATURES = {
    'ssh':          'SSH',
    'ftp':          'FTP',
    '220 ':         'FTP',
    'smtp':         'SMTP',
    'esmtp':        'SMTP',
    'pop3':         'POP3',
    '+ok':          'POP3',
    'imap':         'IMAP',
    'http/1':       'HTTP',
    'html':         'HTTP',
    '<html':        'HTTP',
    'rdp':          'RDP',
    'telnet':       'Telnet',
    'mysql':        'MySQL',
    'mariadb':      'MySQL',
    'postgresql':   'PostgreSQL',
    'redis':        'Redis',
    '+pong':        'Redis',
    'mongodb':      'MongoDB',
    'elastic':      'Elasticsearch',
    'smb':          'SMB',
    'samba':        'SMB',
    'vnc':          'VNC',
    'rfb ':         'VNC',
    'memcached':    'Memcached',
    'version':      'Memcached',
}

# Banner CVE map — substring → list of CVE dicts
BANNER_CVE_MAP = {
    'apache/2.2':  [{'cve': 'CVE-2017-7679', 'severity': 'CRITICAL',
                     'desc': 'Apache 2.2.x mod_mime buffer overread'}],
    'apache/2.4.49': [{'cve': 'CVE-2021-41773', 'severity': 'CRITICAL',
                       'desc': 'Apache 2.4.49 path traversal / RCE'}],
    'apache/2.4.50': [{'cve': 'CVE-2021-42013', 'severity': 'CRITICAL',
                       'desc': 'Apache 2.4.50 path traversal bypass'}],
    'nginx/1.14':  [{'cve': 'CVE-2019-9511', 'severity': 'HIGH',
                     'desc': 'nginx HTTP/2 Data Dribble DoS'}],
    'microsoft-iis/6': [{'cve': 'CVE-2017-7269', 'severity': 'CRITICAL',
                          'desc': 'IIS 6.0 WebDAV ScStoragePathFromUrl buffer overflow'}],
    'openssh':     [],   # handled by ssh_scanner.map_cves()
    'vsftpd 2.3.4': [{'cve': 'CVE-2011-2523', 'severity': 'CRITICAL',
                       'desc': 'vsftpd 2.3.4 backdoor'}],
    'proftpd 1.3.5': [{'cve': 'CVE-2015-3306', 'severity': 'CRITICAL',
                        'desc': 'ProFTPD mod_copy unauthenticated file copy'}],
}

# Ports where we attempt additional unauthenticated checks
QUICK_CHECK_PORTS = {
    6379:  'redis',
    27017: 'mongodb',
    9200:  'elasticsearch',
    11211: 'memcached',
    5432:  'postgresql_anon',
    3306:  'mysql_anon',
}

_shutdown_event = threading.Event()

# ─── Data types ───────────────────────────────────────────────────────────────

@dataclass
class PortResult:
    port: int
    state: str       # 'open', 'closed'
    banner: str = ''
    service: str = ''
    cves: list = field(default_factory=list)
    extra: str = ''  # additional check result (e.g. "Redis: unauthenticated")


@dataclass
class HostResult:
    host: str
    status: str      # 'scanned', 'unreachable'
    open_ports: list = field(default_factory=list)   # list of PortResult
    os_hint: str = ''
    timestamp: str = ''
    duration: float = 0.0

# ─── Service fingerprinting ───────────────────────────────────────────────────

def identify_service(port: int, banner: str) -> str:
    """Identify service from port number and/or banner content."""
    banner_lower = banner.lower()
    for sig, name in SERVICE_SIGNATURES.items():
        if sig in banner_lower:
            return name
    # Fall back to well-known port numbers
    port_defaults = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
        993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
        8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch',
        11211: 'Memcached', 27017: 'MongoDB',
    }
    return port_defaults.get(port, 'Unknown')


def map_banner_cves(banner: str) -> list:
    """Return CVE dicts matching banner substrings."""
    banner_lower = banner.lower()
    results = []
    seen = set()
    for key, cve_list in BANNER_CVE_MAP.items():
        if key in banner_lower:
            for c in cve_list:
                if c['cve'] not in seen:
                    seen.add(c['cve'])
                    results.append(c)
    return results


def os_hint_from_ttl(host: str) -> str:
    """Guess OS from ICMP TTL via ping (Linux=64, Windows=128, Cisco=255)."""
    try:
        import subprocess
        out = subprocess.run(['ping', '-c', '1', '-W', '1', host],
                             capture_output=True, text=True, timeout=3).stdout
        m = re.search(r'ttl=(\d+)', out, re.IGNORECASE)
        if m:
            ttl = int(m.group(1))
            if ttl <= 64:
                return 'Linux/Unix (TTL=%d)' % ttl
            elif ttl <= 128:
                return 'Windows (TTL=%d)' % ttl
            else:
                return 'Network device (TTL=%d)' % ttl
    except Exception:
        pass
    return ''

# ─── Unauthenticated service checks ──────────────────────────────────────────

def quick_check(host: str, port: int, service: str, timeout: float) -> str:
    """Probe a service for unauthenticated access. Returns finding string or ''."""
    try:
        if service == 'redis':
            s = socket.socket()
            s.settimeout(timeout)
            s.connect((host, port))
            s.send(b'PING\r\n')
            resp = s.recv(64).decode('utf-8', errors='replace')
            s.close()
            if '+PONG' in resp or 'PONG' in resp:
                return 'Redis: UNAUTHENTICATED (responds to PING)'

        elif service == 'mongodb':
            # MongoDB wire protocol: isMaster command
            s = socket.socket()
            s.settimeout(timeout)
            s.connect((host, port))
            # Minimal isMaster BSON request
            msg = (b'\x48\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
                   b'\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00'
                   b'\x00\x00\x00\x00\xff\xff\xff\xff'
                   b'\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00')
            s.send(msg)
            resp = s.recv(256)
            s.close()
            if resp and len(resp) > 16:
                return 'MongoDB: port open, no auth probe response received'

        elif service == 'elasticsearch':
            import urllib.request
            req = urllib.request.Request(
                'http://%s:%d/_cat/indices' % (host, port),
                headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(256).decode('utf-8', errors='replace')
                if r.status == 200:
                    return 'Elasticsearch: UNAUTHENTICATED (_cat/indices accessible)'

        elif service == 'memcached':
            s = socket.socket()
            s.settimeout(timeout)
            s.connect((host, port))
            s.send(b'stats\r\n')
            resp = s.recv(256).decode('utf-8', errors='replace')
            s.close()
            if 'STAT ' in resp:
                return 'Memcached: UNAUTHENTICATED (stats command accessible)'

        elif service == 'mysql_anon':
            s = socket.socket()
            s.settimeout(timeout)
            s.connect((host, port))
            banner = s.recv(256).decode('utf-8', errors='replace')
            s.close()
            if 'mysql' in banner.lower() or len(banner) > 5:
                return 'MySQL: banner received — %s' % banner[:60].strip()

        elif service == 'postgresql_anon':
            # Just confirm port responds; full auth check needs psycopg2
            s = socket.socket()
            s.settimeout(timeout)
            s.connect((host, port))
            s.close()
            return 'PostgreSQL: port open (try postgres:postgres manually)'

    except Exception:
        pass
    return ''

# ─── Port scanner ─────────────────────────────────────────────────────────────

def scan_port(host: str, port: int, timeout: float) -> Optional[PortResult]:
    """Attempt TCP connect to one port. Returns PortResult if open, None if closed."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        try:
            s.send(b'\r\n')
            banner_raw = s.recv(1024)
            banner = banner_raw.decode('utf-8', errors='replace').strip()[:200]
        except Exception:
            banner = ''
        s.close()

        service = identify_service(port, banner)
        cves = map_banner_cves(banner)

        return PortResult(port=port, state='open', banner=banner,
                          service=service, cves=cves)
    except Exception:
        return None


def scan_host(host: str, ports: list, config, stats: dict) -> HostResult:
    """Scan all ports on a host, then run service-specific checks."""
    import time
    t_start = time.monotonic()
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result = HostResult(host=host, status='scanned', timestamp=ts)

    if _shutdown_event.is_set():
        result.status = 'skipped'
        return result

    pp.info('[scanning] %s — %d ports' % (host, len(ports)))

    # Scan all ports in parallel within this host
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(50, len(ports))) as inner:
        port_futures = {inner.submit(scan_port, host, p, config.timeout): p for p in ports}
        for f in concurrent.futures.as_completed(port_futures):
            pr = f.result()
            if pr is not None:
                open_ports.append(pr)

    open_ports.sort(key=lambda x: x.port)

    if not open_ports:
        pp.info('[done] %s — no open ports' % host)
        result.duration = time.monotonic() - t_start
        return result

    # Print open ports
    for pr in open_ports:
        cve_str = (' [CVEs: %s]' % ', '.join(c['cve'] for c in pr.cves)) if pr.cves else ''
        pp.status('[open] %s:%d  %s%s' % (host, pr.port, pr.service, cve_str))
        if pr.banner and config.verbose:
            pp.info_spaces('Banner: %s' % pr.banner[:100])
        if pr.cves:
            for c in pr.cves:
                pp.warning('       [%s] %s — %s' % (c['severity'], c['cve'], c['desc']))

    # OS hint from TTL
    if config.os_hint:
        hint = os_hint_from_ttl(host)
        if hint:
            result.os_hint = hint
            pp.info('[OS hint] %s — %s' % (host, hint))

    # Service-specific auto-checks
    for pr in open_ports:
        if _shutdown_event.is_set():
            break

        # Quick unauthenticated checks
        if pr.port in QUICK_CHECK_PORTS:
            finding = quick_check(host, pr.port, QUICK_CHECK_PORTS[pr.port], config.timeout)
            if finding:
                pr.extra = finding
                pp.warning('[%s] %s:%d — %s' % (
                    'UNAUTH', host, pr.port, finding))

        # Auto-exploit SSH
        if pr.port == 22 and config.auto_exploit:
            pp.info('[auto-exploit] %s:%d — invoking SSH scanner' % (host, pr.port))
            ssh_err, ssh_out, ssh_verb, ssh_warn = ssh_scanner.SSHBruteForce(host, None, None)
            for msg in ssh_out:
                pp.status(msg)
                pr.extra = msg
            for msg in ssh_warn:
                if config.verbose:
                    pp.warning(msg)

        # Auto-exploit FTP
        if pr.port == 21 and config.auto_exploit:
            pp.info('[auto-exploit] %s:%d — invoking FTP scanner' % (host, pr.port))
            ftp_err, ftp_out, ftp_verb, ftp_warn = ftp_scanner.FTPBruteForce(host, None, None)
            for msg in ftp_out:
                pp.status(msg)
                pr.extra = msg
            for msg in ftp_warn:
                if config.verbose:
                    pp.warning(msg)

    result.open_ports = open_ports
    result.duration = time.monotonic() - t_start

    with threading.Lock():
        stats['open_ports'] = stats.get('open_ports', 0) + len(open_ports)

    return result

# ─── Target loading ───────────────────────────────────────────────────────────

def load_targets(source: str) -> list:
    """Parse hosts from CIDR, single IP, file, or stdin. Returns list of host strings."""
    targets = []
    seen = set()

    def _add(host):
        if host not in seen:
            seen.add(host)
            targets.append(host)

    def _parse(line):
        line = line.strip()
        if not line or line.startswith('#'):
            return
        line = re.sub(r'^https?://', '', line).split('/')[0].split('?')[0]
        # Strip any :port suffix for host list (port is set separately)
        if ':' in line and line.count(':') == 1:
            line = line.rsplit(':', 1)[0]
        _add(line)

    if source != '-' and not os.path.exists(source):
        try:
            net = ipaddress.ip_network(source, strict=False)
            for ip in net.hosts():
                _add(str(ip))
            return targets
        except ValueError:
            pass
        _parse(source)
        return targets

    lines = sys.stdin.readlines() if source == '-' else open(source, encoding='utf-8').readlines()
    for line in lines:
        _parse(line)
    return targets


def parse_ports(port_str: str) -> list:
    """Parse port spec: '22,80,443' or '1-1024' or '-' (all) or 'top100' / 'top1000'."""
    if port_str == '-':
        return list(range(1, 65536))
    if port_str.lower() == 'top100':
        return sorted(TOP_100_PORTS)
    if port_str.lower() == 'top1000':
        return sorted(TOP_1000_PORTS)
    if ',' in port_str:
        return [int(p) for p in port_str.split(',')]
    if '-' in port_str:
        lo, hi = port_str.split('-', 1)
        return list(range(int(lo), int(hi) + 1))
    return [int(port_str)]

# ─── Output writers ───────────────────────────────────────────────────────────

def write_json(results: list, path: str):
    try:
        with open(path, 'w', encoding='utf-8') as f:
            for r in results:
                if r.open_ports:
                    f.write(json.dumps(dataclasses.asdict(r)) + '\n')
        pp.info('JSON written to %s' % path)
    except OSError as e:
        pp.error('Cannot write JSON: %s' % e)


def write_csv(results: list, path: str):
    fields = ['HOST', 'PORT', 'SERVICE', 'BANNER', 'CVE_COUNT', 'EXTRA',
              'OS_HINT', 'TIMESTAMP']
    try:
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fields, quoting=csv.QUOTE_ALL)
            writer.writeheader()
            for r in results:
                for pr in r.open_ports:
                    writer.writerow({
                        'HOST': r.host,
                        'PORT': pr.port,
                        'SERVICE': pr.service,
                        'BANNER': pr.banner[:100],
                        'CVE_COUNT': len(pr.cves),
                        'EXTRA': pr.extra,
                        'OS_HINT': r.os_hint,
                        'TIMESTAMP': r.timestamp,
                    })
        pp.info('CSV written to %s' % path)
    except OSError as e:
        pp.error('Cannot write CSV: %s' % e)


def write_nuclei_hosts(results: list, path: str):
    """Write HTTP/HTTPS hosts to a live_hosts.txt for nuclei_scanner pipeline."""
    http_ports = {80, 8080, 8000, 8008}
    https_ports = {443, 8443, 4443, 9443}
    try:
        with open(path, 'w', encoding='utf-8') as f:
            for r in results:
                for pr in r.open_ports:
                    if pr.port in https_ports:
                        f.write('https://%s:%d\n' % (r.host, pr.port))
                    elif pr.port in http_ports:
                        f.write('http://%s:%d\n' % (r.host, pr.port))
        pp.info('Nuclei live_hosts written to %s' % path)
    except OSError as e:
        pp.error('Cannot write nuclei hosts: %s' % e)


def write_html(results: list, start_dt: datetime.datetime,
               end_dt: datetime.datetime, path: str):
    duration = str(end_dt - start_dt).split('.')[0]
    all_open = [(r, pr) for r in results for pr in r.open_ports]
    cve_findings = [(r, pr, c) for r, pr in all_open for c in pr.cves]
    unauth = [(r, pr) for r, pr in all_open if pr.extra]

    sev_color = {'CRITICAL': '#dc3545', 'HIGH': '#fd7e14',
                 'MEDIUM': '#ffc107', 'LOW': '#17a2b8'}

    port_rows = ''
    for r, pr in all_open:
        cve_str = ', '.join(
            "<a href='https://nvd.nist.gov/vuln/detail/%s' target='_blank'>%s</a>" % (c['cve'], c['cve'])
            for c in pr.cves
        )
        port_rows += ('<tr><td>%s</td><td>%d</td><td>%s</td><td>%s</td>'
                      '<td>%s</td><td>%s</td></tr>\n') % (
            html.escape(r.host), pr.port,
            html.escape(pr.service),
            html.escape(pr.banner[:80]),
            cve_str,
            html.escape(pr.extra),
        )

    cve_rows = ''
    for r, pr, c in cve_findings:
        color = sev_color.get(c['severity'], '#6c757d')
        cve_rows += ('<tr><td>%s:%d</td><td>%s</td>'
                     "<td><a href='https://nvd.nist.gov/vuln/detail/%s' "
                     "target='_blank'>%s</a></td>"
                     "<td style='color:%s;font-weight:bold'>%s</td>"
                     '<td>%s</td></tr>\n') % (
            html.escape(r.host), pr.port,
            html.escape(pr.banner[:60]),
            c['cve'], c['cve'],
            color, c['severity'],
            html.escape(c['desc']),
        )

    content = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Port Scan Report</title>
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
<h1>Port Scan Report</h1>
<div class="meta">Date: <strong>%s</strong> | Duration: <strong>%s</strong></div>
<div class="cards">
  <div class="card"><div class="count" style="color:#00d4ff">%d</div><div>Hosts Scanned</div></div>
  <div class="card"><div class="count" style="color:#28a745">%d</div><div>Open Ports</div></div>
  <div class="card"><div class="count" style="color:#dc3545">%d</div><div>CVE Findings</div></div>
  <div class="card"><div class="count" style="color:#fd7e14">%d</div><div>Unauth Access</div></div>
</div>
<h2>Open Ports (%d)</h2>
<table><tr><th>Host</th><th>Port</th><th>Service</th><th>Banner</th><th>CVEs</th><th>Extra</th></tr>
%s</table>
<h2>CVE Findings (%d)</h2>
<table><tr><th>Host:Port</th><th>Banner</th><th>CVE</th><th>Severity</th><th>Description</th></tr>
%s</table>
</body></html>""" % (
        html.escape(start_dt.strftime('%Y-%m-%d %H:%M:%S')),
        html.escape(duration),
        len(results), len(all_open), len(cve_findings), len(unauth),
        len(all_open),
        port_rows or "<tr><td colspan='6' style='color:#6c757d'>No open ports found.</td></tr>",
        len(cve_findings),
        cve_rows or "<tr><td colspan='5' style='color:#6c757d'>No CVEs identified.</td></tr>",
    )

    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        pp.info('HTML report written to %s' % path)
    except OSError as e:
        pp.error('Cannot write HTML: %s' % e)

# ─── Signal handler ───────────────────────────────────────────────────────────

def _signal_handler(sig, frame):
    pp.error('Interrupt received — finishing current scans...')
    _shutdown_event.set()

signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)

# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog='port_scanner.py',
        description='Port Scanner v%s — Authorized Penetration Testing Tool' % VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./port_scanner.py -r 10.0.0.0/24
  ./port_scanner.py -r 192.168.1.1 -p 1-65535
  ./port_scanner.py -r targets.txt -p top100 --auto-exploit --html-report report.html
  ./port_scanner.py -r 10.0.0.1 -p 80,443,8080 --nuclei-output live_hosts.txt
  ./port_scanner.py -r results_*/live_hosts.txt --json-output ports.json
"""
    )
    parser.add_argument('-r', '--target', dest='target', metavar='TARGET', required=True,
        help='CIDR, host, file, or "-" for stdin')
    parser.add_argument('-p', '--ports', dest='ports', default='21,22,23,25,80,110,139,443,445,3306,3389,5432,6379,8080,8443,9200,27017',
        metavar='PORTS',
        help='Ports: "22,80,443", "1-1024", "-" (all), "top100", "top1000"')
    parser.add_argument('-m', '--maxthread', dest='threads', type=int, default=DEFAULT_THREADS,
        help='Max concurrent host threads (default: 10)')
    parser.add_argument('-t', '--timeout', dest='timeout', type=float, default=DEFAULT_TIMEOUT,
        help='Per-connection timeout in seconds (default: 5)')
    parser.add_argument('--auto-exploit', dest='auto_exploit', default=False,
        action='store_true',
        help='Auto-invoke SSH/FTP credential scanners on open ports 22/21')
    parser.add_argument('--os-hint', dest='os_hint', default=False,
        action='store_true', help='Guess OS from ICMP TTL via ping')
    parser.add_argument('-o', '--output', dest='text_output', metavar='FILE',
        help='Append text log to file')
    parser.add_argument('--json-output', dest='json_output', default='port_scan.json',
        metavar='FILE', help='JSONL output (default: port_scan.json)')
    parser.add_argument('--no-json', dest='json_output', action='store_const', const=None,
        help='Disable JSON output')
    parser.add_argument('--csv-output', dest='csv_output', metavar='FILE',
        help='CSV output file')
    parser.add_argument('--html-report', dest='html_report', metavar='FILE',
        help='HTML report output file')
    parser.add_argument('--nuclei-output', dest='nuclei_output', metavar='FILE',
        help='Write HTTP/HTTPS hosts to file for nuclei_scanner pipeline')
    parser.add_argument('-v', '--verbose', dest='verbose', default=False,
        action='store_true', help='Verbose output (show closed ports, banners)')
    return parser

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    banner_art = """
  ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗  ██╗
  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗ ██║
  ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗██║
  ██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚████║
  ██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚███║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝
              Port Scanner + Service Fingerprinting v%s
""" % VERSION
    print(banner_art)

    parser = build_parser()
    options = parser.parse_args()

    ctime = datetime.datetime.now()

    try:
        ports = parse_ports(options.ports)
    except ValueError:
        pp.error('Invalid port specification: %s' % options.ports)
        sys.exit(1)

    targets = load_targets(options.target)
    if not targets:
        pp.error('No valid targets found')
        sys.exit(1)

    pp.status('Targets:  %d hosts' % len(targets))
    pp.status('Ports:    %d  |  Threads: %d  |  Timeout: %.0fs' % (
        len(ports), options.threads, options.timeout))
    if options.auto_exploit:
        pp.status('Auto-exploit: ON (SSH port 22, FTP port 21)')

    stats: dict = {'open_ports': 0}
    all_results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=options.threads) as executor:
        futures = {
            executor.submit(scan_host, host, ports, options, stats): host
            for host in targets
        }
        for f in concurrent.futures.as_completed(futures):
            if _shutdown_event.is_set():
                break
            all_results.append(f.result())

    etime = datetime.datetime.now()
    total = str(etime - ctime).split('.')[0]

    open_count = sum(len(r.open_ports) for r in all_results)
    cve_count = sum(len(pr.cves) for r in all_results for pr in r.open_ports)

    pp.status('Scan completed in: %s' % total)
    pp.status('Results: %d hosts | %d open ports | %d CVEs' % (
        len(all_results), open_count, cve_count))

    if options.json_output:
        write_json(all_results, options.json_output)
    if options.csv_output:
        write_csv(all_results, options.csv_output)
    if options.html_report:
        write_html(all_results, ctime, etime, options.html_report)
    if options.nuclei_output:
        write_nuclei_hosts(all_results, options.nuclei_output)
    if options.text_output:
        pp.log_status('Port scan completed in %s — %d open ports' % (total, open_count),
                      options.text_output)


if __name__ == '__main__':
    main()
