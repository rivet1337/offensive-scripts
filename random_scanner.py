#!/usr/bin/env python3
"""random_scanner.py — Threat Actor Simulation: Internet Exposure Proof-of-Concept v1.0

Simulates how a threat actor discovers vulnerable internet targets at random.
Supports targeting by random, ASN, country, organisation, or CIDR.

Usage:
  ./random_scanner.py --count 50 --asn --presentation
  ./random_scanner.py --country DE,FR --count 100
  ./random_scanner.py --asn-target AS13335 --count 20 --seed 42
  ./random_scanner.py --cidr 1.1.1.0/24 --count 10 --html-report

LEGAL NOTICE: Only use against infrastructure you own or have explicit written
permission to test. Unauthorised scanning is illegal in most jurisdictions.
"""

# ── stdlib ────────────────────────────────────────────────────────────────────
import argparse
import collections
import concurrent.futures
import csv
import dataclasses
import datetime
import html
import ipaddress
import json
import math
import os
import random
import re
import signal
import socket
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

# ── local modules ─────────────────────────────────────────────────────────────
import port_scanner
import ssh_scanner
import ftp_scanner
import ipmagic
import prettyprint as pp

# ─── Version & constants ──────────────────────────────────────────────────────

VERSION = '1.0'

TOP_20_PORTS = [
    21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432,
    5900, 6379, 8080, 8443, 9200, 11211, 27017, 2181, 5555, 4444,
]

EXCLUDED_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('224.0.0.0/4'),
    ipaddress.ip_network('240.0.0.0/4'),
    ipaddress.ip_network('192.0.2.0/24'),
    ipaddress.ip_network('198.51.100.0/24'),
    ipaddress.ip_network('203.0.113.0/24'),
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('100.64.0.0/10'),
    ipaddress.ip_network('192.88.99.0/24'),
    ipaddress.ip_network('198.18.0.0/15'),
]

# Attack score point values
SCORE_PER_OPEN_PORT = 2
SCORE_PER_CVE       = 3
SCORE_CRITICAL_CVE  = 5
SCORE_HIGH_CVE      = 3
SCORE_UNAUTH_DB     = 10
SCORE_TELNET        = 5
SCORE_RDP           = 5
SCORE_SMB           = 3
SCORE_FTP_ANON      = 2

THRESH_CRITICAL = 25
THRESH_HIGH     = 15
THRESH_MEDIUM   = 6

# RIR delegation file URLs
RIR_URLS = {
    'arin':    'https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest',
    'ripe':    'https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest',
    'apnic':   'https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest',
    'lacnic':  'https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest',
    'afrinic': 'https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest',
}
RIR_CACHE_DIR  = os.path.join(os.path.expanduser('~'), '.cache', 'random_scanner')
RIR_MAX_AGE_H  = 24

# Populated in main()
_ALL_EXCLUDED: list = []
_TARGET_POOL:  list = []
_shutdown_event = threading.Event()
_print_lock     = threading.Lock()
_feed_lock      = threading.Lock()
_output_lock    = threading.Lock()

# ─── Dataclasses ─────────────────────────────────────────────────────────────

@dataclass
class AttackScore:
    score:          int = 0
    open_ports_pts: int = 0
    cve_pts:        int = 0
    service_pts:    int = 0
    label:          str = 'Low'

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclass
class TargetResult:
    ip:           str
    timestamp:    str
    open_ports:   list = field(default_factory=list)
    os_hint:      str  = ''
    asn_info:     dict = field(default_factory=dict)
    attack_score: Optional[AttackScore] = None
    duration:     float = 0.0

    def to_dict(self) -> dict:
        return {
            'ip':        self.ip,
            'timestamp': self.timestamp,
            'open_ports': [dataclasses.asdict(pr) for pr in self.open_ports],
            'os_hint':   self.os_hint,
            'asn':       self.asn_info,
            'score':     self.attack_score.to_dict() if self.attack_score else {},
            'duration':  round(self.duration, 3),
        }


class ScanStats:
    def __init__(self):
        self.ips_generated    = 0
        self.ips_scanned      = 0
        self.ips_open         = 0
        self.total_open_ports = 0
        # CVE counts (individual CVE hits)
        self.cve_count        = 0
        self.cve_critical     = 0
        self.cve_high         = 0
        # Host counts by score label
        self.hosts_critical   = 0
        self.hosts_high       = 0
        self.hosts_medium     = 0
        # Unauthenticated access (service count)
        self.unauth_count     = 0
        self.start_time       = time.monotonic()
        self._lock            = threading.Lock()

    def inc_generated(self):
        with self._lock:
            self.ips_generated += 1

    def inc_scanned(self):
        with self._lock:
            self.ips_scanned += 1

    def record_host(self, result: 'TargetResult'):
        sc = result.attack_score
        unauth = sum(1 for pr in result.open_ports
                     if pr.extra and 'unauth' in pr.extra.lower())
        cves   = sum(len(pr.cves) for pr in result.open_ports)
        cve_crits = sum(1 for pr in result.open_ports
                        for c in pr.cves if c.get('severity') == 'CRITICAL')
        cve_highs = sum(1 for pr in result.open_ports
                        for c in pr.cves if c.get('severity') == 'HIGH')
        with self._lock:
            if result.open_ports:
                self.ips_open += 1
            self.total_open_ports += len(result.open_ports)
            self.cve_count    += cves
            self.cve_critical += cve_crits
            self.cve_high     += cve_highs
            self.unauth_count += unauth
            if sc:
                if sc.label == 'Critical':
                    self.hosts_critical += 1
                elif sc.label == 'High':
                    self.hosts_high += 1
                elif sc.label == 'Medium':
                    self.hosts_medium += 1

    def rate(self) -> float:
        elapsed = time.monotonic() - self.start_time
        return self.ips_scanned / elapsed if elapsed > 0 else 0.0

# ─── ANSI helpers ─────────────────────────────────────────────────────────────

_ANSI_RE = re.compile(r'\033\[[\d;]*m')

def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub('', s)

# ─── Console helpers (print-lock aware) ──────────────────────────────────────

_dashboard_ref: Optional['DashboardThread'] = None

def _console(fn, *args, **kwargs):
    """Erase dashboard, print permanently via pp.*, then let dashboard resume below."""
    with _print_lock:
        if _dashboard_ref:
            _dashboard_ref.pause_and_clear()
        fn(*args, **kwargs)
        if _dashboard_ref:
            _dashboard_ref.resume()

def _type_print(text: str, delay: float = 0.04):
    """Print text one char at a time (presentation mode)."""
    with _print_lock:
        if _dashboard_ref:
            _dashboard_ref.pause_and_clear()
        for ch in text:
            sys.stdout.write(ch)
            sys.stdout.flush()
            time.sleep(delay)
        sys.stdout.write('\n')
        sys.stdout.flush()
        if _dashboard_ref:
            _dashboard_ref.resume()

# ─── RIR Delegation File handling ────────────────────────────────────────────

def _rir_cache_path(name: str) -> str:
    return os.path.join(RIR_CACHE_DIR, 'rir_%s.txt' % name)

def _rir_data_stale(force: bool = False) -> bool:
    if force:
        return True
    cutoff = time.time() - RIR_MAX_AGE_H * 3600
    for name in RIR_URLS:
        p = _rir_cache_path(name)
        if not os.path.exists(p) or os.path.getmtime(p) < cutoff:
            return True
    return False

def _fetch_rir_files(force: bool = False):
    import requests as _req
    os.makedirs(RIR_CACHE_DIR, exist_ok=True)
    cutoff = time.time() - RIR_MAX_AGE_H * 3600
    for name, url in RIR_URLS.items():
        path = _rir_cache_path(name)
        if not force and os.path.exists(path) and os.path.getmtime(path) >= cutoff:
            continue
        _console(pp.status, 'Fetching RIR data: %s ...' % name)
        try:
            r = _req.get(url, timeout=60, stream=True)
            r.raise_for_status()
            with open(path, 'wb') as f:
                for chunk in r.iter_content(65536):
                    f.write(chunk)
        except Exception as e:
            _console(pp.error, 'Failed to fetch %s: %s' % (name, e))

def _load_rir_data() -> dict:
    result: dict = {}
    for name in RIR_URLS:
        path = _rir_cache_path(name)
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding='utf-8', errors='replace') as f:
                for line in f:
                    if line.startswith('#') or not line.strip():
                        continue
                    parts = line.split('|')
                    if len(parts) < 7 or parts[2].lower() != 'ipv4':
                        continue
                    status = parts[6].strip().lower()
                    if status not in ('allocated', 'assigned'):
                        continue
                    cc    = parts[1].upper()
                    start = parts[3]
                    try:
                        count = int(parts[4])
                    except ValueError:
                        continue
                    if count <= 0 or cc in ('*', ''):
                        continue
                    prefix_len = 32 - int(math.log2(count)) if count > 0 else 32
                    try:
                        net = ipaddress.IPv4Network('%s/%d' % (start, prefix_len), strict=False)
                    except ValueError:
                        continue
                    result.setdefault(cc, []).append(net)
        except OSError:
            pass
    return result

def get_country_cidrs(countries: list) -> list:
    data = _load_rir_data()
    nets = []
    for cc in countries:
        nets.extend(data.get(cc.upper(), []))
    return nets

def get_asn_cidrs(asns: list) -> list:
    nets = []
    for asn in asns:
        asn_str = asn.upper().lstrip('AS').strip()
        try:
            subnets = ipmagic.asn2IP(asn_str)
            for cidr in subnets:
                try:
                    nets.append(ipaddress.IPv4Network(cidr, strict=False))
                except ValueError:
                    pass
        except Exception as e:
            _console(pp.warning, 'ASN lookup failed for AS%s: %s' % (asn_str, e))
    return nets

def get_org_cidrs(org_name: str) -> list:
    nets = []
    org_lower = org_name.lower()
    for name in RIR_URLS:
        path = _rir_cache_path(name)
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding='utf-8', errors='replace') as f:
                for line in f:
                    if line.startswith('#') or not line.strip():
                        continue
                    parts = line.split('|')
                    if len(parts) < 8 or parts[2].lower() != 'ipv4':
                        continue
                    extra = '|'.join(parts[7:]).lower()
                    if org_lower not in extra:
                        continue
                    status = parts[6].strip().lower()
                    if status not in ('allocated', 'assigned'):
                        continue
                    start = parts[3]
                    try:
                        count = int(parts[4])
                    except ValueError:
                        continue
                    if count <= 0:
                        continue
                    prefix_len = 32 - int(math.log2(count)) if count > 0 else 32
                    try:
                        net = ipaddress.IPv4Network('%s/%d' % (start, prefix_len), strict=False)
                        nets.append(net)
                    except ValueError:
                        continue
        except OSError:
            pass
    return nets

# ─── IP Generation ────────────────────────────────────────────────────────────

def _is_excluded(addr: ipaddress.IPv4Address) -> bool:
    if not addr.is_global:
        return True
    for net in _ALL_EXCLUDED:
        if addr in net:
            return True
    return False

def random_ip_from_pool(rng: random.Random, pool: list) -> str:
    weights = [net.num_addresses for net in pool]
    net = rng.choices(pool, weights=weights, k=1)[0]
    host_int = rng.randint(int(net.network_address), int(net.broadcast_address))
    return str(ipaddress.IPv4Address(host_int))

def random_public_ip(rng: random.Random) -> str:
    while True:
        addr = ipaddress.IPv4Address(rng.randint(0, 0xFFFFFFFF))
        if not _is_excluded(addr):
            return str(addr)

def load_exclude_file(path: str) -> list:
    nets = []
    try:
        with open(path, encoding='utf-8') as f:
            for line in f:
                line = line.split('#')[0].strip()
                if not line:
                    continue
                try:
                    if '/' in line:
                        nets.append(ipaddress.ip_network(line, strict=False))
                    else:
                        nets.append(ipaddress.ip_network(line + '/32'))
                except ValueError:
                    pass
    except OSError as e:
        _console(pp.error, 'Cannot read exclude file: %s' % e)
    return nets

def ip_generator(rng: random.Random, count: Optional[int], pool: list):
    n = 0
    while count is None or n < count:
        if _shutdown_event.is_set():
            return
        if pool:
            ip = random_ip_from_pool(rng, pool)
            addr = ipaddress.IPv4Address(ip)
            if _is_excluded(addr):
                continue
        else:
            ip = random_public_ip(rng)
        yield ip
        n += 1

# ─── Scoring ─────────────────────────────────────────────────────────────────

def score_target(result: TargetResult) -> AttackScore:
    open_ports_pts = len(result.open_ports) * SCORE_PER_OPEN_PORT
    cve_pts = 0
    service_pts = 0
    open_port_nums = {pr.port for pr in result.open_ports}

    for pr in result.open_ports:
        for cve in pr.cves:
            cve_pts += SCORE_PER_CVE
            sev = cve.get('severity', '')
            if sev == 'CRITICAL':
                cve_pts += SCORE_CRITICAL_CVE
            elif sev == 'HIGH':
                cve_pts += SCORE_HIGH_CVE
        # Unauthenticated access: check for multiple keywords quick_check() may return
        if pr.extra:
            extra_lower = pr.extra.lower()
            if any(kw in extra_lower for kw in
                   ('unauthenticated', 'no auth', '+pong',
                    'stats command', '_cat/indices',
                    'port open', 'banner received')):
                service_pts += SCORE_UNAUTH_DB

    if 23   in open_port_nums: service_pts += SCORE_TELNET
    if 3389 in open_port_nums: service_pts += SCORE_RDP
    if 445  in open_port_nums: service_pts += SCORE_SMB
    # FTP anonymous: check banner for typical anonymous-allowed indicators
    for pr in result.open_ports:
        if pr.port == 21 and pr.banner:
            banner_lower = pr.banner.lower()
            if any(kw in banner_lower for kw in ('anonymous', 'anon', 'guest')):
                service_pts += SCORE_FTP_ANON
                break

    score = open_ports_pts + cve_pts + service_pts
    if score >= THRESH_CRITICAL:
        label = 'Critical'
    elif score >= THRESH_HIGH:
        label = 'High'
    elif score >= THRESH_MEDIUM:
        label = 'Medium'
    else:
        label = 'Low'

    return AttackScore(score=score, open_ports_pts=open_ports_pts,
                       cve_pts=cve_pts, service_pts=service_pts, label=label)

# ─── Per-service enrichment ───────────────────────────────────────────────────

def _enrich_ssh(ip: str, pr, timeout: float):
    try:
        banner = ssh_scanner.grab_banner(ip, 22, timeout)
        if not banner:
            return
        if not pr.banner:
            pr.banner = banner
        software, version = ssh_scanner.parse_banner(banner)
        cve_entries = ssh_scanner.map_cves(software, version, banner)
        for c in cve_entries:
            pr.cves.append({'cve': c.cve, 'severity': c.severity, 'desc': c.desc})
    except Exception:
        pass

def _enrich_http(ip: str, pr, timeout: float):
    """Send a proper HTTP request to get Server header for CVE matching."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, pr.port))
        s.send(b'HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n' % ip.encode())
        resp = s.recv(2048).decode('utf-8', errors='replace')
        s.close()
        # Extract Server header
        for line in resp.split('\r\n'):
            if line.lower().startswith('server:'):
                server = line.split(':', 1)[1].strip()
                pr.banner = server
                # Re-run CVE matching on the server banner
                new_cves = port_scanner.map_banner_cves(server)
                for c in new_cves:
                    if c['cve'] not in {existing['cve'] for existing in pr.cves}:
                        pr.cves.append(c)
                break
    except Exception:
        pass


def _enrich_ftp(ip: str, pr, timeout: float):
    try:
        banner = ftp_scanner.grab_ftp_banner(ip, 21, timeout)
        if not banner:
            return
        if not pr.banner:
            pr.banner = banner
        _software, cve_entries = ftp_scanner.fingerprint_ftp(banner)
        for c in cve_entries:
            pr.cves.append({'cve': c.cve, 'severity': c.severity, 'desc': c.description})
    except Exception:
        pass

# ─── Scan worker ─────────────────────────────────────────────────────────────

def scan_target(ip: str, ports: list, config, stats: ScanStats) -> TargetResult:
    t0 = time.monotonic()
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(20, len(ports))) as inner:
        futs = {inner.submit(port_scanner.scan_port, ip, p, config.timeout): p
                for p in ports}
        for f in concurrent.futures.as_completed(futs):
            try:
                pr = f.result()
                if pr is not None:
                    open_ports.append(pr)
            except Exception:
                pass

    open_ports.sort(key=lambda x: x.port)

    HTTP_PORTS = {80, 8080, 8000, 8008, 443, 8443, 4443, 9443}
    for pr in open_ports:
        if pr.port == 22:
            _enrich_ssh(ip, pr, config.timeout)
        elif pr.port == 21:
            _enrich_ftp(ip, pr, config.timeout)
        elif pr.port in HTTP_PORTS and not pr.banner:
            _enrich_http(ip, pr, config.timeout)
        if pr.port in port_scanner.QUICK_CHECK_PORTS and not pr.extra:
            svc = port_scanner.QUICK_CHECK_PORTS[pr.port]
            try:
                pr.extra = port_scanner.quick_check(ip, pr.port, svc, config.timeout)
            except Exception:
                pass

    os_hint = ''
    if config.os_hint and open_ports:
        try:
            os_hint = port_scanner.os_hint_from_ttl(ip)
        except Exception:
            pass

    asn_info = {}
    if config.asn:
        try:
            asn_info = ipmagic.get_full_info(ip) or {}
        except Exception:
            pass

    result = TargetResult(
        ip=ip, timestamp=ts, open_ports=open_ports,
        os_hint=os_hint, asn_info=asn_info,
        duration=time.monotonic() - t0,
    )
    result.attack_score = score_target(result)
    stats.record_host(result)
    return result

# ─── Live dashboard ───────────────────────────────────────────────────────────

class DashboardThread(threading.Thread):
    BOX_W = 61
    FEED_SLOTS = 8

    def __init__(self, stats: ScanStats, live_feed: deque, mode_label: str):
        super().__init__(daemon=True, name='dashboard')
        self._stats       = stats
        self._feed        = live_feed
        self._mode_label  = mode_label
        self._lines_drawn = 0
        self._interval    = 0.5
        self._paused      = False

    def run(self):
        if not sys.stdout.isatty():
            return
        while not _shutdown_event.is_set():
            if not self._paused:
                with _print_lock:
                    if not self._paused:
                        self._render()
            time.sleep(self._interval)

    def pause_and_clear(self):
        """Erase dashboard from screen. Caller MUST hold _print_lock."""
        self._paused = True
        if self._lines_drawn > 0 and sys.stdout.isatty():
            sys.stdout.write('\033[%dA\r\033[J' % self._lines_drawn)
            sys.stdout.flush()
            self._lines_drawn = 0

    def resume(self):
        self._paused = False

    def stop(self):
        self._paused = True
        if self._lines_drawn > 0 and sys.stdout.isatty():
            with _print_lock:
                sys.stdout.write('\033[%dA\r\033[J' % self._lines_drawn)
                sys.stdout.flush()
            self._lines_drawn = 0

    def _pad(self, text: str) -> str:
        visible = len(_strip_ansi(text))
        pad = max(0, self.BOX_W - visible)
        return text + ' ' * pad

    def _row(self, text: str) -> str:
        c = pp.bcolors
        return c.CYAN + '║' + c.ENDC + self._pad(text) + c.CYAN + '║' + c.ENDC

    def _render(self):
        c = pp.bcolors
        s = self._stats
        W = self.BOX_W

        lines = []
        top    = c.CYAN + '╔' + '═' * W + '╗' + c.ENDC
        mid    = c.CYAN + '╠' + '═' * W + '╣' + c.ENDC
        feed_h = c.CYAN + '╠' + '═' * 21 + ' LIVE FEED ' + '═' * (W - 32) + '╣' + c.ENDC
        bot    = c.CYAN + '╚' + '═' * W + '╝' + c.ENDC

        title = c.BOLD + '  THREAT ACTOR SIMULATION — Internet Exposure Scan' + c.ENDC
        mode  = c.GREY + ' [%s]' % self._mode_label + c.ENDC
        lines.append(top)
        lines.append(self._row(title))
        lines.append(self._row(mode))
        lines.append(mid)

        rate = s.rate()
        lines.append(self._row(
            '  Scanned: %s%-8s%s  Open: %s%-6s%s  Rate: %s%.1f/s%s' % (
                c.GREEN, '{:,}'.format(s.ips_scanned), c.ENDC,
                c.BLUE,  '{:,}'.format(s.total_open_ports), c.ENDC,
                c.CYAN,  rate, c.ENDC,
            )
        ))
        lines.append(self._row(
            '  %sCRIT: %-3d%s  %sHIGH: %-3d%s  %sMED: %-3d%s  %sUNAUTH: %-3d%s' % (
                c.RED,    s.hosts_critical, c.ENDC,
                c.YELLOW, s.hosts_high,     c.ENDC,
                c.BLUE,   s.hosts_medium,   c.ENDC,
                c.PURPLE, s.unauth_count,   c.ENDC,
            )
        ))
        lines.append(feed_h)

        feed_items = list(self._feed)[-self.FEED_SLOTS:]
        if not feed_items:
            lines.append(self._row(c.GREY + '  waiting for findings...' + c.ENDC))
            for _ in range(self.FEED_SLOTS - 1):
                lines.append(self._row(''))
        else:
            for entry in feed_items:
                lines.append(self._row(' ' + entry))
            for _ in range(self.FEED_SLOTS - len(feed_items)):
                lines.append(self._row(''))

        lines.append(bot)

        if self._lines_drawn > 0:
            sys.stdout.write('\033[%dA\r' % self._lines_drawn)
        for line in lines:
            sys.stdout.write(line + '\033[K\n')
        sys.stdout.flush()
        self._lines_drawn = len(lines)

# ─── Result formatting ────────────────────────────────────────────────────────

def _make_feed_entry(result: TargetResult) -> str:
    c = pp.bcolors
    sc = result.attack_score
    label = sc.label if sc else 'Low'

    prefixes = {
        'Critical': c.RED + c.BOLD + '[!!]' + c.ENDC,
        'High':     c.RED    + '[!] ' + c.ENDC,
        'Medium':   c.YELLOW + '[!] ' + c.ENDC,
        'Low':      c.BLUE   + '[+] ' + c.ENDC,
    }
    prefix = prefixes.get(label, '[+] ')

    services = ', '.join(dict.fromkeys(
        pr.service for pr in result.open_ports if pr.service
    ))[:28]
    country  = result.asn_info.get('country', '')
    asn_num  = result.asn_info.get('asn', '')
    asn_str  = ('AS%s %s' % (asn_num, country)).strip() if asn_num else country

    score_str = ('[%d]' % sc.score) if sc else ''
    return '%s %-15s  %-28s %s %s' % (
        prefix, result.ip, services, score_str, asn_str
    )

def _format_finding_line(result: TargetResult, config) -> str:
    sc = result.attack_score
    label = sc.label if sc else 'Low'
    score = sc.score if sc else 0

    ports_str = ', '.join('%d/%s' % (pr.port, pr.service or '?')
                          for pr in result.open_ports[:6])
    if len(result.open_ports) > 6:
        ports_str += ' +%d' % (len(result.open_ports) - 6)

    cve_count = sum(len(pr.cves) for pr in result.open_ports)
    unauth    = sum(1 for pr in result.open_ports
                   if pr.extra and 'unauth' in pr.extra.lower())

    country  = result.asn_info.get('country', '')
    asn_desc = result.asn_info.get('asn_description', '')[:30]
    geo_str  = (' [%s %s]' % (country, asn_desc)).rstrip() if (country or asn_desc) else ''

    extras = []
    if cve_count:
        extras.append('%d CVE%s' % (cve_count, 's' if cve_count > 1 else ''))
    if unauth:
        extras.append('%d UNAUTH' % unauth)
    extra_str = ' | ' + ', '.join(extras) if extras else ''

    return '%s (score %d) %s  %s%s%s' % (
        label.upper(), score, result.ip, ports_str, extra_str, geo_str
    )

def _print_found_banner():
    c = pp.bcolors
    banner = (
        c.RED + c.BOLD +
        '\n ███████╗ ██████╗ ██╗   ██╗███╗  ██╗██████╗ ██╗\n'
        ' ██╔════╝██╔═══██╗██║   ██║████╗ ██║██╔══██╗██║\n'
        ' █████╗  ██║   ██║██║   ██║██╔██╗██║██║  ██║██║\n'
        ' ██╔══╝  ██║   ██║██║   ██║██║╚████║██║  ██║╚═╝\n'
        ' ██║     ╚██████╔╝╚██████╔╝██║ ╚███║██████╔╝██╗\n'
        ' ╚═╝      ╚═════╝  ╚═════╝ ╚═╝  ╚══╝╚═════╝ ╚═╝\n'
        + c.ENDC
    )
    sys.stdout.write(banner)
    sys.stdout.flush()

def _console_finding(result: TargetResult, config):
    """Output a finding permanently. Dashboard erases itself first, redraws after."""
    label = result.attack_score.label if result.attack_score else 'Low'
    line  = _format_finding_line(result, config)

    if config.presentation:
        if label == 'Critical':
            with _print_lock:
                if _dashboard_ref:
                    _dashboard_ref.pause_and_clear()
                _print_found_banner()
                time.sleep(0.5)
                for ch in (pp.bcolors.RED + pp.bcolors.BOLD + '  ' + line + pp.bcolors.ENDC):
                    sys.stdout.write(ch)
                    sys.stdout.flush()
                    time.sleep(0.03)
                sys.stdout.write('\n')
                sys.stdout.flush()
                if _dashboard_ref:
                    _dashboard_ref.resume()
            time.sleep(1.2)
        elif label == 'High':
            _console(pp.critical, line)
            time.sleep(0.3)
        elif label == 'Medium':
            _console(pp.warning, line)
            time.sleep(0.1)
        else:
            _console(pp.info, line)
    else:
        if label == 'Critical':
            _console(pp.critical, line)
        elif label == 'High':
            _console(pp.error, line)
        elif label == 'Medium':
            _console(pp.warning, line)
        else:
            _console(pp.info, line)

        # Print CVE and unauth sub-details
        for pr in result.open_ports:
            for cve in pr.cves:
                _console(pp.info_spaces,
                         '%d/%s  %s [%s] %s' % (
                             pr.port, pr.service or '?',
                             cve.get('cve', '?'),
                             cve.get('severity', '?'),
                             cve.get('desc', '')[:60]))
            if pr.extra and 'unauth' in pr.extra.lower():
                _console(pp.info_spaces,
                         '%d/%s  UNAUTHENTICATED ACCESS: %s' % (
                             pr.port, pr.service or '?', pr.extra[:80]))

# ─── Output functions ─────────────────────────────────────────────────────────

def _init_csv(path: str):
    with _output_lock:
        with open(path, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['IP', 'TIMESTAMP', 'OPEN_PORTS', 'SCORE', 'LABEL',
                        'CVE_COUNT', 'UNAUTH', 'COUNTRY', 'ASN', 'DURATION_S'])

def write_json_line(result: TargetResult, path: str):
    with _output_lock:
        with open(path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(result.to_dict()) + '\n')

def write_csv_row(result: TargetResult, path: str):
    sc = result.attack_score
    unauth = sum(1 for pr in result.open_ports
                 if pr.extra and 'unauth' in pr.extra.lower())
    with _output_lock:
        with open(path, 'a', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow([
                result.ip, result.timestamp, len(result.open_ports),
                sc.score if sc else 0, sc.label if sc else 'Low',
                sum(len(pr.cves) for pr in result.open_ports), unauth,
                result.asn_info.get('country', ''),
                result.asn_info.get('asn', ''),
                round(result.duration, 3),
            ])

def write_pipeline_files(results: list, output_dir: str):
    """Write target files for piping into the other scanners."""
    HTTP_PORTS  = {80, 8080, 8000, 8008}
    HTTPS_PORTS = {443, 8443, 4443, 9443}

    targets, ssh_targets, ftp_targets, nuclei_hosts = [], [], [], []
    seen_ips = set()
    for r in results:
        if not r.open_ports:
            continue
        if r.ip not in seen_ips:
            seen_ips.add(r.ip)
            targets.append(r.ip)
        port_nums = {pr.port for pr in r.open_ports}
        if 22 in port_nums:
            ssh_targets.append('%s:22' % r.ip)
        if 21 in port_nums:
            ftp_targets.append('%s:21' % r.ip)
        for pr in r.open_ports:
            if pr.port in HTTPS_PORTS:
                nuclei_hosts.append('https://%s:%d' % (r.ip, pr.port))
            elif pr.port in HTTP_PORTS:
                nuclei_hosts.append('http://%s:%d' % (r.ip, pr.port))

    written = []
    for name, items in [('targets.txt', targets),
                        ('ssh_targets.txt', ssh_targets),
                        ('ftp_targets.txt', ftp_targets),
                        ('nuclei_hosts.txt', nuclei_hosts)]:
        if items:
            path = os.path.join(output_dir, name)
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(items) + '\n')
            written.append((name, len(items)))
    return written


def write_html_report(results: list, stats: ScanStats, output_dir: str, config):
    path = os.path.join(output_dir, 'report.html')
    elapsed = time.monotonic() - stats.start_time
    elapsed_str = str(datetime.timedelta(seconds=int(elapsed)))

    # All hosts with open ports, sorted by score
    findings = [r for r in results if r.open_ports]
    findings.sort(key=lambda r: (r.attack_score.score if r.attack_score else 0),
                  reverse=True)

    all_cves = []
    all_unauth = []
    for r in findings:
        for pr in r.open_ports:
            for cve in pr.cves:
                all_cves.append((r.ip, pr.port, pr.service, cve))
            if pr.extra and 'unauth' in pr.extra.lower():
                all_unauth.append((r.ip, pr.port, pr.service, pr.extra))

    banner_art = (
        'RANDOM SCANNER v%s — Threat Actor Simulation\n'
        'IPs Scanned: %d  |  Open Ports: %d  |  CVEs: %d\n'
        'Duration: %s  |  Rate: %.1f/s'
    ) % (VERSION, stats.ips_scanned, stats.total_open_ports,
         stats.cve_count, elapsed_str, stats.rate())

    def sev_cls(sev):
        return {'CRITICAL': 'sev-critical', 'HIGH': 'sev-high',
                'MEDIUM': 'sev-medium'}.get(sev, 'sev-low')
    def label_cls(label):
        return {'Critical': 'sev-critical', 'High': 'sev-high',
                'Medium': 'sev-medium'}.get(label, 'sev-low')

    top_rows = ''
    for r in findings[:500]:
        sc = r.attack_score
        ports_str = html.escape(', '.join('%d/%s' % (p.port, p.service or '?')
                                          for p in r.open_ports[:5]))
        cve_n  = sum(len(p.cves) for p in r.open_ports)
        svcs   = html.escape(', '.join(dict.fromkeys(
                     p.service for p in r.open_ports if p.service))[:40])
        cc     = html.escape(r.asn_info.get('country', ''))
        asn    = html.escape(r.asn_info.get('asn', ''))
        top_rows += (
            '<tr><td>%s</td><td class="%s"><b>%d</b></td>'
            '<td class="%s">%s</td><td>%s</td>'
            '<td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>\n'
        ) % (html.escape(r.ip), label_cls(sc.label), sc.score,
             label_cls(sc.label), html.escape(sc.label), ports_str,
             cve_n, svcs, cc, asn)

    cve_rows = ''
    for (ip, port, svc, cve) in all_cves[:200]:
        nvd_url = 'https://nvd.nist.gov/vuln/detail/%s' % html.escape(cve.get('cve', ''))
        sev = cve.get('severity', 'UNKNOWN')
        cve_rows += (
            '<tr><td>%s:%d (%s)</td>'
            '<td><a href="%s" target="_blank">%s</a></td>'
            '<td class="%s">%s</td><td>%s</td></tr>\n'
        ) % (html.escape(ip), port, html.escape(svc or '?'),
             nvd_url, html.escape(cve.get('cve', '?')),
             sev_cls(sev), html.escape(sev),
             html.escape(cve.get('desc', '')[:100]))

    unauth_rows = ''
    for (ip, port, svc, extra) in all_unauth[:100]:
        unauth_rows += (
            '<tr><td>%s</td><td>%d</td><td>%s</td><td>%s</td></tr>\n'
        ) % (html.escape(ip), port, html.escape(svc or '?'),
             html.escape(extra[:120]))

    mode_info = getattr(config, 'mode', 'random')

    doc = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Threat Actor Simulation — Random Scanner v{ver}</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
     margin:20px;background:#1a1a2e;color:#e0e0e0;}}
h1,h2{{color:#00d4ff;}} h1{{margin-top:0;}}
.meta{{color:#aaa;margin-bottom:20px;font-size:0.9em;}}
.cards{{display:flex;flex-wrap:wrap;gap:15px;margin:15px 0 30px;}}
.card{{background:#16213e;padding:15px 25px;border-radius:8px;text-align:center;min-width:120px;}}
.card .count{{font-size:2em;font-weight:bold;color:#00d4ff;}}
.card .lbl{{font-size:0.8em;color:#aaa;}}
.sev-critical{{color:#dc3545;font-weight:bold;}}
.sev-high{{color:#fd7e14;font-weight:bold;}}
.sev-medium{{color:#ffc107;}}
.sev-low{{color:#17a2b8;}}
table{{border-collapse:collapse;width:100%;margin-bottom:30px;}}
th,td{{border:1px solid #333;padding:8px;text-align:left;vertical-align:top;font-size:0.9em;}}
th{{background:#16213e;color:#00d4ff;}}
tr:nth-child(even){{background:#0f3460;}}
tr:hover{{background:#1a1a4e;}}
a{{color:#00d4ff;}}
.banner{{font-family:monospace;color:#00ff41;background:#000;padding:15px;
         border-radius:4px;white-space:pre;font-size:0.8em;margin-bottom:20px;}}
</style></head><body>
<div class="banner">{banner}</div>
<h1>Threat Actor Simulation — Internet Exposure Scan</h1>
<div class="meta">Mode: <b>{mode}</b> &nbsp;|&nbsp; Generated: {dt}</div>
<div class="cards">
  <div class="card"><div class="count">{ips_scanned:,}</div><div class="lbl">IPs Scanned</div></div>
  <div class="card"><div class="count">{open_ports:,}</div><div class="lbl">Open Ports</div></div>
  <div class="card"><div class="count sev-critical">{hosts_critical}</div><div class="lbl">Critical Hosts</div></div>
  <div class="card"><div class="count sev-high">{hosts_high}</div><div class="lbl">High Hosts</div></div>
  <div class="card"><div class="count sev-medium">{hosts_medium}</div><div class="lbl">Medium Hosts</div></div>
  <div class="card"><div class="count">{cve_count}</div><div class="lbl">CVEs Found</div></div>
  <div class="card"><div class="count sev-critical">{unauth}</div><div class="lbl">Unauth Access</div></div>
  <div class="card"><div class="count">{duration}</div><div class="lbl">Duration</div></div>
</div>
<h2>Top Findings (by score)</h2>
<table><tr><th>IP</th><th>Score</th><th>Label</th><th>Open Ports</th>
<th>CVEs</th><th>Services</th><th>Country</th><th>ASN</th></tr>
{top_rows}
</table>
<h2>CVE Findings</h2>
<table><tr><th>Host</th><th>CVE</th><th>Severity</th><th>Description</th></tr>
{cve_rows}
</table>
<h2>Unauthenticated Access</h2>
<table><tr><th>IP</th><th>Port</th><th>Service</th><th>Finding</th></tr>
{unauth_rows}
</table>
</body></html>
""".format(
        ver=VERSION, banner=html.escape(banner_art),
        mode=html.escape(mode_info),
        dt=html.escape(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
        ips_scanned=stats.ips_scanned,
        open_ports=stats.total_open_ports,
        hosts_critical=stats.hosts_critical,
        hosts_high=stats.hosts_high,
        hosts_medium=stats.hosts_medium,
        cve_count=stats.cve_count,
        unauth=stats.unauth_count,
        duration=elapsed_str,
        top_rows=top_rows,
        cve_rows=cve_rows or '<tr><td colspan="4">No CVEs found</td></tr>',
        unauth_rows=unauth_rows or '<tr><td colspan="4">No unauthenticated access found</td></tr>',
    )

    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(doc)
        _console(pp.info, 'HTML report written to %s' % path)
    except OSError as e:
        _console(pp.error, 'Cannot write HTML report: %s' % e)

# ─── Result processing ────────────────────────────────────────────────────────

def _process_result(result: TargetResult, stats: ScanStats,
                    live_feed: deque, all_results: list,
                    json_path: Optional[str], csv_path: str, config,
                    vulnerable_count: list):
    stats.inc_scanned()
    all_results.append(result)

    sc    = result.attack_score
    label = sc.label if sc else 'Low'

    write_csv_row(result, csv_path)

    if not result.open_ports:
        if config.verbose:
            _console(pp.debug, '[no open ports] %s' % result.ip)
        return

    entry = _make_feed_entry(result)
    with _feed_lock:
        live_feed.appendleft(entry)

    if label in ('Critical', 'High', 'Medium'):
        _console_finding(result, config)
        vulnerable_count[0] += 1
    elif label == 'Low' and config.verbose:
        _console(pp.info, _format_finding_line(result, config))

    if label != 'Low' and json_path:
        write_json_line(result, json_path)

def _print_summary(stats: ScanStats, all_results: list):
    elapsed = time.monotonic() - stats.start_time
    elapsed_str = str(datetime.timedelta(seconds=int(elapsed)))
    _console(pp.status, 'Scan completed in: %s' % elapsed_str, newline=True)
    _console(pp.status, 'IPs scanned:   %d  |  Rate: %.1f/s' % (
        stats.ips_scanned, stats.rate()))
    _console(pp.status, 'Open ports:    %d  |  Unauth access: %d' % (
        stats.total_open_ports, stats.unauth_count))
    _console(pp.status, 'CVEs found:    %d  (CRITICAL: %d  HIGH: %d)' % (
        stats.cve_count, stats.cve_critical, stats.cve_high))
    _console(pp.status, 'Hosts:         CRITICAL: %d  |  HIGH: %d  |  MEDIUM: %d' % (
        stats.hosts_critical, stats.hosts_high, stats.hosts_medium))

# ─── CLI ─────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='random_scanner.py',
        description=(
            'Threat Actor Simulation — Internet Exposure Proof-of-Concept v%s\n\n'
            'Demonstrates how easily a threat actor discovers exposed services\n'
            'across the internet. For authorised security awareness use only.' % VERSION
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./random_scanner.py --count 100 --asn --presentation
  ./random_scanner.py --seed 42 --count 50 -p top100
  ./random_scanner.py --asn-target AS13335 --count 20
  ./random_scanner.py --country DE,FR --count 50
  ./random_scanner.py --cidr 1.1.1.0/24 --count 10
  ./random_scanner.py --org-name "Cloudflare" --count 20
  ./random_scanner.py --stop-at 5 --rate 5 --stealth --html-report
""",
    )

    sel = parser.add_argument_group('Target Selection')
    sel.add_argument('--mode', choices=['random', 'asn', 'country', 'org', 'cidr'],
                     default='random',
                     help='Targeting mode (default: auto-detected from flags)')
    sel.add_argument('--asn-target', metavar='ASN[,ASN]',
                     help='ASN(s) e.g. "AS13335" or "AS13335,AS15169"')
    sel.add_argument('--country', metavar='CC[,CC]',
                     help='ISO country codes e.g. "US" or "US,DE,GB"')
    sel.add_argument('--org-name', metavar='NAME',
                     help='Organisation name substring')
    sel.add_argument('--cidr', metavar='CIDR[,CIDR]',
                     help='CIDR(s) e.g. "1.2.3.0/24,5.6.0.0/16"')
    sel.add_argument('--refresh-rir', action='store_true', default=False,
                     help='Force re-download of RIR delegation files (cached 24h)')

    gen = parser.add_argument_group('Target Generation')
    gen.add_argument('--count', type=int, default=None, metavar='N',
                     help='IPs to scan before stopping (default: unlimited)')
    gen.add_argument('--stop-at', dest='stop_at', type=int, default=None, metavar='N',
                     help='Stop after N vulnerable hosts found (score >= Medium)')
    gen.add_argument('--seed', type=int, default=None, metavar='N',
                     help='RNG seed for reproducible demo sequences')
    gen.add_argument('--exclude', metavar='FILE',
                     help='File of CIDRs/IPs to never scan')

    scan = parser.add_argument_group('Scan Configuration')
    scan.add_argument('-p', '--ports', dest='ports', default='top20', metavar='SPEC',
                      help='top20 (default), top100, or "22,80,443"')
    scan.add_argument('-m', '--maxthread', dest='maxthread', type=int, default=20,
                      metavar='N', help='Concurrent host threads (default: 20)')
    scan.add_argument('-t', '--timeout', dest='timeout', type=float, default=3.0,
                      metavar='N', help='Per-connection timeout seconds (default: 3)')
    scan.add_argument('--rate', type=float, default=10.0, metavar='N',
                      help='Max host scans per second (default: 10)')
    scan.add_argument('--stealth', action='store_true', default=False,
                      help='Add jitter 0.5-3s between hosts; halve rate')

    enr = parser.add_argument_group('Enrichment')
    enr.add_argument('--asn', action='store_true', default=False,
                     help='ASN/geo lookup on all hits (uses ipmagic, cached)')
    enr.add_argument('--os-hint', dest='os_hint', action='store_true', default=False,
                     help='Guess OS from ICMP TTL via ping')

    pres = parser.add_argument_group('Presentation')
    pres.add_argument('--presentation', action='store_true', default=False,
                      help='Dramatic mode: typing effect, FOUND! banner, pacing sleeps')

    out = parser.add_argument_group('Output')
    out.add_argument('-o', '--output', dest='output_dir', metavar='DIR', default=None,
                     help='Results directory (default: random_scan_YYYYMMDD_HHMMSS)')
    out.add_argument('--no-json', dest='json_output', action='store_false', default=True,
                     help='Disable JSONL findings output')
    out.add_argument('--html-report', dest='html_report', action='store_true', default=False,
                     help='Generate HTML report at end of run')
    out.add_argument('-v', '--verbose', action='store_true', default=False,
                     help='Show all banners, debug info, and Low-score hosts')

    return parser

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    global _ALL_EXCLUDED, _TARGET_POOL, _dashboard_ref

    banner_art = r"""
  ██████╗  █████╗ ███╗  ██╗██████╗  ██████╗ ███╗  ███╗
  ██╔══██╗██╔══██╗████╗ ██║██╔══██╗██╔═══██╗████╗████║
  ██████╔╝███████║██╔██╗██║██║  ██║██║   ██║██╔████╔██║
  ██╔══██╗██╔══██║██║╚████║██║  ██║██║   ██║██║╚██╔╝██║
  ██║  ██║██║  ██║██║ ╚███║██████╔╝╚██████╔╝██║ ╚═╝ ██║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝╚═════╝  ╚═════╝ ╚═╝     ╚═╝
         ███████╗ ██████╗ █████╗ ███╗  ██╗███╗  ██╗███████╗██████╗
         ██╔════╝██╔════╝██╔══██╗████╗ ██║████╗ ██║██╔════╝██╔══██╗
         ███████╗██║     ███████║██╔██╗██║██╔██╗██║█████╗  ██████╔╝
         ╚════██║██║     ██╔══██║██║╚████║██║╚████║██╔══╝  ██╔══██╗
         ███████║╚██████╗██║  ██║██║ ╚███║██║ ╚███║███████╗██║  ██║
         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝╚═╝  ╚══╝╚══════╝╚═╝  ╚═╝
    Threat Actor Simulation  —  Internet Exposure PoC  v%s
    For authorised security awareness presentations only.
""" % VERSION
    print(banner_art)

    parser = build_parser()
    args = parser.parse_args()

    # ── Port list ─────────────────────────────────────────────────────────────
    if args.ports == 'top20':
        ports = TOP_20_PORTS
    elif args.ports == 'top100':
        ports = port_scanner.TOP_100_PORTS
    else:
        try:
            ports = port_scanner.parse_ports(args.ports)
        except SystemExit:
            pp.error('Invalid port spec: %s' % args.ports)
            sys.exit(1)

    # ── Output directory ──────────────────────────────────────────────────────
    if args.output_dir is None:
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        args.output_dir = 'random_scan_%s' % ts
    os.makedirs(args.output_dir, exist_ok=True)

    # ── Exclusions ────────────────────────────────────────────────────────────
    _ALL_EXCLUDED = list(EXCLUDED_NETWORKS)
    if args.exclude:
        extra = load_exclude_file(args.exclude)
        _ALL_EXCLUDED.extend(extra)
        pp.status('Custom exclusions: %d networks loaded' % len(extra))

    # ── Auto-infer mode from target flags ─────────────────────────────────────
    if args.mode == 'random':
        if args.country:
            args.mode = 'country'
        elif args.asn_target:
            args.mode = 'asn'
        elif args.org_name:
            args.mode = 'org'
        elif args.cidr:
            args.mode = 'cidr'

    # ── Build target pool based on mode ──────────────────────────────────────
    mode_label = args.mode
    if args.mode == 'random':
        _TARGET_POOL = []
        pp.status('Mode: RANDOM — scanning full public internet')

    elif args.mode == 'asn':
        if not args.asn_target:
            pp.error('--mode asn requires --asn-target AS<num>')
            sys.exit(1)
        asns = [a.strip() for a in args.asn_target.split(',') if a.strip()]
        pp.status('Mode: ASN — resolving subnets for %s ...' % ', '.join(asns))
        _TARGET_POOL = get_asn_cidrs(asns)
        if not _TARGET_POOL:
            pp.error('No CIDRs found for specified ASN(s)')
            sys.exit(1)
        mode_label = 'ASN %s' % ', '.join(asns)
        pp.info('ASN pool: %d subnets' % len(_TARGET_POOL))

    elif args.mode == 'country':
        if not args.country:
            pp.error('--mode country requires --country CC')
            sys.exit(1)
        countries = [c.strip().upper() for c in args.country.split(',') if c.strip()]
        if _rir_data_stale(args.refresh_rir):
            _fetch_rir_files(args.refresh_rir)
        pp.status('Mode: COUNTRY — loading CIDRs for %s ...' % ', '.join(countries))
        _TARGET_POOL = get_country_cidrs(countries)
        if not _TARGET_POOL:
            pp.error('No CIDRs found for country(s): %s' % ', '.join(countries))
            sys.exit(1)
        mode_label = 'COUNTRY %s' % ', '.join(countries)
        pp.info('Country pool: %d subnets' % len(_TARGET_POOL))

    elif args.mode == 'org':
        if not args.org_name:
            pp.error('--mode org requires --org-name NAME')
            sys.exit(1)
        if _rir_data_stale(args.refresh_rir):
            _fetch_rir_files(args.refresh_rir)
        pp.status('Mode: ORG — searching for "%s" in RIR data ...' % args.org_name)
        _TARGET_POOL = get_org_cidrs(args.org_name)
        if not _TARGET_POOL:
            pp.error('No CIDRs found for org: %s' % args.org_name)
            sys.exit(1)
        mode_label = 'ORG "%s"' % args.org_name
        pp.info('Org pool: %d subnets' % len(_TARGET_POOL))

    elif args.mode == 'cidr':
        if not args.cidr:
            pp.error('--mode cidr requires --cidr CIDR[,CIDR]')
            sys.exit(1)
        _TARGET_POOL = []
        for raw in args.cidr.split(','):
            raw = raw.strip()
            if not raw:
                continue
            try:
                _TARGET_POOL.append(ipaddress.ip_network(raw, strict=False))
            except ValueError as e:
                pp.error('Invalid CIDR "%s": %s' % (raw, e))
                sys.exit(1)
        mode_label = 'CIDR %s' % args.cidr
        pp.info('CIDR pool: %d networks' % len(_TARGET_POOL))

    # ── RNG ───────────────────────────────────────────────────────────────────
    rng = random.Random()
    if args.seed is not None:
        rng.seed(args.seed)
        pp.status('RNG seed: %d (reproducible sequence)' % args.seed)

    # ── Rate limiting & jitter ────────────────────────────────────────────────
    effective_rate = args.rate / 2 if args.stealth else args.rate
    rate_limiter = ssh_scanner.RateLimiter(effective_rate)
    jitter = ssh_scanner.JitterDelay(0.5, 3.0) if args.stealth else ssh_scanner.JitterDelay(0, 0)

    # ── Shared state ──────────────────────────────────────────────────────────
    stats     = ScanStats()
    live_feed = deque(maxlen=12)
    all_results: list = []
    vulnerable_count = [0]

    # ── Output paths ─────────────────────────────────────────────────────────
    json_path = os.path.join(args.output_dir, 'findings.json') if args.json_output else None
    csv_path  = os.path.join(args.output_dir, 'all_scan.csv')
    _init_csv(csv_path)

    # ── Status summary ────────────────────────────────────────────────────────
    pp.status('Ports:    %d  |  Threads: %d  |  Timeout: %.0fs' % (
        len(ports), args.maxthread, args.timeout))
    pp.status('Rate:     %.1f hosts/s%s' % (
        effective_rate, '  (stealth jitter ON)' if args.stealth else ''))
    if args.count:
        pp.status('Count:    %d IPs' % args.count)
    if args.stop_at:
        pp.status('Stop-at:  %d vulnerable hosts' % args.stop_at)
    pp.status('Output:   %s/' % args.output_dir)
    if args.presentation:
        pp.warning('PRESENTATION MODE ACTIVE — dramatic pacing enabled')

    # ── Dashboard ─────────────────────────────────────────────────────────────
    dashboard = DashboardThread(stats, live_feed, mode_label)
    _dashboard_ref = dashboard
    dashboard.start()

    # ── Signal handler — registered AFTER all imports so we win ──────────────
    def _signal_handler(sig, frame):
        _console(pp.error, 'Interrupt received — finishing current scans...',
                 newline=True)
        _shutdown_event.set()

    signal.signal(signal.SIGINT,  _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # ── Main scan loop ────────────────────────────────────────────────────────
    try:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=args.maxthread,
                thread_name_prefix='scanner') as executor:
            pending: dict = {}

            for ip in ip_generator(rng, args.count, _TARGET_POOL):
                if _shutdown_event.is_set():
                    break
                if args.stop_at is not None and vulnerable_count[0] >= args.stop_at:
                    _console(pp.status, 'Stop-at threshold reached (%d vulnerable)' %
                             vulnerable_count[0])
                    break

                stats.inc_generated()
                rate_limiter.acquire()
                jitter.sleep()

                if len(pending) >= args.maxthread * 2:
                    done_f = next(concurrent.futures.as_completed(pending))
                    del pending[done_f]
                    try:
                        _process_result(done_f.result(), stats, live_feed,
                                        all_results, json_path, csv_path,
                                        args, vulnerable_count)
                    except Exception:
                        pass

                future = executor.submit(scan_target, ip, ports, args, stats)
                pending[future] = ip

            for f in concurrent.futures.as_completed(pending):
                if _shutdown_event.is_set():
                    f.cancel()
                    continue
                try:
                    _process_result(f.result(), stats, live_feed, all_results,
                                    json_path, csv_path, args, vulnerable_count)
                except Exception:
                    pass

    finally:
        dashboard.stop()
        _dashboard_ref = None

    # ── Summary ───────────────────────────────────────────────────────────────
    _print_summary(stats, all_results)

    # ── Pipeline target files ─────────────────────────────────────────────────
    pipeline = write_pipeline_files(all_results, args.output_dir)

    # ── Report outputs ────────────────────────────────────────────────────────
    if args.html_report:
        args.mode = mode_label
        write_html_report(all_results, stats, args.output_dir, args)

    # ── Output listing ────────────────────────────────────────────────────────
    _console(pp.status, '─── Output Files ───────────────────────────────────',
             newline=True)

    if json_path and os.path.exists(json_path):
        _console(pp.info_spaces, 'findings.json      JSONL findings (Medium+)')
    _console(pp.info_spaces, 'all_scan.csv       every IP scanned (full CSV)')

    for name, count in pipeline:
        _console(pp.info_spaces, '%-19s %d entries' % (name, count))

    if args.html_report:
        _console(pp.info_spaces, 'report.html        visual HTML report')

    # ── Pipeline usage hints ──────────────────────────────────────────────────
    odir = args.output_dir
    if pipeline:
        _console(pp.status, '─── Feed Into Other Tools ──────────────────────────',
                 newline=True)
        for name, count in pipeline:
            path = '%s/%s' % (odir, name)
            if name == 'targets.txt':
                _console(pp.info_spaces,
                         'Deep scan:   port_scanner.py -r %s -p top100' % path)
            elif name == 'ssh_targets.txt':
                _console(pp.info_spaces,
                         'SSH brute:   ssh_scanner.py -r %s -U users.txt -P passwords.txt' % path)
            elif name == 'ftp_targets.txt':
                _console(pp.info_spaces,
                         'FTP brute:   ftp_scanner.py -r %s --enumerate' % path)
            elif name == 'nuclei_hosts.txt':
                _console(pp.info_spaces,
                         'Vuln scan:   nuclei -l %s -severity critical,high' % path)

    _console(pp.status, 'Done. Results in: %s/' % odir)


if __name__ == '__main__':
    main()
