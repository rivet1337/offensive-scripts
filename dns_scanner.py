#!/usr/bin/env python3

"""DNS Scanner v5 — Authorized Penetration Testing Tool.
Multi-technique subdomain discovery:
  - Wordlist brute-force with wildcard detection
  - Certificate transparency via crt.sh
  - Passive DNS: urlscan.io, HackerTarget, VirusTotal
  - Full DNS record suite (MX, TXT, NS, SOA, SRV, CNAME, CAA)
  - SPF IP extraction + recursive include expansion
  - AXFR zone transfer attempt
  - Subdomain permutation engine
  - CIDR/ASN reverse-DNS inception
  - ASN → all IP subnets expansion
  - CSV / JSON / HTML output
"""

import os
import sys
import re
import csv
import html
import json
import time
import socket
import signal
import random
import string
import argparse
import datetime
import ipaddress
import threading
import concurrent.futures
from typing import Optional

import dns.resolver
import dns.zone
import dns.query
import dns.exception
import requests
import ipmagic
import prettyprint as pp

# ─── Constants ────────────────────────────────────────────────────────────────

VERSION = '5.0'
DEFAULT_NAMESERVER = '8.8.8.8'
DEFAULT_TIMEOUT = 5.0
DEFAULT_THREADS = 20

# Compact but effective default subdomain wordlist (~200 entries)
DEFAULT_WORDLIST = [
    'www', 'www2', 'www3', 'mail', 'mx', 'mx1', 'mx2', 'smtp', 'smtp1',
    'smtp2', 'imap', 'pop', 'pop3', 'webmail', 'email', 'remote',
    'vpn', 'ssh', 'ftp', 'sftp', 'files', 'transfer',
    'ns', 'ns1', 'ns2', 'ns3', 'ns4', 'dns', 'dns1', 'dns2',
    'dev', 'dev1', 'dev2', 'development', 'staging', 'stage',
    'test', 'test1', 'test2', 'testing', 'qa', 'uat', 'sandbox',
    'api', 'api2', 'apis', 'api-v1', 'api-v2', 'rest', 'graphql',
    'admin', 'administrator', 'portal', 'dashboard', 'panel', 'control',
    'app', 'app1', 'app2', 'apps', 'application',
    'web', 'web1', 'web2', 'cdn', 'static', 'assets', 'media',
    'images', 'img', 'upload', 'uploads', 'download', 'downloads',
    'secure', 'security', 'ssl', 'tls',
    'shop', 'store', 'cart', 'checkout', 'payment', 'pay',
    'blog', 'news', 'press', 'media', 'marketing',
    'support', 'help', 'helpdesk', 'ticket', 'kb', 'docs', 'documentation',
    'wiki', 'forum', 'community', 'chat', 'jira', 'confluence', 'jenkins',
    'git', 'gitlab', 'github', 'bitbucket', 'svn', 'ci', 'cd', 'build',
    'monitor', 'monitoring', 'metrics', 'grafana', 'kibana', 'elastic',
    'log', 'logs', 'logging', 'splunk',
    'db', 'database', 'mysql', 'postgres', 'redis', 'mongo', 'elastic',
    'backup', 'bak', 'old', 'archive', 'legacy',
    'internal', 'intranet', 'corp', 'corporate', 'office',
    'proxy', 'gateway', 'lb', 'load', 'ha',
    'auth', 'login', 'sso', 'oauth', 'id', 'identity', 'ldap', 'ad',
    'mobile', 'ios', 'android', 'm',
    'beta', 'alpha', 'preview', 'rc',
    'aws', 'azure', 'gcp', 'cloud', 'k8s', 'kubernetes',
    'time', 'ntp', 'whois', 'host', 'direct',
    'local', 'localhost', 'router', 'switch', 'firewall',
]

# Common SRV service prefixes to probe
SRV_SERVICES = [
    '_http._tcp', '_https._tcp', '_sip._tcp', '_sip._udp',
    '_xmpp-client._tcp', '_xmpp-server._tcp', '_smtp._tcp',
    '_submission._tcp', '_imaps._tcp', '_pop3s._tcp',
    '_ftp._tcp', '_ssh._tcp', '_ldap._tcp', '_kerberos._tcp',
    '_autodiscover._tcp', '_caldav._tcp', '_carddav._tcp',
]

_shutdown_event = threading.Event()

# ─── Result type ─────────────────────────────────────────────────────────────

class Finding:
    """Represents one discovered subdomain/record."""
    __slots__ = ('fqdn', 'ips', 'asn_cidr', 'asn_description', 'method')

    def __init__(self, fqdn, ips, asn_cidr='', asn_description='', method=''):
        self.fqdn = fqdn
        self.ips = ips if isinstance(ips, list) else [ips]
        self.asn_cidr = asn_cidr
        self.asn_description = asn_description
        self.method = method

    def to_dict(self):
        return {
            'fqdn': self.fqdn,
            'ips': self.ips,
            'asn_cidr': self.asn_cidr,
            'asn_description': self.asn_description,
            'method': self.method,
        }

# ─── DNS helpers ─────────────────────────────────────────────────────────────

def make_resolver(nameserver: str, timeout: float) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [nameserver]
    r.timeout = timeout
    r.lifetime = timeout * 2
    return r


def resolve_a(fqdn: str, resolver: dns.resolver.Resolver) -> list:
    """Resolve A records. Returns list of IP strings or []."""
    try:
        return [str(rr) for rr in resolver.resolve(fqdn, 'A')]
    except Exception:
        return []


def resolve_record(fqdn: str, rdtype: str,
                   resolver: dns.resolver.Resolver) -> list:
    """Generic resolver. Returns list of record strings."""
    try:
        return [str(rr) for rr in resolver.resolve(fqdn, rdtype)]
    except Exception:
        return []


def detect_wildcard(domain: str, resolver: dns.resolver.Resolver) -> Optional[str]:
    """Resolve a random nonexistent subdomain to detect wildcard DNS.
    Returns the wildcard IP if detected, None otherwise.
    """
    rand_sub = ''.join(random.choices(string.ascii_lowercase, k=16))
    ips = resolve_a('%s.%s' % (rand_sub, domain), resolver)
    return ips[0] if ips else None

# ─── Enrichment ──────────────────────────────────────────────────────────────

def enrich(fqdn: str, ips: list, method: str) -> Finding:
    """Build a Finding, adding ASN info for the first IP."""
    asn_cidr = ''
    asn_desc = ''
    if ips:
        info = ipmagic.get_full_info(ips[0])
        asn_cidr = info.get('asn_cidr', '')
        asn_desc = info.get('asn_description', '')
    return Finding(fqdn, ips, asn_cidr, asn_desc, method)

# ─── Phase 1: Wordlist brute-force ───────────────────────────────────────────

def phase_wordlist(domain: str, wordlist: list, resolver: dns.resolver.Resolver,
                   threads: int, wildcard_ip: Optional[str]) -> list:
    pp.status('Wordlist brute-force: %d entries' % len(wordlist), newline=True)
    findings = []
    lock = threading.Lock()

    def _check(sub):
        if _shutdown_event.is_set():
            return
        fqdn = '%s.%s' % (sub, domain)
        ips = resolve_a(fqdn, resolver)
        if not ips:
            return
        if wildcard_ip and all(ip == wildcard_ip for ip in ips):
            return  # Wildcard hit — suppress
        f = enrich(fqdn, ips, 'wordlist')
        pp.info('[wordlist] %s → %s' % (fqdn, ', '.join(ips)))
        with lock:
            findings.append(f)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        list(concurrent.futures.as_completed(
            [ex.submit(_check, sub) for sub in wordlist]))

    return findings

# ─── Phase 2: Certificate transparency (crt.sh) ──────────────────────────────

def phase_crtsh(domain: str, resolver: dns.resolver.Resolver,
                wildcard_ip: Optional[str]) -> list:
    pp.status('Certificate transparency (crt.sh)...', newline=True)
    findings = []
    try:
        r = requests.get(
            'https://crt.sh/?q=%%.%s&output=json' % domain,
            timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
        if r.status_code != 200:
            pp.warning('crt.sh returned %d' % r.status_code)
            return findings

        names = set()
        for entry in r.json():
            for name in (entry.get('name_value', '') or '').split('\n'):
                name = name.strip().lstrip('*.')
                if name.endswith(domain) and ' ' not in name:
                    names.add(name)

        pp.info('crt.sh: %d unique names to resolve' % len(names))
        for name in sorted(names):
            if _shutdown_event.is_set():
                break
            ips = resolve_a(name, resolver)
            if not ips:
                continue
            if wildcard_ip and all(ip == wildcard_ip for ip in ips):
                continue
            f = enrich(name, ips, 'crt.sh')
            pp.info('[crt.sh] %s → %s' % (name, ', '.join(ips)))
            findings.append(f)

    except Exception as e:
        pp.warning('crt.sh failed: %s' % e)

    return findings

# ─── Phase 3: Passive DNS sources ────────────────────────────────────────────

def phase_passive(domain: str, resolver: dns.resolver.Resolver,
                  wildcard_ip: Optional[str],
                  urlscanio: bool, hackertarget: bool,
                  vt_key: Optional[str], aliases: list) -> list:
    findings = []
    found_names = set()
    lock = threading.Lock()

    def _resolve_and_add(name: str, source: str):
        if name in found_names:
            return
        ips = resolve_a(name, resolver)
        if not ips:
            return
        if wildcard_ip and all(ip == wildcard_ip for ip in ips):
            return
        f = enrich(name, ips, source)
        pp.info('[%s] %s → %s' % (source, name, ', '.join(ips)))
        with lock:
            found_names.add(name)
            findings.append(f)

    def _is_in_scope(name: str) -> bool:
        name_l = name.lower()
        if domain.lower() in name_l:
            return True
        return any(a.lower() in name_l for a in aliases)

    # urlscan.io
    if urlscanio:
        pp.status('Passive DNS: urlscan.io...', newline=True)
        try:
            r = requests.get(
                'https://urlscan.io/api/v1/search/?q=domain:%s&size=100' % domain,
                timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
            if r.status_code == 200:
                for item in r.json().get('results', []):
                    name = item.get('task', {}).get('domain', '')
                    if name and _is_in_scope(name):
                        _resolve_and_add(name, 'urlscan.io')
            elif r.status_code == 429:
                pp.warning('urlscan.io rate-limited (429) — skipping')
            time.sleep(1)  # rate limit courtesy
        except Exception as e:
            pp.warning('urlscan.io error: %s' % e)

    # HackerTarget
    if hackertarget:
        pp.status('Passive DNS: HackerTarget...', newline=True)
        try:
            r = requests.get(
                'https://api.hackertarget.com/hostsearch/?q=%s' % domain,
                timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
            if r.status_code == 200:
                for line in r.text.splitlines():
                    parts = line.split(',')
                    if len(parts) >= 1:
                        name = parts[0].strip()
                        if name.endswith(domain):
                            ip = parts[1].strip() if len(parts) > 1 else ''
                            if ip:
                                f = enrich(name, [ip], 'hackertarget')
                                pp.info('[hackertarget] %s → %s' % (name, ip))
                                findings.append(f)
        except Exception as e:
            pp.warning('HackerTarget error: %s' % e)

    # VirusTotal (free tier, requires no key for domain report)
    if vt_key:
        pp.status('Passive DNS: VirusTotal...', newline=True)
        try:
            r = requests.get(
                'https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40' % domain,
                headers={'x-apikey': vt_key, 'User-Agent': 'Mozilla/5.0'},
                timeout=15)
            if r.status_code == 200:
                for item in r.json().get('data', []):
                    name = item.get('id', '')
                    if name:
                        _resolve_and_add(name, 'virustotal')
        except Exception as e:
            pp.warning('VirusTotal error: %s' % e)

    return findings

# ─── Phase 4: DNS record suite ────────────────────────────────────────────────

def phase_dns_records(domain: str, resolver: dns.resolver.Resolver) -> dict:
    pp.status('DNS record suite...', newline=True)
    records = {}

    for rdtype in ('MX', 'NS', 'TXT', 'SOA', 'CAA', 'AAAA'):
        recs = resolve_record(domain, rdtype, resolver)
        if recs:
            records[rdtype] = recs
            pp.info('[%s] %s' % (rdtype, domain))
            for r in recs:
                pp.info_spaces(r[:120])

    # SRV probing
    srv_found = {}
    for svc in SRV_SERVICES:
        recs = resolve_record('%s.%s' % (svc, domain), 'SRV', resolver)
        if recs:
            srv_found[svc] = recs
            pp.info('[SRV] %s.%s' % (svc, domain))
            for r in recs:
                pp.info_spaces(r)
    if srv_found:
        records['SRV'] = srv_found

    # CNAME on www
    cname = resolve_record('www.%s' % domain, 'CNAME', resolver)
    if cname:
        records['CNAME_www'] = cname
        pp.info('[CNAME] www.%s → %s' % (domain, cname[0]))

    return records

# ─── Phase 5: SPF IP extraction ──────────────────────────────────────────────

def phase_spf(domain: str, resolver: dns.resolver.Resolver,
              inception_cidrs: set):
    """Parse SPF TXT, extract ip4/ip6/include, recursively follow includes."""
    pp.status('SPF extraction...', newline=True)
    visited = set()

    def _parse_spf(d: str):
        if d in visited:
            return
        visited.add(d)
        txt_records = resolve_record(d, 'TXT', resolver)
        for rec in txt_records:
            if not rec.lower().startswith('v=spf1'):
                continue
            pp.info('[SPF] %s: %s' % (d, rec[:100]))
            for token in rec.split():
                if token.startswith('ip4:'):
                    cidr = token[4:]
                    pp.info_spaces('ip4: %s' % cidr)
                    inception_cidrs.add(cidr)
                elif token.startswith('ip6:'):
                    pp.info_spaces('ip6: %s' % token[4:])
                elif token.startswith('include:'):
                    _parse_spf(token[8:])
                elif token.startswith('a:') or token == 'a':
                    target = token[2:] if ':' in token else d
                    ips = resolve_a(target, resolver)
                    for ip in ips:
                        info = ipmagic.get_full_info(ip)
                        cidr = info.get('asn_cidr', '')
                        if cidr:
                            inception_cidrs.add(cidr)

    _parse_spf(domain)

# ─── Phase 6: AXFR zone transfer ─────────────────────────────────────────────

def phase_axfr(domain: str, nameservers: list,
               resolver: dns.resolver.Resolver) -> list:
    pp.status('AXFR zone transfer attempt...', newline=True)
    findings = []

    for ns in nameservers:
        # Resolve the NS hostname to an IP
        ns_hostname = ns.rstrip('.')
        ns_ips = resolve_a(ns_hostname, resolver)
        if not ns_ips:
            try:
                ns_ips = [socket.gethostbyname(ns_hostname)]
            except Exception:
                continue

        for ns_ip in ns_ips:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
                pp.warning('[AXFR] ZONE TRANSFER SUCCEEDED on %s (%s) — misconfiguration!' % (
                    ns_hostname, ns_ip))
                for name, node in zone.nodes.items():
                    fqdn = '%s.%s' % (name, domain) if str(name) != '@' else domain
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            pp.info_spaces('%s  %s' % (fqdn, rdata))
                    ips = resolve_a(fqdn, resolver)
                    if ips:
                        f = enrich(fqdn, ips, 'axfr')
                        findings.append(f)
                return findings  # One success is enough
            except dns.exception.FormError:
                pass  # AXFR refused (expected)
            except Exception as e:
                if 'refused' not in str(e).lower() and 'query' not in str(e).lower():
                    pp.warning('[AXFR] %s (%s): %s' % (ns_hostname, ns_ip, e))

    if not findings:
        pp.info('[AXFR] All nameservers refused zone transfer (expected)')

    return findings

# ─── Phase 7: Permutation engine ─────────────────────────────────────────────

def phase_permutate(domain: str, known_subs: list,
                    resolver: dns.resolver.Resolver,
                    wildcard_ip: Optional[str], threads: int) -> list:
    pp.status('Permutation engine...', newline=True)
    PERMUTATION_AFFIXES = [
        'dev', 'staging', 'stage', 'test', 'qa', 'uat', 'old', 'new',
        'v1', 'v2', 'v3', '2', '3', 'internal', 'ext', 'external',
        'api', 'app', 'admin', 'secure', 'prod', 'production', 'beta',
    ]
    candidates = set()
    for sub in known_subs:
        base = sub.split('.')[0]  # 'api' from 'api.example.com'
        for affix in PERMUTATION_AFFIXES:
            candidates.add('%s-%s' % (base, affix))
            candidates.add('%s-%s' % (affix, base))
            candidates.add('%s%s' % (base, affix))

    pp.info('Permutation: testing %d candidates' % len(candidates))
    findings = []
    lock = threading.Lock()

    def _check(sub):
        fqdn = '%s.%s' % (sub, domain)
        ips = resolve_a(fqdn, resolver)
        if not ips:
            return
        if wildcard_ip and all(ip == wildcard_ip for ip in ips):
            return
        f = enrich(fqdn, ips, 'permutation')
        pp.info('[permutate] %s → %s' % (fqdn, ', '.join(ips)))
        with lock:
            findings.append(f)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        list(concurrent.futures.as_completed([ex.submit(_check, s) for s in candidates]))

    return findings

# ─── Phase 8: ipwhois + ASN expansion ────────────────────────────────────────

def phase_ipwhois(inception_cidrs: set):
    pp.status('IP WHOIS on identified CIDRs...', newline=True)
    asn_numbers = set()
    for cidr in inception_cidrs:
        ip = cidr.split('/')[0]
        info = ipmagic.get_full_info(ip)
        pp.info('CIDR: %-20s  ASN: %-8s  %s' % (
            cidr, info.get('asn', ''), info.get('asn_description', '')))
        if info.get('asn'):
            asn_numbers.add(info['asn'])
    return asn_numbers


def phase_asn2ip(asn_numbers: set) -> set:
    pp.status('ASN → IP subnet expansion...', newline=True)
    extra_cidrs = set()
    for asn in asn_numbers:
        for asn_part in asn.split():
            subnets = ipmagic.asn2IP(asn_part)
            pp.info('AS%s: %d subnets' % (asn_part, len(subnets)))
            for cidr, desc in sorted(subnets.items()):
                pp.info_spaces('%s  %s' % (cidr, desc))
                extra_cidrs.add(cidr)
    return extra_cidrs

# ─── Phase 9: Reverse-DNS inception ──────────────────────────────────────────

def _reverse_dns_ip(ip_str: str, domain: str, aliases: list,
                    resolver: dns.resolver.Resolver) -> Optional[Finding]:
    """Reverse-DNS a single IP. Returns a Finding if it matches domain/aliases."""
    try:
        hostname = socket.gethostbyaddr(ip_str)[0]
        hostname_l = hostname.lower()
        if domain.lower() in hostname_l or any(a.lower() in hostname_l for a in aliases):
            ips = resolve_a(hostname, resolver)
            return enrich(hostname, ips or [ip_str], 'inception')
    except Exception:
        pass
    return None


def phase_inception(inception_cidrs: set, domain: str, aliases: list,
                    resolver: dns.resolver.Resolver, threads: int) -> list:
    pp.status('Reverse-DNS inception on %d CIDRs...' % len(inception_cidrs), newline=True)
    all_ips = []
    for cidr in inception_cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.num_addresses > 65536:
                pp.warning('Skipping large CIDR %s (%d IPs) — use smaller ranges' % (
                    cidr, net.num_addresses))
                continue
            all_ips.extend(str(ip) for ip in net.hosts())
        except ValueError:
            pass

    pp.info('Reverse-DNS on %d IPs across %d CIDRs' % (len(all_ips), len(inception_cidrs)))
    findings = []
    lock = threading.Lock()

    def _check(ip_str):
        if _shutdown_event.is_set():
            return
        f = _reverse_dns_ip(ip_str, domain, aliases, resolver)
        if f:
            pp.info('[inception] %s → %s (%s)' % (f.fqdn, ip_str, ', '.join(f.ips)))
            with lock:
                findings.append(f)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        list(concurrent.futures.as_completed([ex.submit(_check, ip) for ip in all_ips]))

    return findings

# ─── Output writers ───────────────────────────────────────────────────────────

def write_csv(findings: list, path: str):
    fieldnames = ['FQDN', 'IP', 'ASN_CIDR', 'ASN_DESCRIPTION', 'METHOD']
    try:
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
            writer.writeheader()
            for finding in findings:
                for ip in finding.ips:
                    writer.writerow({
                        'FQDN': finding.fqdn,
                        'IP': ip,
                        'ASN_CIDR': finding.asn_cidr,
                        'ASN_DESCRIPTION': finding.asn_description,
                        'METHOD': finding.method,
                    })
        pp.info('CSV written to %s' % path)
    except OSError as e:
        pp.error('Cannot write CSV: %s' % e)


def write_json_output(findings: list, records: dict, domain: str, path: str):
    try:
        data = {
            'domain': domain,
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'subdomains': [f.to_dict() for f in findings],
            'dns_records': records,
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        pp.info('JSON written to %s' % path)
    except OSError as e:
        pp.error('Cannot write JSON: %s' % e)


def write_html(findings: list, records: dict, domain: str,
               start_dt: datetime.datetime, end_dt: datetime.datetime, path: str):
    duration = str(end_dt - start_dt).split('.')[0]
    method_counts: dict = {}
    for f in findings:
        method_counts[f.method] = method_counts.get(f.method, 0) + 1

    rows = ''
    for f in sorted(findings, key=lambda x: x.fqdn):
        rows += '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' % (
            html.escape(f.fqdn),
            html.escape(', '.join(f.ips)),
            html.escape(f.asn_cidr),
            html.escape(f.asn_description),
            html.escape(f.method),
        )

    rec_rows = ''
    for rdtype, values in records.items():
        if isinstance(values, dict):
            for svc, recs in values.items():
                rec_rows += '<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n' % (
                    html.escape(rdtype), html.escape(svc),
                    html.escape(', '.join(recs)[:200]))
        else:
            rec_rows += '<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n' % (
                html.escape(rdtype), html.escape(domain),
                html.escape(', '.join(values)[:200]))

    method_cards = ''.join(
        "<div class='card'><div class='count' style='color:#00d4ff'>%d</div>"
        "<div>%s</div></div>" % (count, html.escape(method))
        for method, count in sorted(method_counts.items())
    )

    content = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>DNS Scan — %s</title>
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
</style></head><body>
<h1>DNS Recon Report — %s</h1>
<div class="meta">Date: <strong>%s</strong> | Duration: <strong>%s</strong> | Total Findings: <strong>%d</strong></div>
<div class="cards">
  <div class="card"><div class="count" style="color:#28a745">%d</div><div>Subdomains</div></div>
  %s
</div>
<h2>Subdomains (%d)</h2>
<table><tr><th>FQDN</th><th>IPs</th><th>ASN CIDR</th><th>ASN Org</th><th>Method</th></tr>
%s</table>
<h2>DNS Records</h2>
<table><tr><th>Type</th><th>Name</th><th>Value</th></tr>
%s</table>
</body></html>""" % (
        html.escape(domain),
        html.escape(domain),
        html.escape(start_dt.strftime('%Y-%m-%d %H:%M:%S')),
        html.escape(duration),
        len(findings), len(findings),
        method_cards,
        len(findings),
        rows or "<tr><td colspan='5' style='color:#6c757d'>No subdomains found.</td></tr>",
        rec_rows or "<tr><td colspan='3' style='color:#6c757d'>No records retrieved.</td></tr>",
    )

    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        pp.info('HTML report written to %s' % path)
    except OSError as e:
        pp.error('Cannot write HTML: %s' % e)

# ─── Signal handler ───────────────────────────────────────────────────────────

def _signal_handler(sig, frame):
    pp.error('Interrupt received — stopping...')
    _shutdown_event.set()

signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)

# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog='dns_scanner.py',
        description='DNS Scanner v%s — Subdomain Enumeration & ASN Recon' % VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./dns_scanner.py -d example.com
  ./dns_scanner.py -d example.com --crtsh --passive --axfr --full-records
  ./dns_scanner.py -d example.com -w wordlist.txt --permutate --inception
  ./dns_scanner.py -d example.com --aliases=1e100.net,google --inception --asn2ip
  ./dns_scanner.py -l domains.txt -o results.csv --json-output results.json
"""
    )
    tgt = parser.add_argument_group('Target')
    tgt.add_argument('-d', '--domain', dest='domain', metavar='DOMAIN',
        help='Single domain to enumerate')
    tgt.add_argument('-l', '--domain-list', dest='domain_list', metavar='FILE',
        help='File of domains (one per line)')

    disc = parser.add_argument_group('Discovery methods')
    disc.add_argument('-w', '--wordlist', dest='wordlist', metavar='FILE',
        help='Wordlist for subdomain brute-force (default: built-in ~200 entries)')
    disc.add_argument('--crtsh', dest='crtsh', default=False, action='store_true',
        help='Certificate transparency via crt.sh')
    disc.add_argument('--passive', dest='passive', default=False, action='store_true',
        help='Passive DNS: urlscan.io + HackerTarget')
    disc.add_argument('--urlscanio', dest='urlscanio', default=False, action='store_true',
        help='urlscan.io passive DNS (subset of --passive)')
    disc.add_argument('--hackertarget', dest='hackertarget', default=False,
        action='store_true', help='HackerTarget passive DNS (subset of --passive)')
    disc.add_argument('--vt-key', dest='vt_key', metavar='KEY',
        help='VirusTotal API key for passive DNS')
    disc.add_argument('--axfr', dest='axfr', default=False, action='store_true',
        help='Attempt AXFR zone transfer on all identified nameservers')
    disc.add_argument('--full-records', dest='full_records', default=False,
        action='store_true', help='Enumerate MX/TXT/NS/SOA/SRV/CAA/CNAME records')
    disc.add_argument('--spf', dest='spf', default=False, action='store_true',
        help='Extract IPs from SPF record and add to inception list')
    disc.add_argument('--permutate', dest='permutate', default=False, action='store_true',
        help='Generate and test subdomain permutations from found names')

    adv = parser.add_argument_group('ASN inception')
    adv.add_argument('--ipwhois', dest='ipwhois', default=False, action='store_true',
        help='WHOIS lookup on identified IP ranges')
    adv.add_argument('--asn2ip', dest='asn2ip', default=False, action='store_true',
        help='Expand identified ASNs to all announced IP subnets')
    adv.add_argument('--inception', dest='inception', default=False, action='store_true',
        help='Reverse-DNS sweep on identified CIDRs')
    adv.add_argument('--aliases', dest='aliases', metavar='ALIAS1,ALIAS2',
        help='Comma-separated alias domains for inception matching')

    cfg = parser.add_argument_group('Configuration')
    cfg.add_argument('--nameserver', dest='nameserver', default=DEFAULT_NAMESERVER,
        metavar='IP', help='DNS resolver IP (default: 8.8.8.8)')
    cfg.add_argument('--timeout', dest='timeout', type=float, default=DEFAULT_TIMEOUT,
        metavar='SECS', help='DNS query timeout (default: 5)')
    cfg.add_argument('--maxthread', dest='threads', type=int, default=DEFAULT_THREADS,
        metavar='N', help='Max concurrent threads (default: 20)')
    cfg.add_argument('-v', '--verbose', dest='verbose', default=False,
        action='store_true', help='Verbose output')

    out = parser.add_argument_group('Output')
    out.add_argument('-o', '--output', dest='output', metavar='FILE',
        help='CSV output file')
    out.add_argument('--json-output', dest='json_output', metavar='FILE',
        help='JSON output file')
    out.add_argument('--html-report', dest='html_report', metavar='FILE',
        help='HTML report file')

    return parser

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    banner_art = """
  ██████╗ ███╗   ██╗███████╗    ███████╗ ██████╗ █████╗ ███╗  ██╗
  ██╔══██╗████╗  ██║██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗ ██║
  ██║  ██║██╔██╗ ██║███████╗    ███████╗██║     ███████║██╔██╗██║
  ██║  ██║██║╚██╗██║╚════██║    ╚════██║██║     ██╔══██║██║╚████║
  ██████╔╝██║ ╚████║███████║    ███████║╚██████╗██║  ██║██║ ╚███║
  ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝
         DNS Subdomain Enumeration + ASN Recon v%s
""" % VERSION
    print(banner_art)

    parser = build_parser()
    options = parser.parse_args()

    if not options.domain and not options.domain_list:
        parser.print_help()
        sys.exit(1)

    ctime = datetime.datetime.now()

    # Expand --passive shorthand
    if options.passive:
        options.urlscanio = True
        options.hackertarget = True

    aliases = [a.strip() for a in options.aliases.split(',')] if options.aliases else []

    # Load domain list
    domain_list = []
    if options.domain:
        domain_list.append(options.domain.strip())
    if options.domain_list:
        try:
            with open(options.domain_list, encoding='utf-8') as f:
                domain_list.extend(l.strip() for l in f if l.strip() and not l.startswith('#'))
        except OSError as e:
            pp.error('Cannot open domain list: %s' % e); sys.exit(1)

    # Load wordlist
    wordlist = DEFAULT_WORDLIST[:]
    if options.wordlist:
        try:
            with open(options.wordlist, encoding='utf-8') as f:
                wordlist = [l.rstrip('\n') for l in f if l.strip()]
        except OSError as e:
            pp.error('Cannot open wordlist: %s' % e); sys.exit(1)

    resolver = make_resolver(options.nameserver, options.timeout)

    all_findings: list = []
    all_records: dict = {}
    inception_cidrs: set = set()

    for domain in domain_list:
        pp.status('═══ Scanning: %s ═══' % domain, newline=True)

        # Wildcard detection
        wildcard_ip = detect_wildcard(domain, resolver)
        if wildcard_ip:
            pp.warning('[wildcard] %s has wildcard DNS → %s (results filtered)' % (
                domain, wildcard_ip))

        # ── Discovery phases ──────────────────────────────────────────────
        findings: list = []

        # Wordlist
        findings += phase_wordlist(domain, wordlist, resolver,
                                   options.threads, wildcard_ip)

        # crt.sh
        if options.crtsh and not _shutdown_event.is_set():
            findings += phase_crtsh(domain, resolver, wildcard_ip)

        # Passive DNS
        if (options.urlscanio or options.hackertarget or options.vt_key) \
                and not _shutdown_event.is_set():
            findings += phase_passive(domain, resolver, wildcard_ip,
                                      options.urlscanio, options.hackertarget,
                                      options.vt_key, aliases)

        # Collect CIDRs from findings
        for f in findings:
            if f.asn_cidr:
                inception_cidrs.add(f.asn_cidr)

        # Full DNS records
        if options.full_records and not _shutdown_event.is_set():
            all_records.update(phase_dns_records(domain, resolver))

        # SPF extraction
        if options.spf and not _shutdown_event.is_set():
            phase_spf(domain, resolver, inception_cidrs)

        # AXFR
        if options.axfr and not _shutdown_event.is_set():
            ns_records = resolve_record(domain, 'NS', resolver)
            if ns_records:
                findings += phase_axfr(domain, ns_records, resolver)

        # ipwhois + ASN expansion
        if options.ipwhois and inception_cidrs and not _shutdown_event.is_set():
            asn_numbers = phase_ipwhois(inception_cidrs)
            if options.asn2ip and asn_numbers:
                extra = phase_asn2ip(asn_numbers)
                inception_cidrs.update(extra)

        # Inception (reverse-DNS sweep)
        if options.inception and inception_cidrs and not _shutdown_event.is_set():
            findings += phase_inception(inception_cidrs, domain, aliases,
                                        resolver, options.threads)

        # Permutation engine
        if options.permutate and findings and not _shutdown_event.is_set():
            known_subs = list({f.fqdn for f in findings})
            findings += phase_permutate(domain, known_subs, resolver,
                                        wildcard_ip, options.threads)

        # Deduplicate by FQDN
        seen_fqdns = set()
        unique = []
        for f in findings:
            if f.fqdn not in seen_fqdns:
                seen_fqdns.add(f.fqdn)
                unique.append(f)
        findings = unique

        pp.status('Domain %s: %d unique subdomains found' % (domain, len(findings)), newline=True)
        all_findings.extend(findings)

    etime = datetime.datetime.now()
    total = str(etime - ctime).split('.')[0]

    # ── Summary ───────────────────────────────────────────────────────────
    pp.status('Scan completed in: %s' % total)
    pp.status('Total findings: %d subdomains across %d domain(s)' % (
        len(all_findings), len(domain_list)))

    method_counts: dict = {}
    for f in all_findings:
        method_counts[f.method] = method_counts.get(f.method, 0) + 1
    for method, count in sorted(method_counts.items()):
        pp.info_spaces('%s: %d' % (method, count))

    # ── Output ────────────────────────────────────────────────────────────
    domain_str = domain_list[0] if len(domain_list) == 1 else 'multi'

    if options.output:
        write_csv(all_findings, options.output)
    elif all_findings:
        # Default: print CSV to stdout if no output file specified
        write_csv(all_findings, '%s_dns.csv' % domain_str.replace('.', '_'))

    if options.json_output:
        write_json_output(all_findings, all_records, domain_str, options.json_output)

    if options.html_report:
        write_html(all_findings, all_records, domain_str, ctime, etime, options.html_report)


if __name__ == '__main__':
    main()
