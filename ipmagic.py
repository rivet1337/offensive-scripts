#!/usr/bin/env python3

"""ipmagic — IP → ASN/WHOIS lookup library and CLI.

Library functions (used by dns_scanner, ftp_scanner, port_scanner):
    get_full_info(ip)   → dict with all fields, cached
    get_asn_info(ip)    → ASN description string
    get_asn_cidr(ip)    → ASN CIDR string
    get_asn_number(ip)  → ASN number string
    get_nets_cidr(ip)   → NETS CIDR string
    get_nets_info(ip)   → NETS name string
    asn2IP(asn_number)  → dict of {cidr: description}

CLI: python3 ipmagic.py -a 8.8.8.8
"""

import sys
import csv
import json
import argparse
import ipaddress
import threading
import signal

import ipwhois
import prettyprint as pp

# ─── Signal handler ───────────────────────────────────────────────────────────

def _signal_handler(sig, frame):
    pp.error('Interrupt received, exiting.')
    sys.exit(1)

signal.signal(signal.SIGINT, _signal_handler)

# ─── Cache (thread-safe) ──────────────────────────────────────────────────────

_cache: dict = {}
_cache_lock = threading.Lock()

# ─── Core lookup ─────────────────────────────────────────────────────────────

def ip2ASN(ip: str) -> dict:
    """Full WHOIS/RDAP lookup for an IP. Returns a result dict; cached per IP.

    Keys: asn, asn_cidr, asn_description, nets_cidr, nets_name,
          nets_description, country, abuse_email
    Returns an empty dict on any failure.
    """
    ip = str(ip).strip()

    with _cache_lock:
        if ip in _cache:
            return _cache[ip]

    result = {
        'asn': '',
        'asn_cidr': '',
        'asn_description': '',
        'nets_cidr': '',
        'nets_name': '',
        'nets_description': '',
        'country': '',
        'abuse_email': '',
    }

    try:
        obj = ipwhois.IPWhois(ip)
        data = obj.lookup_rdap(depth=1)

        result['asn']             = data.get('asn', '') or ''
        result['asn_cidr']        = data.get('asn_cidr', '') or ''
        result['asn_description'] = data.get('asn_description', '') or ''
        result['country']         = data.get('asn_country_code', '') or ''

        nets = data.get('network', {})
        if nets:
            result['nets_cidr']        = nets.get('cidr', '') or ''
            result['nets_name']        = nets.get('name', '') or ''
            result['nets_description'] = (nets.get('remarks', '') or '').replace('\n', ' ')

        # Abuse contact from entities
        for entity in data.get('entities', []):
            roles = entity.get('roles', [])
            if 'abuse' in roles:
                vcard = entity.get('contact', {})
                emails = vcard.get('email', [])
                if emails:
                    result['abuse_email'] = emails[0].get('value', '')
                    break

    except Exception:
        pass  # Return empty result dict — callers handle missing data

    with _cache_lock:
        _cache[ip] = result

    return result


def asn2IP(asn_number: str) -> dict:
    """Resolve an ASN number → dict of {cidr: description} for all announced prefixes."""
    results = {}
    try:
        # Use a well-known routable IP as the seed for ASNOrigin (not a dummy)
        net = ipwhois.net.Net('8.8.8.8')
        origin = ipwhois.asn.ASNOrigin(net)
        data = origin.lookup(asn='AS%s' % str(asn_number).lstrip('AS'))
        for entry in data.get('nets', []):
            cidr = entry.get('cidr', '')
            desc = entry.get('description', '')
            if cidr:
                results[cidr] = desc
    except Exception:
        pass
    return results

# ─── Convenience wrappers ─────────────────────────────────────────────────────

def get_full_info(ip: str) -> dict:
    """Return all cached WHOIS fields for an IP in one call."""
    return ip2ASN(ip)


def get_asn_info(ip: str) -> str:
    return ip2ASN(ip).get('asn_description', '')


def get_asn_cidr(ip: str) -> str:
    return ip2ASN(ip).get('asn_cidr', '')


def get_nets_cidr(ip: str) -> str:
    return ip2ASN(ip).get('nets_cidr', '')


def get_nets_info(ip: str) -> str:
    return ip2ASN(ip).get('nets_name', '')


def get_asn_number(ip: str) -> str:
    return ip2ASN(ip).get('asn', '')


def get_country(ip: str) -> str:
    return ip2ASN(ip).get('country', '')


def get_abuse_email(ip: str) -> str:
    return ip2ASN(ip).get('abuse_email', '')

# ─── CLI ──────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='ipmagic.py',
        description='IP → ASN/WHOIS lookup and ASN → IP subnet expansion',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 ipmagic.py -a 8.8.8.8
  python3 ipmagic.py -l ips.txt -o results.csv
  python3 ipmagic.py -a 8.8.8.8 --json
  python3 ipmagic.py --asn2ip 15169
  echo "8.8.8.8" | python3 ipmagic.py -a -
'''
    )
    parser.add_argument('-a', '--ip-address', dest='ip_address', metavar='IP',
        help='IP address to look up, CIDR, or "-" for stdin')
    parser.add_argument('-l', '--ip-list', dest='ip_list', metavar='FILE',
        help='File of IP addresses (one per line)')
    parser.add_argument('-o', '--output', dest='output', metavar='FILE',
        help='Output CSV file (or "-" for stderr)')
    parser.add_argument('--json', dest='json_out', default=False,
        action='store_true', help='Output JSON instead of CSV')
    parser.add_argument('--geo', dest='geo', default=False,
        action='store_true', help='Include country code in output')
    parser.add_argument('--abuse', dest='abuse', default=False,
        action='store_true', help='Include abuse contact email in output')

    adv = parser.add_argument_group('Advanced (single-field output, for piping)')
    adv.add_argument('--asn-cidr',    dest='asncidr',    action='store_true', help='Print ASN CIDR only')
    adv.add_argument('--net-cidr',    dest='netcidr',    action='store_true', help='Print NET CIDR only')
    adv.add_argument('--asn-number',  dest='asnnumber',  action='store_true', help='Print ASN number only')
    adv.add_argument('--asn2ip',      dest='asn2ip',     metavar='ASN',
        help='Expand ASN number to all announced IP prefixes')

    return parser


def main():
    parser = _build_parser()
    options = parser.parse_args()

    # ── Single-field quick-exit modes ────────────────────────────────────────
    if options.asn2ip:
        subnets = asn2IP(options.asn2ip)
        pp.status('AS%s has %d subnets:' % (options.asn2ip, len(subnets)))
        for cidr, desc in sorted(subnets.items()):
            pp.info_spaces('%s  %s' % (cidr, desc))
        return

    # ── Build IP list ─────────────────────────────────────────────────────────
    ip_list = []
    if options.ip_address:
        src = options.ip_address
        if src == '-':
            ip_list = [line.rstrip('\n') for line in sys.stdin if line.strip()]
        else:
            try:
                net = ipaddress.ip_network(src, strict=False)
                if net.num_addresses > 256:
                    pp.warning('Large CIDR (%d addresses) — WHOIS lookups may be slow/rate-limited' %
                               net.num_addresses)
                ip_list = [str(ip) for ip in net.hosts()] if net.num_addresses > 1 else [src]
            except ValueError:
                ip_list = [src]
    elif options.ip_list:
        try:
            with open(options.ip_list, 'r', encoding='utf-8') as f:
                ip_list = [line.rstrip('\n') for line in f if line.strip()]
        except OSError as e:
            pp.error('Cannot open IP list: %s' % e)
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

    # Deduplicate while preserving order
    seen = set()
    unique_ips = []
    for ip in ip_list:
        if ip not in seen:
            seen.add(ip)
            unique_ips.append(ip)

    # ── Single-field pipe modes ───────────────────────────────────────────────
    if options.asncidr:
        for ip in unique_ips:
            print(get_asn_cidr(ip))
        return
    if options.netcidr:
        for ip in unique_ips:
            print(get_nets_cidr(ip))
        return
    if options.asnnumber:
        for ip in unique_ips:
            print(get_asn_number(ip))
        return

    # ── Full lookup ───────────────────────────────────────────────────────────
    fieldnames = ['IP', 'ASN', 'ASN_CIDR', 'ASN_DESCRIPTION',
                  'NETS_CIDR', 'NETS_NAME', 'NETS_DESCRIPTION']
    if options.geo:
        fieldnames.append('COUNTRY')
    if options.abuse:
        fieldnames.append('ABUSE_EMAIL')

    all_results = []
    for idx, ip in enumerate(unique_ips):
        info = ip2ASN(ip)
        pp.status('IP Address: %s' % ip, newline=(idx > 0))
        pp.info_spaces('ASN:         %s' % info['asn'])
        pp.info_spaces('ASN CIDR:    %s' % info['asn_cidr'])
        pp.info_spaces('ASN Desc:    %s' % info['asn_description'])
        pp.info_spaces('NETS CIDR:   %s' % info['nets_cidr'])
        pp.info_spaces('NETS Name:   %s' % info['nets_name'])
        if options.geo:
            pp.info_spaces('Country:     %s' % info['country'])
        if options.abuse:
            pp.info_spaces('Abuse Email: %s' % info['abuse_email'])
        all_results.append(info | {'IP': ip})

        # Also expand ASN to subnets
        if info['asn']:
            for asn_part in info['asn'].split():
                subnets = asn2IP(asn_part)
                if subnets:
                    pp.info('AS%s has %d announced prefix(es)' % (asn_part, len(subnets)))
                    for cidr, desc in sorted(subnets.items()):
                        pp.info_spaces('%s  %s' % (cidr, desc))

    # ── Output ────────────────────────────────────────────────────────────────
    if options.output:
        if options.json_out:
            out_path = options.output if options.output != '-' else None
            out_str = json.dumps(all_results, indent=2)
            if out_path:
                with open(out_path, 'w', encoding='utf-8') as f:
                    f.write(out_str)
                pp.info('JSON written to %s' % out_path)
            else:
                print(out_str)
        else:
            dest = sys.stdout if options.output == '-' else open(options.output, 'w',
                                                                   encoding='utf-8', newline='')
            writer = csv.DictWriter(dest, fieldnames=fieldnames,
                                    quoting=csv.QUOTE_ALL, extrasaction='ignore')
            writer.writeheader()
            for r in all_results:
                row = {
                    'IP': r['IP'],
                    'ASN': r['asn'],
                    'ASN_CIDR': r['asn_cidr'],
                    'ASN_DESCRIPTION': r['asn_description'],
                    'NETS_CIDR': r['nets_cidr'],
                    'NETS_NAME': r['nets_name'],
                    'NETS_DESCRIPTION': r['nets_description'],
                }
                if options.geo:
                    row['COUNTRY'] = r['country']
                if options.abuse:
                    row['ABUSE_EMAIL'] = r['abuse_email']
                writer.writerow(row)
            if options.output != '-':
                dest.close()
                pp.info('CSV written to %s' % options.output)


if __name__ == '__main__':
    main()
