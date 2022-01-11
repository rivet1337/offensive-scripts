#!/usr/bin/env python3

from urllib import parse
import ipwhois
import sys
import csv
from optparse import OptionParser, OptionGroup
import prettyprint as pp
import ipaddress
import signal


''' parse a list of IPs as input and outputs the associated CIDRs based on WHOIS information!'''

def signal_handler(signal, frame):
		pp.error('System Interupt requested, attempting to exit cleanly!')
		exit(1)

signal.signal(signal.SIGINT, signal_handler)

def ip2ASN(ip):
   
    asn, asn_cidr, asn_description, nets_cidr, nets_name, nets_description = '', '', '', '', '', ''
    try:
        whois_info = ipwhois.IPWhois(ip).lookup_whois()

        asn = whois_info['asn']
        asn_cidr = whois_info['asn_cidr']
        asn_description = whois_info['asn_description']
        nets_cidr = whois_info['nets'][0]['cidr']
        nets_name = whois_info['nets'][0]['name']
        nets_description = whois_info['nets'][0]['description'].replace('\n', ' ').replace('\r', ' ')


    except:
        pass

    return asn, asn_cidr, asn_description, nets_cidr, nets_name, nets_description

def get_asn_info(ip):
    asn, asn_cidr, asn_description, nets_cidr, nets_name, nets_description = ip2ASN(ip)
    return asn_description

def get_asn_cidr(ip):
    asn, asn_cidr, asn_description, nets_cidr, nets_name, nets_description = ip2ASN(ip)
    return asn_cidr

def get_nets_cidr(ip):
    asn, asn_cidr, asn_description, nets_cidr, nets_name, nets_description = ip2ASN(ip)
    return nets_cidr

def get_nets_info(ip):
    asn, asn_cidr, asn_description, nets_cidr, nets_name, nets_description = ip2ASN(ip)
    return nets_name

def main():
    ''' main function '''
    parser = OptionParser(version="%prog 1.0",usage="%prog [options]")
    parser.add_option("-l", "--ip-list", dest="ip_list",
                        help="List of IP addresses to lookup", metavar="IP_LIST")
    parser.add_option("-a", "--ip-address", dest="ip_address",
                        help="IP address to lookup (or \"-\" for stdin)", metavar="IP_ADDRESS")  
    parser.add_option("-o", "--output", dest="output",
                        help="Output CSV file (or \"-\" for stderr)", metavar="OUTPUT")

    group = OptionGroup(parser, "Advanced checks",
                    "Only peform one of these checks and then exit. "
                    "This is only meant to be used for parsing to other scripts. "
                    "If you specify more than one, only the last one will be used.")
    group.add_option( "--asn-cidr", action="store_true", dest="asncidr", help="Return ASN CIDR")
    group.add_option( "--net-cidr", action="store_true", dest="netcidr", help="Return NET CIDR")

    parser.add_option_group(group)

    (options, args) = parser.parse_args()

    
    if options.output:
        if options.output == '-':
            logfile = sys.stderr
            fieldnames = ['IP', 'ASN', 'ASN_CIDR', 'ASN_DESCRIPTION', 'NETS_CIDR', 'NETS_NAME', 'NETS_DESCRIPTION']
            logfile.writer = csv.DictWriter(logfile, delimiter=',',
                                    quotechar='"', quoting=csv.QUOTE_ALL,fieldnames=fieldnames)
        else:     
            ''' write the results to a CSV'''
            logfile = open(options.output, 'w')
            fieldnames = ['IP', 'ASN', 'ASN_CIDR', 'ASN_DESCRIPTION', 'NETS_CIDR', 'NETS_NAME', 'NETS_DESCRIPTION']
            logfile.writer = csv.DictWriter(logfile, delimiter=',',
                                    quotechar='"', quoting=csv.QUOTE_ALL,fieldnames=fieldnames)
            logfile.writer.writeheader()
    else:
        logfile = None

    try:
        ip_list=[]
        if options.ip_address:

            if options.ip_address=="-":
                # ip_list = list(str(sys.stdin.readlines().strip()))
                ip_list=[line.rstrip() for line in sys.stdin.readlines()]
            else:
                target=options.ip_address
                ip_list=list(ipaddress.ip_network(target, False).hosts())
            
        elif options.ip_list:
            ip_list=[line.rstrip() for line in open(options.ip_list)]
        else:
            parser.error("IP address not specified")
    
    except Exception as e:
        pp.error("Bad IP address (%s)"%target)
        if logfile:
            pp.log_error("Bad IP address (%s)"%target, logfile)
        exit(1)  


    if options.asncidr:
        for ip in ip_list:
            print(get_asn_cidr(ip))
    elif options.netcidr:
        for ip in ip_list:
            print(get_nets_cidr(ip))
    else:
        for ip in ip_list:
            ''' convert an IP to an ASN CIDR '''
            asn, asn_cidr, asn_description, nets_cidr, nets_name, nets_description = ip2ASN(ip)
            pp.status("IP Address: %s"%ip)
            pp.info_spaces("ASN: %s"%asn)
            pp.info_spaces("ASN CIDR: %s"%asn_cidr)
            pp.info_spaces("ASN Description: %s"%asn_description)
            pp.info_spaces("NETS CIDR: %s"%nets_cidr)
            pp.info_spaces("NETS Name: %s"%nets_name)
            pp.info_spaces("NETS Description: %s"%nets_description)
        
        

        '''Write the results to a CSV'''
        if options.output:
                logfile.writer.writerow({'IP': ip, 'ASN': asn, 'ASN_CIDR': asn_cidr, 'ASN_DESCRIPTION': asn_description, 'NETS_CIDR': nets_cidr, 'NETS_NAME': nets_name, 'NETS_DESCRIPTION': nets_description})


    #Done, close the file
    if options.output:
        logfile.close()


if __name__=="__main__":
    main()

