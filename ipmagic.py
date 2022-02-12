#!/usr/bin/env python3

from urllib import parse
import ipwhois
import sys
import csv
from optparse import OptionParser, OptionGroup
import prettyprint as pp
import ipaddress
import signal



''' - - parse a list of IPs as input and outputs the associated CIDRs based on WHOIS information!'''

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

def asn2IP(asnNum):
    
    results = ipwhois.asn.ASNOrigin(ipwhois.net.Net("1.2.3.4")).lookup(asn=asnNum)

    asnDict = {}
    for i in range(0,len(results['nets'])):
        asnDict[results['nets'][i]['cidr']] = results['nets'][i]['description']
        
    return asnDict



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

def get_asn_number(ip):
    asn, asn_cidr, asn_description, nets_cidr, nets_name, nets_description = ip2ASN(ip)
    return asn

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
    group.add_option( "--asn-number", action="store_true", dest="asnnumber", help="Return the ASN number")
    group.add_option( "--asn2ip", dest="asn2ip", help="Input ASN and return IP subnets associated with it")

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
        
        if options.ip_address:

            if options.ip_address=="-":
                # ip_list = list(str(sys.stdin.readlines().strip()))
                ip_list=[line.rstrip() for line in sys.stdin.readlines()]
            else:
                target=options.ip_address
                ip_list=list(ipaddress.ip_network(target, False).hosts())
            
        elif options.ip_list:
            ip_list=[line.rstrip() for line in open(options.ip_list)]

        elif options.asn2ip:
            asnNum = options.asn2ip
            ip_list=["0.0.0.0"]
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
    elif options.asnnumber:
        for ip in ip_list:
            print(get_asn_number(ip))
    elif options.asn2ip:
        asnSubnets = asn2IP(asnNum)
        pp.status("%s has %d subnets:"%(asnNum, len(asnSubnets)))
        for i in asnSubnets:
            pp.info_spaces("%s: %s"%(i, asnSubnets[i]))
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

            ''' Analyze the ASN as well to identify any further subnets'''
            for asnN in asn.split(" "):
                print("\n")
                asnSubnets = asn2IP(asnN)
                pp.status("%s has %d subnets:"%(asnN, len(asnSubnets)))
                for i in asnSubnets:
                    pp.info_spaces("%s: %s"%(i, asnSubnets[i]))
            
        
        

        '''Write the results to a CSV'''
        if options.output:
                logfile.writer.writerow({'IP': ip, 'ASN': asn, 'ASN_CIDR': asn_cidr, 'ASN_DESCRIPTION': asn_description, 'NETS_CIDR': nets_cidr, 'NETS_NAME': nets_name, 'NETS_DESCRIPTION': nets_description})


    #Done, close the file
    if options.output:
        logfile.close()


if __name__=="__main__":
    main()

