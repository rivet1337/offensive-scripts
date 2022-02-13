#!/bin/env python3

''' takes a domain as input and returns a CSV file with the following columns:
    1. Subdomain
    2. IP address
    3. ASN CIDR
    4. ASN Description

    TODO: Add curl "https://urlscan.io/api/v1/search/?q=domain:<domain.com>"
    TODO: Add --AXFR check
    TODO: Add --MX check
    TODO: Add --SRV check
    TODO: Check for --SPF record IPs
    TODO: Add --crt-sh check (https://github.com/YashGoti/crtsh/blob/master/crtsh.py)
    TODO: Check for other --TLDs that match the domain and/or aliases
    TODO: Export to --sqlite3
    TODO: Export to --json

'''

from optparse import OptionParser, OptionGroup
import prettyprint as pp
import ipaddress
import signal
import ipmagic
import time
import datetime
import socket
import threading
import ipaddress
import concurrent.futures
import sys
import csv
import dns.resolver


def signal_handler(signal, frame):
		pp.error('System Interupt requested, attempting to exit cleanly!')
		exit(1)

signal.signal(signal.SIGINT, signal_handler)

def check_domain_exists(domain):
    ips=[]
    try:
        #ip = socket.gethostbyname(domain)
        for ip in dns_resolver.resolve(domain,"A"):
            if ip:
                ips.append(str(ip))
        
        return (domain,ips)

    except Exception as e:
        return (domain,None)


def check_cidr(inception_cidr, domain, aliases):

    if verbose:
        pp.info("Checking CIDR: %s"%inception_cidr)
    
    inception_ips=ipaddress.ip_network(inception_cidr).hosts()
    valid_inception_domains={}
    for inception_ip in inception_ips:
       
        try:
            inception_domain=socket.gethostbyaddr(str(inception_ip))[0]
            if verbose:
                pp.info("%s resolves to %s"%(inception_ip, inception_domain))

            # Does the IP resolve to a hostname that matches -d flag? Add it to the list!
            if domain.lower() in inception_domain.lower():
                #print("[domain] Adding %s"%inception_domain)
                valid_inception_domains[inception_domain]=inception_ip
            
            for alias in aliases:
                # Does the IP resolve to a hostname that matches any of the --aliases flags? Add it to the list!
                if alias.lower() in inception_domain.lower():
                    #print("[Alias] Adding %s"%inception_domain)
                    valid_inception_domains[inception_domain]=inception_ip
                
                # # Does the IP ASN description matches any of the --aliases flags? Add it to the list!
                if ipmagic.get_asn_info(inception_ip) != None:
                    if alias.lower() in ipmagic.get_asn_info(inception_ip).lower():
                        #print("[ASN] Adding %s"%inception_domain)
                        valid_inception_domains[inception_domain]=inception_ip

                # Does the IP NETS description matches any of the --aliases flags? Add it to the list!
                if alias.lower() in ipmagic.get_nets_info(inception_ip).lower():
                   #print("[NETS] Adding %s"%inception_domain)
                   valid_inception_domains[inception_domain]=inception_ip
        
        except:
            pass
        

    #return set(valid_inception_domains)
    return valid_inception_domains



def is_ip_address(address):
    try:
        ip = ipaddress.ip_address(address)
        return True
    except ValueError:
        return False     

def main():
    ''' main function '''
    ctime=datetime.datetime.now() # returns "yy-mm-dd hh:mm:ss.xx"

    parser = OptionParser(version="%prog 1.0",usage="%prog [options]")
    parser.add_option("-l", "--domain-list", dest="domain_list",
                        help="List of domains to lookup", metavar="DOM_LIST")
    parser.add_option("-d", "--domain-host", dest="domain_host",
                        help="Single domain to lookup", metavar="DOM_ADDRESS")
    parser.add_option("-w", "--wordlist", dest="wordlist",
                        help="Wordlist to use for subomain enumeration", metavar="WORDLIST")    
    parser.add_option("-o", "--output", dest="output",
                        help="Output CSV file  (or \"-\" for stderr)", metavar="OUTPUT")
    parser.add_option("-v", "--verbose", dest="verbose", default=False,\
                      action="store_true", help="Verbose output")


    group = OptionGroup(parser, "Advanced options")

    group.add_option( "--ipwhois", action="store_true", dest="ipwhois", 
                    help="Perform an IP whois lookup")
    group.add_option("--timeout", dest="timeout", type="float",
                      help="Socket timeout in seconds")
    group.add_option("--maxthread", dest="max", type="int",
                      help="Maximum thread count")
    group.add_option("--nameserver", dest="nameserver", help="IP address of a nameserver (default: 8.8.8.8)", metavar="NAMESERVER")


    group1 = OptionGroup(parser, "Using inception & aliases",
                    "Inception is simply a recursive reverse DNS lookup of the subnets (CIDRs) from the domains identified via the wordlist."
                    " Some companies use aliases when creating domain names. For example Google uses google.com but also googledomains.com, "
                    "google-access.net, .google (TLD), 1e100.net, etc."
                    " Using --aliases allows you to widen the reverse DNS lookup via --inception. Otherwise strictly only the domain name is used for reverse lookup."
                    " Aliases are incomaptible with --domain-list."
                    " Aliases require and assume --ipwhois and --inception."
                    " e.g. -d google.com --inception --aliases=1e100.net,google")
    
    group1.add_option("--inception", dest="inception", action="store_true", 
                    help="Recursive subdomain enumeration using identified CIDRs")
    group1.add_option("--aliases", dest="aliases", help="Comma separated list of aliases to use", metavar="ALIASES")
    group1.add_option("--asn2ip", dest="asn2ips", action="store_true", 
                    help="From the existing IPs identify the ASN, and then any further IP subnets associated with that ASN")


    parser.add_option_group(group)
    parser.add_option_group(group1)

    (options, args) = parser.parse_args()

    
    if options.output:
        if options.output == '-':
            logfile = sys.stderr
            fieldnames = ['FQDN', 'IP', 'ASN_CIDR', 'ASN_DESCRIPTION', 'METHOD']
            logfile.writer = csv.DictWriter(logfile, delimiter=',',
                                    quotechar='"', quoting=csv.QUOTE_ALL,fieldnames=fieldnames)
        else:     
            ''' write the results to a CSV'''
            logfile = open(options.output, 'w')
            fieldnames = ['FQDN', 'IP', 'ASN_CIDR', 'ASN_DESCRIPTION', 'METHOD']
            logfile.writer = csv.DictWriter(logfile, delimiter=',',
                                    quotechar='"', quoting=csv.QUOTE_ALL,fieldnames=fieldnames)
            logfile.writer.writeheader()
    else:
        logfile = None

    if options.wordlist:
        wordlist_file=options.wordlist
    else:
        wordlist_file=None

    if options.ipwhois:
        ipwhois=True
    else:
        ipwhois=False

    if options.inception:
        inception=True
        ipwhois=True
    else:
        inception=False
    
    if options.asn2ips:
        asn2ips=True
        ipwhois=True
        #inception=True
    else:
        asn2ips=False

    global verbose
    if options.verbose:
        verbose=True
    else:
        verbose=False
    if options.timeout:
        timeout=options.timeout
    else:
        timeout=5
    
    global tmax
    if options.max:
        tmax=options.max
    else:
        tmax=10

    try:
        domain_list=[]
        if options.domain_host:
            target=options.domain_host
            if not is_ip_address(target):
                domain_list.append(target)
            else:
                raise Exception("Target is an IP address")
            
            
        elif options.domain_list:
            domain_list=[line.rstrip() for line in open(options.domain_list)]
        else:
            parser.error("Domain not specified")
    
    except Exception as e:
        parser.error("%s (%s)"%(e, target))

    
    if options.aliases and options.domain_list:
        parser.error("--aliases is not compatible with --domain-list")
    elif options.aliases:
        inception=True
        ipwhois=True
        aliases=options.aliases.split(',')
    else:
        aliases=[]

    global dns_resolver
    dns_resolver = dns.resolver.Resolver(configure=False)
    dns_resolver.timeout = timeout
    try:
        if options.nameserver:
                if is_ip_address(options.nameserver):
                    dns_resolver.nameservers = [options.nameserver]
                else:
                    raise Exception("Nameserver is not an IP address")          
        else:
            dns_resolver.nameservers = ['8.8.8.8']
    except Exception as e:
        parser.error("%s (%s)"%(e, options.nameserver))

    nthreads=threading.activeCount() # get initial number of running threads
    socket.setdefaulttimeout(timeout) # set timeout

    pp.status("Starting scan...")

    inception_list=set()
    asn2ip_list=set()
    asn_number_set=set()


    if wordlist_file:
        wordlist=[line.rstrip() for line in open(wordlist_file)]
    else:
        wordlist=["ns", "ns1", "ns2", "ns3", "ns4", "dns", "www", "www2", "time", "whois", "mail", 
        "host", "dev", "test", "web", "webmail", "backup", "direct", "ftp", "secure", "imap", "pop", "smtp", "proxy", "local"]
        # wordlist=["webmail"]

    for domain in domain_list:
        pp.status("Scanning %s"%domain)
        with concurrent.futures.ThreadPoolExecutor(max_workers=tmax) as executor:
            results = [executor.submit(check_domain_exists, (sub_domain + "." + domain)) for sub_domain in wordlist]
            for f in concurrent.futures.as_completed(results):
                full_domain, ips = f.result()
                if ips == None:
                    if verbose:
                        pp.warning("Subdomain: %s (No IP address)"%full_domain)
                    continue
                
                pp.info("Subdomain: %s (%s)"%(full_domain, ", ".join(ips)))

                
                for ip in ips:
                    ip_cidr = ipmagic.get_asn_cidr(ip)
                    if ip_cidr != '':
                        inception_list.add(ip_cidr)        
                        if logfile:
                            logfile.writer.writerow({'FQDN':full_domain, 'IP':ip, 'ASN_CIDR':ip_cidr, 'ASN_DESCRIPTION':ipmagic.get_asn_info(ip.rsplit('/', 1)[0]), 'METHOD':'wordlist'})



    
    if ipwhois:
        print("\n")
        pp.status("Performing IP whois lookup on idendified IP ranges")
        for ip in set(inception_list):          
            asn_info=ipmagic.get_asn_info(ip.rsplit('/', 1)[0])
            asn_nets=ipmagic.get_nets_info(ip.rsplit('/', 1)[0])
            asn_number=ipmagic.get_asn_number(ip.rsplit('/', 1)[0])
            asn_number_set.add(asn_number)
            pp.info("CIDR: %s - Owner: %s - NETS: %s - ASN: %s"%(ip, asn_info, asn_nets, asn_number))
            if logfile:
                logfile.writer.writerow({'FQDN':'N/A', 'IP':'N/A', 'ASN_CIDR':ip, 'ASN_DESCRIPTION':asn_info, 'METHOD':'ipwhois'})


    if asn2ips:
        print("\n")
        pp.status("ASN Inception checks for %s"%domain)

        for asn in asn_number_set:
            for asnN in asn.split(" "):
                    asnSubnets = ipmagic.asn2IP(asnN)
                    pp.info("AS%s has %d subnets"%(asnN, len(asnSubnets)))
                    for i in asnSubnets:
                        if verbose:
                            pp.info_spaces("%s: %s (%s)"%(asnN, i, asnSubnets[i]))
                        asn2ip_list.add(i)  
                        if logfile:
                            logfile.writer.writerow({'FQDN':'N/A', 'IP':'N/A', 'ASN_CIDR':i, 'ASN_DESCRIPTION':asnSubnets[i], 'METHOD':'asn2ip'})    

              
        


    if inception:
        inception_list.update(asn2ip_list) #merge inception (created during the original run) and asn2ip (created during asn2ips) lists
        print("\n")
        pp.status("Inception checks for %s"%domain)
        with concurrent.futures.ThreadPoolExecutor(max_workers=tmax) as executor:
            results = [executor.submit(check_cidr, inception_cidr, domain, aliases) for inception_cidr in set(inception_list)]
            for f in concurrent.futures.as_completed(results):
                full_domain_dict = f.result()

                for domain_name in full_domain_dict:
                    try:
                        pp.info("Subdomain: %s (%s)"%(domain_name,full_domain_dict[domain_name]))
                        if logfile:
                            logfile.writer.writerow({'FQDN':domain_name, 'IP':full_domain_dict[domain_name], 'ASN_CIDR':'N/A', 'ASN_DESCRIPTION':'N/A', 'METHOD':'inception'})
                    except Exception as e:
                        if verbose:
                            pp.warning("Subdomain: %s (%s)"%(domain_name,e))
                        continue

   

                

    etime=datetime.datetime.now() # returns "yy-mm-dd hh:mm:ss.xx
    total =  etime - ctime

    tcount=0
    while threading.activeCount()>nthreads:
        if tcount == 0:
            pp.info("Waiting for threads to finish...")
            tcount=1
        else:
            pp.info_spaces("Still %s/%d threads running..."%((threading.activeCount()-1),tmax))
            time.sleep(1)                      # wait for all threads to finish

    pp.status("Scan completed in: %s"%str(total)[:str(total).index(".")])

        

    #Done, close the file
    if options.output:
        logfile.close()





if __name__=="__main__":
    main()