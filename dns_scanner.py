#!/bin/env python3

''' takes a domain as input and returns a CSV file with the following columns:
    1. Subdomain
    2. IP address
    3. ASN CIDR
    4. ASN Description
    
    STILL HEAVILY UNFINISHED WIP!!!
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
    #turn the IP into a domain
    valid_inception_domains=[]
    for inception_ip in inception_ips:
        try:
            inception_domain=socket.gethostbyaddr(str(inception_ip))[0]

            if domain in inception_domain:
                valid_inception_domains.append(inception_domain)
            for alias in aliases:
                if alias in inception_domain:
                    valid_inception_domains.append(inception_domain)
        except:
            pass


    return set(valid_inception_domains)



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


    group = OptionGroup(parser, "Advanced checks",
                    "Extra options for advanced users")

    group.add_option( "--ipwhois", action="store_true", dest="ipwhois", 
                    help="Perform an IP whois lookup")
    group.add_option("--timeout", dest="timeout", type="float",
                      help="Timeout in seconds")
    group.add_option("--maxthread", dest="max", type="int",
                      help="Maximum thread count")


    group1 = OptionGroup(parser, "Using inception & aliases",
                    "Inception is useful to check if the identified CIDR of an identified subdomain contains any further subdomains of interest."
                    " When doing an inception search it's possible to identify other TLDs used by the same company as some companies"
                    " use aliases for their domains. This will allow you to use the alias instead of their defined domain "
                    " to identify more valid subdomains."
                    " Aliases are incomaptible with --domain-list."
                    " The main differnce between using a domain or using an alias is that aliases are only used inside inception checks."
                    " This is very much an edge case, but it can be useful."
                    " e.g. -d google.com --inception --aliases=1e100.net,google")
    
    group1.add_option("--inception", dest="inception", action="store_true", 
                    help="Recursive subdomain enumeration based on identified CIDRs")
    group1.add_option("--aliases", dest="aliases", help="Comma separated list of aliases to use as well as the full domain", metavar="ALIASES")
    group1.add_option("--nameserver", dest="nameserver", help="IP address of a nameserver (otherwise 8.8.8.8 will be used)", metavar="NAMESERVER")


    parser.add_option_group(group)
    parser.add_option_group(group1)

    (options, args) = parser.parse_args()

    
    if options.output:
        if options.output == '-':
            logfile = sys.stderr
            fieldnames = ['DOMAIN', 'IP', 'ASN_CIDR', 'ASN_DESCRIPTION']
            logfile.writer = csv.DictWriter(logfile, delimiter=',',
                                    quotechar='"', quoting=csv.QUOTE_ALL,fieldnames=fieldnames)
        else:     
            ''' write the results to a CSV'''
            logfile = open(options.output, 'w')
            fieldnames = ['DOMAIN', 'IP', 'ASN_CIDR', 'ASN_DESCRIPTION']
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
        pp.error("Bad domain (%s)"%target)
        exit(1)  
    
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
    if options.nameserver:
        dns_resolver.nameservers = [options.nameserver]
    else:
        dns_resolver.nameservers = ['8.8.8.8']
    nthreads=threading.activeCount() # get initial number of running threads
    socket.setdefaulttimeout(timeout) # set timeout

    pp.status("Starting scan...")

    inception_list=[]


    if wordlist_file:
        wordlist=[line.rstrip() for line in open(wordlist_file)]
    else:
        wordlist=["test", "www"]

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
                    if ipmagic.get_asn_cidr(ip) != '':
                        inception_list.append(ipmagic.get_asn_cidr(ip))


    
    if ipwhois:
        print("\n")
        pp.status("Performing IP whois lookup on idendified IP ranges")
        for ip in set(inception_list):
           pp.info("CIDR: %s - Owner: %s"%(ip, ipmagic.get_asn_info(ip.rsplit('/', 1)[0])))
    
                        

        if inception:
            print("\n")
            pp.status("Inception checks for %s"%domain)
            with concurrent.futures.ThreadPoolExecutor(max_workers=tmax) as executor:
                results = [executor.submit(check_cidr, inception_cidr, domain, aliases) for inception_cidr in set(inception_list)]
                for f in concurrent.futures.as_completed(results):
                    full_domain_list = f.result()
                    for domain_name in full_domain_list:
                        pp.info("Subdomain: %s (%s)"%(domain_name,socket.gethostbyname(domain_name)))
                    

   

                

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
    if logfile:
        pp.log_status("Scan completed in: %s"%str(total)[:str(total).index(".")], logfile)    
        

        # '''Write the results to a CSV'''
        # if options.output:
        #         logfile.writer.writerow({'IP': ip, 'ASN': asn, 'ASN_CIDR': asn_cidr, 'ASN_DESCRIPTION': asn_description, 'NETS_CIDR': nets_cidr, 'NETS_NAME': nets_name, 'NETS_DESCRIPTION': nets_description})


    #Done, close the file
    if options.output:
        logfile.close()





if __name__=="__main__":
    main()
