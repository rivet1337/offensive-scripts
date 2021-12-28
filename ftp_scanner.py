#!/usr/bin/env python3

""" Anonymous FTP Login Scanner  """        


import ftplib
import time
import datetime
import socket
import random
import threading
import ipaddress
import signal
from typing import DefaultDict
import prettyprint as pp
from optparse import OptionParser, OptionGroup
import concurrent.futures
import ipmagic


def signal_handler(signal, frame):
		pp.error('System Interupt requested, attempting to exit cleanly!')
		exit(1)

signal.signal(signal.SIGINT, signal_handler)



def FTPBruteForce(host,userlist, passwordlist):
    """ Bruteforce FTP login """

    err = []
    out = []
    verb = []
    warn = []
    description = ["ASN Info: " + ipmagic.get_asn_info(host), "ASN CIDR: " + ipmagic.get_asn_cidr(host)]

    verb.append("Performing FTP bruteforce login on %s"%host)

    if not userlist:
        userlist=["test", "anonymous"]
    if not passwordlist:
        passwordlist=["anonymous@","test"]

    #check that port 21 on host is open
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, 21))
        banner = s.recv(1024).strip().decode('utf-8').lower()
        s.close()
        if "220" not in banner:
            err.append("Bad response from %s, aborting!"%host)
            return (err, out, verb, warn, description)
    except Exception as e:
        err.append("FTP is not available on %s (%s)"%(host,e))
        return (err, out, verb, warn, description)

    

    for username in userlist:
        for password in passwordlist:
            try:
                ftp=ftplib.FTP(host)
                ftp.login(user=username, passwd=password)
                out.append("FTP login successful on %s (%s:%s) [%s]"%(host, username, password, ftp.getwelcome()))

                if dirlist:
                    for line in ftp.nlst():
                        verb.append("Found directory [ %s ] on %s"%(line, host))
                    
                ftp.quit()
                return (err,out,verb,warn, description)

            except Exception as e:
                warn.append("FTP login failed on %s (%s:%s) [%s]"%(host, username, password, e))
                ftp.quit()
    return (err,out,verb,warn, description)



    

def randomHost():
    """ Generates a random IP address """
    host=str(random.randint(1,254))
    host+="."+str(random.randint(0,255))
    host+="."+str(random.randint(0,255))
    host+="."+str(random.randint(0,254))
    return host


def main():
    ctime=datetime.datetime.now() # returns "yy-mm-dd hh:mm:ss.xx"
 
    parser=OptionParser(version="4.0") # Parser for command line arguments
    parser.add_option("-n", dest="nhost", type="int",\
                      help="Number of hosts", metavar="nHost")
    parser.add_option("-o", "--output", dest="oFile", type="string",\
                      help="File to save logs", metavar="FILE")
    parser.add_option("-v", "--verbose", dest="verbose", default=False,\
                      action="store_true",\
                      help="Logs everything")
    parser.add_option("-t", "--timeout", dest="timeout", type="float",\
                      help="Timeout in seconds")
    parser.add_option("-m", "--maxthread", dest="max", type="int",\
                      help="Maximum thread number")
    parser.add_option("-r", "--remote", dest="target", type="string",\
                        help="Targeted host to scan")
    parser.add_option("-U", "--userlist", dest="userlist", type="string",\
                        help="List of users to check")
    parser.add_option("-P", "--passlist", dest="passlist", type="string",\
                        help="List of passwords to check")


    group = OptionGroup(parser, "Post-authentication checks",
                    "Checks that take place after a successful authentication.")
    group.add_option("-d", "--dir-list", action="store_true", dest="dirlist", help="List directories")
    parser.add_option_group(group)

    (options, args)= parser.parse_args()
    """ parse options"""
    if options.nhost:
        nhost=options.nhost
    else:   
        nhost=10
    if options.oFile: 
        global logfile
        logfile = options.oFile
        pp.log_status("Scan started at: %s"%ctime, logfile)
   
    else:
        logfile=None
    if options.verbose:
        verbose=True
    else:
        verbose=False
    if options.timeout:
        timeout=options.timeout
    else:
        timeout=5
    if options.max:
        tmax=options.max
    else:
        tmax=10
    
    if options.userlist:
        userlist=[line.rstrip() for line in open(options.userlist)]
    else:
        userlist=None

    if options.passlist:
        passwordlist=[line.rstrip() for line in open(options.passlist)]
    else:
        passwordlist=None

    if options.dirlist:
        global dirlist
        dirlist=True
    else:
        dirlist=False
    
    try:
        ip_list=[]
        if options.target:
            target=options.target
            
            ip_list=list(ipaddress.ip_network(target, False).hosts())
            nhost=len(ip_list)
        else:
            for _ in range(nhost):
                ip_list.append(ipaddress.ip_address(randomHost()))


    except Exception as e:
        pp.error("Bad IP address (%s)"%target)
        if logfile:
            pp.log_error("Bad IP address (%s)"%target, logfile)
        exit(1)

    nthreads=threading.activeCount() # get initial number of running threads
    socket.setdefaulttimeout(timeout) # set timeout

    pp.status("Starting scan...")
    if logfile:
        pp.log_status("Starting scan...", logfile)

    
    with concurrent.futures.ThreadPoolExecutor(max_workers=tmax) as executor:
        results = [executor.submit(FTPBruteForce, str(ip),userlist, passwordlist) for ip in ip_list]
        for f in concurrent.futures.as_completed(results):
            err,out,verb,warn, description = f.result()

            
            for v in verb:
                if verbose:
                    pp.info(v)
                if logfile:
                    pp.log_info(v, logfile)            
            
            for d in description:
                if verbose:
                    pp.info(d)
                if logfile:
                    pp.log_info(d, logfile)

            for o in out:
                pp.status(o)
                if logfile:
                    pp.log_status(o, logfile)
            

            for e in err:
                if verbose:
                    pp.error(e)
                if logfile:
                    pp.log_error(e, logfile)
                
            for w in warn:
                if verbose:
                    pp.warning(w)
                if logfile:
                    pp.log_warning(w, logfile)


                

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




if __name__=="__main__":
    main()

   
   

