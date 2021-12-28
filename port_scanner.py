#!/usr/bin/env python3

""" Port Scanner v4     """        


import time
import datetime
import socket
import random
import threading
import ipaddress
import re
from optparse import OptionParser
import ftp_scanner
import ssh_scanner
import prettyprint as pp
import concurrent.futures


def portscan(host, ports):
    """ Scan specified ports """

    err = []
    out = []
    verb = []
    warn = []

    verb.append("Starting portscan on %s"%host)

    for port in ports:
        try:
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            banner = s.recv(1024).strip().decode('utf-8')[0:100]
            s.close()
            out.append("%s:%s OPEN"%(host, port))
            verb.append("%s:%s Banner: %s"%(host, port, banner))

            if port == 21:
               ftp_results = ftp_scanner.FTPBruteForce(host, None, None)
               ftp_err, ftp_out, ftp_verb, ftp_warn = ftp_results
               if len(ftp_out) > 0:
                   out.append(ftp_out[0])
               
            if port == 22:
               ssh_results = ssh_scanner.SSHBruteForce(host, None, None)
               ssh_err, ssh_out, ssh_verb, ssh_warn = ssh_results
               if len(ssh_out) > 0:
                     out.append(ssh_out[0])
                
        except Exception as e:
            verb.append("%s:%s CLOSED (%s)"%(host, port, e))
            #return (err, out, verb, warn)
    return (err, out, verb, warn)

def randomHost():
    """ Generates a random IP address """
    host=str(random.randint(1,254))
    host+="."+str(random.randint(0,255))
    host+="."+str(random.randint(0,255))
    host+="."+str(random.randint(0,254))
    return host

def main():
    ctime=datetime.datetime.now() # returns "yy-mm-dd hh:mm:ss.xx"
 
    parser=OptionParser(version="%prog 4.0") # Parser for command line arguments
    parser.add_option("-n", dest="nhost", type="int",\
                      help="Number of hosts", metavar="nHost")
    parser.add_option("-p", dest="ports", type="string",\
                      help="Ports to scan (e.g. \"-p20,21,80,443 or -p20-25\")")
    parser.add_option("-o", "--output", dest="oFile", type="string",\
                      help="File to save logs", metavar="FILE")
    parser.add_option("-v", "--verbose", dest="verbose", default=False,\
                      action="store_true",\
                      help="Verbose output")
    parser.add_option("-t", "--timeout", dest="timeout", type="float",\
                      help="Timeout in seconds")
    parser.add_option("-m", "--maxthread", dest="max", type="int",\
                      help="Maximum thread number")
    parser.add_option("-r", "--remote", dest="target", type="string",\
                        help="Targeted host to scan")

    (options, args)= parser.parse_args()
    """ parse options"""

    if options.nhost:
        nhost=options.nhost
    else:   
        nhost=10

    if options.ports:
        try:
            if "," in options.ports:
                ports=[int(port) for port in options.ports.split(",")]
            elif options.ports == "-":
                ports=[int(port) for port in range(1, 65536)]
            elif "-" in options.ports:
                portList=options.ports.split("-")
                ports=[int(port) for port in range(int(portList[0]), int(portList[1])+1)]
            else:
                ports=[int(options.ports)]
        except:
            print("[-] Invalid port range ")
            exit(1)

    else:   
        ports=[21, 22, 23, 25, 80, 110, 139, 443, 445, 3306, 3389, 8080]

    

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
        timeout=20
    if options.max:
        tmax=options.max
    else:
        tmax=10
    
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
        results = [executor.submit(portscan, str(ip), ports) for ip in ip_list]
        
        for f in concurrent.futures.as_completed(results):
            err,out,verb,warn = f.result()
            
            for v in verb:
                if verbose:
                    pp.info(v)
                if logfile:
                    pp.log_info(v, logfile)

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

   
   

