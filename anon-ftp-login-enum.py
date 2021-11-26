#!/usr/bin/env python3

""" Anonymous FTP Login Scanner v0.1     """        


import ftplib
import time
import datetime
import socket
import random
import threading
from optparse import OptionParser


def FTPAnonLogin(host, logfile, verbose):
    """ Anonymous FTP login """

    if verbose:
        print("[+] Testing %s"%host)
    if logfile:
        logfile.write("[+] Testing %s\n"%host)

    try:
        ftp=ftplib.FTP(host)
    except Exception as e:
        if e.errno==60:
            if verbose:
                print("[-] ERROR: Connection timed out for %s"%host)
            if logfile:
                logfile.write("[-] %s Connection timed out for %s\n"%host)
        else:
            if verbose:
                print("[-] ERROR: Bad IP address (%s)"%host)
            if logfile:
                logfile.write("[-] ERROR: Bad IP address (%s)\n"%host)
        return
    
    try:  
        ftp.login()
        print("[+] Anonymous FTP login successful on %s"%host)
        if logfile:
            logfile.write("[+] Anonymous FTP login successful on %s\n"%host)
        ftp.quit()
    except:
        if verbose:
            print("[-] Anonymous FTP login failed on %s"%host)
        if logfile:
            logfile.write("[-] Anonymous FTP login failed on %s\n"%host)
    
    

def randomHost():
    """ Generates a random IP address """
    host=str(random.randint(1,254))
    host+="."+str(random.randint(0,255))
    host+="."+str(random.randint(0,255))
    host+="."+str(random.randint(0,254))
    return host


def main():
    
    parser=OptionParser() # Parser for command line arguments
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

    (options, args)= parser.parse_args()
    """ parse options"""
    if options.nhost:
        nhost=options.nhost
    else:   
        nhost=10
    if options.oFile: 
        global logfile
        logfile=open(options.oFile, "w")
        ctime=str(datetime.datetime.now()) # returns "yy-mm-dd hh:mm:ss.xx
        ctime=ctime[:ctime.index(".")]
        logfile.write("\nScan time: %s\n"%ctime)
   
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
    if options.target:
        target=options.target
        nhost=1
    else:
        target=None



    nthreads=threading.activeCount() # get initial number of running threads
    socket.setdefaulttimeout(options.timeout) # set timeout

    print("[+] Starting scan...")
    if logfile:
        logfile.write("[+] Starting scan...\n")


    for i in range(nhost):
        if target:
            host=target
        else:   
            host=randomHost()
        
        try:
            while threading.activeCount()>tmax: # wait for threads to finish
                time.sleep(10)
            t=threading.Thread(target=FTPAnonLogin, args=(host, logfile, verbose)) # create thread
            t.start()
     
        except Exception as e:
            if verbose:
                print("[-] Error: %s"%e) 
            if logfile:
                logfile.write("[-] Error: %s\n"%e)
    while threading.activeCount()>1:
        time.sleep(10)
    print("[+] Scan completed")
    if logfile:
        logfile.write("[+] Scan completed\n")
    if logfile:
        logfile.close()
    while threading.activeCount()>nthreads: 
        time.sleep(10)                      # wait for all threads to finish



if __name__=="__main__":
    main()
