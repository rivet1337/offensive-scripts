#!/usr/bin/env python3

""" Anonymous FTP Login Scanner v0.3     """        


import ftplib
import time
import datetime
import socket
import random
import threading
import ipaddress
import re
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
        
        e2=re.sub("\[.*\] ","",str(e))
        if verbose:
            print("[-] ERROR: %s (%s)"%(e2, host))
        if logfile:
            logfile.write("[-] ERROR: %s (%s)\n"%(e2, host))
        return
    
    try:  
        ftp.login()
        print("[+] Anonymous FTP login successful on %s"%host)
        if logfile:
            logfile.write("[+] Anonymous FTP login successful on %s\n"%host)
        
    except:
        if verbose:
            print("[-] Anonymous FTP login failed on %s"%host)
        if logfile:
            logfile.write("[-] Anonymous FTP login failed on %s\n"%host)
        #ftp.quit()    
        return
    
    try:
        
        if verbose or logfile:
            fptdirlist = []
            ftpdirlist = ftp.nlst()
            for dir in ftpdirlist:
                if verbose:
                    print("[+] Found directory [ %s ] on %s"%(dir, host))
                if logfile:
                    logfile.write("[+] %s: Found directory [ %s ] on %s\n"%(dir, host))
        ftp.quit()

        
        
    except:
        if verbose:
            print("[-] Directory listing failed on %s"%host)
        if logfile:
            logfile.write("[-] Directory listing failed on %s\n"%host)
        ftp.quit()
        return
    
    

def randomHost():
    """ Generates a random IP address """
    host=str(random.randint(1,254))
    host+="."+str(random.randint(0,255))
    host+="."+str(random.randint(0,255))
    host+="."+str(random.randint(0,254))
    return host


def main():
    ctime=datetime.datetime.now() # returns "yy-mm-dd hh:mm:ss.xx"
 
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
        ip_list=[]
        try:
            ip_list=list(ipaddress.ip_network(target, False).hosts())
        except Exception as e:
            print("[-] ERROR: Bad IP address (%s)"%target)
            if logfile:
                logfile.write("[-] ERROR: Bad IP address (%s)\n"%target)
            exit(1)
        nhost=len(ip_list)
    else:
        target=None


    nthreads=threading.activeCount() # get initial number of running threads
    socket.setdefaulttimeout(timeout) # set timeout

    print("[+] Starting scan...")
    if logfile:
        logfile.write("[+] Starting scan...\n")



    for i in range(nhost):
        if target:
            host=str(ip_list[i])
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
    
    etime=datetime.datetime.now() # returns "yy-mm-dd hh:mm:ss.xx
    total =  etime - ctime

    print("[+] Scan completed in: %s"%str(total)[:str(total).index(".")])
    if logfile:
        logfile.write("[+] Scan completed in: %s"%str(total)[:str(total).index(".")])
    if logfile:
        logfile.close()
    while threading.activeCount()>nthreads: 
        time.sleep(10)                      # wait for all threads to finish



if __name__=="__main__":
    main()

   
   

