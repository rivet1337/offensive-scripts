#!/usr/bin/env python3

""" Port Scanner v0.1     """        


import ftplib
import time
import datetime
import socket
import random
import threading
import ipaddress
import re
from optparse import OptionParser
import ftp_scanner


def portscan(host, logfile, verbose, ports):
    """ Scan specified ports """
    for port in ports:
        try:
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            s.close()
            print("[+] %s:%s OPEN"%(host, port))
            if logfile:
                logfile.write("[+] %s:%s OPEN\n"%(host, port))
            
            if port == 21:
                ftp_scanner.FTPAnonLogin(host,logfile, verbose)
                
        except Exception as e:
            if verbose:
                print("[-] %s:%s CLOSED"%(host, port))
            if logfile:
                logfile.write("[-] %s:%s CLOSED\n"%(host, port))


def main():
    ctime=datetime.datetime.now() # returns "yy-mm-dd hh:mm:ss.xx"
 
    parser=OptionParser() # Parser for command line arguments
    parser.add_option("-p", dest="ports", type="string",\
                      help="Ports to scan (e.g. \"-p20,21,80,443 or -p20-25\")")
    parser.add_option("-o", "--output", dest="oFile", type="string",\
                      help="File to save logs", metavar="FILE")
    parser.add_option("-v", "--verbose", dest="verbose", default=False,\
                      action="store_true",\
                      help="Verbose output")
    parser.add_option("--timeout", dest="timeout", type="float",\
                      help="Timeout in seconds")
    parser.add_option("-m", "--maxthread", dest="max", type="int",\
                      help="Maximum thread number")
    parser.add_option("-r", "--remote", dest="target", type="string",\
                        help="Targeted host to scan")

    (options, args)= parser.parse_args()
    """ parse options"""
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
            print("[-] ERROR: No target specified")
            exit(1)

        try:
            while threading.activeCount()>tmax: # wait for threads to finish
                time.sleep(10)
            t=threading.Thread(target=portscan, args=(host, logfile, verbose, ports)) # create thread
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

   
   

