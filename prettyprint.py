#!/usr/bin/env python3

import csv

class bcolors:
	PURPLE = '\033[95m'
	CYAN = '\033[96m'
	DARKCYAN = '\033[36m'
	BLUE = '\033[94m'
	GREEN = '\033[92m'
	YELLOW = '\033[93m'
	RED = '\033[91m'
	BOLD = '\033[1m'
	UNDERL = '\033[4m'
	ENDC = '\033[0m'
	backBlack = '\033[40m'
	backRed = '\033[41m'
	backGreen = '\033[42m'
	backYellow = '\033[43m'
	backBlue = '\033[44m'
	backMagenta = '\033[45m'
	backCyan = '\033[46m'
	backWhite = '\033[47m'

def status(message):
	print(bcolors.GREEN + bcolors.BOLD + "[*] " + bcolors.ENDC + str(message))

def info(message):
	print(bcolors.BLUE + bcolors.BOLD + "[+] " + bcolors.ENDC + str(message))

def info_spaces(message):
	print(bcolors.BLUE + bcolors.BOLD + "  [-] " + bcolors.ENDC + str(message))

def warning(message):
	print(bcolors.YELLOW + bcolors.BOLD + "[!] " + bcolors.ENDC + str(message))

def error(message):
	print(bcolors.RED + bcolors.BOLD + "[!] " + bcolors.ENDC + bcolors.RED + str(message) + bcolors.ENDC)


def csv_write(message, filename):
	with open(filename, 'a') as csvfile:
		writer = csv.writer(csvfile, delimiter=',',
                                quotechar='"', quoting=csv.QUOTE_ALL)
		writer.writerow([message])

def log_status(message, filename):
	with open(filename, 'a') as logfile:
		logfile.write("[*] " + str(message) + "\n")

def log_info(message, filename):
	with open(filename, 'a') as logfile:
		logfile.write("[+] " + str(message) + "\n")

def log_info_spaces(message, filename):
	with open(filename, 'a') as logfile:
		logfile.write("  [-] " + str(message) + "\n")

def log_warning(message, filename):
	with open(filename, 'a') as logfile:
		logfile.write("[!] " + str(message) + "\n")

def log_error(message, filename):
	with open(filename, 'a') as logfile:
		logfile.write("[!] " + str(message) + "\n")



def help():
	print('''	

██████  ██████  ███████ ████████ ████████ ██    ██     ██████  ██████  ██ ███    ██ ████████ 
██   ██ ██   ██ ██         ██       ██     ██  ██      ██   ██ ██   ██ ██ ████   ██    ██    
██████  ██████  █████      ██       ██      ████       ██████  ██████  ██ ██ ██  ██    ██    
██      ██   ██ ██         ██       ██       ██        ██      ██   ██ ██ ██  ██ ██    ██    
██      ██   ██ ███████    ██       ██       ██        ██      ██   ██ ██ ██   ████    ██    

	NOTE: This is not meant to be executed directly.

Example use:

================================================================================
#!/usr/bin/env python3

import prettyprint as pp

var = "test"

pp.info("This is an info message: %s " % var)
pp.info_spaces("This is an info message with spaces")
pp.warning("This is a warning message")
pp.error("This is an error message")
pp.status("This is a status message")
pp.log_info("This is a log info message", "log.txt")
pp.log_info_spaces("This is a log info message with spaces", "log.txt")
================================================================================

Output:
	''')
	var = "test"

	info("This is an info message: %s " % var)
	info_spaces("This is an info message with spaces")
	warning("This is a warning message")
	error("This is an error message")
	status("This is a status message")
	print("\nBye!\n")


if __name__ == "__main__":
	help()
	
