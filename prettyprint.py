#!/usr/bin/env python3

"""prettyprint — Thread-safe ANSI console output and log file library.

Used by all scripts in the offensive-scripts suite.
Not meant to be executed directly — import as: import prettyprint as pp
"""

import re
import csv
import datetime
import threading

# ─── ANSI colour palette ──────────────────────────────────────────────────────

class bcolors:
    PURPLE    = '\033[95m'
    CYAN      = '\033[96m'
    DARKCYAN  = '\033[36m'
    BLUE      = '\033[94m'
    GREEN     = '\033[92m'
    YELLOW    = '\033[93m'
    RED       = '\033[91m'
    GREY      = '\033[90m'
    BOLD      = '\033[1m'
    UNDERL    = '\033[4m'
    ENDC      = '\033[0m'
    backBlack   = '\033[40m'
    backRed     = '\033[41m'
    backGreen   = '\033[42m'
    backYellow  = '\033[43m'
    backBlue    = '\033[44m'
    backMagenta = '\033[45m'
    backCyan    = '\033[46m'
    backWhite   = '\033[47m'

# ─── Internal helpers ─────────────────────────────────────────────────────────

_log_lock = threading.Lock()
_verbose = False   # set to True to enable debug() output


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes so log files are clean plain text."""
    return re.sub(r'\033\[[\d;]*m', '', text)


def _timestamp() -> str:
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def _log(level_tag: str, message: str, filename: str):
    """Thread-safe append to a log file with timestamp and plain text."""
    line = '[%s] %s %s\n' % (_timestamp(), level_tag, _strip_ansi(str(message)))
    with _log_lock:
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(line)

# ─── Console output ───────────────────────────────────────────────────────────

def status(message, newline=False):
    """[*] Green bold prefix — general progress / phase announcements."""
    if newline:
        print()
    print(bcolors.GREEN + bcolors.BOLD + '[*] ' + bcolors.ENDC + str(message))


def info(message, newline=False):
    """[+] Blue bold prefix — positive findings / results."""
    if newline:
        print()
    print(bcolors.BLUE + bcolors.BOLD + '[+] ' + bcolors.ENDC + str(message))


def info_spaces(message, newline=False):
    """  [-] Blue bold prefix, indented — sub-items under an info line."""
    if newline:
        print()
    print(bcolors.BLUE + bcolors.BOLD + '  [-] ' + bcolors.ENDC + str(message))


def warning(message, newline=False):
    """[!] Yellow bold prefix — non-fatal issues, soft findings."""
    if newline:
        print()
    print(bcolors.YELLOW + bcolors.BOLD + '[!] ' + bcolors.ENDC + str(message))


def error(message, newline=False):
    """[!] Red bold prefix — errors and failures."""
    if newline:
        print()
    print(bcolors.RED + bcolors.BOLD + '[!] ' + bcolors.ENDC
          + bcolors.RED + str(message) + bcolors.ENDC)


def critical(message, newline=False):
    """[!!] Bold red prefix + red body — critical findings (compromise, critical CVE)."""
    if newline:
        print()
    print(bcolors.RED + bcolors.BOLD + '[!!] ' + str(message) + bcolors.ENDC)


def debug(message, newline=False):
    """[~] Grey prefix — verbose debug output, suppressed unless _verbose=True."""
    if not _verbose:
        return
    if newline:
        print()
    print(bcolors.GREY + '[~] ' + str(message) + bcolors.ENDC)

# ─── Log file writers (thread-safe) ──────────────────────────────────────────

def log_status(message, filename):
    _log('[*]', message, filename)


def log_info(message, filename):
    _log('[+]', message, filename)


def log_info_spaces(message, filename):
    _log('  [-]', message, filename)


def log_warning(message, filename):
    _log('[!]', message, filename)


def log_error(message, filename):
    _log('[!] ERROR:', message, filename)


def log_critical(message, filename):
    _log('[!!]', message, filename)


def log_debug(message, filename):
    if _verbose:
        _log('[~]', message, filename)

# ─── Self-demo ────────────────────────────────────────────────────────────────

def _demo():
    print('''
██████  ██████  ███████ ████████ ████████ ██    ██     ██████  ██████  ██ ███    ██ ████████
██   ██ ██   ██ ██         ██       ██     ██  ██      ██   ██ ██   ██ ██ ████   ██    ██
██████  ██████  █████      ██       ██      ████       ██████  ██████  ██ ██ ██  ██    ██
██      ██   ██ ██         ██       ██       ██        ██      ██   ██ ██ ██  ██ ██    ██
██      ██   ██ ███████    ██       ██       ██        ██      ██   ██ ██ ██   ████    ██

    NOTE: This is not meant to be executed directly.  Import as: import prettyprint as pp
''')
    status('This is a status message')
    info('This is an info message')
    info_spaces('This is an indented sub-item')
    warning('This is a warning message')
    error('This is an error message')
    critical('This is a CRITICAL finding')
    global _verbose
    _verbose = True
    debug('This is a debug message (only shown when verbose)')
    print()


if __name__ == '__main__':
    _demo()
