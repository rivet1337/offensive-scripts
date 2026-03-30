#!/usr/bin/env python3

"""Nuclei Web Assessment Pipeline v2.0 - Bug Bounty Automation"""

import os
import sys
import signal
import datetime
import shutil
import subprocess
import json
import csv
import re
import html
import threading
from optparse import OptionParser, OptionGroup
import prettyprint as pp

# === Constants ===
GOBIN = os.path.join(os.environ.get("GOPATH", os.path.expanduser("~/go")), "bin")
NMAP_BIN = shutil.which("nmap") or "/home/linuxbrew/.linuxbrew/bin/nmap"

NUCLEI_CONFIG = os.path.expanduser("~/.config/nuclei/config.yaml")
CENT_CONFIG = os.path.expanduser("~/.config/cent/.cent.yaml")
CENT_TEMPLATES_DIR = os.path.expanduser("~/cent-nuclei-templates")
NOTIFY_CONFIG = os.path.expanduser("~/.config/notify/provider-config.yaml")

STEALTH_HEADERS = [
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language: en-US,en;q=0.5",
]
STEALTH_RATE_LIMIT = 30
STEALTH_CONCURRENCY = 3

TOOL_INSTALL_MAP = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "cent": "github.com/xm1k3/cent/v2@latest",
    "notify": "github.com/projectdiscovery/notify/cmd/notify@latest",
}

REQUIRED_TOOLS = ["subfinder", "httpx", "katana", "nuclei"]

GO_INSTALL_DIR = os.path.expanduser("~/go-sdk")

# System packages needed to compile CGo dependencies (katana, etc.)
BUILD_DEPS_APT = ["gcc", "build-essential", "libpcap-dev"]

# Max templates per nuclei invocation when running community sets.
# Keeps open-socket/fd count manageable and prevents goroutine deadlock.
COMMUNITY_BATCH_SIZE = 2000

# Cap on buffered stderr lines in run_tool() to avoid unbounded memory growth
# during long-running nuclei scans that emit stats every 10 s.
STDERR_LINE_CAP = 500

DEFAULT_NUCLEI_CONFIG = """# Nuclei config - Bug Bounty optimized (auto-generated)
header:
  - "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
scan-strategy: host-spray
rate-limit: 150
bulk-size: 25
concurrency: 25
retries: 2
timeout: 10
max-host-error: 30
follow-redirects: true
interactsh-server: "oast.pro"
interactsh-eviction: 120
stats: true
stats-interval: 10
"""

DEFAULT_CENT_CONFIG = """# Cent v2 community template aggregator config (auto-generated)
# Directories to exclude
exclude-dirs:
  - .git

# Files to exclude
exclude-files:
  - README.md
  - .gitignore
  - .pre-commit-config.yaml
  - LICENSE

# Add github urls (must be full https:// URLs for cent v2)
community-templates:
  - https://github.com/projectdiscovery/nuclei-templates
  - https://github.com/projectdiscovery/fuzzing-templates
  - https://github.com/geeknik/the-nuclei-templates
  - https://github.com/Spix0r/Nuclei-Community-Templates
  - https://github.com/topscoder/nuclei-wordfence-cve
  - https://github.com/edoardottt/missing-cve-nuclei-templates
  - https://github.com/0xAwali/Blind-SSRF
  - https://github.com/daffainfo/my-nuclei-templates
  - https://github.com/h0tak88r/nuclei_templates
  - https://github.com/esetal/nuclei-bb-templates
  - https://github.com/kh4sh3i/nuclei-templates
  - https://github.com/pikpikcu/my-nuclei-templates
  - https://github.com/R-s0n/Custom_Vuln_Scan_Templates
  - https://github.com/praetorian-inc/chariot-launch-nuclei-templates
  - https://github.com/randomstr1ng/nuclei-sap-templates
"""

DEFAULT_NOTIFY_CONFIG = """# Notification provider config (auto-generated)
# Fill in your webhook URLs to enable notifications
discord:
  - id: "bugbounty-alerts"
    discord_channel: "alerts"
    discord_username: "NucleiBot"
    discord_webhook_url: "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN"
    discord_format: "{{data}}"
# telegram:
#   - id: "bugbounty-tg"
#     telegram_api_key: "YOUR_BOT_TOKEN"
#     telegram_chat_id: "YOUR_CHAT_ID"
#     telegram_format: "{{data}}"
"""

# === Globals ===
verbose = False
current_process = None


# === Signal Handler ===
def signal_handler(sig, frame):
    pp.error('System Interrupt requested, attempting to exit cleanly!')
    if current_process and current_process.poll() is None:
        current_process.terminate()
    exit(1)

signal.signal(signal.SIGINT, signal_handler)


# === Tool Management ===
def _detect_go_platform():
    """Return (GOOS, GOARCH) for the current machine."""
    import platform
    machine = platform.machine().lower()
    arch_map = {
        "x86_64": "amd64", "amd64": "amd64",
        "aarch64": "arm64", "arm64": "arm64",
        "armv7l": "armv6l", "armv6l": "armv6l",
    }
    goarch = arch_map.get(machine)
    if not goarch:
        return None, None
    goos = "linux" if sys.platform.startswith("linux") else (
        "darwin" if sys.platform == "darwin" else None)
    return goos, goarch


def _fetch_latest_go_version():
    """Fetch the latest stable Go version string from go.dev."""
    try:
        import urllib.request
        req = urllib.request.Request(
            "https://go.dev/VERSION?m=text",
            headers={"User-Agent": "Mozilla/5.0"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            # Response is multi-line; first line is e.g. "go1.23.1"
            return resp.read().decode().strip().split("\n")[0]
    except Exception as e:
        pp.warning("Could not fetch latest Go version: %s" % e)
        return None


def ensure_go():
    """Check for Go and offer to install it from go.dev if missing. Returns go binary path."""
    go_bin = shutil.which("go")
    if go_bin:
        return go_bin

    # Check our own install location
    local_go = os.path.join(GO_INSTALL_DIR, "bin", "go")
    if os.path.exists(local_go):
        os.environ["PATH"] = os.path.join(GO_INSTALL_DIR, "bin") + os.pathsep + os.environ["PATH"]
        return local_go

    pp.warning("Go is required but not installed.")
    goos, goarch = _detect_go_platform()
    if not goos or not goarch:
        pp.error("Unsupported platform for automatic Go install (%s/%s). Install Go manually." % (sys.platform, goos))
        sys.exit(1)

    version = _fetch_latest_go_version()
    if not version:
        pp.error("Could not determine latest Go version. Install Go manually from https://go.dev/dl/")
        sys.exit(1)

    tarball = "%s.%s-%s.tar.gz" % (version, goos, goarch)
    url = "https://go.dev/dl/%s" % tarball

    pp.status("Installing %s for %s/%s..." % (version, goos, goarch))
    pp.info("Downloading %s" % url)

    import urllib.request
    import tempfile
    import tarfile

    tmp_path = os.path.join(tempfile.gettempdir(), tarball)
    try:
        urllib.request.urlretrieve(url, tmp_path)
    except Exception as e:
        pp.error("Failed to download Go: %s" % e)
        sys.exit(1)

    # Extract to GO_INSTALL_DIR (tarball contains a top-level "go/" directory)
    pp.status("Extracting to %s..." % GO_INSTALL_DIR)
    if os.path.exists(GO_INSTALL_DIR):
        shutil.rmtree(GO_INSTALL_DIR)
    os.makedirs(GO_INSTALL_DIR, exist_ok=True)

    try:
        with tarfile.open(tmp_path, "r:gz") as tf:
            tf.extractall(path=GO_INSTALL_DIR, filter="data")
    except TypeError:
        # Python < 3.12 doesn't support the filter parameter
        with tarfile.open(tmp_path, "r:gz") as tf:
            tf.extractall(path=GO_INSTALL_DIR)

    # The tarball extracts as go/, so the binary is at GO_INSTALL_DIR/go/bin/go
    extracted_bin = os.path.join(GO_INSTALL_DIR, "go", "bin", "go")
    if not os.path.exists(extracted_bin):
        pp.error("Go binary not found after extraction")
        sys.exit(1)

    # Flatten: move contents of go/ up to GO_INSTALL_DIR
    extracted_go_dir = os.path.join(GO_INSTALL_DIR, "go")
    for item in os.listdir(extracted_go_dir):
        src = os.path.join(extracted_go_dir, item)
        dst = os.path.join(GO_INSTALL_DIR, item)
        if os.path.exists(dst):
            if os.path.isdir(dst):
                shutil.rmtree(dst)
            else:
                os.remove(dst)
        shutil.move(src, dst)
    os.rmdir(extracted_go_dir)

    os.remove(tmp_path)

    local_go = os.path.join(GO_INSTALL_DIR, "bin", "go")
    os.environ["PATH"] = os.path.join(GO_INSTALL_DIR, "bin") + os.pathsep + os.environ["PATH"]

    # Verify
    try:
        result = subprocess.run([local_go, "version"], capture_output=True, text=True, timeout=10)
        pp.info("Installed: %s" % result.stdout.strip())
    except Exception as e:
        pp.error("Go installed but verification failed: %s" % e)
        sys.exit(1)

    return local_go


def ensure_build_deps():
    """Install C compiler and libraries required by CGo-dependent tools."""
    if shutil.which("gcc"):
        return

    pp.warning("C compiler (gcc) not found — required to build katana and other CGo tools.")

    # Detect package manager
    apt_bin = shutil.which("apt-get")
    dnf_bin = shutil.which("dnf")
    yum_bin = shutil.which("yum")
    pacman_bin = shutil.which("pacman")

    if apt_bin:
        pp.status("Installing build dependencies via apt (%s)..." % ", ".join(BUILD_DEPS_APT))
        proc = subprocess.run(
            [apt_bin, "install", "-y"] + BUILD_DEPS_APT,
            capture_output=True, text=True, timeout=120,
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
        )
    elif dnf_bin:
        pkgs = ["gcc", "make", "libpcap-devel"]
        pp.status("Installing build dependencies via dnf (%s)..." % ", ".join(pkgs))
        proc = subprocess.run(
            [dnf_bin, "install", "-y"] + pkgs,
            capture_output=True, text=True, timeout=120,
        )
    elif yum_bin:
        pkgs = ["gcc", "make", "libpcap-devel"]
        pp.status("Installing build dependencies via yum (%s)..." % ", ".join(pkgs))
        proc = subprocess.run(
            [yum_bin, "install", "-y"] + pkgs,
            capture_output=True, text=True, timeout=120,
        )
    elif pacman_bin:
        pkgs = ["gcc", "make", "libpcap"]
        pp.status("Installing build dependencies via pacman (%s)..." % ", ".join(pkgs))
        proc = subprocess.run(
            [pacman_bin, "-S", "--noconfirm"] + pkgs,
            capture_output=True, text=True, timeout=120,
        )
    else:
        pp.error("No supported package manager found (apt/dnf/yum/pacman). Install gcc manually.")
        sys.exit(1)

    if proc.returncode != 0:
        pp.error("Failed to install build dependencies:\n%s" % proc.stderr.strip()[-500:])
        sys.exit(1)

    if not shutil.which("gcc"):
        pp.error("gcc still not found after installation. Check your system.")
        sys.exit(1)

    pp.info("Build dependencies installed")


def get_tool_path(name):
    """Resolve tool binary path: check ~/go/bin/ first, then PATH."""
    gobin_path = os.path.join(GOBIN, name)
    if os.path.exists(gobin_path):
        return gobin_path
    system_path = shutil.which(name)
    if system_path:
        return system_path
    return None


def ensure_tool(name):
    """Install a Go tool if not already present."""
    path = get_tool_path(name)
    if path:
        pp.info("Found %s at %s" % (name, path))
        return path

    if name not in TOOL_INSTALL_MAP:
        pp.error("Unknown tool: %s" % name)
        sys.exit(1)

    pp.status("Installing %s..." % name)
    install_url = TOOL_INSTALL_MAP[name]

    go_bin = ensure_go()
    ensure_build_deps()

    stderr_lines = []
    proc = subprocess.Popen(
        [go_bin, "install", "-v", install_url],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    for line in proc.stderr:
        line = line.rstrip('\n')
        if line:
            stderr_lines.append(line)
            display = line if len(line) <= 120 else line[:117] + "..."
            sys.stderr.write("\r\033[K  \033[36m%s\033[0m" % display)
            sys.stderr.flush()
    proc.wait()
    sys.stderr.write("\r\033[K")
    sys.stderr.flush()

    if proc.returncode != 0:
        # Show the last few lines of stderr so the user can diagnose
        pp.error("Failed to install %s (exit code %d)" % (name, proc.returncode))
        for err_line in stderr_lines[-10:]:
            pp.error("  %s" % err_line)
        sys.exit(1)

    path = get_tool_path(name)
    if not path:
        pp.error("Binary not found after installing %s" % name)
        sys.exit(1)

    pp.info("Installed %s at %s" % (name, path))
    return path


def ensure_optional_tool(name):
    """Install an optional tool if not already present. Returns None on failure."""
    path = get_tool_path(name)
    if path:
        pp.info("Found %s at %s" % (name, path))
        return path

    if name not in TOOL_INSTALL_MAP:
        pp.warning("Unknown optional tool: %s" % name)
        return None

    pp.status("Installing optional tool %s..." % name)
    go_bin = ensure_go()
    ensure_build_deps()

    try:
        stderr_lines = []
        proc = subprocess.Popen(
            [go_bin, "install", "-v", TOOL_INSTALL_MAP[name]],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        for line in proc.stderr:
            line = line.rstrip('\n')
            if line:
                stderr_lines.append(line)
                display = line if len(line) <= 120 else line[:117] + "..."
                sys.stderr.write("\r\033[K  \033[36m%s\033[0m" % display)
                sys.stderr.flush()
        proc.wait(timeout=300)
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()
        if proc.returncode != 0:
            pp.warning("Failed to install %s" % name)
            for err_line in stderr_lines[-10:]:
                pp.warning("  %s" % err_line)
            return None
    except subprocess.TimeoutExpired:
        proc.terminate()
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()
        pp.warning("Installation of %s timed out" % name)
        return None

    path = get_tool_path(name)
    if path:
        pp.info("Installed %s at %s" % (name, path))
    return path


def ensure_all_tools():
    """Install all required tools and update nuclei templates."""
    tools = {}
    for name in REQUIRED_TOOLS:
        tools[name] = ensure_tool(name)

    # Update nuclei templates
    pp.status("Updating nuclei templates...")
    try:
        proc = subprocess.Popen(
            [tools["nuclei"], "-update-templates"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        for line in proc.stderr:
            line = line.rstrip('\n')
            if line:
                display = line if len(line) <= 120 else line[:117] + "..."
                sys.stderr.write("\r\033[K  \033[36m%s\033[0m" % display)
                sys.stderr.flush()
        proc.wait(timeout=120)
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()
        pp.info("Nuclei templates updated")
    except subprocess.TimeoutExpired:
        proc.terminate()
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()
        pp.warning("Template update timed out, continuing with existing templates")

    return tools


def _write_config_if_missing(path, content, name):
    """Write a config file if it doesn't exist. Returns True if created."""
    if os.path.exists(path):
        pp.info("%s config already exists at %s" % (name, path))
        return False
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(content)
    pp.info("Created %s config at %s" % (name, path))
    return True


def ensure_configs(options):
    """Create default config files if they don't exist."""
    pp.status("Checking configuration files...", newline=True)

    # Always create nuclei config
    _write_config_if_missing(NUCLEI_CONFIG, DEFAULT_NUCLEI_CONFIG, "nuclei")

    # Create cent config if community templates requested
    if options.community_templates:
        _write_config_if_missing(CENT_CONFIG, DEFAULT_CENT_CONFIG, "cent")

    # Create notify config if notifications requested
    if options.notify:
        created = _write_config_if_missing(NOTIFY_CONFIG, DEFAULT_NOTIFY_CONFIG, "notify")
        if created:
            pp.warning("Notify config created with placeholders -- edit %s with your webhook URLs" % NOTIFY_CONFIG)


# === Tool Runner ===
def run_tool(tool_path, args, output_file=None, timeout=600):
    """Run an external tool via subprocess with live status line output."""
    global current_process
    cmd = [tool_path] + args

    if verbose:
        pp.info_spaces("Running: %s" % " ".join(cmd))

    stdout_lines = []
    stderr_lines = []

    def _read_stream(stream, lines_list):
        """Read a stream line by line and show live status.

        lines_list is capped at STDERR_LINE_CAP to prevent unbounded growth
        during long-running tools (e.g. nuclei emitting stats every 10 s).
        """
        for line in stream:
            line = line.rstrip('\n')
            if line:
                if len(lines_list) >= STDERR_LINE_CAP:
                    lines_list.pop(0)
                lines_list.append(line)
                # Overwrite the current terminal line with latest output
                display = line if len(line) <= 120 else line[:117] + "..."
                sys.stderr.write("\r\033[K  \033[36m%s\033[0m" % display)
                sys.stderr.flush()

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        current_process = proc

        # Read stdout and stderr in parallel threads for live output
        t_out = threading.Thread(target=_read_stream, args=(proc.stdout, stdout_lines))
        t_err = threading.Thread(target=_read_stream, args=(proc.stderr, stderr_lines))
        t_out.daemon = True
        t_err.daemon = True
        t_out.start()
        t_err.start()

        # Wait for process with timeout
        proc.wait(timeout=timeout)
        t_out.join(timeout=5)
        t_err.join(timeout=5)

        current_process = None

        # Clear the live status line
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()

        stdout = "\n".join(stdout_lines)
        stderr = "\n".join(stderr_lines)

        if output_file and stdout:
            with open(output_file, 'w') as f:
                f.write(stdout)

        if verbose and stderr:
            for line in stderr.strip().split('\n')[:10]:
                pp.info_spaces("  %s" % line)

        return proc.returncode, stdout, stderr

    except subprocess.TimeoutExpired:
        current_process = None
        proc.terminate()
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()
        pp.warning("Command timed out after %d seconds" % timeout)
        return -1, "", "timeout"


# === Pipeline Phases ===
def phase_subdomain_enum(domain, results_dir, tools, options):
    """Phase 1: Subdomain enumeration with subfinder."""
    pp.status("Phase 1: Subdomain Enumeration (subfinder)", newline=True)

    output_file = os.path.join(results_dir, "subdomains.txt")

    args = ["-d", domain, "-all", "-o", output_file]
    if options.timeout:
        args.extend(["-timeout", str(min(options.timeout, 30))])

    retcode, stdout, stderr = run_tool(tools["subfinder"], args, timeout=options.timeout)

    if retcode != 0:
        pp.error("subfinder failed: %s" % stderr.strip()[:200])
        sys.exit(1)

    if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
        pp.error("No subdomains found for %s" % domain)
        sys.exit(1)

    with open(output_file, 'r') as f:
        count = sum(1 for line in f if line.strip())

    pp.info("Found %d subdomains" % count)
    return output_file


def phase_httpx(results_dir, tools, options):
    """Phase 2: HTTP probing with httpx."""
    pp.status("Phase 2: HTTP Probing (httpx)", newline=True)

    subdomains_file = os.path.join(results_dir, "subdomains.txt")
    httpx_json = os.path.join(results_dir, "httpx_output.json")
    live_hosts_file = os.path.join(results_dir, "live_hosts.txt")

    threads = STEALTH_CONCURRENCY if options.stealth else options.max

    args = [
        "-l", subdomains_file,
        "-sc", "-td", "-title", "-server",
        "-json", "-o", httpx_json,
        "-ports", options.httpx_ports,
        "-threads", str(threads),
    ]

    if options.proxy:
        args.extend(["-http-proxy", options.proxy])

    retcode, stdout, stderr = run_tool(tools["httpx"], args, timeout=options.timeout)

    if retcode != 0:
        pp.error("httpx failed: %s" % stderr.strip()[:200])
        sys.exit(1)

    # Extract live URLs from JSON output
    live_urls = []
    if os.path.exists(httpx_json):
        with open(httpx_json, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    url = data.get("url", "")
                    if url:
                        live_urls.append(url)
                        status_code = data.get("status_code", "")
                        title = data.get("title", "")
                        tech = ", ".join(data.get("tech", []))
                        server = data.get("webserver", "")
                        info_parts = [str(status_code)]
                        if title:
                            info_parts.append(title)
                        if server:
                            info_parts.append(server)
                        if tech:
                            info_parts.append(tech)
                        pp.info_spaces("%s [%s]" % (url, " | ".join(info_parts)))
                except (json.JSONDecodeError, KeyError):
                    if verbose:
                        pp.warning("Skipping malformed httpx output line")

    if not live_urls:
        pp.error("No live hosts found")
        sys.exit(1)

    with open(live_hosts_file, 'w') as f:
        f.write("\n".join(live_urls) + "\n")

    pp.info("Found %d live hosts" % len(live_urls))
    return live_hosts_file


def phase_crawl(results_dir, tools, options):
    """Phase 3: Web crawling with katana."""
    pp.status("Phase 3: Web Crawling (katana)", newline=True)

    live_hosts_file = os.path.join(results_dir, "live_hosts.txt")
    output_file = os.path.join(results_dir, "katana_urls.txt")

    concurrency = STEALTH_CONCURRENCY if options.stealth else options.max

    args = [
        "-list", live_hosts_file,
        "-d", "3",
        "-jc",
        "-kf", "all",
        "-ef", "css,png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico",
        "-o", output_file,
        "-c", str(concurrency),
    ]

    if options.proxy:
        args.extend(["-proxy", options.proxy])

    retcode, stdout, stderr = run_tool(tools["katana"], args, timeout=options.timeout)

    if retcode != 0:
        pp.warning("katana crawling failed, nuclei will use live hosts list instead")
        return None

    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        with open(output_file, 'r') as f:
            count = sum(1 for line in f if line.strip())
        pp.info("Discovered %d URLs" % count)
        return output_file
    else:
        pp.warning("No URLs discovered by katana")
        return None


def _run_nuclei_community_batched(nuclei_bin, input_file, tmpl_dir, out_json,
                                   base_args, batch_timeout, target_count, options):
    """Run community templates in batches to avoid socket/fd exhaustion.

    Each batch symlinks ~COMMUNITY_BATCH_SIZE templates into a temp dir and
    runs nuclei against it, appending JSONL findings to out_json.
    """
    import glob as _glob
    import tempfile as _tempfile

    yamls = sorted(_glob.glob(os.path.join(tmpl_dir, "**", "*.yaml"), recursive=True))
    total = len(yamls)
    if total == 0:
        pp.warning("No community templates found in %s" % tmpl_dir)
        return

    batches = [yamls[i:i + COMMUNITY_BATCH_SIZE]
               for i in range(0, total, COMMUNITY_BATCH_SIZE)]
    pp.status("Running community templates in %d batches of ~%d (%d total)" % (
        len(batches), COMMUNITY_BATCH_SIZE, total), newline=True)

    # Strip the output-file args from base_args; we'll append to out_json ourselves
    # Base args already contain -jsonl -o <path> so we reuse them directly.

    per_batch_timeout = max(target_count * 10 * 60, batch_timeout // max(len(batches), 1), 600)

    for idx, batch in enumerate(batches):
        pp.status("Community batch %d/%d (%d templates)..." % (idx + 1, len(batches), len(batch)))

        # Write a flat temp dir with symlinks to this batch's templates
        tmpdir = _tempfile.mkdtemp(prefix="nuclei_batch_")
        batch_out = _tempfile.NamedTemporaryFile(
            prefix="nuclei_batch_out_", suffix=".json", delete=False)
        batch_out_path = batch_out.name
        batch_out.close()

        try:
            for i, tmpl_path in enumerate(batch):
                link_name = os.path.join(tmpdir, "%05d_%s" % (i, os.path.basename(tmpl_path)))
                try:
                    os.symlink(tmpl_path, link_name)
                except OSError:
                    pass

            # Build batch args: write to a temp file per batch so nuclei's
            # truncate-on-open doesn't wipe findings from previous batches.
            batch_args = []
            skip_next = False
            for arg in base_args:
                if skip_next:
                    skip_next = False
                    continue
                if arg == "-t":
                    skip_next = True
                    continue
                if arg in ("-as",):
                    continue
                # Replace the main output file with the per-batch temp file
                if arg == out_json:
                    batch_args.append(batch_out_path)
                    continue
                batch_args.append(arg)

            batch_args.extend(["-t", tmpdir])

            retcode, _, _ = run_tool(nuclei_bin, batch_args, timeout=per_batch_timeout)

            # Append batch findings to the main output file
            new_findings = 0
            if os.path.exists(batch_out_path) and os.path.getsize(batch_out_path) > 0:
                with open(batch_out_path, 'r') as src, open(out_json, 'a') as dst:
                    for line in src:
                        if line.strip():
                            dst.write(line)
                            new_findings += 1

            if retcode == -1:
                pp.warning("Batch %d/%d timed out — %d findings appended, continuing" % (
                    idx + 1, len(batches), new_findings))
            elif retcode not in (0, 1):
                pp.warning("Batch %d/%d exited with code %d (%d findings)" % (
                    idx + 1, len(batches), retcode, new_findings))
            else:
                current = 0
                if os.path.exists(out_json):
                    with open(out_json) as f:
                        current = sum(1 for l in f if l.strip())
                pp.info("Batch %d/%d done — +%d findings (%d total)" % (
                    idx + 1, len(batches), new_findings, current))

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
            try:
                os.unlink(batch_out_path)
            except OSError:
                pass


def phase_nuclei(results_dir, tools, options):
    """Phase 4: Vulnerability scanning with nuclei."""
    pp.status("Phase 4: Vulnerability Scanning (nuclei)", newline=True)

    katana_file = os.path.join(results_dir, "katana_urls.txt")
    live_hosts_file = os.path.join(results_dir, "live_hosts.txt")
    nuclei_json = os.path.join(results_dir, "nuclei_output.json")

    # Use katana URLs if available, otherwise live hosts
    if os.path.exists(katana_file) and os.path.getsize(katana_file) > 0:
        input_file = katana_file
        pp.info("Scanning %s (crawled URLs)" % katana_file)
    else:
        input_file = live_hosts_file
        pp.info("Scanning %s (live hosts)" % live_hosts_file)

    # Determine effective rate limit and concurrency
    rl = STEALTH_RATE_LIMIT if options.stealth else options.rate_limit
    conc = STEALTH_CONCURRENCY if options.stealth else options.max

    # Use -jsonl + -o so findings are written incrementally (survives timeout/kill).
    # The -je flag only dumps on clean exit and is lost if nuclei is interrupted.
    #
    # With large community template sets (80K+), interactsh opens thousands of
    # long-lived OOB callback sockets which deadlocks nuclei's goroutine pool.
    # Disable it when community templates are active; OAST-only templates will
    # be skipped but everything else (CVE probes, misconfigs) still runs fine.
    has_community = bool(options.community_templates and
                         os.path.isdir(options.community_templates or ""))
    no_interactsh_flag = ["-ni"] if has_community else []

    # Reduce bulk-size with community templates to avoid goroutine explosion.
    effective_bulk = 5 if has_community else 25

    args = [
        "-l", input_file,
        "-severity", options.severity,
        "-rl", str(rl),
        "-jsonl", "-o", nuclei_json,
        "-c", str(conc),
        "-bs", str(effective_bulk),
        # Restrict to web-relevant protocols only (skip network/cloud/file/code)
        "-type", "http",
        "-type", "dns",
        "-type", "ssl",
        "-type", "headless",
    ] + no_interactsh_flag

    # Allow scanning all protocols if user explicitly wants it
    if options.all_protocols:
        args = [
            "-l", input_file,
            "-severity", options.severity,
            "-rl", str(rl),
            "-jsonl", "-o", nuclei_json,
            "-c", str(conc),
            "-bs", str(effective_bulk),
        ] + no_interactsh_flag

    # Template selection
    if options.templates:
        args.extend(["-t", options.templates])

    if options.auto_scan:
        args.append("-as")

    if options.new_templates_only:
        args.append("-nt")

    # Scan strategy
    if options.scan_strategy:
        args.extend(["-ss", options.scan_strategy])

    # Proxy
    if options.proxy:
        args.extend(["-proxy", options.proxy])

    # Headers (stealth or custom)
    headers_to_add = []
    if options.stealth:
        headers_to_add.extend(STEALTH_HEADERS)
    if options.custom_headers:
        headers_to_add.extend([h.strip() for h in options.custom_headers.split(",")])
    for h in headers_to_add:
        args.extend(["-H", h])

    # Calculate per-run timeout (default templates only).
    with open(input_file, 'r') as f:
        target_count = max(sum(1 for line in f if line.strip()), 1)

    # Stealth: slow rate/concurrency means much more time needed per host.
    # Non-stealth: ~7 min/host is sufficient at full speed.
    per_host_minutes = 35 if options.stealth else 7

    nuclei_timeout = max(target_count * per_host_minutes * 60, options.timeout)
    pp.info("Nuclei timeout: %ds (~%dm) for %d targets (default templates)" % (
        nuclei_timeout, nuclei_timeout // 60, target_count))

    retcode, stdout, stderr = run_tool(tools["nuclei"], args, timeout=nuclei_timeout)

    if retcode == -1:
        pp.warning("nuclei timed out after %ds — partial results may still be available" % nuclei_timeout)
    elif retcode != 0:
        pp.warning("nuclei exited with code %d" % retcode)

    # --- Community templates: run in batches to avoid socket/fd exhaustion ---
    # Passing 80K+ templates in one nuclei invocation causes goroutine explosion
    # (15K+ open sockets → futex deadlock). Batching at ~2000 templates/run
    # keeps the fd count manageable while still covering all templates.
    if options.community_templates and os.path.isdir(options.community_templates):
        _run_nuclei_community_batched(
            tools["nuclei"], input_file, options.community_templates,
            nuclei_json, args, nuclei_timeout, target_count, options
        )

    # Display findings (JSONL written incrementally, so partial results survive timeout)
    findings = []
    if os.path.exists(nuclei_json):
        with open(nuclei_json, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    findings.append(data)
                    severity = data.get("info", {}).get("severity", "unknown").upper()
                    name = data.get("info", {}).get("name", "Unknown")
                    template_id = data.get("template-id", "")
                    matched = data.get("matched-at", "")

                    if severity in ("CRITICAL", "HIGH"):
                        pp.error("[%s] %s - %s (%s)" % (severity, name, matched, template_id))
                    elif severity == "MEDIUM":
                        pp.warning("[%s] %s - %s (%s)" % (severity, name, matched, template_id))
                    else:
                        pp.info_spaces("[%s] %s - %s (%s)" % (severity, name, matched, template_id))
                except (json.JSONDecodeError, KeyError):
                    pass

    pp.info("Total findings: %d" % len(findings))
    return findings


def phase_nmap(results_dir, options):
    """Phase 5: Optional nmap service scan."""
    pp.status("Phase 5: Service Scanning (nmap)", newline=True)

    live_hosts_file = os.path.join(results_dir, "live_hosts.txt")
    nmap_txt = os.path.join(results_dir, "nmap_output.txt")
    nmap_xml = os.path.join(results_dir, "nmap_output.xml")

    if not os.path.exists(NMAP_BIN):
        pp.warning("nmap not found at %s, skipping" % NMAP_BIN)
        return

    # Extract unique hostnames from live hosts
    hosts = set()
    with open(live_hosts_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Strip protocol and path to get hostname
            host = re.sub(r'^https?://', '', line)
            host = host.split('/')[0].split(':')[0]
            hosts.add(host)

    if not hosts:
        pp.warning("No hosts to scan with nmap")
        return

    host_list = ",".join(hosts)
    args = [
        "-sV", "-sC",
        "-p", options.nmap_ports,
        "-oN", nmap_txt,
        "-oX", nmap_xml,
        host_list
    ]

    retcode, stdout, stderr = run_tool(NMAP_BIN, args, timeout=options.timeout)

    if retcode != 0:
        pp.warning("nmap scan failed")
    else:
        pp.info("nmap scan completed, results in %s" % nmap_txt)


def phase_notify(results_dir, tools, options):
    """Phase 6 (optional): Send findings via notify."""
    pp.status("Phase 6: Sending Notifications", newline=True)

    notify_path = tools.get("notify")
    if not notify_path:
        notify_path = ensure_optional_tool("notify")
    if not notify_path:
        pp.warning("notify tool not available, skipping notifications")
        return

    nuclei_json = os.path.join(results_dir, "nuclei_output.json")
    if not os.path.exists(nuclei_json) or os.path.getsize(nuclei_json) == 0:
        pp.info("No findings to notify about")
        return

    if not os.path.exists(NOTIFY_CONFIG):
        pp.warning("Notify provider config not found at %s" % NOTIFY_CONFIG)
        return

    args = [
        "-pc", NOTIFY_CONFIG,
        "-bulk",
        "-data", nuclei_json,
    ]

    retcode, stdout, stderr = run_tool(notify_path, args, timeout=60)

    if retcode == 0:
        pp.info("Notifications sent successfully")
    else:
        pp.warning("Notification delivery failed: %s" % stderr.strip()[:200])


# === Report Generation ===
def generate_report(results_dir, domain, start_time, end_time, options):
    """Generate summary report from all phase outputs."""
    pp.status("Generating Report", newline=True)

    report_txt = os.path.join(results_dir, "report.txt")
    report_csv = os.path.join(results_dir, "report.csv")
    duration = str(end_time - start_time).split('.')[0]

    # Count subdomains
    sub_count = 0
    subdomains_file = os.path.join(results_dir, "subdomains.txt")
    if os.path.exists(subdomains_file):
        with open(subdomains_file, 'r') as f:
            sub_count = sum(1 for line in f if line.strip())

    # Count live hosts
    live_count = 0
    live_file = os.path.join(results_dir, "live_hosts.txt")
    if os.path.exists(live_file):
        with open(live_file, 'r') as f:
            live_count = sum(1 for line in f if line.strip())

    # Count crawled URLs
    url_count = 0
    katana_file = os.path.join(results_dir, "katana_urls.txt")
    if os.path.exists(katana_file):
        with open(katana_file, 'r') as f:
            url_count = sum(1 for line in f if line.strip())

    # Parse nuclei findings
    findings = []
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    nuclei_json = os.path.join(results_dir, "nuclei_output.json")
    if os.path.exists(nuclei_json):
        with open(nuclei_json, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    severity = data.get("info", {}).get("severity", "info").upper()
                    finding = {
                        "severity": severity,
                        "template_id": data.get("template-id", ""),
                        "name": data.get("info", {}).get("name", ""),
                        "url": data.get("matched-at", ""),
                        "description": data.get("info", {}).get("description", ""),
                        "matcher_name": data.get("matcher-name", ""),
                    }
                    findings.append(finding)
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                except (json.JSONDecodeError, KeyError):
                    pass

    # Parse httpx tech info
    techs = set()
    httpx_json = os.path.join(results_dir, "httpx_output.json")
    if os.path.exists(httpx_json):
        with open(httpx_json, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    for t in data.get("tech", []):
                        techs.add(t)
                except (json.JSONDecodeError, KeyError):
                    pass

    # Write text report
    with open(report_txt, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write(" Nuclei Web Assessment Report\n")
        f.write(" Domain: %s\n" % domain)
        f.write(" Date: %s\n" % start_time.strftime("%Y-%m-%d %H:%M:%S"))
        f.write(" Duration: %s\n" % duration)
        f.write("=" * 70 + "\n\n")

        f.write("[RECON SUMMARY]\n")
        f.write("  Subdomains found: %d\n" % sub_count)
        f.write("  Live hosts: %d\n" % live_count)
        f.write("  URLs crawled: %d\n\n" % url_count)

        f.write("[SCAN CONFIGURATION]\n")
        f.write("  Severity filter: %s\n" % options.severity)
        f.write("  Rate limit: %d rps\n" % (STEALTH_RATE_LIMIT if options.stealth else options.rate_limit))
        f.write("  Concurrency: %d\n" % (STEALTH_CONCURRENCY if options.stealth else options.max))
        f.write("  Stealth mode: %s\n" % ("Yes" if options.stealth else "No"))
        f.write("  Auto scan: %s\n" % ("Yes" if options.auto_scan else "No"))
        f.write("  Scan strategy: %s\n" % (options.scan_strategy or "default"))
        f.write("  Proxy: %s\n" % (options.proxy or "None"))
        f.write("  Community templates: %s\n\n" % (options.community_templates or "None"))

        f.write("[VULNERABILITY SUMMARY]\n")
        f.write("  Critical: %d\n" % severity_counts["CRITICAL"])
        f.write("  High:     %d\n" % severity_counts["HIGH"])
        f.write("  Medium:   %d\n" % severity_counts["MEDIUM"])
        f.write("  Low:      %d\n" % severity_counts["LOW"])
        f.write("  Info:     %d\n\n" % severity_counts["INFO"])

        if findings:
            f.write("[FINDINGS]\n")
            # Sort by severity
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            findings.sort(key=lambda x: sev_order.get(x["severity"], 5))
            for finding in findings:
                f.write("  [%s] %s\n" % (finding["severity"], finding["name"]))
                f.write("         URL: %s\n" % finding["url"])
                f.write("         Template: %s\n" % finding["template_id"])
                if finding["description"]:
                    f.write("         Desc: %s\n" % finding["description"][:200])
                f.write("\n")

        if techs:
            f.write("[TECHNOLOGIES DETECTED]\n")
            for t in sorted(techs):
                f.write("  - %s\n" % t)
            f.write("\n")

        f.write("=" * 70 + "\n")

    # Write CSV report
    with open(report_csv, 'w', newline='') as f:
        writer = csv.DictWriter(f,
            fieldnames=["SEVERITY", "TEMPLATE_ID", "NAME", "URL", "DESCRIPTION", "MATCHER_NAME"],
            quoting=csv.QUOTE_ALL
        )
        writer.writeheader()
        for finding in findings:
            writer.writerow({
                "SEVERITY": finding["severity"],
                "TEMPLATE_ID": finding["template_id"],
                "NAME": finding["name"],
                "URL": finding["url"],
                "DESCRIPTION": finding["description"],
                "MATCHER_NAME": finding["matcher_name"],
            })

    pp.info("Report written to %s" % report_txt)
    pp.info("CSV written to %s" % report_csv)

    # Print summary to console
    pp.status("Results Summary:")
    pp.info_spaces("Subdomains: %d | Live hosts: %d | URLs crawled: %d" % (sub_count, live_count, url_count))
    pp.info_spaces("Critical: %d | High: %d | Medium: %d | Low: %d | Info: %d" % (
        severity_counts["CRITICAL"], severity_counts["HIGH"],
        severity_counts["MEDIUM"], severity_counts["LOW"], severity_counts["INFO"]
    ))


def generate_html_report(results_dir, domain, start_time, end_time):
    """Generate an HTML version of the scan report."""
    report_html = os.path.join(results_dir, "report.html")
    duration = str(end_time - start_time).split('.')[0]

    findings = []
    nuclei_json = os.path.join(results_dir, "nuclei_output.json")
    if os.path.exists(nuclei_json):
        with open(nuclei_json, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    severity_colors = {
        "critical": "#dc3545", "high": "#fd7e14",
        "medium": "#ffc107", "low": "#17a2b8", "info": "#6c757d"
    }

    rows = ""
    for finding in findings:
        sev = finding.get("info", {}).get("severity", "info").lower()
        color = severity_colors.get(sev, "#6c757d")
        name = html.escape(finding.get("info", {}).get("name", ""))
        matched = finding.get("matched-at", "")
        matched_escaped = html.escape(matched)
        template_id = html.escape(finding.get("template-id", ""))
        desc = html.escape(finding.get("info", {}).get("description", "")[:200])
        rows += (
            "<tr>"
            "<td style='color:%s;font-weight:bold'>%s</td>"
            "<td>%s</td>"
            "<td><a href='%s'>%s</a></td>"
            "<td>%s</td>"
            "<td>%s</td>"
            "</tr>\n" % (color, sev.upper(), name, matched_escaped, matched_escaped, template_id, desc)
        )

    html = """<!DOCTYPE html>
<html><head><title>Nuclei Report - %s</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 20px; background: #1a1a2e; color: #e0e0e0; }
h1 { color: #00d4ff; }
.meta { color: #aaa; margin-bottom: 20px; }
table { border-collapse: collapse; width: 100%%; margin-top: 10px; }
th, td { border: 1px solid #333; padding: 10px; text-align: left; }
th { background: #16213e; color: #00d4ff; }
tr:nth-child(even) { background: #0f3460; }
tr:hover { background: #1a1a4e; }
a { color: #00d4ff; text-decoration: none; }
a:hover { text-decoration: underline; }
.summary { display: flex; gap: 15px; margin: 15px 0; }
.summary-card { background: #16213e; padding: 15px 25px; border-radius: 8px; text-align: center; }
.summary-card .count { font-size: 2em; font-weight: bold; }
</style></head>
<body>
<h1>Nuclei Web Assessment Report</h1>
<div class="meta">Domain: <strong>%s</strong> | Date: %s | Duration: %s | Findings: %d</div>
<table>
<tr><th>Severity</th><th>Name</th><th>URL</th><th>Template</th><th>Description</th></tr>
%s
</table>
</body></html>""" % (
        domain, domain, start_time.strftime("%%Y-%%m-%%d %%H:%%M:%%S"),
        duration, len(findings), rows
    )

    with open(report_html, 'w') as f:
        f.write(html)
    pp.info("HTML report written to %s" % report_html)


# === Privilege Escalation ===
def escalate_privileges():
    """Re-exec as root via sudo if not already elevated, preserving user env."""
    if os.geteuid() == 0:
        return

    pp.warning("Root privileges required. Re-launching with sudo...")

    # Preserve the original user's HOME, GOPATH, and PATH so all data
    # (Go SDK, tool binaries, configs) stays in the user's directories.
    preserve_vars = ["HOME", "GOPATH", "PATH", "USER", "LOGNAME", "TERM"]
    preserve_arg = ",".join(v for v in preserve_vars if os.environ.get(v))

    cmd = ["sudo", "--preserve-env=%s" % preserve_arg, "--"] + [sys.executable] + sys.argv

    try:
        os.execvp("sudo", cmd)
    except OSError as e:
        pp.error("Failed to escalate privileges: %s" % e)
        sys.exit(1)


# === Main ===
def main():
    global verbose

    escalate_privileges()

    banner = """
 ███╗   ██╗██╗   ██╗ ██████╗██╗     ███████╗██╗    ██████╗ ██╗██████╗ ███████╗
 ████╗  ██║██║   ██║██╔════╝██║     ██╔════╝██║    ██╔══██╗██║██╔══██╗██╔════╝
 ██╔██╗ ██║██║   ██║██║     ██║     █████╗  ██║    ██████╔╝██║██████╔╝█████╗
 ██║╚██╗██║██║   ██║██║     ██║     ██╔══╝  ██║    ██╔═══╝ ██║██╔═══╝ ██╔══╝
 ██║ ╚████║╚██████╔╝╚██████╗███████╗███████╗██║    ██║     ██║██║     ███████╗
 ╚═╝  ╚═══╝ ╚═════╝  ╚═════╝╚══════╝╚══════╝╚═╝    ╚═╝     ╚═╝╚═╝     ╚══════╝
                    Bug Bounty Web Assessment Pipeline v2.0
    """
    print(banner)

    parser = OptionParser(version="%prog 2.0", usage="%prog [options] -d <domain>")
    parser.add_option("-d", "--domain", dest="domain",
        help="Target root domain (e.g. example.com)", metavar="DOMAIN")
    parser.add_option("-o", "--output", dest="output_dir",
        help="Results output directory", metavar="DIR")
    parser.add_option("-v", "--verbose", dest="verbose",
        default=False, action="store_true", help="Verbose output")

    group1 = OptionGroup(parser, "Phase Control")
    group1.add_option("--skip-enum", dest="skip_enum",
        default=False, action="store_true",
        help="Skip subdomain enumeration (expects subdomains.txt in output dir)")
    group1.add_option("--skip-crawl", dest="skip_crawl",
        default=False, action="store_true", help="Skip web crawling phase")
    group1.add_option("--nmap", dest="run_nmap",
        default=False, action="store_true", help="Enable nmap service scan")
    group1.add_option("--skip-install", dest="skip_install",
        default=False, action="store_true", help="Skip tool installation checks")
    parser.add_option_group(group1)

    group2 = OptionGroup(parser, "Nuclei Settings")
    group2.add_option("-s", "--severity", dest="severity",
        default="critical,high,medium,low,info",
        help="Severity filter (default: critical,high,medium,low,info)")
    group2.add_option("--templates", dest="templates",
        help="Specific nuclei template path or tag", metavar="TEMPLATES")
    group2.add_option("--rate-limit", dest="rate_limit",
        type="int", default=150,
        help="Nuclei requests per second (default: 150)")
    parser.add_option_group(group2)

    group3 = OptionGroup(parser, "General Settings")
    group3.add_option("-m", "--maxthread", dest="max",
        type="int", default=10,
        help="Maximum thread/concurrency count (default: 10)")
    group3.add_option("--timeout", dest="timeout",
        type="int", default=600,
        help="Per-phase timeout in seconds (default: 600)")
    group3.add_option("--nmap-ports", dest="nmap_ports",
        default="80,443,8080,8443",
        help="Ports for nmap scan (default: 80,443,8080,8443)")
    group3.add_option("--httpx-ports", dest="httpx_ports",
        default="80,443,8080,8443,8000,3000,9443,4443,8888",
        help="Ports for httpx probing (default: 80,443,8080,8443,8000,3000,9443,4443,8888)")
    parser.add_option_group(group3)

    group4 = OptionGroup(parser, "Advanced Scanning")
    group4.add_option("--auto-scan", dest="auto_scan",
        default=False, action="store_true",
        help="Use nuclei automatic tech-based template selection (-as)")
    group4.add_option("--scan-strategy", dest="scan_strategy",
        type="choice", choices=["host-spray", "template-spray"],
        default=None,
        help="Nuclei scan strategy: host-spray or template-spray")
    group4.add_option("--stealth", dest="stealth",
        default=False, action="store_true",
        help="Stealth mode: low rate-limit (30rps), reduced concurrency, evasion headers")
    group4.add_option("--proxy", dest="proxy",
        default=None,
        help="HTTP proxy URL (e.g. http://127.0.0.1:8080 for Burp)", metavar="URL")
    group4.add_option("--community-templates", dest="community_templates",
        default=None, action="store_const",
        const=CENT_TEMPLATES_DIR,
        help="Enable community templates (pulled to ~/cent-nuclei-templates via cent)")
    group4.add_option("--notify", dest="notify",
        default=False, action="store_true",
        help="Send findings via notify tool (requires provider-config.yaml)")
    group4.add_option("--new-templates-only", dest="new_templates_only",
        default=False, action="store_true",
        help="Only scan with newly added nuclei templates")
    group4.add_option("--headers", dest="custom_headers",
        default=None,
        help="Custom HTTP headers (comma-separated Key:Value pairs)", metavar="HEADERS")
    group4.add_option("--html-report", dest="html_report",
        default=False, action="store_true",
        help="Generate HTML report in addition to TXT and CSV")
    group4.add_option("--all-protocols", dest="all_protocols",
        default=False, action="store_true",
        help="Scan all nuclei protocols (default: web-only — http,dns,ssl,headless)")
    parser.add_option_group(group4)

    (options, args) = parser.parse_args()

    if not options.domain:
        parser.error("Target domain is required. Use -d <domain>")

    verbose = options.verbose
    domain = options.domain.strip()

    # Create results directory
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if options.output_dir:
        results_dir = options.output_dir
    else:
        results_dir = os.path.join(os.getcwd(), "results_%s_%s" % (
            domain.replace(".", "_"), timestamp))
    os.makedirs(results_dir, exist_ok=True)

    ctime = datetime.datetime.now()
    pp.status("Target: %s" % domain)
    pp.status("Results directory: %s" % results_dir)

    # Ensure configs exist
    ensure_configs(options)

    # Install tools
    if not options.skip_install:
        tools = ensure_all_tools()
    else:
        tools = {}
        for name in REQUIRED_TOOLS:
            path = get_tool_path(name)
            if path:
                tools[name] = path
            else:
                pp.error("Tool %s not found (use without --skip-install to auto-install)" % name)
                sys.exit(1)

    # Install optional tools if requested
    if options.community_templates:
        tools["cent"] = ensure_optional_tool("cent")
        # Pull community templates if cent is available and dir doesn't exist
        if tools.get("cent") and not os.path.isdir(options.community_templates):
            pp.status("Pulling community templates via cent (first run — may take a few minutes)...")
            run_tool(tools["cent"], ["-p", options.community_templates], timeout=600)
    if options.notify:
        tools["notify"] = ensure_optional_tool("notify")

    # Phase 1: Subdomain Enumeration
    if not options.skip_enum:
        phase_subdomain_enum(domain, results_dir, tools, options)
    else:
        sub_file = os.path.join(results_dir, "subdomains.txt")
        if not os.path.exists(sub_file):
            pp.error("--skip-enum requires subdomains.txt in the output directory")
            sys.exit(1)
        pp.info("Skipping enumeration, using existing subdomains.txt")

    # Phase 2: HTTP Probing
    phase_httpx(results_dir, tools, options)

    # Phase 3: Web Crawling
    if not options.skip_crawl:
        phase_crawl(results_dir, tools, options)
    else:
        pp.info("Skipping web crawling phase")

    # Phase 4: Nuclei Scanning
    phase_nuclei(results_dir, tools, options)

    # Phase 5: Nmap (optional)
    if options.run_nmap:
        phase_nmap(results_dir, options)

    # Phase 6: Notifications (optional)
    if options.notify:
        phase_notify(results_dir, tools, options)

    # Reports
    etime = datetime.datetime.now()
    generate_report(results_dir, domain, ctime, etime, options)

    if options.html_report:
        generate_html_report(results_dir, domain, ctime, etime)

    total = str(etime - ctime).split('.')[0]
    pp.status("Scan completed in: %s" % total)
    pp.status("All results saved to: %s" % results_dir)

    # Fix ownership: running as root creates files owned by root, but the
    # results should be accessible by the original user.
    _fix_ownership(results_dir)
    if options.community_templates and os.path.isdir(options.community_templates):
        _fix_ownership(options.community_templates)


def _fix_ownership(path):
    """Recursively chown a path back to the real (non-root) user."""
    real_user = os.environ.get("SUDO_USER") or os.environ.get("USER")
    if not real_user or real_user == "root" or os.geteuid() != 0:
        return
    try:
        subprocess.run(
            ["chown", "-R", "%s:%s" % (real_user, real_user), path],
            capture_output=True, timeout=30,
        )
    except Exception:
        pass


if __name__ == "__main__":
    main()
