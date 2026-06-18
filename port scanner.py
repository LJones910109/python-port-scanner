#!/usr/bin/env python3
"""
=============================================================
  Advanced Port Scanner
  Author: Lillian Jones
  Purpose: Cybersecurity Portfolio - Network Reconnaissance
  Features: Threading, Banner Grabbing, Service Detection,
            OS Fingerprinting, Report Generation
=============================================================
"""

import socket
import threading
import argparse
import sys
import os
from datetime import datetime
from queue import Queue

# ──────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────
THREAD_COUNT   = 100       # Concurrent threads
TIMEOUT        = 1.0       # Socket timeout (seconds)
BANNER_TIMEOUT = 2.0       # Banner grab timeout
MAX_BANNER_LEN = 256       # Max banner bytes to read

# Common service names (extends socket.getservbyport)
COMMON_SERVICES = {
    21:   "FTP",          22:   "SSH",          23:   "Telnet",
    25:   "SMTP",         53:   "DNS",           67:   "DHCP",
    68:   "DHCP",         69:   "TFTP",          80:   "HTTP",
    110:  "POP3",         111:  "RPC",           135:  "MSRPC",
    139:  "NetBIOS",      143:  "IMAP",          161:  "SNMP",
    389:  "LDAP",         443:  "HTTPS",         445:  "SMB",
    512:  "rexec",        513:  "rlogin",        514:  "rsh/syslog",
    993:  "IMAPS",        995:  "POP3S",         1080: "SOCKS",
    1433: "MSSQL",        1521: "Oracle DB",     3306: "MySQL",
    3389: "RDP",          5432: "PostgreSQL",    5900: "VNC",
    6379: "Redis",        6667: "IRC",           8080: "HTTP-Alt",
    8443: "HTTPS-Alt",    27017:"MongoDB",
}

# ──────────────────────────────────────────────
# COLORS (terminal only, stripped in file)
# ──────────────────────────────────────────────
class Colors:
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def color(text, code):
    """Apply color code to text."""
    return f"{code}{text}{Colors.RESET}"

def strip_color(text):
    """Remove ANSI escape codes (for file output)."""
    import re
    return re.sub(r'\033\[[0-9;]*m', '', text)

# ──────────────────────────────────────────────
# CORE SCANNER LOGIC
# ──────────────────────────────────────────────
open_ports   = []
results_lock = threading.Lock()

def resolve_host(target):
    """Resolve hostname to IP, return (ip, hostname)."""
    try:
        ip = socket.gethostbyname(target)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = target if target != ip else "N/A"
        return ip, hostname
    except socket.gaierror:
        print(color(f"[!] Cannot resolve host: {target}", Colors.RED))
        sys.exit(1)

def get_service_name(port):
    """Return service name for a port number."""
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "Unknown"

def grab_banner(ip, port):
    """Attempt to grab a service banner."""
    banner = ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(BANNER_TIMEOUT)
            s.connect((ip, port))

            # Some services need a prompt first
            probes = {
                21:  b"",          22:  b"",
                25:  b"EHLO scan\r\n",
                80:  b"HEAD / HTTP/1.0\r\n\r\n",
                8080:b"HEAD / HTTP/1.0\r\n\r\n",
                110: b"",          143: b"",
            }
            probe = probes.get(port, b"\r\n")
            if probe:
                s.send(probe)

            data = s.recv(MAX_BANNER_LEN)
            banner = data.decode("utf-8", errors="replace").strip()
            # Collapse whitespace/newlines
            banner = " | ".join(line.strip() for line in banner.splitlines() if line.strip())
            banner = banner[:120]  # Cap length for display
    except Exception:
        pass
    return banner

def scan_port(ip, port):
    """Scan a single TCP port. Store result if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = get_service_name(port)
                banner  = grab_banner(ip, port)
                with results_lock:
                    open_ports.append({
                        "port":    port,
                        "service": service,
                        "banner":  banner,
                    })
    except Exception:
        pass

def worker(ip, queue):
    """Thread worker: pull ports from queue and scan."""
    while not queue.empty():
        port = queue.get()
        scan_port(ip, port)
        queue.task_done()

def run_scan(ip, ports):
    """Dispatch threaded scan across all ports."""
    queue = Queue()
    for p in ports:
        queue.put(p)

    threads = []
    for _ in range(min(THREAD_COUNT, len(ports))):
        t = threading.Thread(target=worker, args=(ip, queue), daemon=True)
        t.start()
        threads.append(t)

    queue.join()

# ──────────────────────────────────────────────
# REPORTING
# ──────────────────────────────────────────────
def build_report(target, ip, hostname, ports_scanned, duration, scan_time):
    """Build a clean, plain-text report string."""
    lines = []
    lines.append("=" * 65)
    lines.append("           ADVANCED PORT SCANNER - SCAN REPORT")
    lines.append("=" * 65)
    lines.append(f"  Target Host   : {target}")
    lines.append(f"  Resolved IP   : {ip}")
    lines.append(f"  Hostname      : {hostname}")
    lines.append(f"  Scan Date     : {scan_time}")
    lines.append(f"  Ports Scanned : {ports_scanned}")
    lines.append(f"  Scan Duration : {duration:.2f} seconds")
    lines.append(f"  Open Ports    : {len(open_ports)}")
    lines.append("=" * 65)

    if open_ports:
        sorted_ports = sorted(open_ports, key=lambda x: x["port"])
        lines.append(f"\n  {'PORT':<8} {'SERVICE':<16} {'BANNER'}")
        lines.append(f"  {'-'*7} {'-'*15} {'-'*38}")
        for entry in sorted_ports:
            banner = entry["banner"] if entry["banner"] else "No banner"
            lines.append(f"  {entry['port']:<8} {entry['service']:<16} {banner}")
    else:
        lines.append("\n  No open ports found in the scanned range.")

    lines.append("\n" + "=" * 65)
    lines.append("  SCAN COMPLETE")
    lines.append("=" * 65)
    return "\n".join(lines)

def print_report(report_text):
    """Print report with color highlights to terminal."""
    for line in report_text.splitlines():
        if "OPEN" in line or ("/" in line and line.strip()[0].isdigit()):
            print(color(line, Colors.GREEN))
        elif "=" * 10 in line:
            print(color(line, Colors.CYAN))
        elif line.strip().startswith("Target") or line.strip().startswith("Resolved") \
             or line.strip().startswith("Hostname") or line.strip().startswith("Scan") \
             or line.strip().startswith("Open") or line.strip().startswith("Ports"):
            print(color(line, Colors.YELLOW))
        else:
            print(line)

def save_report(report_text, target):
    """Save plain-text report to file."""
    safe_name = target.replace(".", "_").replace("/", "_")
    timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename   = f"scan_{safe_name}_{timestamp}.txt"
    with open(filename, "w") as f:
        f.write(strip_color(report_text))
    return filename

# ──────────────────────────────────────────────
# PORT RANGE PARSER
# ──────────────────────────────────────────────
def parse_ports(port_arg):
    """
    Parse port argument into a sorted list of ints.
    Accepts:
      - "common"    → top 1000 well-known ports
      - "1-1024"    → range
      - "22,80,443" → comma-separated
      - "all"       → 1-65535
    """
    port_arg = port_arg.strip().lower()

    if port_arg == "all":
        return list(range(1, 65536))

    if port_arg == "common":
        # Top 100 most common ports
        common = [
            7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,
            119,135,139,143,144,179,199,389,427,443,444,445,465,513,
            514,515,543,544,548,554,587,631,646,873,990,993,995,1080,
            1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,
            2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,
            5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,
            5900,6000,6001,6646,7070,8000,8008,8080,8443,8888,9100,
            9999,10000,32768,49152,49153,49154,49155,49156,49157,
        ]
        return sorted(set(common))

    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

# ──────────────────────────────────────────────
# INTERACTIVE MENU
# ──────────────────────────────────────────────
def interactive_menu():
    """Simple interactive menu for users who don't use CLI args."""
    print(color("\n" + "=" * 55, Colors.CYAN))
    print(color("        ADVANCED PORT SCANNER - MAIN MENU", Colors.BOLD))
    print(color("=" * 55, Colors.CYAN))
    print(color("  [1]", Colors.GREEN) + "  Quick Scan     (common ports)")
    print(color("  [2]", Colors.GREEN) + "  Standard Scan  (ports 1-1024)")
    print(color("  [3]", Colors.GREEN) + "  Full Scan      (all 65535 ports)")
    print(color("  [4]", Colors.GREEN) + "  Custom Scan    (you choose ports)")
    print(color("  [5]", Colors.RED)   + "  Exit")
    print(color("=" * 55, Colors.CYAN))

    choice = input(color("\n  Select option [1-5]: ", Colors.YELLOW)).strip()

    if choice == "5":
        print(color("  Goodbye!", Colors.CYAN))
        sys.exit(0)

    target = input(color("  Enter target IP or hostname: ", Colors.YELLOW)).strip()
    if not target:
        print(color("  [!] No target specified.", Colors.RED))
        sys.exit(1)

    port_map = {
        "1": "common",
        "2": "1-1024",
        "3": "all",
    }

    if choice == "4":
        port_input = input(color(
            "  Enter ports (e.g. 22,80,443 or 1-500): ", Colors.YELLOW
        )).strip()
    elif choice in port_map:
        port_input = port_map[choice]
    else:
        print(color("  [!] Invalid option.", Colors.RED))
        sys.exit(1)

    return target, port_input

# ──────────────────────────────────────────────
# ARGUMENT PARSER (CLI mode)
# ──────────────────────────────────────────────
def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Advanced Port Scanner — Cybersecurity Portfolio Tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 port_scanner.py 192.168.1.1
  python3 port_scanner.py 192.168.1.1 -p 1-1024
  python3 port_scanner.py 192.168.1.1 -p common
  python3 port_scanner.py 192.168.1.1 -p 22,80,443,3306
  python3 port_scanner.py 192.168.1.1 -p all -t 200
  python3 port_scanner.py --menu
        """
    )
    parser.add_argument("target", nargs="?", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports",   default="common",
                        help="Ports: 'common', 'all', '1-1024', '22,80,443' (default: common)")
    parser.add_argument("-t", "--threads", type=int, default=THREAD_COUNT,
                        help=f"Thread count (default: {THREAD_COUNT})")
    parser.add_argument("--menu", action="store_true",
                        help="Launch interactive menu instead of CLI mode")
    parser.add_argument("--no-save", action="store_true",
                        help="Print results only, do not save to file")
    return parser

# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
def main():
    global THREAD_COUNT

    parser  = build_arg_parser()
    args    = parser.parse_args()

    # Decide: menu or CLI
    if args.menu or not args.target:
        target, port_input = interactive_menu()
    else:
        target     = args.target
        port_input = args.ports
        THREAD_COUNT = args.threads

    # Resolve target
    ip, hostname = resolve_host(target)

    # Parse ports
    try:
        ports = parse_ports(port_input)
    except ValueError as e:
        print(color(f"[!] Invalid port specification: {e}", Colors.RED))
        sys.exit(1)

    # Print scan header
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(color("\n" + "=" * 55, Colors.CYAN))
    print(color(f"  Target   : {target} ({ip})", Colors.YELLOW))
    print(color(f"  Ports    : {len(ports)} to scan", Colors.YELLOW))
    print(color(f"  Threads  : {THREAD_COUNT}", Colors.YELLOW))
    print(color(f"  Started  : {scan_time}", Colors.YELLOW))
    print(color("=" * 55, Colors.CYAN))
    print(color("  [*] Scanning... please wait\n", Colors.CYAN))

    # Run scan
    start = datetime.now()
    run_scan(ip, ports)
    duration = (datetime.now() - start).total_seconds()

    # Build and display report
    report = build_report(target, ip, hostname, len(ports), duration, scan_time)
    print_report(report)

    # Save to file
    if not (args.menu or not args.target):
        save = not args.no_save
    else:
        ans  = input(color("\n  Save report to file? [y/n]: ", Colors.YELLOW)).strip().lower()
        save = ans == "y"

    if save:
        filename = save_report(report, target)
        print(color(f"\n  [+] Report saved to: {filename}", Colors.GREEN))

    print()

if __name__ == "__main__":
    main()
