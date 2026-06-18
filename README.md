# 🔍 Advanced Port Scanner

**Author:** Lillian Jones  
**Tools:** Python 3, socket, threading, argparse  
**Category:** Network Reconnaissance | Cybersecurity Portfolio

-----

## Overview

A full-featured TCP port scanner built in Python that mimics core functionality of Nmap. Designed to demonstrate understanding of network sockets, threading, service detection, and banner grabbing — key skills for SOC Analyst and IT roles.

-----

## Features

|Feature                    |Description                                              |
|---------------------------|---------------------------------------------------------|
|**Multi-threaded Scanning**|Up to 100 concurrent threads for fast scans              |
|**Banner Grabbing**        |Pulls service version info from open ports               |
|**Service Detection**      |Maps port numbers to service names (SSH, HTTP, SMB, etc.)|
|**Flexible Port Selection**|`common`, `all`, range (`1-1024`), or custom list        |
|**Dual Output**            |Colored terminal display + plain-text report file        |
|**Two Run Modes**          |CLI flags or interactive menu                            |

-----

## Technologies Used

- `socket` — TCP connections and banner grabbing
- `threading` + `queue.Queue` — concurrent port scanning
- `argparse` — command-line argument parsing
- `datetime` — timestamped reports
- `re` — ANSI color stripping for clean file output

-----

## Usage

### CLI Mode

```bash
# Scan common ports (default)
python3 port_scanner.py 192.168.1.1

# Scan ports 1–1024
python3 port_scanner.py 192.168.1.1 -p 1-1024

# Scan specific ports
python3 port_scanner.py 192.168.1.1 -p 22,80,443,3306

# Full scan with 200 threads, no file save
python3 port_scanner.py 192.168.1.1 -p all -t 200 --no-save
```

### Interactive Menu Mode

```bash
python3 port_scanner.py --menu
```

-----

## Sample Output

```
=======================================================
  Target   : 172.16.148.133 (172.16.148.133)
  Ports    : 100 to scan
  Threads  : 100
  Started  : 2026-06-17 14:32:10
=======================================================
  [*] Scanning... please wait

=================================================================
           ADVANCED PORT SCANNER - SCAN REPORT
=================================================================
  Target Host   : 172.16.148.133
  Resolved IP   : 172.16.148.133
  Hostname      : metasploitable
  Scan Date     : 2026-06-17 14:32:10
  Ports Scanned : 100
  Scan Duration : 3.21 seconds
  Open Ports    : 8

  PORT     SERVICE          BANNER
  ------- --------------- --------------------------------------
  21       FTP              220 (vsFTPd 2.3.4)
  22       SSH              SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
  80       HTTP             HTTP/1.1 200 OK | Server: Apache/2.2.8
  139      NetBIOS          No banner
  445      SMB              No banner
  3306     MySQL            5.0.51a-3ubuntu5
  5432     PostgreSQL       No banner
  6667     IRC              :irc.Metasploitable.LAN NOTICE ...
=================================================================
  SCAN COMPLETE
=================================================================

  [+] Report saved to: scan_172_16_148_133_20260617_143213.txt
```

-----

## Lab Environment

|Device                  |IP            |OS          |
|------------------------|--------------|------------|
|Kali Linux (attacker)   |172.16.148.132|Kali Rolling|
|Metasploitable2 (target)|172.16.148.133|Ubuntu 8.04 |


> ⚠️ **Legal Notice:** Only scan systems you own or have explicit written permission to test. Unauthorized port scanning may violate laws including the Computer Fraud and Abuse Act (CFAA).

-----

## Skills Demonstrated

- TCP socket programming
- Multithreaded application design
- Network service enumeration
- Banner grabbing / version detection
- CLI tool development with argparse
- Report generation and file I/O

-----

## Related Portfolio Projects

- [Nmap Scanning Lab](../nmap-scanning-lab)
- [Metasploit Exploitation Lab](../metasploit-exploitation-lab)
- [Wireshark ARP/MITM Detection Lab](../wireshark-arp-mitm-lab)
- [Splunk SIEM Analysis Lab](../splunk-siem-lab)
