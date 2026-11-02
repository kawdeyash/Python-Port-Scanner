#!/usr/bin/env python3
"""
Python Port Scanner
A multi-threaded port scanner for network exploration and security auditing.
Built for cybersecurity students and ethical penetration testers.
"""

import sys
import socket
import argparse
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple

# Optional styling via colorama if available
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    GREEN = Fore.GREEN
    RED = Fore.RED
    YELLOW = Fore.YELLOW
    CYAN = Fore.CYAN
    RESET = Style.RESET_ALL
    BRIGHT = Style.BRIGHT
except ImportError:
    GREEN = ""
    RED = ""
    YELLOW = ""
    CYAN = ""
    RESET = ""
    BRIGHT = ""

# Common Well-Known Ports and Services Mapping
COMMON_SERVICES = {
    20: "FTP (Data)",
    21: "FTP (Control)",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP (Submission)",
    993: "IMAPS",
    995: "POP3S",
    1433: "MS SQL Server",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP Dev / Alt",
    8080: "HTTP Proxy / Alt",
    8443: "HTTPS Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

def get_service_name(port: int) -> str:
    """Return common service name or resolve via socket library."""
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp").upper()
    except (OSError, socket.error):
        return "Unknown Service"

def grab_banner(target_ip: str, port: int, timeout: float = 1.0) -> str:
    """Attempt banner grabbing on open port."""
    banner = ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target_ip, port))
            # Send HTTP HEAD request for web ports, or newline for generic services
            if port in (80, 8080, 8000):
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
            elif port == 443:
                # SSL handshake required for 443 banner, skip raw socket banner
                return "SSL/TLS Service"
            else:
                s.sendall(b"\r\n")
            
            data = s.recv(1024)
            banner = data.decode(errors="ignore").strip().splitlines()[0]
            if len(banner) > 60:
                banner = banner[:57] + "..."
    except Exception:
        pass
    return banner

def scan_single_port(target_ip: str, port: int, timeout: float = 1.0, banner_grab: bool = False) -> Optional[Dict]:
    """Scan an individual TCP port. Returns port info dict if open, else None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            start_time = time.time()
            result = s.connect_ex((target_ip, port))
            latency = (time.time() - start_time) * 1000

            if result == 0:
                service = get_service_name(port)
                banner = grab_banner(target_ip, port, timeout) if banner_grab else ""
                return {
                    "port": port,
                    "state": "OPEN",
                    "service": service,
                    "latency_ms": round(latency, 2),
                    "banner": banner
                }
    except Exception:
        pass
    return None

def parse_port_range(port_arg: str) -> List[int]:
    """Parse port range strings like '80', '1-1024', or '21,22,80,443'."""
    ports = set()
    parts = port_arg.replace(" ", "").split(",")
    for part in parts:
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start, end = int(start_str), int(end_str)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"Port number out of range: {p}")
            ports.add(p)
    return sorted(list(ports))

def print_banner():
    banner = f"""
{CYAN}======================================================================
     ____        _   _                   ____                                
    |  _ \ _   _| |_| |__   ___  _ __   / ___|  ___ __ _ _ __  _ __   ___ _ __ 
    | |_) | | | | __| '_ \ / _ \| '_ \  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
    |  __/| |_| | |_| | | | (_) | | | |  ___) | (_| (_| | | | | | | |  __/ |   
    |_|    \__, |\__|_| |_|\___/|_| |_| |____/ \___\__,_|_| |_|_| |_|\___|_|   
           |___/                                                               
======================================================================
  Tool: Multi-threaded Python Port Scanner
  Purpose: Ethical Security Auditing & Network Discovery
======================================================================{RESET}
"""
    print(banner)

def generate_report(target_host: str, target_ip: str, open_ports: List[Dict], 
                    duration: float, total_scanned: int, report_path: str):
    """Write structured scan report to a file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write(" " * 22 + "PORT SCAN REPORT\n")
        f.write("=" * 70 + "\n")
        f.write(f"Target Hostname : {target_host}\n")
        f.write(f"Target IP       : {target_ip}\n")
        f.write(f"Scan Timestamp  : {timestamp}\n")
        f.write(f"Total Ports     : {total_scanned}\n")
        f.write(f"Open Ports      : {len(open_ports)}\n")
        f.write(f"Duration        : {duration:.2f} seconds\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<25} {'LATENCY':<12} {'BANNER'}\n")
        f.write("-" * 70 + "\n")
        if open_ports:
            for p in open_ports:
                banner_str = p['banner'] if p.get('banner') else "-"
                f.write(f"{p['port']:<10} {p['state']:<10} {p['service']:<25} {p['latency_ms']} ms{'':<5} {banner_str}\n")
        else:
            f.write("No open ports discovered in the specified range.\n")
        f.write("\n" + "=" * 70 + "\n")
        f.write("Report generated by Python-Port-Scanner.\n")

def run_scanner(target: str, ports: List[int], threads: int = 50, timeout: float = 1.0, 
                banner_grab: bool = False, output_file: Optional[str] = None):
    """Orchestrate the multi-threaded scan."""
    print_banner()

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"{RED}[-] Error: Could not resolve target host '{target}'. Check your network connection or hostname.{RESET}")
        return

    print(f"{BRIGHT}[*] Target Host       : {YELLOW}{target}{RESET}")
    print(f"{BRIGHT}[*] Target IP         : {YELLOW}{target_ip}{RESET}")
    print(f"{BRIGHT}[*] Total Ports       : {CYAN}{len(ports)}{RESET}")
    print(f"{BRIGHT}[*] Concurrent Threads: {CYAN}{threads}{RESET}")
    print(f"{BRIGHT}[*] Connection Timeout: {CYAN}{timeout}s{RESET}")
    print(f"{BRIGHT}[*] Banner Grabbing   : {CYAN}{'Enabled' if banner_grab else 'Disabled'}{RESET}")
    print(f"{BRIGHT}[*] Scan Started At   : {CYAN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print("-" * 70)

    start_time = time.time()
    open_ports = []

    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_port = {
                executor.submit(scan_single_port, target_ip, p, timeout, banner_grab): p
                for p in ports
            }
            
            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
                    banner_info = f" | Banner: {result['banner']}" if result.get("banner") else ""
                    print(f"{GREEN}[+] Port {result['port']:<5} OPEN {RESET} -> "
                          f"{CYAN}{result['service']:<20}{RESET} ({result['latency_ms']} ms){banner_info}")

    except KeyboardInterrupt:
        print(f"\n{RED}[!] Scan aborted by user (Ctrl+C). Compiling partial results...{RESET}")

    duration = time.time() - start_time
    open_ports.sort(key=lambda x: x["port"])

    print("-" * 70)
    print(f"{BRIGHT}[*] Scan Completed in {duration:.2f} seconds.{RESET}")
    print(f"{BRIGHT}[*] Open Ports Found : {GREEN}{len(open_ports)}{RESET} / {len(ports)}")

    # Print summary table
    if open_ports:
        print("\n" + "=" * 70)
        print(f"{'PORT':<8} {'STATE':<8} {'SERVICE':<22} {'LATENCY':<10} {'BANNER'}")
        print("=" * 70)
        for p in open_ports:
            banner_display = p['banner'] if p.get('banner') else "-"
            print(f"{p['port']:<8} {GREEN}{p['state']:<8}{RESET} {p['service']:<22} {str(p['latency_ms']) + ' ms':<10} {banner_display}")
        print("=" * 70)
    else:
        print(f"{YELLOW}[!] No open ports detected within the target range.{RESET}")

    # Generate file report
    if output_file:
        generate_report(target, target_ip, open_ports, duration, len(ports), output_file)
        print(f"{GREEN}[+] Detailed scan report saved to: {output_file}{RESET}")

def interactive_mode():
    """Prompt user interactively if no command-line arguments are supplied."""
    print_banner()
    print(f"{CYAN}[ Interactive Mode ]{RESET}")
    target = input("Enter target IP or hostname [default: 127.0.0.1]: ").strip() or "127.0.0.1"
    port_range = input("Enter port range (e.g., 20-100 or 1-1024 or 21,22,80,443) [default: 1-1024]: ").strip() or "1-1024"
    threads_input = input("Enter number of threads [default: 50]: ").strip() or "50"
    banner_input = input("Enable banner grabbing? (y/n) [default: y]: ").strip().lower() or "y"
    output_input = input("Save report to file? [default: results/scan_report.txt]: ").strip() or "results/scan_report.txt"

    try:
        ports = parse_port_range(port_range)
        threads = int(threads_input)
        banner_grab = banner_input == "y"
    except Exception as e:
        print(f"{RED}[-] Error parsing inputs: {e}{RESET}")
        sys.exit(1)

    run_scanner(
        target=target,
        ports=ports,
        threads=threads,
        timeout=1.0,
        banner_grab=banner_grab,
        output_file=output_input
    )

def main():
    parser = argparse.ArgumentParser(
        description="Fast Multi-threaded Python Port Scanner for Cybersecurity Students & Ethical Hackers.",
        epilog="Examples:\n"
               "  python scanner.py -t 127.0.0.1\n"
               "  python scanner.py -t scanme.nmap.org -p 20-100 -th 100\n"
               "  python scanner.py -t 192.168.1.1 -p 21,22,80,443 -b -o results/scan_report.txt\n",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("-t", "--target", help="Target hostname or IP address (e.g. 127.0.0.1, scanme.nmap.org)")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range to scan (e.g. 1-1024, 80,443, 20-80) [default: 1-1024]")
    parser.add_argument("-th", "--threads", type=int, default=50, help="Number of concurrent worker threads [default: 50]")
    parser.add_argument("-to", "--timeout", type=float, default=1.0, help="Socket timeout in seconds [default: 1.0]")
    parser.add_argument("-b", "--banner", action="store_true", help="Enable service banner grabbing")
    parser.add_argument("-o", "--output", default="results/scan_report.txt", help="Path to save text report [default: results/scan_report.txt]")

    # If run with no CLI arguments, switch to interactive user-friendly prompt
    if len(sys.argv) == 1:
        interactive_mode()
        return

    args = parser.parse_args()

    if not args.target:
        parser.print_help()
        sys.exit(1)

    try:
        ports = parse_port_range(args.ports)
    except ValueError as e:
        print(f"{RED}[-] Error: {e}{RESET}")
        sys.exit(1)

    run_scanner(
        target=args.target,
        ports=ports,
        threads=args.threads,
        timeout=args.timeout,
        banner_grab=args.banner,
        output_file=args.output
    )

if __name__ == "__main__":
    main()
