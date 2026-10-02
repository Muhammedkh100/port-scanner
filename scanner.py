#!/usr/bin/env python3
"""
Advanced Port Scanner
A multi-threaded port scanner with service detection and banner grabbing.

For educational use and authorized security testing only.
"""

import socket
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import json


class PortScanner:
    def __init__(self, target, ports, threads=100, timeout=1, verbose=False):
        self.target = target
        self.ports = ports
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.open_ports = []

        # Common service signatures
        self.services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Proxy",
            27017: "MongoDB", 5900: "VNC", 1433: "MSSQL"
        }

    def resolve_target(self):
        """Resolve hostname to IP address"""
        try:
            ip = socket.gethostbyname(self.target)
            if self.verbose:
                print(f"[*] Resolved {self.target} to {ip}")
            return ip
        except socket.gaierror:
            print(f"[!] Error: Unable to resolve hostname {self.target}")
            sys.exit(1)

    def grab_banner(self, sock, port):
        """Attempt to grab service banner from an already-connected socket"""
        try:
            if port in (80, 8080, 443):
                sock.send(b"GET / HTTP/1.1\r\nHost: target\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner[:100]  # Limit banner length
        except socket.error:
            return None

    def scan_port(self, ip, port):
        """Scan a single port and close the socket in every code path"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            result = sock.connect_ex((ip, port))

            if result != 0:
                return None

            service = self.services.get(port, "Unknown")
            banner = self.grab_banner(sock, port)

            port_info = {
                "port": port,
                "state": "open",
                "service": service,
                "banner": banner
            }

            self.open_ports.append(port_info)

            if self.verbose:
                banner_text = f" - {banner}" if banner else ""
                print(f"[+] Port {port}/tcp is OPEN - {service}{banner_text}")

            return port_info

        except socket.error:
            return None
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
            sys.exit(0)
        finally:
            sock.close()

    def parse_ports(self, port_range):
        """Parse port range string to list of ports"""
        if port_range == "common":
            # Top 20 most common ports
            return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                    993, 995, 1723, 3306, 3389, 5900, 8080]

        ports = []
        for part in port_range.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))

        return sorted(set(ports))

    def run(self):
        """Execute the port scan"""
        ip = self.resolve_target()

        print("=" * 60)
        print(f"Port Scanner - Target: {self.target} ({ip})")
        print(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

        port_list = self.parse_ports(self.ports)
        print(f"[*] Scanning {len(port_list)} ports...")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, ip, port): port
                       for port in port_list}

            completed = 0
            for future in as_completed(futures):
                completed += 1
                if not self.verbose and completed % 100 == 0:
                    print(f"[*] Progress: {completed}/{len(port_list)} ports scanned")

        self.display_results()

    def display_results(self):
        """Display scan results"""
        print("\n" + "=" * 60)
        print("SCAN RESULTS")
        print("=" * 60)

        if not self.open_ports:
            print("[!] No open ports found")
            return

        print(f"\n[+] Found {len(self.open_ports)} open port(s):\n")

        for port_info in sorted(self.open_ports, key=lambda x: x['port']):
            print(f"Port {port_info['port']}/tcp")
            print(f"  State:   {port_info['state']}")
            print(f"  Service: {port_info['service']}")
            if port_info['banner']:
                print(f"  Banner:  {port_info['banner']}")
            print()

        print("=" * 60)
        print(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

    def export_json(self, filename):
        """Export results to JSON"""
        data = {
            "target": self.target,
            "scan_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "open_ports": self.open_ports
        }

        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)

        print(f"[+] Results exported to {filename}")


def main():
    parser = argparse.ArgumentParser(
        description="Advanced Port Scanner - Multi-threaded network port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py 192.168.1.1 -p 1-1000
  python scanner.py example.com -p common
  python scanner.py 10.0.0.1 -p 80,443,8080 -t 200 -v
  python scanner.py scanme.nmap.org -p 1-65535 -o results.json
        """
    )

    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="common",
                         help="Port range (e.g., 1-1000, 80,443, or 'common')")
    parser.add_argument("-t", "--threads", type=int, default=100,
                         help="Number of threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                         help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="Verbose output")
    parser.add_argument("-o", "--output", help="Export results to JSON file")

    args = parser.parse_args()

    try:
        scanner = PortScanner(
            target=args.target,
            ports=args.ports,
            threads=args.threads,
            timeout=args.timeout,
            verbose=args.verbose
        )

        scanner.run()

        if args.output:
            scanner.export_json(args.output)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
