#!/usr/bin/env python3
"""
Port Scanner - Blue Team Edition

"""

import socket
import sys
import threading
import time
from datetime import datetime
from colorama import init, Fore, Style


init(autoreset=True)

class PortScanner:
    """A professional port scanner with service detection capabilities."""
    
    COMMON_PORTS = {
        20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP',
        53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPCBIND', 135: 'MSRPC',
        139: 'NETBIOS-SSN', 143: 'IMAP', 443: 'HTTPS', 445: 'MICROSOFT-DS',
        993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'ORACLE-DB',
        1723: 'PPTP', 3306: 'MYSQL', 3389: 'RDP', 5432: 'POSTGRESQL',
        5900: 'VNC', 6379: 'REDIS', 8080: 'HTTP-ALT', 8443: 'HTTPS-ALT',
        27017: 'MONGODB'
    }
    
    VULNERABLE_SERVICES = {
        21: 'FTP (clear text credentials)',
        23: 'TELNET (unencrypted)',
        1433: 'MSSQL (default credentials risk)',
        3306: 'MySQL (default credentials risk)',
        3389: 'RDP (brute force target)',
        5900: 'VNC (default credentials risk)'
    }
    
    def __init__(self, target, timeout=2, max_threads=50):
        self.target = target
        self.timeout = timeout
        self.max_threads = max_threads
        self.open_ports = []
        self.closed_ports = []
        self.scan_results = {}
        self.threads = []
        self.lock = threading.Lock()
        
    def resolve_hostname(self):
        try:
            ip = socket.gethostbyname(self.target)
            print(f"{Fore.GREEN}Resolved {self.target} -> {ip}{Style.RESET_ALL}")
            return ip
        except socket.gaierror:
            print(f"{Fore.RED}Could not resolve hostname: {self.target}{Style.RESET_ALL}")
            return None
    
    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                service = self.COMMON_PORTS.get(port, 'UNKNOWN')
                is_vulnerable = port in self.VULNERABLE_SERVICES
                
                with self.lock:
                    self.open_ports.append(port)
                    self.scan_results[port] = {
                        'service': service,
                        'vulnerable': is_vulnerable,
                        'vulnerability_note': self.VULNERABLE_SERVICES.get(port, 'None')
                    }
                
                try:
                    sock.settimeout(3)
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    with self.lock:
                        self.scan_results[port]['banner'] = banner[:100]
                except:
                    with self.lock:
                        self.scan_results[port]['banner'] = 'No banner retrieved'
            else:
                with self.lock:
                    self.closed_ports.append(port)
            
            sock.close()
            
        except socket.error:
            with self.lock:
                self.closed_ports.append(port)
    
    def scan_ports(self, ports):
        print(f"\n{Fore.CYAN}🔍 Scanning {len(ports)} ports on {self.target}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}⏱️  Timeout: {self.timeout}s | Max Threads: {self.max_threads}{Style.RESET_ALL}")
        print("-" * 50)
        
        start_time = time.time()
        
        for port in ports:
            thread = threading.Thread(target=self.scan_port, args=(port,))
            self.threads.append(thread)
            thread.start()
            
            if len(self.threads) >= self.max_threads:
                for t in self.threads:
                    t.join()
                self.threads = []
        
        for thread in self.threads:
            thread.join()
        
        elapsed = time.time() - start_time
        print(f"\n{Fore.GREEN} Scan completed in {elapsed:.2f} seconds{Style.RESET_ALL}")
    
    def scan_common_ports(self):
        ports = [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 
                445, 993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 
                6379, 8080, 8443, 27017]
        self.scan_ports(ports)
    
    def scan_range(self, start_port, end_port):
        ports = list(range(start_port, end_port + 1))
        self.scan_ports(ports)
    
    def scan_custom(self, ports):
        self.scan_ports(ports)
    
    def generate_report(self):
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Style.BRIGHT}{Fore.MAGENTA} PORT SCAN REPORT{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}SCAN SUMMARY:{Style.RESET_ALL}")
        print(f"  Target: {self.target}")
        print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Total Ports Scanned: {len(self.open_ports) + len(self.closed_ports)}")
        print(f"  Open Ports: {len(self.open_ports)}")
        print(f"  Closed Ports: {len(self.closed_ports)}")
        
        if self.open_ports:
            print(f"\n{Fore.GREEN}🔓 OPEN PORTS:{Style.RESET_ALL}")
            print("-" * 70)
            
            self.open_ports.sort()
            
            for port in self.open_ports:
                info = self.scan_results[port]
                service = info['service']
                vulnerable = info['vulnerable']
                banner = info.get('banner', 'N/A')
                
                if vulnerable:
                    port_color = Fore.RED
                    vuln_tag = f"{Fore.RED} VULNERABLE{Style.RESET_ALL} ⚠️ "
                else:
                    port_color = Fore.GREEN
                    vuln_tag = f"{Fore.GREEN}Secure{Style.RESET_ALL} ✅ "
                
                print(f"  {port_color}Port {port:>5}{Style.RESET_ALL} | {service:<12} | {vuln_tag}")
                if vulnerable:
                    print(f"          └─ {Fore.YELLOW}Note: {info['vulnerability_note']}{Style.RESET_ALL}")
                if banner and banner != 'N/A':
                    print(f"          └─ Banner: {banner[:60]}...")
            
            print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
            print(f"{Style.BRIGHT}{Fore.GREEN}🛡️SECURITY RECOMMENDATIONS🛡️{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
            
            recommendations = []
            
            vulnerable_ports = [p for p in self.open_ports if p in self.VULNERABLE_SERVICES]
            if vulnerable_ports:
                recommendations.append(f"{Fore.RED}Vulnerable services detected on ports: {', '.join(map(str, vulnerable_ports))}")
                recommendations.append(f"{Fore.YELLOW}Consider implementing: Service hardening, ACLs, firewall rules")
            
            admin_ports = [22, 3389, 5900, 8080, 8443]
            open_admin = [p for p in self.open_ports if p in admin_ports]
            if open_admin:
                recommendations.append(f"{Fore.YELLOW} Administrative ports open: {', '.join(map(str, open_admin))}")
                recommendations.append(f"{Fore.YELLOW} Restrict access using IP whitelisting or VPN")
            
            if len(self.open_ports) > 5:
                recommendations.append(f"{Fore.YELLOW}High number of open ports detected. Review necessity.")
            
            recommendations.append(f"{Fore.GREEN}-Implement proper firewall rules")
            recommendations.append(f"{Fore.GREEN}-Use strong authentication for all services")
            recommendations.append(f"{Fore.GREEN}-Keep all services patched and updated")
            recommendations.append(f"{Fore.GREEN}-Monitor logs for suspicious connection attempts")
            
            for rec in recommendations:
                print(f"  {rec}")
            
        else:
            print(f"\n{Fore.GREEN}🔒 No open ports found. Target appears secure.{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.GREEN} Scan complete!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")

def get_example_targets():
    return ['localhost', '192.168.1.1', 'google.com', 'scanme.nmap.org', 'github.com']

def interactive_mode():
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}{Fore.MAGENTA}🛡️  PORT SCANNER - Blue Team Edition{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"\n{Fore.WHITE}Options:{Style.RESET_ALL}")
    print("  1. Scan common ports (Top 27)")
    print("  2. Scan port range (e.g., 1-1000)")
    print("  3. Scan custom ports")
    print("  4. Quick scan (Most vulnerable ports)")
    print("  5. Use example target")
    print("  6. Exit")
    
    try:
        choice = input(f"\n{Fore.YELLOW}Select an option (1-6): {Style.RESET_ALL}").strip()
        
        if choice == '6':
            print(f"\n{Fore.GREEN}👋 Goodbye!{Style.RESET_ALL}")
            sys.exit(0)
        
        target = input(f"{Fore.YELLOW}Enter target (IP or hostname): {Style.RESET_ALL}").strip()
        if not target:
            if choice == '5':
                print(f"\n{Fore.CYAN}Example targets:{Style.RESET_ALL}")
                for i, ex in enumerate(get_example_targets(), 1):
                    print(f"  {i}. {ex}")
                ex_choice = input(f"{Fore.YELLOW}Select example (1-5): {Style.RESET_ALL}").strip()
                try:
                    target = get_example_targets()[int(ex_choice) - 1]
                except:
                    target = 'scanme.nmap.org'
            else:
                target = 'scanme.nmap.org'
                print(f"{Fore.YELLOW}⚠️  No target entered. Using: {target}{Style.RESET_ALL}")
        
        scanner = PortScanner(target)
        
        if not scanner.resolve_hostname():
            return
        
        if choice == '1':
            scanner.scan_common_ports()
        elif choice == '2':
            try:
                range_input = input(f"{Fore.YELLOW}Enter port range (e.g., 1-1000): {Style.RESET_ALL}").strip()
                start, end = map(int, range_input.split('-'))
                scanner.scan_range(start, end)
            except ValueError:
                print(f"{Fore.RED}❌ Invalid range format. Using 1-1000.{Style.RESET_ALL}")
                scanner.scan_range(1, 1000)
        elif choice == '3':
            ports_input = input(f"{Fore.YELLOW}Enter ports (comma-separated, e.g., 22,80,443): {Style.RESET_ALL}").strip()
            try:
                ports = [int(p.strip()) for p in ports_input.split(',')]
                scanner.scan_custom(ports)
            except ValueError:
                print(f"{Fore.RED}❌ Invalid port list. Using common ports.{Style.RESET_ALL}")
                scanner.scan_common_ports()
        elif choice == '4':
            quick_ports = [21, 22, 23, 25, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5900, 8080]
            scanner.scan_custom(quick_ports)
        elif choice == '5':
            scanner.scan_common_ports()
        else:
            print(f"{Fore.RED}❌ Invalid choice. Scanning common ports.{Style.RESET_ALL}")
            scanner.scan_common_ports()
        
        scanner.generate_report()
        
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}⚠️  Scan interrupted{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}❌ Error: {e}{Style.RESET_ALL}")

def command_line_mode():
    if len(sys.argv) < 2:
        print(f"{Fore.YELLOW}💡 Usage: python port_scanner.py <target> [ports]{Style.RESET_ALL}")
        print(f"   Examples:")
        print(f"     python port_scanner.py scanme.nmap.org")
        print(f"     python port_scanner.py 192.168.1.1 22,80,443")
        print(f"     python port_scanner.py localhost 1-1000")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = PortScanner(target)
    
    if not scanner.resolve_hostname():
        sys.exit(1)
    
    if len(sys.argv) >= 3:
        ports_input = sys.argv[2]
        if '-' in ports_input:
            start, end = map(int, ports_input.split('-'))
            scanner.scan_range(start, end)
        else:
            ports = [int(p.strip()) for p in ports_input.split(',')]
            scanner.scan_custom(ports)
    else:
        scanner.scan_common_ports()
    
    scanner.generate_report()

def main():
    if len(sys.argv) > 1:
        command_line_mode()
    else:
        interactive_mode()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}⚠️  Operation cancelled{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}❌ An unexpected error occurred: {e}{Style.RESET_ALL}")
        sys.exit(1)