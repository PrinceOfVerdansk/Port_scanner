
"""
Port Scanner - Blue Team Edition
Day 4 - Cybersecurity Daily Project

A lightweight port scanner for network reconnaissance and security auditing.
Can be used to identify open ports, running services, and potential vulnerabilities.
"""

import socket
import sys
import threading
import time
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class PortScanner:
    """A professional port scanner with service detection capabilities."""
    
    # Common ports and their associated services
    COMMON_PORTS = {
        20: 'FTP-DATA',
        21: 'FTP',
        22: 'SSH',
        23: 'TELNET',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        111: 'RPCBIND',
        135: 'MSRPC',
        139: 'NETBIOS-SSN',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'MICROSOFT-DS',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'MSSQL',
        1521: 'ORACLE-DB',
        1723: 'PPTP',
        3306: 'MYSQL',
        3389: 'RDP',
        5432: 'POSTGRESQL',
        5900: 'VNC',
        6379: 'REDIS',
        8080: 'HTTP-ALT',
        8443: 'HTTPS-ALT',
        27017: 'MONGODB'
    }
    
    # Vulnerable services to flag
    VULNERABLE_SERVICES = {
        21: 'FTP (clear text credentials)',
        23: 'TELNET (unencrypted)',
        1433: 'MSSQL (default credentials risk)',
        3306: 'MySQL (default credentials risk)',
        3389: 'RDP (brute force target)',
        5900: 'VNC (default credentials risk)'
    }

    def __init__(self, target, timeout=2, max_threads=50):
        """
        Initialize the port scanner.
        
        Args:
            target (str): IP address or hostname to scan
            timeout (int): Connection timeout in seconds
            max_threads (int): Maximum number of concurrent threads
        """
        self.target = target
        self.timeout = timeout
        self.max_threads = max_threads
        self.open_ports = []
        self.closed_ports = []
        self.scan_results = {}
        self.threads = []
        self.lock = threading.Lock()

    def resolve_hostname(self):
        """Resolve hostname to IP address."""
        try:
            ip = socket.gethostbyname(self.target)
            print(f"{Fore.GREEN} Resolved {self.target} -> {ip}{Style.RESET_ALL}")
            return ip
        except socket.gaierror:
            print(f"{Fore.RED} Could not resolve hostname: {self.target}{Style.RESET_ALL}")
            return None

    def scan_port(self, port):
        """
        Scan a single port to check if it's open.
        
        Args:
            port (int): Port number to scan
        """
        try:
            # Create a socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt connection
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                # Port is open
                service = self.COMMON_PORTS.get(port, 'UNKNOWN')
                is_vulnerable = port in self.VULNERABLE_SERVICES
                
                with self.lock:
                    self.open_ports.append(port)
                    self.scan_results[port] = {
                        'service': service,
                        'vulnerable': is_vulnerable,
                        'vulnerability_note': self.VULNERABLE_SERVICES.get(port, 'None')
                    }
                
                # Try to get banner (service fingerprinting)
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
            # Socket error, port is likely closed
            with self.lock:
                self.closed_ports.append(port)
    
    def scan_ports(self, ports):
        """
        Scan a list of ports using threading.
        
        Args:
            ports (list): List of port numbers to scan
        """
        print(f"\n{Fore.CYAN}Scanning {len(ports)} ports on {self.target}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW} Timeout: {self.timeout}s | Max Threads: {self.max_threads}{Style.RESET_ALL}")
        print("-" * 50)
        
        start_time = time.time()
        
        # Create thread pool
        for port in ports:
            thread = threading.Thread(target=self.scan_port, args=(port,))
            self.threads.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(self.threads) >= self.max_threads:
                for t in self.threads:
                    t.join()
                self.threads = []
        
        # Wait for remaining threads
        for thread in self.threads:
            thread.join()
        
        elapsed = time.time() - start_time
        print(f"\n{Fore.GREEN} Scan completed in {elapsed:.2f} seconds{Style.RESET_ALL}")
    
    def scan_common_ports(self):
        """Scan the most common 20 ports."""
        ports = [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 
                445, 993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 
                6379, 8080, 8443, 27017]
        self.scan_ports(ports)
    
    def scan_range(self, start_port, end_port):
        """Scan a range of ports."""
        ports = list(range(start_port, end_port + 1))
        self.scan_ports(ports)