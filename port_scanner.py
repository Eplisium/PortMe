#!/usr/bin/env python3
"""
Advanced Port Scanner
A comprehensive port scanning tool for Windows and Linux/WSL systems
Supports multi-threading, service detection, and banner grabbing
"""

import socket
import threading
import time
import argparse
import sys
import os
import subprocess
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import ipaddress
import logging
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple, Callable
import platform

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('port_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ScanResult:
    """Data class to store scan results"""
    host: str
    port: int
    status: str
    service: str = ""
    banner: str = ""
    response_time: float = 0.0

class PortScanner:
    """Advanced port scanner with multi-threading support"""
    
    def __init__(self, timeout: float = 1.0, max_workers: int = 100):
        self.timeout = timeout
        self.max_workers = max_workers
        self.results: List[ScanResult] = []
        self.common_ports = {
            20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 69: "TFTP", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            135: "MS RPC", 139: "NetBIOS", 445: "SMB", 1433: "MSSQL",
            1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 6379: "Redis", 8080: "HTTP Alt", 8443: "HTTPS Alt",
            3000: "Node.js/Development", 3001: "Node.js Alt", 5000: "Flask/Development",
            8000: "Django/Development", 9000: "Development", 27017: "MongoDB"
        }
        
    def is_valid_ip(self, ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
            
    def resolve_hostname(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror as e:
            logger.error(f"Failed to resolve hostname {hostname}: {e}")
            return None
            
    def get_service_name(self, port: int) -> str:
        """Get service name for a given port"""
        if port in self.common_ports:
            return self.common_ports[port]
        try:
            return socket.getservbyport(port)
        except OSError:
            return "Unknown"
            
    def grab_banner(self, host: str, port: int) -> str:
        """Attempt to grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Try to grab banner for common services
            if port in [21, 22, 23, 25, 110, 143]:  # Services that send banners
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            elif port in [80, 8080]:  # HTTP services
                sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            else:
                # Try generic banner grab
                sock.send(b"\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                
            sock.close()
            return banner[:200] if banner else ""  # Limit banner length
        except:
            return ""
            
    def scan_port(self, host: str, port: int) -> ScanResult:
        """Scan a single port"""
        start_time = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            response_time = time.time() - start_time
            
            if result == 0:
                service = self.get_service_name(port)
                banner = self.grab_banner(host, port)
                sock.close()
                return ScanResult(host, port, "OPEN", service, banner, response_time)
            else:
                sock.close()
                return ScanResult(host, port, "CLOSED", "", "", response_time)
                
        except socket.timeout:
            return ScanResult(host, port, "FILTERED", "", "", self.timeout)
        except Exception as e:
            logger.debug(f"Error scanning {host}:{port} - {e}")
            return ScanResult(host, port, "ERROR", "", str(e), time.time() - start_time)
            
    def scan_host_ports(self, host: str, ports: List[int], show_progress: bool = True, progress_callback: Optional[Callable[[int, int, ScanResult], None]] = None) -> List[ScanResult]:
        """Scan multiple ports on a single host"""
        results = []
        
        # Resolve hostname if needed
        if not self.is_valid_ip(host):
            resolved_ip = self.resolve_hostname(host)
            if not resolved_ip:
                logger.error(f"Could not resolve hostname: {host}")
                return results
            host = resolved_ip
            
        logger.info(f"Scanning {len(ports)} ports on {host}")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all port scanning tasks
            future_to_port = {
                executor.submit(self.scan_port, host, port): port 
                for port in ports
            }
            
            completed = 0
            for future in as_completed(future_to_port):
                result = future.result()
                results.append(result)
                completed += 1
                
                if show_progress and completed % 10 == 0:
                    print(f"Progress: {completed}/{len(ports)} ports scanned", end='\r')
                
                # Notify progress callback, if provided
                if progress_callback is not None:
                    try:
                        progress_callback(completed, len(ports), result)
                    except Exception:
                        # Ensure scanning continues even if callback has issues
                        pass
                    
        if show_progress:
            print()  # New line after progress
            
        # Sort results by port number
        results.sort(key=lambda x: x.port)
        self.results.extend(results)
        return results
        
    def scan_network_range(self, network: str, ports: List[int], progress_callback: Optional[Callable[[int, int, ScanResult], None]] = None) -> Dict[str, List[ScanResult]]:
        """Scan ports across a network range. If a progress_callback is provided, it will
        be invoked for each completed port across all hosts with (completed, total, result)."""
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            logger.error(f"Invalid network range: {network} - {e}")
            return {}
            
        all_results = {}

        # Prepare aggregated progress if callback provided
        total_hosts = sum(1 for _ in network_obj.hosts())
        total_ports = len(ports)
        grand_total = total_hosts * total_ports if total_ports > 0 else 0
        completed_counter = 0

        def _wrap_progress_callback(_completed_for_host: int, _total_for_host: int, result: ScanResult):
            nonlocal completed_counter
            # Increment global counter for each finished port
            completed_counter += 1
            if progress_callback is not None and grand_total > 0:
                try:
                    progress_callback(completed_counter, grand_total, result)
                except Exception:
                    pass
        
        for host in network_obj.hosts():
            host_str = str(host)
            logger.info(f"Scanning host: {host_str}")
            results = self.scan_host_ports(host_str, ports, progress_callback=_wrap_progress_callback)
            open_ports = [r for r in results if r.status == "OPEN"]
            
            if open_ports:  # Only store hosts with open ports
                all_results[host_str] = results
                
        return all_results
        
    def get_common_ports(self) -> List[int]:
        """Get list of common ports to scan"""
        return list(self.common_ports.keys())
        
    def get_port_range(self, start: int, end: int) -> List[int]:
        """Generate port range"""
        return list(range(start, end + 1))
        
    def print_results(self, results: List[ScanResult], show_closed: bool = False):
        """Print scan results in a formatted way"""
        if not results:
            print("No results to display")
            return
            
        print(f"\n{'='*80}")
        print(f"SCAN RESULTS FOR {results[0].host}")
        print(f"{'='*80}")
        print(f"{'PORT':<8} {'STATUS':<12} {'SERVICE':<20} {'BANNER':<30}")
        print(f"{'-'*80}")
        
        for result in results:
            if result.status == "OPEN" or (show_closed and result.status in ["CLOSED", "FILTERED"]):
                banner = result.banner[:30] + "..." if len(result.banner) > 30 else result.banner
                print(f"{result.port:<8} {result.status:<12} {result.service:<20} {banner:<30}")
                
        open_count = sum(1 for r in results if r.status == "OPEN")
        print(f"\nSummary: {open_count} open ports found out of {len(results)} scanned")
        
    def export_results(self, filename: str, format: str = "json"):
        """Export results to file"""
        if not self.results:
            logger.warning("No results to export")
            return
            
        try:
            if format.lower() == "json":
                data = []
                for result in self.results:
                    data.append({
                        "host": result.host,
                        "port": result.port,
                        "status": result.status,
                        "service": result.service,
                        "banner": result.banner,
                        "response_time": result.response_time
                    })
                    
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
                    
            elif format.lower() == "csv":
                with open(filename, 'w') as f:
                    f.write("Host,Port,Status,Service,Banner,ResponseTime\n")
                    for result in self.results:
                        banner_escaped = result.banner.replace('"', '""').replace('\n', ' ')
                        f.write(f'{result.host},{result.port},{result.status},{result.service},"{banner_escaped}",{result.response_time}\n')
                        
            logger.info(f"Results exported to {filename}")
            
        except Exception as e:
            logger.error(f"Failed to export results: {e}")

def check_system_requirements():
    """Check if system meets requirements"""
    system = platform.system().lower()
    logger.info(f"Running on {platform.system()} {platform.release()}")
    
    # Check if running in WSL
    if system == "linux":
        try:
            with open("/proc/version", "r") as f:
                if "microsoft" in f.read().lower():
                    logger.info("Detected WSL environment")
        except:
            pass
            
    return True

def main():
    """Main function with CLI interface"""
    parser = argparse.ArgumentParser(
        description="Advanced Port Scanner - Works on Windows and WSL",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -H 192.168.1.1 -p 80,443,22
  %(prog)s -H example.com --common
  %(prog)s -H 192.168.1.0/24 -p 1-1000
  %(prog)s -H localhost -p 3000 --banner
  %(prog)s -H 127.0.0.1 -p 3000-3010 --timeout 2
        """
    )
    
    parser.add_argument('-H', '--host', required=True,
                       help='Target host or network (e.g., 192.168.1.1 or 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', 
                       help='Ports to scan (e.g., 80,443,22 or 1-1000)')
    parser.add_argument('--common', action='store_true',
                       help='Scan common ports only')
    parser.add_argument('-t', '--timeout', type=float, default=1.0,
                       help='Socket timeout in seconds (default: 1.0)')
    parser.add_argument('-w', '--workers', type=int, default=100,
                       help='Number of worker threads (default: 100)')
    parser.add_argument('--banner', action='store_true',
                       help='Enable banner grabbing')
    parser.add_argument('--show-closed', action='store_true',
                       help='Show closed/filtered ports in results')
    parser.add_argument('-o', '--output',
                       help='Output file (supports .json and .csv)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        
    # Check system requirements
    if not check_system_requirements():
        sys.exit(1)
        
    # Initialize scanner
    scanner = PortScanner(timeout=args.timeout, max_workers=args.workers)
    
    # Determine ports to scan
    ports_to_scan = []
    
    if args.common:
        ports_to_scan = scanner.get_common_ports()
        logger.info("Scanning common ports")
    elif args.ports:
        # Parse port specification
        for port_spec in args.ports.split(','):
            if '-' in port_spec:
                start, end = map(int, port_spec.split('-'))
                ports_to_scan.extend(scanner.get_port_range(start, end))
            else:
                ports_to_scan.append(int(port_spec))
    else:
        # Default to common ports if nothing specified
        ports_to_scan = scanner.get_common_ports()
        logger.info("No ports specified, scanning common ports")
    
    # Remove duplicates and sort
    ports_to_scan = sorted(list(set(ports_to_scan)))
    
    # Start scanning
    start_time = datetime.now()
    logger.info(f"Starting port scan at {start_time}")
    
    try:
        if '/' in args.host:  # Network range
            logger.info(f"Scanning network range: {args.host}")
            all_results = scanner.scan_network_range(args.host, ports_to_scan)
            
            for host, results in all_results.items():
                scanner.print_results(results, args.show_closed)
        else:  # Single host
            results = scanner.scan_host_ports(args.host, ports_to_scan)
            scanner.print_results(results, args.show_closed)
            
        end_time = datetime.now()
        duration = end_time - start_time
        logger.info(f"Scan completed in {duration}")
        
        # Export results if requested
        if args.output:
            format_type = "json" if args.output.endswith('.json') else "csv"
            scanner.export_results(args.output, format_type)
            
    except KeyboardInterrupt:
        logger.info("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
