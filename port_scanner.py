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
import re
import csv

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
    pid: Optional[int] = None
    process: str = ""
    process_path: str = ""
    local_address: str = ""
    # Environment annotations
    is_wsl: bool = False
    wsl_distro: str = ""
    wsl_process: str = ""
    wsl_path: str = ""
    docker_container: str = ""
    docker_image: str = ""
    docker_container_id: str = ""

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
        self._system = platform.system().lower()
        self._local_port_proc_map: Dict[int, Dict[str, str]] = {}
        
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
    
    def is_local_target(self, host: str) -> bool:
        """Determine if the target host refers to the local machine.
        Conservative: only treat loopback as local to avoid false positives."""
        host_l = host.strip().lower()
        return host_l in {"127.0.0.1", "::1", "localhost"}

    def _parse_local_endpoint(self, endpoint: str) -> Tuple[str, Optional[int]]:
        """Parse local endpoint like 127.0.0.1:3000 or [::]:3000 into (addr, port)."""
        ep = endpoint.strip().strip('[]')
        if ':' not in ep:
            return ep, None
        addr, port_str = ep.rsplit(':', 1)
        try:
            return addr, int(port_str)
        except ValueError:
            return addr, None

    def _windows_pid_info_map(self) -> Dict[int, Dict[str, str]]:
        """Build PID -> {name, path} mapping on Windows using WMIC or PowerShell, fallback to tasklist."""
        pid_info: Dict[int, Dict[str, str]] = {}
        # Try WMIC CSV first
        try:
            proc = subprocess.run([
                "wmic", "process", "get", "ProcessId,Name,ExecutablePath", "/format:csv"
            ], capture_output=True, text=True, check=False)
            output = proc.stdout
            if output:
                reader = csv.DictReader([line for line in output.splitlines() if line.strip()])
                for row in reader:
                    try:
                        pid = int(row.get('ProcessId') or row.get('ProcessID') or 0)
                    except Exception:
                        continue
                    if pid:
                        pid_info[pid] = {
                            'name': row.get('Name', '') or '',
                            'path': row.get('ExecutablePath', '') or ''
                        }
                if pid_info:
                    return pid_info
        except FileNotFoundError:
            pass

        # PowerShell fallback
        try:
            ps_cmd = (
                "Get-Process | Select-Object Id,ProcessName,Path | ConvertTo-Json -Depth 1 -Compress"
            )
            proc = subprocess.run([
                "powershell", "-NoProfile", "-Command", ps_cmd
            ], capture_output=True, text=True, check=False)
            if proc.stdout:
                try:
                    data = json.loads(proc.stdout)
                    if isinstance(data, list):
                        for item in data:
                            try:
                                pid = int(item.get('Id'))
                            except Exception:
                                continue
                            if pid:
                                pid_info[pid] = {
                                    'name': item.get('ProcessName') or '',
                                    'path': item.get('Path') or ''
                                }
                        if pid_info:
                            return pid_info
                except Exception:
                    pass
        except FileNotFoundError:
            pass

        # tasklist final fallback (no path info)
        try:
            proc = subprocess.run(["tasklist", "/FO", "CSV"], capture_output=True, text=True, check=False)
            if proc.stdout:
                reader = csv.DictReader([line for line in proc.stdout.splitlines() if line.strip()])
                for row in reader:
                    try:
                        pid = int((row.get('PID') or '').strip().strip('"'))
                    except Exception:
                        continue
                    name = (row.get('Image Name') or row.get('Image Name') or '').strip('"')
                    if pid:
                        pid_info[pid] = {'name': name, 'path': ''}
        except Exception:
            pass
        return pid_info

    def _build_windows_port_process_map(self) -> Dict[int, Dict[str, str]]:
        """Build mapping of local port -> {pid, name, path, address} using netstat on Windows."""
        port_map: Dict[int, Dict[str, str]] = {}
        try:
            proc = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, check=False)
            lines = proc.stdout.splitlines() if proc.stdout else []
        except Exception:
            lines = []

        # Parse netstat output
        for line in lines:
            line = line.strip()
            if not line:
                continue
            parts = re.split(r"\s+", line)
            if not parts:
                continue
            proto = parts[0].upper() if parts else ''
            if proto not in ("TCP", "UDP"):
                continue
            try:
                local_ep = parts[1]
                pid_str = parts[-1]
                addr, port = self._parse_local_endpoint(local_ep)
                pid = int(pid_str)
            except Exception:
                continue
            if port is None:
                continue
            # Keep first seen mapping per port
            port_map.setdefault(port, {
                'pid': pid,
                'address': addr,
            })

        # Enrich with PID info (names and paths)
        if port_map:
            pid_info = self._windows_pid_info_map()
            for p, info in list(port_map.items()):
                pid = info.get('pid')
                meta = pid_info.get(pid, {}) if isinstance(pid, int) else {}
                info['name'] = meta.get('name', '')
                info['path'] = meta.get('path', '')
        return port_map

    def _detect_wsl_default_distro(self) -> str:
        """Detect the default WSL distro name on Windows (best-effort)."""
        try:
            proc = subprocess.run(["wsl.exe", "-l", "-v"], capture_output=True, text=True, check=False)
            out = proc.stdout.splitlines()
            # Look for line starting with '*'
            for line in out:
                if line.strip().startswith('*'):
                    # Format: * Ubuntu-22.04           Running         2
                    return line.strip('* ').split()[0]
            # Fallback: find first non-header line
            for line in out:
                if line.lower().startswith('name'):
                    continue
                if line.strip():
                    return line.split()[0]
        except Exception:
            pass
        return ""

    def _build_wsl_port_process_map(self) -> Dict[int, Dict[str, str]]:
        """From Windows, query the default WSL distro for its listening ports and owning processes."""
        port_map: Dict[int, Dict[str, str]] = {}
        try:
            cmd = (
                "command -v ss >/dev/null 2>&1 && ss -tulpn || netstat -tulpn"
            )
            proc = subprocess.run(["wsl.exe", "-e", "sh", "-lc", cmd], capture_output=True, text=True, check=False)
            lines = proc.stdout.splitlines() if proc.stdout else []
        except Exception:
            lines = []
        for line in lines:
            if not line or line.lower().startswith(('netid', 'proto', 'state')):
                continue
            parts = re.split(r"\s+", line.strip())
            if len(parts) < 5:
                continue
            local_ep = parts[4]
            addr, port = self._parse_local_endpoint(local_ep)
            if port is None:
                continue
            m = re.search(r"users:\(\(\"([^\"]+)\",pid=(\d+)", line)
            pid = None
            name = ''
            if m:
                name = m.group(1)
                try:
                    pid = int(m.group(2))
                except Exception:
                    pid = None
            info: Dict[str, str] = {'address': addr}
            if pid is not None:
                info['pid'] = pid  # type: ignore
                info['name'] = name
                # Resolve path inside WSL
                try:
                    p2 = subprocess.run(["wsl.exe", "-e", "sh", "-lc", f"readlink -f /proc/{pid}/exe || true"], capture_output=True, text=True, check=False)
                    exe_path = (p2.stdout or '').strip()
                except Exception:
                    exe_path = ''
                info['path'] = exe_path
            if port not in port_map:
                port_map[port] = info
        return port_map

    def _build_docker_host_port_map(self) -> Dict[int, Dict[str, str]]:
        """Map host listen ports -> docker container metadata (id, name, image) if Docker is available."""
        mapping: Dict[int, Dict[str, str]] = {}
        cmds = [
            ["docker", "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}"],
        ]
        for cmd in cmds:
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
                if proc.returncode != 0 or not proc.stdout:
                    continue
                for line in proc.stdout.splitlines():
                    parts = line.split('\t')
                    if len(parts) != 4:
                        continue
                    cid, name, image, ports = parts
                    # Extract host ports from Ports column
                    # Examples: "0.0.0.0:3000->3000/tcp, :::3000->3000/tcp" or "127.0.0.1:9229->9229/tcp"
                    for entry in ports.split(','):
                        entry = entry.strip()
                        m = re.search(r":(\d+)->", entry)
                        if not m:
                            continue
                        try:
                            host_port = int(m.group(1))
                        except Exception:
                            continue
                        mapping[host_port] = {"id": cid, "name": name, "image": image}
                if mapping:
                    return mapping
            except FileNotFoundError:
                continue
            except Exception:
                continue
        return mapping

    def _build_linux_port_process_map(self) -> Dict[int, Dict[str, str]]:
        """Build mapping of local port -> {pid, name, path, address} on Linux/WSL using ss or netstat."""
        port_map: Dict[int, Dict[str, str]] = {}
        lines: List[str] = []
        # Try ss first
        try:
            proc = subprocess.run(["ss", "-tulpn"], capture_output=True, text=True, check=False)
            if proc.stdout:
                lines = proc.stdout.splitlines()
        except FileNotFoundError:
            lines = []
        # Fallback to netstat if needed
        if not lines:
            try:
                proc = subprocess.run(["netstat", "-tulpn"], capture_output=True, text=True, check=False)
                if proc.stdout:
                    lines = proc.stdout.splitlines()
            except Exception:
                lines = []
        for line in lines:
            if not line or line.lower().startswith(('netid', 'proto', 'state')):
                continue
            parts = re.split(r"\s+", line.strip())
            if len(parts) < 5:
                continue
            local_ep = parts[4]
            addr, port = self._parse_local_endpoint(local_ep)
            if port is None:
                continue
            # Extract pid and process name from users:(())
            m = re.search(r"users:\(\(\"([^\"]+)\",pid=(\d+)", line)
            pid = None
            name = ''
            if m:
                name = m.group(1)
                try:
                    pid = int(m.group(2))
                except Exception:
                    pid = None
            info: Dict[str, str] = {'address': addr}
            if pid is not None:
                info['pid'] = pid  # type: ignore
                info['name'] = name
                # Try to resolve executable path
                try:
                    exe_path = os.readlink(f"/proc/{pid}/exe")
                except Exception:
                    exe_path = ''
                info['path'] = exe_path
            # Keep first seen for the port
            if port not in port_map:
                port_map[port] = info
        return port_map

    def build_local_port_process_map(self) -> Dict[int, Dict[str, str]]:
        """Public helper to build local port->process mapping based on OS."""
        try:
            if self._system == 'windows':
                return self._build_windows_port_process_map()
            else:
                return self._build_linux_port_process_map()
        except Exception as e:
            logger.debug(f"Failed to build local port/process map: {e}")
            return {}

    def _enrich_with_process_info(self, result: ScanResult, port_proc_map: Dict[int, Dict[str, str]]):
        """Enrich a ScanResult with local process info if available."""
        if result.status != "OPEN":
            return
        info = port_proc_map.get(result.port)
        if not info:
            return
        try:
            result.pid = int(info.get('pid')) if info.get('pid') is not None else None
        except Exception:
            result.pid = None
        result.process = str(info.get('name') or '')
        result.process_path = str(info.get('path') or '')
        result.local_address = str(info.get('address') or '')

    def _enrich_with_envs(self, result: ScanResult, wsl_map: Dict[int, Dict[str, str]], docker_map: Dict[int, Dict[str, str]], wsl_distro: str):
        """Add WSL and Docker annotations when applicable."""
        if result.status != "OPEN":
            return
        # Docker detection (host port mapping)
        d = docker_map.get(result.port)
        if d:
            result.docker_container_id = d.get('id', '')
            result.docker_container = d.get('name', '')
            result.docker_image = d.get('image', '')
        # WSL fallback for Windows localhost when Windows process is generic or empty
        w = wsl_map.get(result.port)
        needs_wsl = False
        if self._system == 'windows' and self.is_local_target(result.host):
            if not result.process or result.process.lower() in {"system", "system idle process", "vmmem", "vmmemwsl", "com.docker.backend", "docker desktop backend"}:
                needs_wsl = True
        if w and needs_wsl:
            # Prefer WSL process details
            result.is_wsl = True
            result.wsl_distro = wsl_distro
            result.wsl_process = str(w.get('name') or '')
            result.wsl_path = str(w.get('path') or '')
            # Overwrite general process fields with WSL ones for display clarity
            try:
                result.pid = int(w.get('pid')) if w.get('pid') is not None else result.pid
            except Exception:
                pass
            result.process = result.wsl_process or result.process
            result.process_path = result.wsl_path or result.process_path
            if not result.local_address:
                result.local_address = str(w.get('address') or '')
            
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
        
        # If target is local, prepare a port->process map to enrich OPEN results
        port_proc_map: Dict[int, Dict[str, str]] = {}
        docker_map: Dict[int, Dict[str, str]] = {}
        wsl_map: Dict[int, Dict[str, str]] = {}
        wsl_distro = ""
        if self.is_local_target(host):
            port_proc_map = self.build_local_port_process_map()
            # Build environment maps
            docker_map = self._build_docker_host_port_map()
            if self._system == 'windows':
                wsl_map = self._build_wsl_port_process_map()
                wsl_distro = self._detect_wsl_default_distro()

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
                # Enrich with process info for local scans
                if port_proc_map:
                    self._enrich_with_process_info(result, port_proc_map)
                # Add WSL and Docker annotations
                if docker_map or wsl_map:
                    self._enrich_with_envs(result, wsl_map, docker_map, wsl_distro)
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
        
    def ping_sweep(self, network: str) -> List[str]:
        """Perform ICMP ping sweep to identify live hosts in a network range
        
        Args:
            network: Network range in CIDR format (e.g., "192.168.1.0/24")
            
        Returns:
            List of live host IP addresses
        """
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            logger.error(f"Invalid network range: {network} - {e}")
            return []
        
        logger.info(f"Starting ping sweep on {network}")
        live_hosts = []
        
        def ping_host(host_ip: str) -> Optional[str]:
            """Ping a single host and return IP if alive"""
            try:
                # Determine ping command based on OS
                if self._system == 'windows':
                    cmd = ["ping", "-n", "1", "-w", "1000", host_ip]
                else:
                    cmd = ["ping", "-c", "1", "-W", "1", host_ip]
                
                # Run ping command
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                
                # Check if ping was successful
                if result.returncode == 0:
                    return host_ip
                return None
                
            except (subprocess.TimeoutExpired, Exception) as e:
                logger.debug(f"Ping failed for {host_ip}: {e}")
                return None
        
        # Multi-threaded ping sweep
        hosts = list(network_obj.hosts())
        logger.info(f"Pinging {len(hosts)} hosts...")
        
        with ThreadPoolExecutor(max_workers=min(50, len(hosts))) as executor:
            future_to_host = {executor.submit(ping_host, str(host)): str(host) for host in hosts}
            
            for future in as_completed(future_to_host):
                result = future.result()
                if result:
                    live_hosts.append(result)
        
        logger.info(f"Found {len(live_hosts)} live hosts out of {len(hosts)} total")
        return sorted(live_hosts, key=lambda x: ipaddress.ip_address(x))
    
    def scan_network_range(self, network: str, ports: List[int], ping_first: bool = True, progress_callback: Optional[Callable[[int, int, ScanResult], None]] = None) -> Dict[str, List[ScanResult]]:
        """Scan ports across a network range. If a progress_callback is provided, it will
        be invoked for each completed port across all hosts with (completed, total, result).
        
        Args:
            network: Network range in CIDR format (e.g., "192.168.1.0/24")
            ports: List of port numbers to scan
            ping_first: If True, perform ping sweep first to identify live hosts
            progress_callback: Optional callback for progress updates
        """
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            logger.error(f"Invalid network range: {network} - {e}")
            return {}
            
        all_results = {}
        
        # Determine which hosts to scan
        if ping_first:
            logger.info("Performing ping sweep to identify live hosts...")
            hosts_to_scan = self.ping_sweep(network)
            if not hosts_to_scan:
                logger.warning("No live hosts found during ping sweep")
                return {}
        else:
            logger.info("Skipping ping sweep as requested")
            hosts_to_scan = [str(host) for host in network_obj.hosts()]

        # Prepare aggregated progress if callback provided
        total_hosts = len(hosts_to_scan)
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
        
        for host_str in hosts_to_scan:
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
        print(f"{'PORT':<8} {'STATUS':<12} {'SERVICE':<14} {'LADDR':<16} {'ENV':<16} {'PROCESS(PID)':<24} {'PATH':<28} {'BANNER':<24}")
        print(f"{'-'*80}")
        
        for result in results:
            if result.status == "OPEN" or (show_closed and result.status in ["CLOSED", "FILTERED"]):
                banner = result.banner[:24] + "..." if len(result.banner) > 24 else result.banner
                proc_label = f"{result.process} ({result.pid})" if result.pid else (result.process or "")
                path = result.process_path
                path_short = (path[:27] + "…") if path and len(path) > 28 else (path or "")
                addr = result.local_address or ""
                addr_short = (addr[:15] + "…") if len(addr) > 16 else addr
                env = ""
                if result.docker_container:
                    env = f"Docker:{result.docker_container}"
                elif result.is_wsl:
                    env = f"WSL:{result.wsl_distro or 'default'}"
                env_short = (env[:15] + "…") if len(env) > 16 else env
                print(f"{result.port:<8} {result.status:<12} {result.service:<14} {addr_short:<16} {env_short:<16} {proc_label:<24} {path_short:<28} {banner:<24}")
        
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
                        "response_time": result.response_time,
                        "pid": result.pid,
                        "process": result.process,
                        "process_path": result.process_path,
                        "local_address": result.local_address,
                        "is_wsl": result.is_wsl,
                        "wsl_distro": result.wsl_distro,
                        "wsl_process": result.wsl_process,
                        "wsl_path": result.wsl_path,
                        "docker_container": result.docker_container,
                        "docker_image": result.docker_image,
                        "docker_container_id": result.docker_container_id
                    })
                    
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
                    
            elif format.lower() == "csv":
                with open(filename, 'w') as f:
                    f.write("Host,Port,Status,Service,Banner,ResponseTime,PID,Process,ProcessPath,LocalAddress,IsWSL,WSLDistro,WSLProcess,WSLPath,DockerContainer,DockerImage,DockerContainerID\n")
                    for result in self.results:
                        banner_escaped = result.banner.replace('"', '""').replace('\n', ' ')
                        proc_path = (result.process_path or '').replace('"', '""')
                        proc_name = (result.process or '').replace('"', '""')
                        local_addr = (result.local_address or '').replace('"', '""')
                        wslp = (result.wsl_path or '').replace('"', '""')
                        wsln = (result.wsl_process or '').replace('"', '""')
                        wsld = (result.wsl_distro or '').replace('"', '""')
                        dname = (result.docker_container or '').replace('"', '""')
                        dimg = (result.docker_image or '').replace('"', '""')
                        dcid = (result.docker_container_id or '').replace('"', '""')
                        f.write(f'{result.host},{result.port},{result.status},{result.service},"{banner_escaped}",{result.response_time},{result.pid or ""},"{proc_name}","{proc_path}","{local_addr}",{str(result.is_wsl).lower()},"{wsld}","{wsln}","{wslp}","{dname}","{dimg}","{dcid}"\n')
                        
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
    parser.add_argument('--no-ping', action='store_true',
                       help='Skip ping sweep for network scans (scan all hosts)')
    
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
            ping_first = not args.no_ping  # Invert the flag
            all_results = scanner.scan_network_range(args.host, ports_to_scan, ping_first=ping_first)
            
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
