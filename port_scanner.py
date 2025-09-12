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
import asyncio
import struct
import random
from pathlib import Path
from html import escape
from urllib.parse import quote

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
    protocol: str = "TCP"  # TCP or UDP
    service: str = ""
    banner: str = ""
    response_time: float = 0.0
    pid: Optional[int] = None
    process: str = ""
    process_path: str = ""
    local_address: str = ""
    # Enhanced service detection
    service_version: str = ""
    service_info: str = ""
    fingerprint: str = ""
    confidence: float = 0.0
    # Environment annotations
    is_wsl: bool = False
    wsl_distro: str = ""
    wsl_process: str = ""
    wsl_path: str = ""
    docker_container: str = ""
    docker_image: str = ""
    docker_container_id: str = ""

class PortScanner:
    """Advanced port scanner with multi-threading and UDP support"""
    
    def __init__(self, timeout: float = 1.0, max_workers: int = 100, enable_banner: bool = False, host_concurrency: int = 16, enable_udp: bool = False):
        self.timeout = timeout
        self.max_workers = max_workers
        self.enable_banner = enable_banner
        self.host_concurrency = host_concurrency
        self.enable_udp = enable_udp
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
        
        # Common UDP ports for scanning
        self.common_udp_ports = {
            53: "DNS", 67: "DHCP Server", 68: "DHCP Client", 69: "TFTP",
            123: "NTP", 161: "SNMP", 162: "SNMP Trap", 514: "Syslog",
            1900: "UPnP", 5353: "mDNS", 137: "NetBIOS Name", 138: "NetBIOS Datagram",
            500: "IPSec", 4500: "IPSec NAT-T", 1701: "L2TP", 1812: "RADIUS Auth",
            1813: "RADIUS Accounting", 623: "IPMI", 5060: "SIP", 5061: "SIP-TLS"
        }
        
        # Service detection patterns
        self.service_patterns = {
            'HTTP': [(r'HTTP/\d\.\d', r'Server:\s*([^\r\n]+)'), (b'HTTP/', 0.9)],
            'SSH': [(r'SSH-\d\.\d-([^\r\n]+)', None), (b'SSH-', 0.95)],
            'FTP': [(r'220[\s-]([^\r\n]+)', None), (b'220 ', 0.9)],
            'SMTP': [(r'220[\s-]([^\r\n]+)', None), (b'220 ', 0.85)],
            'POP3': [(r'\+OK\s+([^\r\n]+)', None), (b'+OK', 0.9)],
            'IMAP': [(r'\*\s+OK\s+([^\r\n]+)', None), (b'* OK', 0.9)],
            'MySQL': [(None, None), (b'\x00\x00\x00\x0a', 0.8)],
            'PostgreSQL': [(None, None), (b'\x00\x00\x00\x08\x04\xd2\x16/', 0.8)],
            'Redis': [(r'-ERR\s+([^\r\n]+)', None), (b'-ERR', 0.9)],
            'MongoDB': [(None, None), (b'\x3a\x00\x00\x00', 0.7)]
        }
        
        self._system = platform.system().lower()
        self._local_port_proc_map: Dict[int, Dict[str, str]] = {}
        self._cancel_event = threading.Event()

    def cancel(self) -> None:
        """Request cooperative cancellation of in-flight scans."""
        self._cancel_event.set()

    def reset_cancel(self) -> None:
        """Clear the cancellation event before starting a new scan."""
        self._cancel_event.clear()

    def is_cancelled(self) -> bool:
        """Check whether a cancellation has been requested."""
        return self._cancel_event.is_set()
        
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
            
    def detect_service(self, host: str, port: int, banner: str, protocol: str = "TCP") -> Tuple[str, str, str, float]:
        """Enhanced service detection using pattern matching and fingerprinting"""
        service_name = ""
        service_version = ""
        service_info = ""
        confidence = 0.0
        
        if not banner:
            # Use port-based detection as fallback
            if protocol == "TCP" and port in self.common_ports:
                service_name = self.common_ports[port]
                confidence = 0.6
            elif protocol == "UDP" and port in self.common_udp_ports:
                service_name = self.common_udp_ports[port]
                confidence = 0.6
            else:
                service_name = "Unknown"
                confidence = 0.1
            return service_name, service_version, service_info, confidence
        
        banner_bytes = banner.encode('utf-8', errors='ignore')
        
        # Check against service patterns
        for service, (patterns, marker_info) in self.service_patterns.items():
            marker, base_confidence = marker_info
            
            if marker and marker in banner_bytes:
                service_name = service
                confidence = base_confidence
                
                if patterns and patterns[0]:  # Version pattern
                    version_match = re.search(patterns[0], banner, re.IGNORECASE)
                    if version_match:
                        service_version = version_match.group(1)
                        confidence += 0.1
                
                if patterns and patterns[1]:  # Additional info pattern
                    info_match = re.search(patterns[1], banner, re.IGNORECASE)
                    if info_match:
                        service_info = info_match.group(1)
                        confidence += 0.05
                
                break
        
        # If no pattern match, try basic service detection
        if not service_name:
            if protocol == "TCP" and port in self.common_ports:
                service_name = self.common_ports[port]
                confidence = 0.4
            elif protocol == "UDP" and port in self.common_udp_ports:
                service_name = self.common_udp_ports[port]
                confidence = 0.4
            else:
                service_name = "Unknown"
                confidence = 0.1
        
        return service_name, service_version, service_info, min(confidence, 1.0)
    
    def grab_banner(self, host: str, port: int, protocol: str = "TCP") -> str:
        """Attempt to grab service banner with protocol support"""
        if protocol == "UDP":
            return self._grab_udp_banner(host, port)
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Try to grab banner for common services
            if port in [21, 22, 23, 25, 110, 143]:  # Services that send banners
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            elif port in [80, 8080, 443, 8443]:  # HTTP/HTTPS services
                request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: PortScanner/1.0\r\nConnection: close\r\n\r\n"
                sock.send(request.encode())
                banner = sock.recv(4096).decode('utf-8', errors='ignore').strip()
            elif port == 3306:  # MySQL
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            elif port == 5432:  # PostgreSQL
                # Send startup message
                startup_msg = struct.pack('>I', 8) + struct.pack('>I', 196608) 
                sock.send(startup_msg)
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            elif port == 6379:  # Redis
                sock.send(b"INFO\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            elif port == 27017:  # MongoDB
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            else:
                # Try generic banner grab
                sock.send(b"\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                
            sock.close()
            return banner[:500] if banner else ""  # Increased limit for better detection
        except:
            return ""
    
    def _grab_udp_banner(self, host: str, port: int) -> str:
        """Attempt to grab UDP service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Service-specific UDP probes
            if port == 53:  # DNS
                # Send DNS query for version.bind
                query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03'
                sock.sendto(query, (host, port))
                data, _ = sock.recvfrom(1024)
                return data.decode('utf-8', errors='ignore')[:200]
            elif port == 123:  # NTP
                # Send NTP query
                ntp_query = b'\x1b' + b'\x00' * 47
                sock.sendto(ntp_query, (host, port))
                data, _ = sock.recvfrom(1024)
                return "NTP Response: " + data.hex()[:50]
            elif port == 161:  # SNMP
                # Send SNMP get request
                snmp_query = b'\x30\x19\x02\x01\x00\x04\x06public\xa0\x0c\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x00'
                sock.sendto(snmp_query, (host, port))
                data, _ = sock.recvfrom(1024)
                return "SNMP Response"
            elif port == 69:  # TFTP
                # Send TFTP read request
                tftp_query = b'\x00\x01test\x00octet\x00'
                sock.sendto(tftp_query, (host, port))
                data, _ = sock.recvfrom(1024)
                return "TFTP Response"
            else:
                # Generic UDP probe
                sock.sendto(b'\x00', (host, port))
                data, _ = sock.recvfrom(1024)
                return data.decode('utf-8', errors='ignore')[:200]
                
        except socket.timeout:
            return "UDP Timeout"
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
                    name = (row.get('Image Name') or row.get('ImageName') or '').strip('"')
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
            
    def scan_udp_port(self, host: str, port: int) -> ScanResult:
        """Scan a single UDP port"""
        start_time = time.time()
        
        if self._cancel_event.is_set():
            return ScanResult(host, port, "CANCELLED", "UDP", "", "", 0.0)
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send a probe packet
            if port == 53:  # DNS
                probe = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01'
            elif port == 123:  # NTP
                probe = b'\x1b' + b'\x00' * 47
            elif port == 161:  # SNMP
                probe = b'\x30\x19\x02\x01\x00\x04\x06public\xa0\x0c\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x00'
            else:
                probe = b'\x00' * 4
            
            sock.sendto(probe, (host, port))
            
            try:
                data, _ = sock.recvfrom(1024)
                response_time = time.time() - start_time
                service = self.common_udp_ports.get(port, "Unknown")
                banner = self._grab_udp_banner(host, port) if self.enable_banner else ""
                
                # Enhanced service detection
                service_name, service_version, service_info, confidence = self.detect_service(host, port, banner, "UDP")
                
                result = ScanResult(host, port, "OPEN", "UDP", service_name, banner, response_time)
                result.service_version = service_version
                result.service_info = service_info
                result.confidence = confidence
                
                sock.close()
                return result
                
            except socket.timeout:
                # UDP timeout doesn't necessarily mean closed
                response_time = time.time() - start_time
                sock.close()
                return ScanResult(host, port, "OPEN|FILTERED", "UDP", "", "", response_time)
                
        except Exception as e:
            logger.debug(f"Error scanning UDP {host}:{port} - {e}")
            return ScanResult(host, port, "ERROR", "UDP", "", str(e), time.time() - start_time)
    
    def scan_port(self, host: str, port: int, protocol: str = "TCP") -> ScanResult:
        """Scan a single port with protocol support"""
        if protocol == "UDP":
            return self.scan_udp_port(host, port)
            
        start_time = time.time()
        
        # Early out if cancelled; avoid any network I/O
        if self._cancel_event.is_set():
            return ScanResult(host, port, "CANCELLED", "TCP", "", "", 0.0)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            response_time = time.time() - start_time
            
            if result == 0:
                service = self.get_service_name(port)
                banner = self.grab_banner(host, port, "TCP") if self.enable_banner else ""
                
                # Enhanced service detection
                service_name, service_version, service_info, confidence = self.detect_service(host, port, banner, "TCP")
                
                scan_result = ScanResult(host, port, "OPEN", "TCP", service_name, banner, response_time)
                scan_result.service_version = service_version
                scan_result.service_info = service_info
                scan_result.confidence = confidence
                scan_result.fingerprint = banner[:100] if banner else ""
                
                sock.close()
                return scan_result
            else:
                sock.close()
                return ScanResult(host, port, "CLOSED", "TCP", "", "", response_time)
                
        except socket.timeout:
            return ScanResult(host, port, "FILTERED", "TCP", "", "", self.timeout)
        except Exception as e:
            logger.debug(f"Error scanning {host}:{port} - {e}")
            return ScanResult(host, port, "ERROR", "TCP", "", str(e), time.time() - start_time)
            
    def scan_host_ports(self, host: str, ports: List[int], protocols: List[str] = None, show_progress: bool = True, progress_callback: Optional[Callable[[int, int, ScanResult], None]] = None) -> List[ScanResult]:
        """Scan multiple ports on a single host with protocol support"""
        if protocols is None:
            protocols = ["TCP"]
            if self.enable_udp:
                protocols.append("UDP")
                
        results = []
        
        if self._cancel_event.is_set():
            return results

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

        total_scans = len(ports) * len(protocols)
        logger.info(f"Scanning {len(ports)} ports on {host} using protocols: {', '.join(protocols)}")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port_protocol: Dict = {}
            # Submit tasks cooperatively, stop if cancelled
            for p in ports:
                for protocol in protocols:
                    if self._cancel_event.is_set():
                        break
                    future_to_port_protocol[executor.submit(self.scan_port, host, p, protocol)] = (p, protocol)

            completed = 0
            try:
                for future in as_completed(future_to_port_protocol):
                    if self._cancel_event.is_set():
                        # Cancel any pending futures and break
                        try:
                            executor.shutdown(cancel_futures=True)  # type: ignore[arg-type]
                        except TypeError:
                            # Python < 3.9 compatibility: fall back to manual cancel
                            for f in future_to_port_protocol:
                                if not f.done():
                                    f.cancel()
                        break

                    result = future.result()
                    # Enrich with process info for local scans
                    if port_proc_map:
                        self._enrich_with_process_info(result, port_proc_map)
                    # Add WSL and Docker annotations
                    if docker_map or wsl_map:
                        self._enrich_with_envs(result, wsl_map, docker_map, wsl_distro)
                    results.append(result)
                    completed += 1

                    # Only print progress if explicitly requested, no callback provided, and not cancelled
                    if show_progress and progress_callback is None and completed % 10 == 0 and not self._cancel_event.is_set():
                        print(f"Progress: {completed}/{total_scans} scans completed", end='\r')

                    # Notify progress callback, if provided and not cancelled
                    if progress_callback is not None and not self._cancel_event.is_set():
                        try:
                            progress_callback(completed, total_scans, result)
                        except Exception:
                            # Ensure scanning continues even if callback has issues
                            pass
            except Exception:
                # Ensure executor is asked to cancel pending futures on unexpected error
                try:
                    executor.shutdown(cancel_futures=True)  # type: ignore[arg-type]
                except TypeError:
                    pass
                raise

        if show_progress and progress_callback is None and not self._cancel_event.is_set():
            print()  # New line after progress when we own console output
        
        # Sort results by port number, then by protocol
        results.sort(key=lambda x: (x.port, x.protocol))
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
                elif self._system == 'darwin':
                    # On macOS, -W is milliseconds
                    cmd = ["ping", "-c", "1", "-W", "1000", host_ip]
                else:
                    # Linux: -W is seconds
                    cmd = ["ping", "-c", "1", "-W", "1", host_ip]
                
                # Run ping command
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                
                # Check if ping was successful
                if result.returncode == 0:
                    return host_ip
                return None
                
            except FileNotFoundError as e:
                logger.debug(f"Ping unavailable on system for {host_ip}: {e}")
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
    
    def scan_network_range(self, network: str, ports: List[int], protocols: List[str] = None, ping_first: bool = True, progress_callback: Optional[Callable[[int, int, ScanResult], None]] = None) -> Dict[str, List[ScanResult]]:
        """Scan ports across a network range with bounded host-level concurrency.
        If a progress_callback is provided, it will be invoked for each completed
        port across all hosts with (completed, total, result).
        
        Args:
            network: Network range in CIDR format (e.g., "192.168.1.0/24")
            ports: List of port numbers to scan
            protocols: List of protocols to scan (TCP, UDP)
            ping_first: If True, perform ping sweep first to identify live hosts
            progress_callback: Optional callback for progress updates
        """
        if protocols is None:
            protocols = ["TCP"]
            if self.enable_udp:
                protocols.append("UDP")
                
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            logger.error(f"Invalid network range: {network} - {e}")
            return {}

        all_results: Dict[str, List[ScanResult]] = {}

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
        total_protocols = len(protocols)
        grand_total = total_hosts * total_ports * total_protocols if total_ports > 0 else 0
        completed_counter = 0

        def _wrap_progress_callback(_completed_for_host: int, _total_for_host: int, result: ScanResult):
            nonlocal completed_counter
            if self._cancel_event.is_set():
                return
            # Increment global counter for each finished port
            completed_counter += 1
            if progress_callback is not None and grand_total > 0:
                try:
                    progress_callback(completed_counter, grand_total, result)
                except Exception:
                    pass

        # Host-level parallelism with bounded concurrency
        host_futures = {}
        with ThreadPoolExecutor(max_workers=self.host_concurrency) as host_executor:
            for host_str in hosts_to_scan:
                if self._cancel_event.is_set():
                    break
                host_futures[host_executor.submit(self.scan_host_ports, host_str, ports, protocols, False, _wrap_progress_callback)] = host_str

            try:
                for fut in as_completed(host_futures):
                    if self._cancel_event.is_set():
                        # Cancel pending host scans and break
                        try:
                            host_executor.shutdown(cancel_futures=True)  # type: ignore[arg-type]
                        except TypeError:
                            for f in host_futures:
                                if not f.done():
                                    f.cancel()
                        break
                    host = host_futures[fut]
                    try:
                        results = fut.result()
                    except Exception as e:
                        logger.debug(f"Host scan failed for {host}: {e}")
                        results = []
                    open_ports = [r for r in results if r.status == "OPEN"]
                    if open_ports:
                        all_results[host] = results
            except Exception:
                try:
                    host_executor.shutdown(cancel_futures=True)  # type: ignore[arg-type]
                except TypeError:
                    pass
                raise

        return all_results
    
    async def async_scan_port(self, host: str, port: int, protocol: str = "TCP") -> ScanResult:
        """Async version of port scanning for better performance"""
        if protocol == "UDP":
            return await self._async_scan_udp_port(host, port)
        
        start_time = time.time()
        
        if self._cancel_event.is_set():
            return ScanResult(host, port, "CANCELLED", "TCP", "", "", 0.0)
        
        try:
            # Use asyncio for non-blocking I/O
            loop = asyncio.get_event_loop()
            
            # Create socket connection with timeout
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )
                
                response_time = time.time() - start_time
                
                # Get banner if enabled
                banner = ""
                if self.enable_banner:
                    banner = await self._async_grab_banner(reader, writer, host, port, "TCP")
                
                writer.close()
                await writer.wait_closed()
                
                # Enhanced service detection
                service_name, service_version, service_info, confidence = self.detect_service(host, port, banner, "TCP")
                
                scan_result = ScanResult(host, port, "OPEN", "TCP", service_name, banner, response_time)
                scan_result.service_version = service_version
                scan_result.service_info = service_info
                scan_result.confidence = confidence
                scan_result.fingerprint = banner[:100] if banner else ""
                
                return scan_result
                
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                response_time = time.time() - start_time
                if response_time >= self.timeout:
                    return ScanResult(host, port, "FILTERED", "TCP", "", "", response_time)
                else:
                    return ScanResult(host, port, "CLOSED", "TCP", "", "", response_time)
                    
        except Exception as e:
            logger.debug(f"Error async scanning {host}:{port} - {e}")
            return ScanResult(host, port, "ERROR", "TCP", "", str(e), time.time() - start_time)
    
    async def _async_scan_udp_port(self, host: str, port: int) -> ScanResult:
        """Async UDP port scanning"""
        start_time = time.time()
        
        if self._cancel_event.is_set():
            return ScanResult(host, port, "CANCELLED", "UDP", "", "", 0.0)
        
        try:
            loop = asyncio.get_event_loop()
            
            # Create UDP socket
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: asyncio.DatagramProtocol(),
                remote_addr=(host, port)
            )
            
            # Send probe packet
            if port == 53:  # DNS
                probe = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01'
            elif port == 123:  # NTP
                probe = b'\x1b' + b'\x00' * 47
            elif port == 161:  # SNMP
                probe = b'\x30\x19\x02\x01\x00\x04\x06public\xa0\x0c\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x00'
            else:
                probe = b'\x00' * 4
            
            transport.sendto(probe)
            
            try:
                # Wait for response with timeout
                await asyncio.wait_for(asyncio.sleep(0.1), timeout=self.timeout)
                response_time = time.time() - start_time
                
                service = self.common_udp_ports.get(port, "Unknown")
                banner = self._grab_udp_banner(host, port) if self.enable_banner else ""
                
                # Enhanced service detection
                service_name, service_version, service_info, confidence = self.detect_service(host, port, banner, "UDP")
                
                result = ScanResult(host, port, "OPEN", "UDP", service_name, banner, response_time)
                result.service_version = service_version
                result.service_info = service_info
                result.confidence = confidence
                
                transport.close()
                return result
                
            except asyncio.TimeoutError:
                response_time = time.time() - start_time
                transport.close()
                return ScanResult(host, port, "OPEN|FILTERED", "UDP", "", "", response_time)
                
        except Exception as e:
            logger.debug(f"Error async scanning UDP {host}:{port} - {e}")
            return ScanResult(host, port, "ERROR", "UDP", "", str(e), time.time() - start_time)
    
    async def _async_grab_banner(self, reader, writer, host: str, port: int, protocol: str) -> str:
        """Async banner grabbing"""
        try:
            if port in [21, 22, 23, 25, 110, 143]:  # Services that send banners
                data = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                return data.decode('utf-8', errors='ignore').strip()
            elif port in [80, 8080, 443, 8443]:  # HTTP/HTTPS services
                request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: PortScanner/1.0\r\nConnection: close\r\n\r\n"
                writer.write(request.encode())
                await writer.drain()
                data = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
                return data.decode('utf-8', errors='ignore').strip()
            elif port == 6379:  # Redis
                writer.write(b"INFO\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                return data.decode('utf-8', errors='ignore').strip()
            else:
                # Try generic banner grab
                writer.write(b"\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                return data.decode('utf-8', errors='ignore').strip()
        except:
            return ""
    
    async def async_scan_host_ports(self, host: str, ports: List[int], protocols: List[str] = None) -> List[ScanResult]:
        """Async version of host port scanning for better performance"""
        if protocols is None:
            protocols = ["TCP"]
            if self.enable_udp:
                protocols.append("UDP")
        
        results = []
        
        if self._cancel_event.is_set():
            return results
        
        # Resolve hostname if needed
        if not self.is_valid_ip(host):
            resolved_ip = self.resolve_hostname(host)
            if not resolved_ip:
                logger.error(f"Could not resolve hostname: {host}")
                return results
            host = resolved_ip
        
        # Create semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(self.max_workers)
        
        async def scan_with_semaphore(port: int, protocol: str):
            async with semaphore:
                return await self.async_scan_port(host, port, protocol)
        
        # Create all scan tasks
        tasks = []
        for port in ports:
            for protocol in protocols:
                if self._cancel_event.is_set():
                    break
                task = asyncio.create_task(scan_with_semaphore(port, protocol))
                tasks.append(task)
        
        # Execute all tasks and collect results
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            # Filter out exceptions and cancelled tasks
            results = [r for r in results if isinstance(r, ScanResult) and r.status != "CANCELLED"]
        
        # Sort results by port number, then by protocol
        results.sort(key=lambda x: (x.port, x.protocol))
        return results
        
    def get_common_ports(self, protocol: str = "TCP") -> List[int]:
        """Get list of common ports to scan for a specific protocol"""
        if protocol == "UDP":
            return list(self.common_udp_ports.keys())
        return list(self.common_ports.keys())
    
    def get_all_common_ports(self) -> List[int]:
        """Get combined list of common TCP and UDP ports"""
        tcp_ports = set(self.common_ports.keys())
        udp_ports = set(self.common_udp_ports.keys())
        return sorted(list(tcp_ports.union(udp_ports)))
        
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
        
    def generate_html_report(self, results: List[ScanResult] = None, output_file: str = "scan_report.html") -> str:
        """Generate a professional HTML report"""
        if results is None:
            results = self.results
            
        if not results:
            logger.warning("No results to generate report")
            return ""
        
        # Group results by host
        hosts_data = {}
        for result in results:
            if result.host not in hosts_data:
                hosts_data[result.host] = {'tcp': [], 'udp': [], 'open_count': 0, 'total_count': 0}
            
            hosts_data[result.host][result.protocol.lower()].append(result)
            hosts_data[result.host]['total_count'] += 1
            if result.status == "OPEN":
                hosts_data[result.host]['open_count'] += 1
        
        # Generate HTML content
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Port Scanner Report - {datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background: #f5f7fa; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .header h1 {{ margin: 0; font-size: 2.5em; }}
        .header .subtitle {{ opacity: 0.9; margin-top: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #667eea; }}
        .stat-label {{ color: #666; margin-top: 5px; }}
        .host-section {{ background: white; margin-bottom: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }}
        .host-header {{ background: #667eea; color: white; padding: 20px; }}
        .host-title {{ margin: 0; font-size: 1.5em; }}
        .host-stats {{ opacity: 0.9; margin-top: 5px; }}
        .results-table {{ width: 100%; border-collapse: collapse; }}
        .results-table th {{ background: #f8f9fa; padding: 12px; text-align: left; font-weight: 600; }}
        .results-table td {{ padding: 12px; border-bottom: 1px solid #eee; }}
        .results-table tr:hover {{ background: #f8f9fa; }}
        .status-open {{ color: #28a745; font-weight: bold; }}
        .status-closed {{ color: #dc3545; }}
        .status-filtered {{ color: #ffc107; }}
        .protocol-tcp {{ background: #007bff; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.8em; }}
        .protocol-udp {{ background: #6f42c1; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.8em; }}
        .service-info {{ font-size: 0.9em; color: #666; }}
        .confidence {{ font-size: 0.8em; padding: 2px 6px; border-radius: 10px; }}
        .confidence-high {{ background: #d4edda; color: #155724; }}
        .confidence-medium {{ background: #fff3cd; color: #856404; }}
        .confidence-low {{ background: #f8d7da; color: #721c24; }}
        .banner-text {{ font-family: monospace; font-size: 0.8em; max-width: 300px; word-break: break-all; }}
        .footer {{ text-align: center; margin-top: 30px; color: #666; }}
        .no-results {{ text-align: center; padding: 40px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Port Scanner Report</h1>
            <div class="subtitle">Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</div>
        </div>
        
        <div class="summary">
            <div class="stat-card">
                <div class="stat-number">{len(hosts_data)}</div>
                <div class="stat-label">Hosts Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len([r for r in results if r.status == 'OPEN'])}</div>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(results)}</div>
                <div class="stat-label">Total Scans</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(set([r.service for r in results if r.service and r.status == 'OPEN']))}</div>
                <div class="stat-label">Services Found</div>
            </div>
        </div>
"""
        
        # Add host sections
        for host, data in hosts_data.items():
            open_count = data['open_count']
            total_count = data['total_count']
            
            html_content += f"""
        <div class="host-section">
            <div class="host-header">
                <h2 class="host-title">🎯 {escape(host)}</h2>
                <div class="host-stats">{open_count} open ports found out of {total_count} scanned</div>
            </div>
            <table class="results-table">
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>Status</th>
                        <th>Service</th>
                        <th>Version</th>
                        <th>Confidence</th>
                        <th>Response Time</th>
                        <th>Banner</th>
                    </tr>
                </thead>
                <tbody>
"""
            
            # Combine and sort all results for this host
            all_host_results = data['tcp'] + data['udp']
            all_host_results.sort(key=lambda x: (x.port, x.protocol))
            
            for result in all_host_results:
                if result.status not in ["OPEN", "CLOSED", "FILTERED"]:
                    continue
                    
                status_class = f"status-{result.status.lower().replace('|', '-')}"
                protocol_class = f"protocol-{result.protocol.lower()}"
                
                confidence_class = "confidence-low"
                confidence_text = f"{result.confidence:.1%}" if hasattr(result, 'confidence') and result.confidence else "N/A"
                
                if hasattr(result, 'confidence') and result.confidence:
                    if result.confidence >= 0.8:
                        confidence_class = "confidence-high"
                    elif result.confidence >= 0.6:
                        confidence_class = "confidence-medium"
                
                service_version = getattr(result, 'service_version', '') or ''
                service_info = getattr(result, 'service_info', '') or ''
                
                version_display = service_version
                if service_info and service_info != service_version:
                    version_display += f" ({service_info})" if version_display else service_info
                
                banner_display = escape(result.banner)[:100] + ("..." if len(result.banner) > 100 else "") if result.banner else ""
                
                html_content += f"""
                    <tr>
                        <td><strong>{result.port}</strong></td>
                        <td><span class="{protocol_class}">{result.protocol}</span></td>
                        <td><span class="{status_class}">{result.status}</span></td>
                        <td>{escape(result.service) if result.service else 'Unknown'}</td>
                        <td class="service-info">{escape(version_display) if version_display else '-'}</td>
                        <td><span class="confidence {confidence_class}">{confidence_text}</span></td>
                        <td>{result.response_time:.3f}s</td>
                        <td class="banner-text">{banner_display}</td>
                    </tr>
"""
            
            if not all_host_results:
                html_content += '<tr><td colspan="8" class="no-results">No scan results available</td></tr>'
            
            html_content += """
                </tbody>
            </table>
        </div>
"""
        
        # Close HTML
        html_content += f"""
        <div class="footer">
            <p>Report generated by Advanced Port Scanner | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>
"""
        
        # Write to file
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"HTML report generated: {output_file}")
            return output_file
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            return ""
    
    def export_results(self, filename: str, format: str = "json"):
        """Export results to file with multiple format support"""
        if not self.results:
            logger.warning("No results to export")
            return
            
        try:
            if format.lower() == "json":
                data = []
                for result in self.results:
                    result_dict = {
                        "host": result.host,
                        "port": result.port,
                        "protocol": result.protocol,
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
                    }
                    
                    # Add enhanced service detection fields if available
                    if hasattr(result, 'service_version'):
                        result_dict['service_version'] = result.service_version
                    if hasattr(result, 'service_info'):
                        result_dict['service_info'] = result.service_info
                    if hasattr(result, 'confidence'):
                        result_dict['confidence'] = result.confidence
                    if hasattr(result, 'fingerprint'):
                        result_dict['fingerprint'] = result.fingerprint
                    
                    data.append(result_dict)
                    
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
                    
            elif format.lower() == "csv":
                with open(filename, 'w', newline='') as f:
                    f.write("Host,Port,Protocol,Status,Service,ServiceVersion,Confidence,Banner,ResponseTime,PID,Process,ProcessPath,LocalAddress,IsWSL,WSLDistro,WSLProcess,WSLPath,DockerContainer,DockerImage,DockerContainerID\n")
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
                        
                        service_version = getattr(result, 'service_version', '') or ''
                        confidence = getattr(result, 'confidence', 0.0) or 0.0
                        
                        f.write(f'{result.host},{result.port},{result.protocol},{result.status},{result.service},"{service_version}",{confidence:.2f},"{banner_escaped}",{result.response_time},{result.pid or ""},"{proc_name}","{proc_path}","{local_addr}",{str(result.is_wsl).lower()},"{wsld}","{wsln}","{wslp}","{dname}","{dimg}","{dcid}"\n')
                        
            elif format.lower() == "html":
                self.generate_html_report(self.results, filename)
                return
                        
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
    parser.add_argument('--host-concurrency', type=int, default=16,
                       help='Max concurrent host scans for network ranges (default: 16)')
    parser.add_argument('--show-closed', action='store_true',
                       help='Show closed/filtered ports in results')
    parser.add_argument('-o', '--output',
                       help='Output file (supports .json and .csv)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--no-ping', action='store_true',
                       help='Skip ping sweep for network scans (scan all hosts)')
    parser.add_argument('--udp', action='store_true',
                       help='Enable UDP scanning in addition to TCP')
    parser.add_argument('--async', action='store_true',
                       help='Use async I/O for better performance')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        
    # Check system requirements
    if not check_system_requirements():
        sys.exit(1)
        
    # Initialize scanner
    scanner = PortScanner(timeout=args.timeout, max_workers=args.workers, enable_banner=args.banner, host_concurrency=args.host_concurrency, enable_udp=args.udp)
    
    # Determine ports to scan
    ports_to_scan = []
    
    if args.common:
        if args.udp:
            ports_to_scan = scanner.get_all_common_ports()
            logger.info("Scanning common TCP and UDP ports")
        else:
            ports_to_scan = scanner.get_common_ports()
            logger.info("Scanning common TCP ports")
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
        if args.udp:
            ports_to_scan = scanner.get_all_common_ports()
            logger.info("No ports specified, scanning common TCP and UDP ports")
        else:
            ports_to_scan = scanner.get_common_ports()
            logger.info("No ports specified, scanning common TCP ports")
    
    # Remove duplicates and sort
    ports_to_scan = sorted(list(set(ports_to_scan)))
    
    # Start scanning
    start_time = datetime.now()
    logger.info(f"Starting port scan at {start_time}")
    
    # Determine protocols to scan
    protocols = ["TCP"]
    if args.udp:
        protocols.append("UDP")
    
    try:
        if '/' in args.host:  # Network range
            logger.info(f"Scanning network range: {args.host}")
            ping_first = not args.no_ping  # Invert the flag
            all_results = scanner.scan_network_range(args.host, ports_to_scan, protocols, ping_first=ping_first)
            
            for host, results in all_results.items():
                scanner.print_results(results, args.show_closed)
        else:  # Single host
            if getattr(args, 'async', False):
                # Use async scanning for better performance
                import asyncio
                results = asyncio.run(scanner.async_scan_host_ports(args.host, ports_to_scan, protocols))
            else:
                results = scanner.scan_host_ports(args.host, ports_to_scan, protocols)
            scanner.print_results(results, args.show_closed)
            
        end_time = datetime.now()
        duration = end_time - start_time
        logger.info(f"Scan completed in {duration}")
        
        # Export results if requested
        if args.output:
            if args.output.endswith('.html'):
                format_type = "html"
            elif args.output.endswith('.json'):
                format_type = "json"
            else:
                format_type = "csv"
            scanner.export_results(args.output, format_type)
            
    except KeyboardInterrupt:
        logger.info("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
