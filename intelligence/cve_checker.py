#!/usr/bin/env python3
"""
CVE Detection and Vulnerability Checking Module
Integrates with NVD (National Vulnerability Database) for CVE lookup
"""

import re
import json
import requests
import logging
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from datetime import datetime, timedelta
import hashlib

logger = logging.getLogger(__name__)


class CVEChecker:
    """Check for CVEs in service versions"""
    
    def __init__(self, cache_dir: str = ".cve_cache", cache_ttl_days: int = 7):
        """
        Initialize CVE Checker
        
        Args:
            cache_dir: Directory to store cached CVE data
            cache_ttl_days: Days before cache expires
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.cache_ttl = timedelta(days=cache_ttl_days)
        
        # NVD API endpoint
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Common service to CPE (Common Platform Enumeration) mappings
        self.service_cpe_map = {
            'ssh': 'openssh',
            'openssh': 'openssh',
            'apache': 'apache',
            'nginx': 'nginx',
            'mysql': 'mysql',
            'mariadb': 'mariadb',
            'postgresql': 'postgresql',
            'redis': 'redis',
            'mongodb': 'mongodb',
            'ftp': 'vsftpd',
            'proftpd': 'proftpd',
            'http': 'apache',
            'https': 'apache',
        }
        
        # Local vulnerability database (common/known CVEs)
        self.known_vulnerabilities = self._load_known_vulnerabilities()
    
    def _load_known_vulnerabilities(self) -> Dict:
        """Load known vulnerabilities from local database"""
        # This is a simplified version. In production, this would be a comprehensive database
        return {
            'openssh': {
                '7.4': [
                    {
                        'cve': 'CVE-2018-15473',
                        'severity': 'MEDIUM',
                        'score': 5.3,
                        'description': 'Username enumeration vulnerability',
                        'link': 'https://nvd.nist.gov/vuln/detail/CVE-2018-15473'
                    }
                ],
                '7.7': [
                    {
                        'cve': 'CVE-2019-6111',
                        'severity': 'MEDIUM',
                        'score': 5.9,
                        'description': 'SCP client vulnerability',
                        'link': 'https://nvd.nist.gov/vuln/detail/CVE-2019-6111'
                    }
                ]
            },
            'apache': {
                '2.4.49': [
                    {
                        'cve': 'CVE-2021-41773',
                        'severity': 'CRITICAL',
                        'score': 9.8,
                        'description': 'Path traversal and RCE vulnerability',
                        'link': 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773'
                    }
                ],
                '2.4.50': [
                    {
                        'cve': 'CVE-2021-42013',
                        'severity': 'CRITICAL',
                        'score': 9.8,
                        'description': 'Path traversal and RCE vulnerability (incomplete fix)',
                        'link': 'https://nvd.nist.gov/vuln/detail/CVE-2021-42013'
                    }
                ]
            },
            'nginx': {
                '1.18.0': [
                    {
                        'cve': 'CVE-2021-23017',
                        'severity': 'HIGH',
                        'score': 8.1,
                        'description': 'DNS resolver off-by-one heap write',
                        'link': 'https://nvd.nist.gov/vuln/detail/CVE-2021-23017'
                    }
                ]
            }
        }
    
    def _get_cache_path(self, service: str, version: str) -> Path:
        """Get cache file path for a service/version"""
        cache_key = hashlib.md5(f"{service}:{version}".encode()).hexdigest()
        return self.cache_dir / f"{cache_key}.json"
    
    def _is_cache_valid(self, cache_path: Path) -> bool:
        """Check if cache file is still valid"""
        if not cache_path.exists():
            return False
        
        try:
            mtime = datetime.fromtimestamp(cache_path.stat().st_mtime)
            return datetime.now() - mtime < self.cache_ttl
        except Exception:
            return False
    
    def _load_from_cache(self, service: str, version: str) -> Optional[List[Dict]]:
        """Load CVEs from cache"""
        cache_path = self._get_cache_path(service, version)
        
        if not self._is_cache_valid(cache_path):
            return None
        
        try:
            with open(cache_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.debug(f"Failed to load cache: {e}")
            return None
    
    def _save_to_cache(self, service: str, version: str, cves: List[Dict]):
        """Save CVEs to cache"""
        cache_path = self._get_cache_path(service, version)
        
        try:
            with open(cache_path, 'w') as f:
                json.dump(cves, f, indent=2)
        except Exception as e:
            logger.debug(f"Failed to save cache: {e}")
    
    def parse_service_version(self, banner: str, service: str) -> Optional[Tuple[str, str]]:
        """
        Parse service name and version from banner
        
        Returns:
            Tuple of (service_name, version) or None
        """
        if not banner:
            return None
        
        # Common patterns for version detection
        patterns = [
            # OpenSSH-7.4p1
            (r'OpenSSH[_-](\d+\.\d+(?:\.\d+)?)', 'openssh'),
            # Apache/2.4.41 (Ubuntu)
            (r'Apache/(\d+\.\d+(?:\.\d+)?)', 'apache'),
            # nginx/1.18.0
            (r'nginx/(\d+\.\d+(?:\.\d+)?)', 'nginx'),
            # MySQL 5.7.33
            (r'MySQL[^\d]*(\d+\.\d+(?:\.\d+)?)', 'mysql'),
            # MariaDB 10.5.9
            (r'MariaDB[^\d]*(\d+\.\d+(?:\.\d+)?)', 'mariadb'),
            # PostgreSQL 13.2
            (r'PostgreSQL[^\d]*(\d+\.\d+(?:\.\d+)?)', 'postgresql'),
            # Redis 6.0.9
            (r'Redis[^\d]*(\d+\.\d+(?:\.\d+)?)', 'redis'),
            # MongoDB 4.4.3
            (r'MongoDB[^\d]*(\d+\.\d+(?:\.\d+)?)', 'mongodb'),
            # Generic version pattern
            (r'(\d+\.\d+(?:\.\d+)?)', None)
        ]
        
        for pattern, detected_service in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                version = match.group(1)
                # Use detected service or fallback to provided service
                svc = detected_service or service.lower()
                return (svc, version)
        
        return None
    
    def check_known_vulnerabilities(self, service: str, version: str) -> List[Dict]:
        """Check against local known vulnerabilities database"""
        service = service.lower()
        
        # Map service name to known database key
        db_key = self.service_cpe_map.get(service, service)
        
        if db_key in self.known_vulnerabilities:
            # Extract major.minor version for matching
            version_parts = version.split('.')
            if len(version_parts) >= 2:
                major_minor = f"{version_parts[0]}.{version_parts[1]}"
                
                # Check exact version match
                if version in self.known_vulnerabilities[db_key]:
                    return self.known_vulnerabilities[db_key][version]
                
                # Check major.minor match
                if major_minor in self.known_vulnerabilities[db_key]:
                    return self.known_vulnerabilities[db_key][major_minor]
        
        return []
    
    def query_nvd_api(self, service: str, version: str) -> List[Dict]:
        """
        Query NVD API for CVEs (optional, requires internet)
        
        Note: This is a simplified implementation. Production use should:
        1. Use API key for higher rate limits
        2. Handle pagination
        3. Better error handling and retries
        """
        try:
            # Build search query
            keyword = f"{service} {version}"
            
            params = {
                'keywordSearch': keyword,
                'resultsPerPage': 20
            }
            
            # Add timeout to prevent hanging
            response = requests.get(
                self.nvd_api_base,
                params=params,
                timeout=5,
                headers={'User-Agent': 'PortMe/2.0'}
            )
            
            if response.status_code != 200:
                logger.debug(f"NVD API returned {response.status_code}")
                return []
            
            data = response.json()
            
            # Parse vulnerabilities
            cves = []
            for item in data.get('vulnerabilities', []):
                cve_data = item.get('cve', {})
                cve_id = cve_data.get('id', '')
                
                # Get CVSS score
                metrics = cve_data.get('metrics', {})
                cvss_v3 = metrics.get('cvssMetricV31', [{}])[0] if 'cvssMetricV31' in metrics else {}
                cvss_data = cvss_v3.get('cvssData', {})
                score = cvss_data.get('baseScore', 0.0)
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                
                # Get description
                descriptions = cve_data.get('descriptions', [])
                description = descriptions[0].get('value', '') if descriptions else ''
                
                cves.append({
                    'cve': cve_id,
                    'severity': severity,
                    'score': score,
                    'description': description[:200],  # Truncate long descriptions
                    'link': f'https://nvd.nist.gov/vuln/detail/{cve_id}'
                })
            
            return cves
            
        except requests.Timeout:
            logger.debug("NVD API request timed out")
            return []
        except Exception as e:
            logger.debug(f"Failed to query NVD API: {e}")
            return []
    
    def check_vulnerabilities(self, service: str, version: str = None, banner: str = None, 
                             use_online: bool = False) -> List[Dict]:
        """
        Check for vulnerabilities in a service
        
        Args:
            service: Service name
            version: Service version (optional, will parse from banner if not provided)
            banner: Service banner (optional, used to extract version)
            use_online: Whether to query online NVD API (requires internet)
            
        Returns:
            List of vulnerability dictionaries
        """
        # Parse version from banner if not provided
        if not version and banner:
            parsed = self.parse_service_version(banner, service)
            if parsed:
                service, version = parsed
        
        if not version:
            logger.debug(f"No version information for {service}")
            return []
        
        # Check cache first
        cached = self._load_from_cache(service, version)
        if cached is not None:
            logger.debug(f"Using cached CVE data for {service} {version}")
            return cached
        
        # Check local known vulnerabilities
        cves = self.check_known_vulnerabilities(service, version)
        
        # Optionally query NVD API
        if use_online and not cves:
            logger.debug(f"Querying NVD API for {service} {version}")
            cves = self.query_nvd_api(service, version)
        
        # Cache results
        self._save_to_cache(service, version, cves)
        
        return cves
    
    def get_cve_summary(self, cves: List[Dict]) -> Dict:
        """
        Get summary statistics for a list of CVEs
        
        Returns:
            Dictionary with counts by severity
        """
        summary = {
            'total': len(cves),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'unknown': 0
        }
        
        for cve in cves:
            severity = cve.get('severity', 'UNKNOWN').upper()
            if severity == 'CRITICAL':
                summary['critical'] += 1
            elif severity == 'HIGH':
                summary['high'] += 1
            elif severity == 'MEDIUM':
                summary['medium'] += 1
            elif severity == 'LOW':
                summary['low'] += 1
            else:
                summary['unknown'] += 1
        
        return summary
