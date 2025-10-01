#!/usr/bin/env python3
"""
Risk Scoring Module
Calculates risk scores for services based on CVEs, ports, and configurations
"""

import logging
from typing import List, Dict, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class RiskAssessment:
    """Risk assessment result"""
    risk_level: str  # critical, high, medium, low, safe
    risk_score: float  # 0-100
    factors: List[str]  # Contributing risk factors
    recommendations: List[str]  # Security recommendations
    cve_count: int = 0
    critical_cves: int = 0
    high_cves: int = 0


class RiskScorer:
    """Calculate risk scores for services and hosts"""
    
    def __init__(self):
        # Risk weights for different factors
        self.weights = {
            'critical_cve': 35.0,
            'high_cve': 20.0,
            'medium_cve': 10.0,
            'low_cve': 3.0,
            'sensitive_port': 15.0,
            'outdated_service': 10.0,
            'common_exploit': 20.0,
            'default_config': 15.0
        }
        
        # Known sensitive/risky ports
        self.sensitive_ports = {
            21: 'FTP - Unencrypted file transfer',
            23: 'Telnet - Unencrypted remote access',
            25: 'SMTP - Email relay risks',
            135: 'MS RPC - Windows vulnerability target',
            139: 'NetBIOS - SMB vulnerabilities',
            445: 'SMB - Ransomware attack vector',
            1433: 'MSSQL - Database exposure',
            3306: 'MySQL - Database exposure',
            3389: 'RDP - Brute force target',
            5432: 'PostgreSQL - Database exposure',
            6379: 'Redis - Unauthorized access',
            27017: 'MongoDB - NoSQL injection'
        }
        
        # Default/development ports
        self.dev_ports = {
            3000: 'Node.js development server',
            3001: 'Development server',
            5000: 'Flask/Python development',
            8000: 'Django/development server',
            8080: 'Alternative HTTP',
            9000: 'Development port'
        }
    
    def score_cves(self, cves: List[Dict]) -> float:
        """Calculate risk score from CVEs"""
        score = 0.0
        
        for cve in cves:
            severity = cve.get('severity', 'UNKNOWN').upper()
            
            if severity == 'CRITICAL':
                score += self.weights['critical_cve']
            elif severity == 'HIGH':
                score += self.weights['high_cve']
            elif severity == 'MEDIUM':
                score += self.weights['medium_cve']
            elif severity == 'LOW':
                score += self.weights['low_cve']
        
        return min(score, 100.0)  # Cap at 100
    
    def score_port(self, port: int) -> tuple:
        """
        Calculate risk score for a port
        
        Returns:
            Tuple of (score, reason)
        """
        if port in self.sensitive_ports:
            return (self.weights['sensitive_port'], self.sensitive_ports[port])
        elif port in self.dev_ports:
            return (self.weights['default_config'], self.dev_ports[port])
        else:
            return (0.0, None)
    
    def assess_service(self, service: str, port: int, version: str = None,
                      cves: List[Dict] = None, banner: str = None) -> RiskAssessment:
        """
        Perform comprehensive risk assessment for a service
        
        Args:
            service: Service name
            port: Port number
            version: Service version
            cves: List of CVEs
            banner: Service banner
            
        Returns:
            RiskAssessment object
        """
        risk_score = 0.0
        factors = []
        recommendations = []
        
        # CVE-based risk
        if cves:
            cve_score = self.score_cves(cves)
            risk_score += cve_score
            
            critical = sum(1 for c in cves if c.get('severity', '').upper() == 'CRITICAL')
            high = sum(1 for c in cves if c.get('severity', '').upper() == 'HIGH')
            medium = sum(1 for c in cves if c.get('severity', '').upper() == 'MEDIUM')
            
            if critical > 0:
                factors.append(f"{critical} critical CVE(s) found")
                recommendations.append(f"URGENT: Update {service} immediately - {critical} critical vulnerabilities")
            
            if high > 0:
                factors.append(f"{high} high severity CVE(s) found")
                recommendations.append(f"Update {service} to patch {high} high-severity vulnerabilities")
            
            if medium > 0:
                factors.append(f"{medium} medium severity CVE(s) found")
        
        # Port-based risk
        port_score, port_reason = self.score_port(port)
        if port_score > 0:
            risk_score += port_score
            factors.append(port_reason)
            
            if port in self.sensitive_ports:
                recommendations.append(f"Consider using encrypted alternatives for port {port}")
                
                # Specific recommendations
                if port == 21:
                    recommendations.append("Use SFTP or FTPS instead of FTP")
                elif port == 23:
                    recommendations.append("Use SSH (port 22) instead of Telnet")
                elif port == 3389:
                    recommendations.append("Enable Network Level Authentication and use VPN")
                elif port in [3306, 5432, 1433, 27017]:
                    recommendations.append("Ensure database is not exposed to public internet")
                    recommendations.append("Use firewall rules to restrict access")
        
        # Development port warnings
        if port in self.dev_ports:
            recommendations.append(f"Port {port} appears to be a development server - ensure it's intentional")
        
        # Version-based risk
        if not version and banner:
            recommendations.append("Unable to determine service version - consider enabling banner grabbing")
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = 'critical'
        elif risk_score >= 50:
            risk_level = 'high'
        elif risk_score >= 30:
            risk_level = 'medium'
        elif risk_score >= 10:
            risk_level = 'low'
        else:
            risk_level = 'safe'
        
        # Default recommendations
        if not recommendations:
            recommendations.append("Service appears secure - maintain current security posture")
            recommendations.append("Regular security updates recommended")
        
        return RiskAssessment(
            risk_level=risk_level,
            risk_score=min(risk_score, 100.0),
            factors=factors,
            recommendations=recommendations,
            cve_count=len(cves) if cves else 0,
            critical_cves=sum(1 for c in (cves or []) if c.get('severity', '').upper() == 'CRITICAL'),
            high_cves=sum(1 for c in (cves or []) if c.get('severity', '').upper() == 'HIGH')
        )
    
    def assess_host(self, results: List) -> Dict:
        """
        Perform comprehensive risk assessment for a host
        
        Args:
            results: List of ScanResult objects for a host
            
        Returns:
            Dictionary with host-level risk assessment
        """
        total_risk = 0.0
        critical_services = []
        high_services = []
        all_recommendations = []
        total_cves = 0
        
        for result in results:
            if result.status != "OPEN":
                continue
            
            # Get CVEs if available
            cves = getattr(result, 'cves', [])
            
            # Assess service
            assessment = self.assess_service(
                service=result.service,
                port=result.port,
                version=result.service_version,
                cves=cves,
                banner=result.banner
            )
            
            total_risk += assessment.risk_score
            total_cves += assessment.cve_count
            
            if assessment.risk_level == 'critical':
                critical_services.append(f"{result.service}:{result.port}")
            elif assessment.risk_level == 'high':
                high_services.append(f"{result.service}:{result.port}")
            
            all_recommendations.extend(assessment.recommendations)
        
        # Calculate overall risk level
        if critical_services:
            overall_risk = 'critical'
        elif high_services:
            overall_risk = 'high'
        elif total_risk > 50:
            overall_risk = 'medium'
        elif total_risk > 0:
            overall_risk = 'low'
        else:
            overall_risk = 'safe'
        
        return {
            'risk_level': overall_risk,
            'total_risk_score': min(total_risk, 100.0),
            'open_ports': len([r for r in results if r.status == "OPEN"]),
            'critical_services': critical_services,
            'high_services': high_services,
            'total_cves': total_cves,
            'recommendations': list(set(all_recommendations))[:10],  # Top 10 unique
            'services_analyzed': len([r for r in results if r.status == "OPEN"])
        }
    
    def get_risk_emoji(self, risk_level: str) -> str:
        """Get emoji representation of risk level"""
        emoji_map = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🔵',
            'safe': '🟢'
        }
        return emoji_map.get(risk_level.lower(), '⚪')
    
    def get_risk_description(self, risk_level: str) -> str:
        """Get human-readable risk description"""
        descriptions = {
            'critical': 'CRITICAL - Immediate action required',
            'high': 'HIGH - Urgent attention needed',
            'medium': 'MEDIUM - Should be addressed soon',
            'low': 'LOW - Minor concerns',
            'safe': 'SAFE - No immediate concerns'
        }
        return descriptions.get(risk_level.lower(), 'UNKNOWN')
