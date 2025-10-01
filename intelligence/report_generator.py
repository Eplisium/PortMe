#!/usr/bin/env python3
"""
Enhanced Report Generation Module
Creates beautiful, comprehensive Markdown reports with AI-style summaries
"""

import logging
from typing import List, Dict
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate enhanced markdown reports with executive summaries"""
    
    def __init__(self):
        self.report_template = None
    
    def generate_executive_summary(self, host_assessment: Dict, results: List) -> str:
        """Generate executive summary section"""
        open_ports = host_assessment.get('open_ports', 0)
        risk_level = host_assessment.get('risk_level', 'safe')
        critical_services = host_assessment.get('critical_services', [])
        total_cves = host_assessment.get('total_cves', 0)
        
        summary = f"## 🎯 Executive Summary\n\n"
        
        # Risk assessment
        if risk_level == 'critical':
            summary += f"**⚠️ CRITICAL RISK DETECTED**\n\n"
            summary += f"Your target exposes **{open_ports} services** across open ports. "
            summary += f"**{len(critical_services)} critical vulnerabilities** require immediate attention.\n\n"
        elif risk_level == 'high':
            summary += f"**⚠️ HIGH RISK DETECTED**\n\n"
            summary += f"Your target exposes **{open_ports} services** with significant security concerns.\n\n"
        elif risk_level == 'medium':
            summary += f"**⚠️ MODERATE RISK**\n\n"
            summary += f"Your target exposes **{open_ports} services** with some security concerns.\n\n"
        else:
            summary += f"**✅ GOOD SECURITY POSTURE**\n\n"
            summary += f"Your target exposes **{open_ports} services**. No critical issues detected.\n\n"
        
        # CVE summary
        if total_cves > 0:
            summary += f"**Total CVEs Found:** {total_cves}\n\n"
        
        # Critical services alert
        if critical_services:
            summary += "**Critical Services Requiring Immediate Action:**\n"
            for svc in critical_services[:5]:  # Top 5
                summary += f"- {svc}\n"
            summary += "\n"
        
        return summary
    
    def generate_risk_assessment(self, host_assessment: Dict) -> str:
        """Generate risk assessment section"""
        risk_level = host_assessment.get('risk_level', 'safe')
        total_risk = host_assessment.get('total_risk_score', 0)
        critical_services = host_assessment.get('critical_services', [])
        high_services = host_assessment.get('high_services', [])
        
        section = "## 📊 Risk Assessment\n\n"
        
        # Risk level badge
        risk_emoji = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🔵',
            'safe': '🟢'
        }
        
        emoji = risk_emoji.get(risk_level, '⚪')
        section += f"**Overall Risk Level:** {emoji} {risk_level.upper()}\n"
        section += f"**Risk Score:** {total_risk:.1f}/100\n\n"
        
        # Service breakdown
        section += "### Service Risk Breakdown\n\n"
        
        if critical_services:
            section += f"- 🔴 **Critical Risk:** {len(critical_services)} service(s)\n"
        if high_services:
            section += f"- 🟠 **High Risk:** {len(high_services)} service(s)\n"
        
        if not critical_services and not high_services:
            section += "- 🟢 **No high-risk services detected**\n"
        
        section += "\n"
        
        return section
    
    def generate_recommendations(self, host_assessment: Dict) -> str:
        """Generate recommendations section"""
        recommendations = host_assessment.get('recommendations', [])
        
        if not recommendations:
            return ""
        
        section = "## 🔧 Security Recommendations\n\n"
        section += "Based on the scan results, we recommend the following actions:\n\n"
        
        for i, rec in enumerate(recommendations, 1):
            section += f"{i}. {rec}\n"
        
        section += "\n"
        
        return section
    
    def generate_port_table(self, results: List) -> str:
        """Generate detailed port table"""
        section = "## 🔍 Detailed Port Analysis\n\n"
        
        # Filter open ports
        open_results = [r for r in results if r.status == "OPEN"]
        
        if not open_results:
            section += "*No open ports detected.*\n\n"
            return section
        
        section += "| Port | Protocol | Service | Version | Risk | CVEs |\n"
        section += "|------|----------|---------|---------|------|------|\n"
        
        for result in sorted(open_results, key=lambda x: x.port):
            port = result.port
            protocol = result.protocol
            service = result.service or "Unknown"
            version = result.service_version or "N/A"
            
            # Get risk level and CVE count
            risk_level = getattr(result, 'risk_level', 'safe')
            cves = getattr(result, 'cves', [])
            cve_count = len(cves)
            
            # Risk emoji
            risk_emoji = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🔵',
                'safe': '🟢'
            }
            risk_display = f"{risk_emoji.get(risk_level, '⚪')} {risk_level.upper()}"
            cve_display = f"{cve_count} found" if cve_count > 0 else "None"
            
            section += f"| {port} | {protocol} | {service} | {version} | {risk_display} | {cve_display} |\n"
        
        section += "\n"
        
        return section
    
    def generate_cve_details(self, results: List) -> str:
        """Generate CVE details section"""
        section = "## 🛡️ Vulnerability Details\n\n"
        
        has_cves = False
        
        for result in results:
            if result.status != "OPEN":
                continue
            
            cves = getattr(result, 'cves', [])
            if not cves:
                continue
            
            has_cves = True
            section += f"### {result.service}:{result.port}\n\n"
            
            if result.service_version:
                section += f"**Version:** {result.service_version}\n\n"
            
            for cve in cves:
                cve_id = cve.get('cve', 'Unknown')
                severity = cve.get('severity', 'UNKNOWN')
                score = cve.get('score', 0.0)
                description = cve.get('description', 'No description available')
                link = cve.get('link', '')
                
                # Severity emoji
                severity_emoji = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🔵'
                }
                emoji = severity_emoji.get(severity, '⚪')
                
                section += f"#### {emoji} {cve_id} - {severity} ({score})\n\n"
                section += f"{description}\n\n"
                
                if link:
                    section += f"**More Info:** [{cve_id}]({link})\n\n"
        
        if not has_cves:
            section += "*No vulnerabilities detected in this scan.*\n\n"
        
        return section
    
    def generate_scan_metadata(self, scan_info: Dict) -> str:
        """Generate scan metadata section"""
        section = "## ℹ️ Scan Information\n\n"
        
        section += f"- **Target:** {scan_info.get('target', 'Unknown')}\n"
        section += f"- **Scan Date:** {scan_info.get('date', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}\n"
        section += f"- **Total Ports Scanned:** {scan_info.get('ports_scanned', 0)}\n"
        section += f"- **Open Ports Found:** {scan_info.get('open_ports', 0)}\n"
        section += f"- **Scan Duration:** {scan_info.get('duration', 'N/A')}\n"
        section += f"- **Scanner Version:** PortMe v2.0\n\n"
        
        return section
    
    def generate_mermaid_diagram(self, results: List) -> str:
        """Generate Mermaid diagram for visualization"""
        section = "## 📈 Network Diagram\n\n"
        section += "```mermaid\n"
        section += "graph TD\n"
        
        # Get unique hosts
        hosts = list(set(r.host for r in results if r.status == "OPEN"))
        
        for host in hosts:
            host_id = host.replace('.', '_').replace(':', '_')
            section += f"    {host_id}[{host}]\n"
            
            host_results = [r for r in results if r.host == host and r.status == "OPEN"]
            for result in host_results[:10]:  # Limit to 10 for readability
                service_id = f"{host_id}_p{result.port}"
                risk_level = getattr(result, 'risk_level', 'safe')
                
                # Style based on risk
                if risk_level == 'critical':
                    style = ":::critical"
                elif risk_level == 'high':
                    style = ":::high"
                elif risk_level == 'medium':
                    style = ":::medium"
                else:
                    style = ""
                
                section += f"    {service_id}[{result.service}:{result.port}]{style}\n"
                section += f"    {host_id} --> {service_id}\n"
        
        # Add style definitions
        section += "    classDef critical fill:#e74c3c,stroke:#c0392b,color:#fff\n"
        section += "    classDef high fill:#e67e22,stroke:#d35400,color:#fff\n"
        section += "    classDef medium fill:#f39c12,stroke:#e67e22,color:#fff\n"
        
        section += "```\n\n"
        
        return section
    
    def generate_report(self, results: List, host_assessment: Dict, 
                       scan_info: Dict, output_path: str = None) -> str:
        """
        Generate comprehensive markdown report
        
        Args:
            results: List of scan results
            host_assessment: Host risk assessment
            scan_info: Scan metadata
            output_path: Optional path to save report
            
        Returns:
            Markdown report content
        """
        report = f"# 🔍 Network Security Scan Report\n\n"
        report += f"*Generated by PortMe on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n"
        report += "---\n\n"
        
        # Executive Summary
        report += self.generate_executive_summary(host_assessment, results)
        
        # Risk Assessment
        report += self.generate_risk_assessment(host_assessment)
        
        # Recommendations
        report += self.generate_recommendations(host_assessment)
        
        # Port Table
        report += self.generate_port_table(results)
        
        # CVE Details
        report += self.generate_cve_details(results)
        
        # Network Diagram
        report += self.generate_mermaid_diagram(results)
        
        # Scan Metadata
        report += self.generate_scan_metadata(scan_info)
        
        # Footer
        report += "---\n\n"
        report += "*This report was automatically generated by PortMe - Advanced Port Scanner*\n"
        report += "*For more information, visit: https://github.com/Eplisium/PortMe*\n"
        
        # Save to file if path provided
        if output_path:
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(report)
                logger.info(f"Report saved to {output_path}")
            except Exception as e:
                logger.error(f"Failed to save report: {e}")
        
        return report
