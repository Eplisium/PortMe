#!/usr/bin/env python3
"""
Network Visualization Module
Creates interactive network topology graphs from scan results
"""

import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import networkx as nx
from typing import List, Dict, Tuple
from port_scanner import ScanResult
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class NetworkVisualizer:
    """Generate network topology visualizations from scan results"""
    
    def __init__(self):
        self.graph = nx.Graph()
        self.risk_colors = {
            'critical': '#e74c3c',  # Red
            'high': '#e67e22',      # Orange
            'medium': '#f39c12',    # Yellow
            'low': '#3498db',       # Blue
            'safe': '#2ecc71'       # Green
        }
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Get color for a risk level"""
        return self.risk_colors.get(risk_level.lower(), self.risk_colors['safe'])
    
    def create_graph(self, results: List[ScanResult]) -> nx.Graph:
        """Create network graph from scan results"""
        self.graph.clear()
        
        # Group results by host
        hosts = {}
        for result in results:
            if result.status == "OPEN":
                if result.host not in hosts:
                    hosts[result.host] = []
                hosts[result.host].append(result)
        
        # Add nodes and edges
        for host, host_results in hosts.items():
            # Add host node (size based on open ports)
            open_ports = len(host_results)
            self.graph.add_node(
                host,
                node_type='host',
                open_ports=open_ports,
                size=300 + (open_ports * 50)
            )
            
            # Add service nodes and edges
            for result in host_results:
                service_id = f"{host}:{result.port}"
                service_label = f"{result.service}\n:{result.port}"
                
                # Determine risk level (will be enhanced with CVE data)
                risk_level = getattr(result, 'risk_level', 'safe')
                
                self.graph.add_node(
                    service_id,
                    node_type='service',
                    label=service_label,
                    risk=risk_level,
                    port=result.port,
                    service=result.service,
                    version=result.service_version or '',
                    banner=result.banner[:50] if result.banner else ''
                )
                
                self.graph.add_edge(host, service_id, protocol=result.protocol)
        
        return self.graph
    
    def plot_graph(self, output_path: str = "network_graph.png", title: str = "Network Topology"):
        """Generate and save network graph visualization"""
        if self.graph.number_of_nodes() == 0:
            logger.warning("No data to visualize")
            return
        
        try:
            # Create figure with larger size for better visibility
            fig, ax = plt.subplots(figsize=(16, 12))
            fig.patch.set_facecolor('#2c3e50')
            ax.set_facecolor('#34495e')
            
            # Use spring layout for better distribution
            pos = nx.spring_layout(self.graph, k=2, iterations=50, seed=42)
            
            # Separate nodes by type
            host_nodes = [n for n, d in self.graph.nodes(data=True) if d.get('node_type') == 'host']
            service_nodes = [n for n, d in self.graph.nodes(data=True) if d.get('node_type') == 'service']
            
            # Draw host nodes (larger, blue)
            if host_nodes:
                host_sizes = [self.graph.nodes[n].get('size', 800) for n in host_nodes]
                nx.draw_networkx_nodes(
                    self.graph, pos,
                    nodelist=host_nodes,
                    node_color='#3498db',
                    node_size=host_sizes,
                    alpha=0.9,
                    ax=ax
                )
            
            # Draw service nodes (colored by risk)
            if service_nodes:
                service_colors = [
                    self._get_risk_color(self.graph.nodes[n].get('risk', 'safe'))
                    for n in service_nodes
                ]
                nx.draw_networkx_nodes(
                    self.graph, pos,
                    nodelist=service_nodes,
                    node_color=service_colors,
                    node_size=400,
                    alpha=0.8,
                    ax=ax
                )
            
            # Draw edges
            nx.draw_networkx_edges(
                self.graph, pos,
                edge_color='#95a5a6',
                width=2,
                alpha=0.6,
                ax=ax
            )
            
            # Draw labels
            # Host labels
            host_labels = {n: n for n in host_nodes}
            nx.draw_networkx_labels(
                self.graph, pos,
                labels=host_labels,
                font_size=10,
                font_weight='bold',
                font_color='white',
                ax=ax
            )
            
            # Service labels
            service_labels = {
                n: self.graph.nodes[n].get('label', n)
                for n in service_nodes
            }
            nx.draw_networkx_labels(
                self.graph, pos,
                labels=service_labels,
                font_size=7,
                font_color='white',
                ax=ax
            )
            
            # Add title and legend
            ax.set_title(title, fontsize=18, fontweight='bold', color='white', pad=20)
            
            # Create legend
            legend_elements = [
                plt.Line2D([0], [0], marker='o', color='w', label='Host',
                          markerfacecolor='#3498db', markersize=12),
                plt.Line2D([0], [0], marker='o', color='w', label='Critical Risk',
                          markerfacecolor=self.risk_colors['critical'], markersize=10),
                plt.Line2D([0], [0], marker='o', color='w', label='High Risk',
                          markerfacecolor=self.risk_colors['high'], markersize=10),
                plt.Line2D([0], [0], marker='o', color='w', label='Medium Risk',
                          markerfacecolor=self.risk_colors['medium'], markersize=10),
                plt.Line2D([0], [0], marker='o', color='w', label='Safe',
                          markerfacecolor=self.risk_colors['safe'], markersize=10),
            ]
            ax.legend(handles=legend_elements, loc='upper right', fontsize=10,
                     facecolor='#2c3e50', edgecolor='white', labelcolor='white')
            
            ax.axis('off')
            plt.tight_layout()
            
            # Save figure
            plt.savefig(output_path, dpi=150, facecolor='#2c3e50', bbox_inches='tight')
            plt.close(fig)
            
            logger.info(f"Network graph saved to {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to generate network graph: {e}")
            raise
    
    def export_to_html(self, results: List[ScanResult], output_path: str = "network_graph.html"):
        """Export network graph as interactive HTML with D3.js"""
        try:
            # Create graph data structure for D3.js
            nodes = []
            links = []
            node_ids = {}
            
            # Group by host
            hosts = {}
            for result in results:
                if result.status == "OPEN":
                    if result.host not in hosts:
                        hosts[result.host] = []
                    hosts[result.host].append(result)
            
            # Create nodes
            node_counter = 0
            for host, host_results in hosts.items():
                # Host node
                host_id = node_counter
                node_ids[host] = host_id
                nodes.append({
                    'id': host_id,
                    'name': host,
                    'type': 'host',
                    'size': 20 + len(host_results) * 2,
                    'color': '#3498db'
                })
                node_counter += 1
                
                # Service nodes
                for result in host_results:
                    service_id = node_counter
                    risk_level = getattr(result, 'risk_level', 'safe')
                    
                    nodes.append({
                        'id': service_id,
                        'name': f"{result.service}:{result.port}",
                        'type': 'service',
                        'size': 10,
                        'color': self._get_risk_color(risk_level),
                        'port': result.port,
                        'service': result.service,
                        'version': result.service_version or '',
                        'banner': result.banner[:100] if result.banner else ''
                    })
                    
                    # Create link
                    links.append({
                        'source': host_id,
                        'target': service_id,
                        'protocol': result.protocol
                    })
                    
                    node_counter += 1
            
            # Generate HTML with embedded D3.js
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Topology - PortMe</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {{
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #2c3e50;
            color: white;
        }}
        #header {{
            background: #1a252f;
            padding: 20px;
            text-align: center;
            border-bottom: 3px solid #3498db;
        }}
        #graph {{
            width: 100vw;
            height: calc(100vh - 100px);
        }}
        .tooltip {{
            position: absolute;
            background: rgba(0, 0, 0, 0.9);
            color: white;
            padding: 10px;
            border-radius: 5px;
            font-size: 12px;
            pointer-events: none;
            opacity: 0;
            transition: opacity 0.3s;
            max-width: 300px;
        }}
        .node {{
            cursor: pointer;
        }}
        .link {{
            stroke: #95a5a6;
            stroke-opacity: 0.6;
        }}
    </style>
</head>
<body>
    <div id="header">
        <h1>🔍 Network Topology Visualization</h1>
        <p>Generated by PortMe on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    <div id="graph"></div>
    <div class="tooltip" id="tooltip"></div>
    
    <script>
        const nodes = {nodes};
        const links = {links};
        
        const width = window.innerWidth;
        const height = window.innerHeight - 100;
        
        const svg = d3.select("#graph")
            .append("svg")
            .attr("width", width)
            .attr("height", height);
        
        const simulation = d3.forceSimulation(nodes)
            .force("link", d3.forceLink(links).id(d => d.id).distance(100))
            .force("charge", d3.forceManyBody().strength(-300))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collision", d3.forceCollide().radius(d => d.size + 5));
        
        const link = svg.append("g")
            .selectAll("line")
            .data(links)
            .join("line")
            .attr("class", "link")
            .attr("stroke-width", 2);
        
        const node = svg.append("g")
            .selectAll("circle")
            .data(nodes)
            .join("circle")
            .attr("class", "node")
            .attr("r", d => d.size)
            .attr("fill", d => d.color)
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended))
            .on("mouseover", showTooltip)
            .on("mouseout", hideTooltip);
        
        const label = svg.append("g")
            .selectAll("text")
            .data(nodes)
            .join("text")
            .text(d => d.name)
            .attr("font-size", 10)
            .attr("fill", "white")
            .attr("text-anchor", "middle")
            .attr("pointer-events", "none");
        
        simulation.on("tick", () => {{
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);
            
            node
                .attr("cx", d => d.x)
                .attr("cy", d => d.y);
            
            label
                .attr("x", d => d.x)
                .attr("y", d => d.y + d.size + 15);
        }});
        
        function dragstarted(event) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            event.subject.fx = event.subject.x;
            event.subject.fy = event.subject.y;
        }}
        
        function dragged(event) {{
            event.subject.fx = event.x;
            event.subject.fy = event.y;
        }}
        
        function dragended(event) {{
            if (!event.active) simulation.alphaTarget(0);
            event.subject.fx = null;
            event.subject.fy = null;
        }}
        
        function showTooltip(event, d) {{
            const tooltip = d3.select("#tooltip");
            let content = `<strong>${{d.name}}</strong><br>Type: ${{d.type}}`;
            
            if (d.type === 'service') {{
                content += `<br>Port: ${{d.port}}<br>Service: ${{d.service}}`;
                if (d.version) content += `<br>Version: ${{d.version}}`;
                if (d.banner) content += `<br>Banner: ${{d.banner}}`;
            }}
            
            tooltip
                .html(content)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 10) + "px")
                .style("opacity", 1);
        }}
        
        function hideTooltip() {{
            d3.select("#tooltip").style("opacity", 0);
        }}
    </script>
</body>
</html>"""
            
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"Interactive HTML graph saved to {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to generate HTML graph: {e}")
            raise


def visualize_network(results: List[ScanResult], output_dir: str = ".") -> Tuple[str, str]:
    """
    Generate both static and interactive network visualizations
    
    Args:
        results: List of scan results
        output_dir: Directory to save output files
        
    Returns:
        Tuple of (png_path, html_path)
    """
    visualizer = NetworkVisualizer()
    
    # Create output directory if needed
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Generate timestamp for unique filenames
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    png_path = output_path / f"network_graph_{timestamp}.png"
    html_path = output_path / f"network_graph_{timestamp}.html"
    
    # Create graph
    visualizer.create_graph(results)
    
    # Generate visualizations
    visualizer.plot_graph(str(png_path), f"Network Topology - {timestamp}")
    visualizer.export_to_html(results, str(html_path))
    
    return str(png_path), str(html_path)
