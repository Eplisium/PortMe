#!/usr/bin/env python3
"""
Port Scanner GUI (Refactored)
Component-based GUI for better maintainability and organization
"""

import tkinter as tk
from tkinter import messagebox, filedialog
import threading
import queue
import asyncio
import time
import os
import webbrowser
from port_scanner import PortScanner, ScanResult
from config_loader import load_config, get_profile_config, list_profiles, config_loader
from gui.components import ThemeManager
from gui.panels import (
    NavigationBar, StatisticsPanel, ProfilePanel, TargetConfigPanel,
    AdvancedOptionsPanel, ControlsPanel, QuickScanPanel, ResultsPanel, FooterPanel
)
# Phase 1 Enhancement imports
from visualizer import visualize_network
from intelligence import CVEChecker, RiskScorer, ReportGenerator
import logging

class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 Advanced Port Scanner")
        self.root.geometry("1200x850")
        self.root.minsize(1000, 700)
        self.root.resizable(True, True)
        
        # Theme manager
        self.theme_manager = ThemeManager('light')
        self.colors = self.theme_manager.colors
        self.root.configure(bg=self.colors['background'])
        
        # Statistics tracking
        self.scan_stats = {
            'total_scans': 0,
            'total_ports_scanned': 0,
            'total_open_ports': 0,
            'last_scan_duration': 0
        }
        
        # Configuration
        self.config = {}
        self.profiles = {}
        self.current_profile = None
        self.load_configuration()
        
        # Scanner
        self.scanner = PortScanner()
        self.scan_thread = None
        self.scan_running = False
        
        # Phase 1: Intelligence modules
        self.cve_checker = CVEChecker()
        self.risk_scorer = RiskScorer()
        self.report_generator = ReportGenerator()
        
        # Queue for thread communication
        self.queue = queue.Queue()
        
        # UI Components (will be initialized in create_widgets)
        self.nav_bar = None
        self.stats_panel = None
        self.profile_panel = None
        self.target_panel = None
        self.advanced_panel = None
        self.controls_panel = None
        self.quick_scan_panel = None
        self.results_panel = None
        self.footer_panel = None
        
        self.theme_manager.setup_styles()
        self.create_widgets()
        
        # Start queue processing
        self.process_queue()
        
        # Setup keyboard shortcuts
        self.setup_keyboard_shortcuts()
    
    def setup_keyboard_shortcuts(self):
        """Setup keyboard shortcuts for better UX"""
        self.root.bind('<Control-s>', lambda e: self.start_scan() if not self.scan_running else None)
        self.root.bind('<Control-q>', lambda e: self.stop_scan())
        self.root.bind('<Control-e>', lambda e: self.export_results())
        self.root.bind('<Control-l>', lambda e: self.clear_results())
        self.root.bind('<F5>', lambda e: self.reload_configuration())
        self.root.bind('<Control-t>', lambda e: self.toggle_theme())
    
    def toggle_theme(self):
        """Toggle between light and dark themes"""
        self.theme_manager.toggle()
        self.colors = self.theme_manager.colors
        
        # Recreate UI with new theme
        for widget in self.root.winfo_children():
            widget.destroy()
        
        self.theme_manager.setup_styles()
        self.create_widgets()
        
        # Show brief notification
        if self.results_panel:
            self.results_panel.progress_var.set(f"Switched to {self.theme_manager.get_theme_name()} theme")
    
    def show_toast_notification(self, message, duration=3000):
        """Show a temporary toast notification"""
        toast = tk.Toplevel(self.root)
        toast.overrideredirect(True)
        toast.configure(bg=self.colors['primary'])
        toast.attributes('-alpha', 0.95)
        toast.attributes('-topmost', True)
        
        # Position at top-right
        x = self.root.winfo_x() + self.root.winfo_width() - 320
        y = self.root.winfo_y() + 20
        toast.geometry(f"300x60+{x}+{y}")
        
        tk.Label(toast, text=message, font=('Segoe UI', 10, 'bold'),
                fg='white', bg=self.colors['primary'],
                wraplength=280, padx=15, pady=15).pack()
        
        # Fade in effect (simplified)
        toast.after(duration, toast.destroy)
    
    def load_configuration(self):
        """Load configuration and profiles"""
        try:
            self.config = load_config()
            self.profiles = list_profiles()
            logging.info(f"Loaded configuration with {len(self.profiles)} profiles")
        except Exception as e:
            logging.error(f"Failed to load configuration: {e}")
            self.config = config_loader.DEFAULT_CONFIG.copy()
            self.profiles = {}
    
    def reload_configuration(self):
        """Reload configuration from file"""
        try:
            config_loader.load_config()  # Reload from file
            self.load_configuration()
            self.update_profile_dropdown()
            self.apply_profile_to_gui("<Custom>")  # Reset to custom
            messagebox.showinfo("Success", f"Configuration reloaded!\nFound {len(self.profiles)} profiles.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to reload configuration: {e}")
    
    def update_profile_dropdown(self):
        """Update the profile dropdown with available profiles"""
        if self.profile_panel:
            self.profile_panel.update_profiles(self.profiles)
    
    def apply_profile_to_gui(self, profile_name):
        """Apply profile settings to GUI controls"""
        if profile_name == "<Custom>" or profile_name not in self.profiles:
            self.current_profile = None
            return
        
        try:
            profile_config = get_profile_config(profile_name, self.config)
            self.current_profile = profile_name
            
            # Apply settings to GUI controls via component references
            if self.target_panel and 'host' in profile_config and profile_config['host']:
                self.target_panel.host_var.set(profile_config['host'])
            
            if self.advanced_panel:
                if 'timeout' in profile_config:
                    self.advanced_panel.timeout_var.set(profile_config['timeout'])
                if 'workers' in profile_config:
                    self.advanced_panel.workers_var.set(profile_config['workers'])
                if 'enable_banner' in profile_config:
                    self.advanced_panel.banner_var.set(profile_config['enable_banner'])
                if 'show_closed' in profile_config:
                    self.advanced_panel.show_closed_var.set(profile_config['show_closed'])
                if 'ping_sweep' in profile_config:
                    self.advanced_panel.ping_sweep_var.set(profile_config['ping_sweep'])
                if 'enable_udp' in profile_config:
                    self.advanced_panel.udp_scan_var.set(profile_config['enable_udp'])
            
            # Handle ports
            if self.target_panel and 'ports' in profile_config and profile_config['ports']:
                ports = profile_config['ports']
                if isinstance(ports, list):
                    port_str = ','.join(map(str, ports))
                else:
                    port_str = str(ports)
                
                self.target_panel.port_option.set("custom")
                self.target_panel.custom_ports_var.set(port_str)
            
            logging.info(f"Applied profile '{profile_name}' to GUI")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to apply profile '{profile_name}': {e}")
            logging.error(f"Failed to apply profile '{profile_name}': {e}")
        
        
    def create_widgets(self):
        """Create and layout GUI widgets using component-based architecture"""
        # Main container
        main_container = tk.Frame(self.root, bg=self.colors['background'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Create navigation bar component
        self.nav_bar = NavigationBar(main_container, self.colors, self.toggle_theme, 
                                     current_theme=self.theme_manager.current_theme)
        self.nav_bar.create()
        
        # Create statistics panel component
        self.stats_panel = StatisticsPanel(main_container, self.colors)
        self.stats_panel.create()
        
        # Main content frame
        content_frame = tk.Frame(main_container, bg=self.colors['background'])
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left panel with scrollable content
        left_container = self.create_scrollable_left_panel(content_frame)
        
        # Create right panel for results
        self.results_panel = ResultsPanel(content_frame, self.colors)
        self.results_panel.create()
        
        # Create footer component
        self.footer_panel = FooterPanel(main_container, self.colors)
        self.footer_panel.create()
    
    def create_scrollable_left_panel(self, parent):
        """Create the scrollable left panel with all configuration components"""
        left_container = tk.Frame(parent, bg=self.colors['surface'], relief='solid', bd=1, width=300)
        left_container.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 8), pady=5)
        left_container.pack_propagate(False)
        
        # Create scrollable canvas
        left_canvas = tk.Canvas(left_container, bg=self.colors['surface'], highlightthickness=0)
        left_scrollbar = tk.ttk.Scrollbar(left_container, orient="vertical", command=left_canvas.yview)
        left_scrollable_frame = tk.Frame(left_canvas, bg=self.colors['surface'])
        
        left_scrollable_frame.bind("<Configure>",
            lambda e: left_canvas.configure(scrollregion=left_canvas.bbox("all")))
        
        left_canvas.create_window((0, 0), window=left_scrollable_frame, anchor="nw")
        left_canvas.configure(yscrollcommand=left_scrollbar.set)
        
        left_canvas.pack(side="left", fill="both", expand=True)
        left_scrollbar.pack(side="right", fill="y")
        
        # Inner frame for components
        left_inner = tk.Frame(left_scrollable_frame, bg=self.colors['surface'])
        left_inner.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Mouse wheel scrolling
        def _on_mousewheel(event):
            left_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        left_scrollable_frame.bind("<Enter>", lambda _: left_canvas.bind_all("<MouseWheel>", _on_mousewheel))
        left_scrollable_frame.bind("<Leave>", lambda _: left_canvas.unbind_all("<MouseWheel>"))
        
        # Create all left panel components
        self.profile_panel = ProfilePanel(left_inner, self.colors, self.profiles,
                                         self.on_profile_change, self.reload_configuration)
        self.profile_panel.create()
        
        self.target_panel = TargetConfigPanel(left_inner, self.colors)
        self.target_panel.create()
        
        self.advanced_panel = AdvancedOptionsPanel(left_inner, self.colors)
        self.advanced_panel.create()
        
        self.controls_panel = ControlsPanel(left_inner, self.colors,
                                           self.start_scan, self.stop_scan, self.clear_results,
                                           self.export_results, self.generate_html_report,
                                           self.visualize_network, self.generate_enhanced_report)
        self.controls_panel.create()
        
        self.quick_scan_panel = QuickScanPanel(left_inner, self.colors,
                                              self.quick_scan, self.quick_scan_udp)
        self.quick_scan_panel.create()
        
        return left_container
        
    def update_statistics(self, open_count, total_scanned, duration):
        """Update statistics after a scan"""
        self.scan_stats['total_scans'] += 1
        self.scan_stats['total_ports_scanned'] += total_scanned
        self.scan_stats['total_open_ports'] += open_count
        self.scan_stats['last_scan_duration'] = duration
        
        # Update stats panel if it exists
        if self.stats_panel:
            self.stats_panel.update(**self.scan_stats)
    
    
    def on_profile_change(self, event=None):
        """Handle profile selection changes"""
        if self.profile_panel:
            selected_profile = self.profile_panel.profile_var.get()
            if selected_profile and selected_profile != "<Custom>":
                self.apply_profile_to_gui(selected_profile)
            else:
                self.current_profile = None
            
    def quick_scan(self, host, ports):
        """Perform a quick scan with predefined parameters"""
        if self.target_panel:
            self.target_panel.host_var.set(host)
            if ports == "common":
                self.target_panel.port_option.set("common")
            else:
                self.target_panel.port_option.set("custom")
                self.target_panel.custom_ports_var.set(ports)
        if self.advanced_panel:
            self.advanced_panel.udp_scan_var.set(False)
        self.start_scan()
    
    def quick_scan_udp(self, host, ports):
        """Perform a quick UDP scan with predefined parameters"""
        if self.target_panel:
            self.target_panel.host_var.set(host)
            self.target_panel.port_option.set("custom")
            self.target_panel.custom_ports_var.set(ports)
        if self.advanced_panel:
            self.advanced_panel.udp_scan_var.set(True)
        self.start_scan()
        
    def start_scan(self):
        """Start the port scan in a separate thread"""
        if self.scan_running:
            messagebox.showwarning("Warning", "A scan is already running!")
            return
        
        if not self.target_panel or not self.advanced_panel or not self.results_panel:
            return
            
        # Validate inputs
        host = self.target_panel.host_var.get().strip()
        if not host:
            messagebox.showerror("Error", "Please enter a target host!")
            return
            
        # Get port list
        try:
            if self.target_panel.port_option.get() == "common":
                ports = self.scanner.get_common_ports()
            else:
                port_str = self.target_panel.custom_ports_var.get().strip()
                if not port_str:
                    messagebox.showerror("Error", "Please enter custom ports!")
                    return
                    
                ports = []
                for part in port_str.split(','):
                    part = part.strip()
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        ports.extend(range(start, end + 1))
                    else:
                        ports.append(int(part))
                        
        except ValueError:
            messagebox.showerror("Error", "Invalid port format! Use: 80,443,22 or 1-1000")
            return
            
        # Update scanner settings
        self.scanner.reset_cancel()
        self.scanner.timeout = self.advanced_panel.timeout_var.get()
        self.scanner.max_workers = self.advanced_panel.workers_var.get()
        self.scanner.enable_banner = bool(self.advanced_panel.banner_var.get())
        self.scanner.enable_udp = bool(self.advanced_panel.udp_scan_var.get())
        
        # Start scan thread
        self.scan_running = True
        if self.controls_panel:
            self.controls_panel.set_scanning_state(True)
        
        # Configure progress bar
        if '/' in host:
            self.results_panel.progress_bar.config(mode='indeterminate')
            self.results_panel.progress_bar.start(10)
            self.results_panel.progress_var.set("Scanning network range...")
        else:
            self.results_panel.progress_bar.stop()
            self.results_panel.progress_bar.config(mode='determinate', maximum=len(ports))
            self.results_panel.progress_bar['value'] = 0
            self.results_panel.progress_var.set(f"Scanning... 0/{len(ports)} (0%)")
        
        self.scan_thread = threading.Thread(target=self.scan_worker, args=(host, ports))
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
    def scan_worker(self, host, ports):
        """Worker thread for scanning"""
        try:
            scan_start_time = time.time()
            
            self.queue.put(("status", f"Starting scan of {host} on {len(ports)} ports..."))
            
            # Clear previous results
            self.scanner.results = []
            
            # Progress callback
            def progress_cb(completed, total, result):
                if not self.scanner.is_cancelled():
                    self.queue.put(("progress", completed, total))

            # Determine protocols to scan
            protocols = ["TCP"]
            if self.advanced_panel and self.advanced_panel.udp_scan_var.get():
                protocols.append("UDP")
            
            if '/' in host:  # Network scan
                ping_first = self.advanced_panel.ping_sweep_var.get() if self.advanced_panel else True
                results = self.scanner.scan_network_range(host, ports, protocols, ping_first=ping_first, progress_callback=progress_cb)
                for host_ip, host_results in results.items():
                    self.queue.put(("results", host_ip, host_results))
            else:  # Single host scan
                if self.advanced_panel and self.advanced_panel.async_scan_var.get():
                    results = asyncio.run(self.scanner.async_scan_host_ports(host, ports, protocols))
                else:
                    results = self.scanner.scan_host_ports(host, ports, protocols, show_progress=False, progress_callback=progress_cb)
                self.queue.put(("results", host, results))
            
            # Calculate scan duration and update stats
            scan_duration = time.time() - scan_start_time
            
            # Count open ports
            open_count = sum(1 for r in self.scanner.results if r.status == "OPEN")
            total_scanned = len(self.scanner.results)
            
            # Update statistics
            self.queue.put(("stats", open_count, total_scanned, scan_duration))
                
            # Only mark complete if not cancelled
            if not self.scanner.is_cancelled():
                self.queue.put(("complete", f"Scan completed in {scan_duration:.1f}s! Found {open_count} open ports."))
            else:
                self.queue.put(("stopped", "Scan stopped by user"))
            
        except Exception as e:
            self.queue.put(("error", f"Scan failed: {str(e)}"))
        finally:
            self.scan_running = False
            
    def stop_scan(self):
        """Stop the current scan"""
        self.scanner.cancel()
        self.scan_running = False
        if self.results_panel:
            self.results_panel.progress_bar.stop()
            self.results_panel.progress_var.set("Scan stopped by user")
        if self.controls_panel:
            self.controls_panel.set_scanning_state(False)
        
    def process_queue(self):
        """Process messages from the scan thread"""
        try:
            while True:
                message = self.queue.get_nowait()
                
                if message[0] == "status":
                    if self.results_panel:
                        self.results_panel.progress_var.set(message[1])
                elif message[0] == "results":
                    self.display_results(message[1], message[2])
                elif message[0] == "stats":
                    open_count, total_scanned, duration = message[1], message[2], message[3]
                    self.update_statistics(open_count, total_scanned, duration)
                elif message[0] == "progress":
                    if self.scanner.is_cancelled() or not self.results_panel:
                        continue
                    completed, total = message[1], message[2]
                    if total > 0:
                        self.results_panel.progress_bar.config(mode='determinate', maximum=total)
                        self.results_panel.progress_bar['value'] = completed
                        pct = int((completed/total)*100)
                        self.results_panel.progress_var.set(f"Scanning... {completed}/{total} ({pct}%)")
                elif message[0] == "complete":
                    if self.results_panel:
                        self.results_panel.progress_bar.stop()
                        self.results_panel.progress_var.set(message[1])
                    if self.controls_panel:
                        self.controls_panel.set_scanning_state(False)
                elif message[0] == "stopped":
                    if self.results_panel:
                        self.results_panel.progress_bar.stop()
                        self.results_panel.progress_var.set(message[1])
                    if self.controls_panel:
                        self.controls_panel.set_scanning_state(False)
                elif message[0] == "error":
                    if self.results_panel:
                        self.results_panel.progress_bar.stop()
                        self.results_panel.progress_var.set("Error occurred")
                        self.results_panel.results_text.insert(tk.END, f"ERROR: {message[1]}\n", 'error')
                    if self.controls_panel:
                        self.controls_panel.set_scanning_state(False)
                    
        except queue.Empty:
            pass
            
        # Schedule next check
        self.root.after(100, self.process_queue)
        
    def display_results(self, host, results):
        """Display scan results with enhanced formatting"""
        if not self.results_panel or not self.advanced_panel:
            return
            
        results_text = self.results_panel.results_text
        
        # Clear welcome message if this is the first scan
        if "Welcome to the Advanced Port Scanner" in results_text.get(1.0, tk.END):
            results_text.delete(1.0, tk.END)
        
        # Header
        results_text.insert(tk.END, f"\n{'='*130}\n", 'header')
        results_text.insert(tk.END, f"🎯 SCAN RESULTS FOR {host.upper()}\n", 'header')
        results_text.insert(tk.END, f"{'='*130}\n", 'header')
        results_text.insert(tk.END, f"{'PORT':<8} {'PROTO':<6} {'STATUS':<12} {'SERVICE':<16} {'VERSION':<20} {'CONF':<6} {'LADDR':<16} {'ENV':<12} {'PROCESS(PID)':<20} {'BANNER':<24}\n", 'header')
        results_text.insert(tk.END, f"{'-'*130}\n", 'header')
        
        open_count = 0
        closed_count = 0
        filtered_count = 0
        
        for result in results:
            if result.status == "OPEN" or (self.advanced_panel.show_closed_var.get() and result.status in ["CLOSED", "FILTERED"]):
                banner = result.banner[:24] + "..." if len(result.banner) > 24 else result.banner
                proc_label = f"{result.process} ({result.pid})" if result.pid else (result.process or "")
                proc_label_short = (proc_label[:19] + "…") if len(proc_label) > 20 else proc_label
                
                addr = result.local_address or ""
                addr_short = (addr[:15] + "…") if len(addr) > 16 else addr
                
                # Environment info (Docker/WSL)
                env = ""
                if getattr(result, 'docker_container', ""):
                    env = f"Docker:{result.docker_container}"
                elif getattr(result, 'is_wsl', False):
                    env = f"WSL:{(result.wsl_distro or 'default')}"
                env_short = (env[:11] + "…") if len(env) > 12 else env
                
                # Enhanced service info
                service_version = getattr(result, 'service_version', '') or ''
                version_display = service_version[:19] + "…" if len(service_version) > 20 else service_version
                
                confidence = getattr(result, 'confidence', 0.0) or 0.0
                confidence_display = f"{confidence:.0%}" if confidence > 0 else "-"
                
                protocol_display = getattr(result, 'protocol', 'TCP')
                
                # Add status icons for better visual feedback
                status_icon = "🟢" if result.status == "OPEN" else ("🔴" if result.status == "CLOSED" else "🟡")
                line = f"{result.port:<8} {protocol_display:<6} {status_icon} {result.status:<10} {result.service:<16} {version_display:<20} {confidence_display:<6} {addr_short:<16} {env_short:<12} {proc_label_short:<20} {banner:<24}\n"
                
                if result.status == "OPEN":
                    results_text.insert(tk.END, line, 'open')
                    open_count += 1
                elif result.status == "CLOSED":
                    results_text.insert(tk.END, line, 'closed')
                    closed_count += 1
                else:
                    results_text.insert(tk.END, line, 'filtered')
                    filtered_count += 1
        
        # Summary
        results_text.insert(tk.END, f"{'-'*130}\n", 'header')
        summary = f"📊 SCAN SUMMARY:\n"
        summary += f"   • Open Ports: {open_count}\n"
        if self.advanced_panel.show_closed_var.get():
            summary += f"   • Closed Ports: {closed_count}\n"
            summary += f"   • Filtered Ports: {filtered_count}\n"
        summary += f"   • Total Scanned: {len(results)}\n"
        summary += f"   • Target: {host}\n\n"
        
        results_text.insert(tk.END, summary, 'info')
        results_text.see(tk.END)
        
    def clear_results(self):
        """Clear the results text area and reset statistics"""
        if self.results_panel:
            self.results_panel.results_text.delete(1.0, tk.END)
            self.results_panel.progress_var.set("Results cleared")
        self.scanner.results = []
        
        # Reset statistics
        self.scan_stats = {
            'total_scans': 0,
            'total_ports_scanned': 0,
            'total_open_ports': 0,
            'last_scan_duration': 0
        }
        
        # Update stats panel to reflect reset
        if self.stats_panel:
            self.stats_panel.update(**self.scan_stats)
        
    def export_results(self):
        """Export results to file"""
        if not self.scanner.results:
            messagebox.showwarning("Warning", "No results to export!")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[
                ("JSON files", "*.json"),
                ("JSON (gzip)", "*.json.gz"),
                ("CSV files", "*.csv"),
                ("Markdown files", "*.md"),
                ("Excel files", "*.xlsx"),
                ("HTML files", "*.html"),
                ("All files", "*.*")
            ]
        )
        
        if filename:
            try:
                lower = filename.lower()
                if lower.endswith('.html'):
                    format_type = "html"
                elif lower.endswith('.json') or lower.endswith('.json.gz') or lower.endswith('.gz'):
                    format_type = "json"
                elif lower.endswith('.md') or lower.endswith('.markdown'):
                    format_type = "md"
                elif lower.endswith('.xlsx'):
                    format_type = "xlsx"
                else:
                    format_type = "csv"
                # gzip is auto-detected by export_results when filename ends with .gz/.json.gz
                self.scanner.export_results(filename, format_type)
                messagebox.showinfo("Success", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export results: {e}")
    
    def generate_html_report(self):
        """Generate and save HTML report"""
        if not self.scanner.results:
            messagebox.showwarning("Warning", "No results to generate report!")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                report_path = self.scanner.generate_html_report(output_file=filename)
                if report_path:
                    messagebox.showinfo("Success", f"HTML report generated: {report_path}\n\nOpen this file in your web browser to view the professional report.")
                else:
                    messagebox.showerror("Error", "Failed to generate HTML report")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate HTML report: {e}")
    
    def visualize_network(self):
        """Generate network visualization graph (Phase 1 Feature)"""
        if not self.scanner.results:
            messagebox.showwarning("Warning", "No results to visualize!")
            return
        
        # Filter for open ports only
        open_results = [r for r in self.scanner.results if r.status == "OPEN"]
        if not open_results:
            messagebox.showwarning("Warning", "No open ports to visualize!")
            return
        
        try:
            # Show progress
            if self.results_panel:
                self.results_panel.progress_var.set("Generating network visualization...")
            
            # Generate visualizations
            output_dir = filedialog.askdirectory(title="Select output directory for visualizations")
            if not output_dir:
                return
            
            png_path, html_path = visualize_network(open_results, output_dir)
            
            if self.results_panel:
                self.results_panel.progress_var.set("Visualization complete!")
            
            # Ask if user wants to open
            response = messagebox.askyesno(
                "Visualization Complete",
                f"Network visualizations generated:\n\n"
                f"📊 Static Graph: {png_path}\n"
                f"🌐 Interactive HTML: {html_path}\n\n"
                f"Would you like to open the interactive HTML visualization?"
            )
            
            if response:
                webbrowser.open(f"file://{os.path.abspath(html_path)}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate visualization: {e}")
            logging.error(f"Visualization error: {e}", exc_info=True)
    
    def generate_enhanced_report(self):
        """Generate enhanced markdown report with CVE detection (Phase 1 Feature)"""
        if not self.scanner.results:
            messagebox.showwarning("Warning", "No results to generate report!")
            return
        
        try:
            # Show progress
            if self.results_panel:
                self.results_panel.progress_var.set("Analyzing vulnerabilities and generating report...")
            
            # Enrich results with CVE data
            for result in self.scanner.results:
                if result.status != "OPEN":
                    continue
                
                # Check for vulnerabilities
                cves = self.cve_checker.check_vulnerabilities(
                    service=result.service,
                    version=result.service_version,
                    banner=result.banner,
                    use_online=False  # Default to offline, can be made configurable
                )
                
                # Attach CVE data to result
                result.cves = cves
                
                # Perform risk assessment
                assessment = self.risk_scorer.assess_service(
                    service=result.service,
                    port=result.port,
                    version=result.service_version,
                    cves=cves,
                    banner=result.banner
                )
                
                # Attach risk data
                result.risk_level = assessment.risk_level
                result.risk_score = assessment.risk_score
            
            # Perform host-level assessment
            host_assessment = self.risk_scorer.assess_host(self.scanner.results)
            
            # Prepare scan info
            scan_info = {
                'target': self.target_panel.host_var.get() if self.target_panel else 'Unknown',
                'ports_scanned': len(self.scanner.results),
                'open_ports': len([r for r in self.scanner.results if r.status == "OPEN"]),
                'duration': f"{self.scan_stats.get('last_scan_duration', 0):.1f}s"
            }
            
            # Generate report
            filename = filedialog.asksaveasfilename(
                defaultextension=".md",
                filetypes=[("Markdown files", "*.md"), ("All files", "*.*")]
            )
            
            if not filename:
                return
            
            report_content = self.report_generator.generate_report(
                results=self.scanner.results,
                host_assessment=host_assessment,
                scan_info=scan_info,
                output_path=filename
            )
            
            if self.results_panel:
                self.results_panel.progress_var.set("Enhanced report generated!")
            
            # Show summary
            risk_emoji = self.risk_scorer.get_risk_emoji(host_assessment['risk_level'])
            messagebox.showinfo(
                "Report Generated",
                f"Enhanced Security Report Generated!\n\n"
                f"{risk_emoji} Risk Level: {host_assessment['risk_level'].upper()}\n"
                f"📊 Total CVEs Found: {host_assessment.get('total_cves', 0)}\n"
                f"🔴 Critical Services: {len(host_assessment.get('critical_services', []))}\n"
                f"📄 Report saved to: {filename}\n\n"
                f"The report includes:\n"
                f"• Executive Summary\n"
                f"• Risk Assessment\n"
                f"• Security Recommendations\n"
                f"• Detailed Vulnerability Analysis"
            )
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate enhanced report: {e}")
            logging.error(f"Enhanced report error: {e}", exc_info=True)

def main():
    """Main function to run the GUI"""
    root = tk.Tk()
    app = PortScannerGUI(root)
    
    # Center the window
    root.update_idletasks()
    x = (root.winfo_screenwidth() - root.winfo_width()) // 2
    y = (root.winfo_screenheight() - root.winfo_height()) // 2
    root.geometry(f"+{x}+{y}")
    
    root.mainloop()

if __name__ == "__main__":
    main()
