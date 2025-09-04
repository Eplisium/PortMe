#!/usr/bin/env python3
"""
Port Scanner GUI
A user-friendly graphical interface for the advanced port scanner
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
from port_scanner import PortScanner, ScanResult
import json

class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 Advanced Port Scanner")
        self.root.geometry("1000x750")
        self.root.minsize(800, 600)  # Set minimum window size
        self.root.resizable(True, True)
        
        # Modern color scheme
        self.colors = {
            'primary': '#2563eb',      # Blue
            'primary_dark': '#1d4ed8', # Darker blue
            'secondary': '#64748b',     # Gray
            'success': '#059669',       # Green
            'danger': '#dc2626',        # Red
            'warning': '#d97706',       # Orange
            'background': '#f8fafc',    # Light gray
            'surface': '#ffffff',       # White
            'text': '#1e293b',          # Dark gray
            'text_light': '#64748b',    # Light gray
            'border': '#e2e8f0'         # Border gray
        }
        
        # Set window background
        self.root.configure(bg=self.colors['background'])
        
        # Initialize scanner
        self.scanner = PortScanner()
        self.scan_thread = None
        self.scan_running = False
        
        # Queue for thread communication
        self.queue = queue.Queue()
        
        self.setup_styles()
        self.create_widgets()
        
        # Start queue processing
        self.process_queue()
        
    def setup_styles(self):
        """Configure modern GUI styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure modern button styles
        style.configure('Primary.TButton',
                       background=self.colors['primary'],
                       foreground='white',
                       font=('Segoe UI', 10, 'bold'),
                       borderwidth=0,
                       focuscolor='none',
                       relief='flat',
                       padding=(15, 8))
        
        style.map('Primary.TButton',
                 background=[('active', self.colors['primary_dark']),
                           ('pressed', self.colors['primary_dark'])])
        
        style.configure('Success.TButton',
                       background=self.colors['success'],
                       foreground='white',
                       font=('Segoe UI', 9),
                       borderwidth=0,
                       focuscolor='none',
                       relief='flat',
                       padding=(12, 6))
        
        style.map('Success.TButton',
                 background=[('active', '#047857'),
                           ('pressed', '#047857')])
        
        style.configure('Danger.TButton',
                       background=self.colors['danger'],
                       foreground='white',
                       font=('Segoe UI', 9),
                       borderwidth=0,
                       focuscolor='none',
                       relief='flat',
                       padding=(12, 6))
        
        style.map('Danger.TButton',
                 background=[('active', '#b91c1c'),
                           ('pressed', '#b91c1c')])
        
        style.configure('Secondary.TButton',
                       background=self.colors['secondary'],
                       foreground='white',
                       font=('Segoe UI', 9),
                       borderwidth=0,
                       focuscolor='none',
                       relief='flat',
                       padding=(12, 6))
        
        style.map('Secondary.TButton',
                 background=[('active', '#475569'),
                           ('pressed', '#475569')])
        
        # Configure entry styles
        style.configure('Modern.TEntry',
                       fieldbackground=self.colors['surface'],
                       borderwidth=2,
                       relief='solid',
                       bordercolor=self.colors['border'],
                       font=('Segoe UI', 10),
                       padding=(10, 8))
        
        style.map('Modern.TEntry',
                 bordercolor=[('focus', self.colors['primary'])])
        
        # Configure spinbox styles
        style.configure('Modern.TSpinbox',
                       fieldbackground=self.colors['surface'],
                       borderwidth=2,
                       relief='solid',
                       bordercolor=self.colors['border'],
                       font=('Segoe UI', 9),
                       padding=(8, 6))
        
        # Configure label frame styles
        style.configure('Modern.TLabelframe',
                       background=self.colors['background'],
                       borderwidth=2,
                       relief='solid',
                       bordercolor=self.colors['border'])
        
        style.configure('Modern.TLabelframe.Label',
                       background=self.colors['background'],
                       foreground=self.colors['primary'],
                       font=('Segoe UI', 10, 'bold'))
        
        # Configure checkbox styles
        style.configure('Modern.TCheckbutton',
                       background=self.colors['background'],
                       foreground=self.colors['text'],
                       font=('Segoe UI', 9),
                       focuscolor='none')
        
        # Configure radiobutton styles
        style.configure('Modern.TRadiobutton',
                       background=self.colors['background'],
                       foreground=self.colors['text'],
                       font=('Segoe UI', 9),
                       focuscolor='none')
        
        # Configure progressbar
        style.configure('Modern.Horizontal.TProgressbar',
                       background=self.colors['primary'],
                       troughcolor=self.colors['border'],
                       borderwidth=0,
                       lightcolor=self.colors['primary'],
                       darkcolor=self.colors['primary'])
        
    def create_widgets(self):
        """Create and layout GUI widgets with modern styling"""
        # Main container with background and responsive padding
        main_container = tk.Frame(self.root, bg=self.colors['background'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Header section
        header_frame = tk.Frame(main_container, bg=self.colors['background'])
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        title_label = tk.Label(header_frame, 
                              text="🔍 Advanced Port Scanner", 
                              font=('Segoe UI', 18, 'bold'),
                              fg=self.colors['primary'],
                              bg=self.colors['background'])
        title_label.pack(side=tk.LEFT)
        
        subtitle_label = tk.Label(header_frame,
                                 text="Network Security & Diagnostics Tool",
                                 font=('Segoe UI', 10),
                                 fg=self.colors['text_light'],
                                 bg=self.colors['background'])
        subtitle_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Main content frame with responsive sizing
        content_frame = tk.Frame(main_container, bg=self.colors['background'])
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left panel container with responsive width but scrollable content
        left_container = tk.Frame(content_frame, bg=self.colors['surface'], relief='solid', bd=1, width=300)
        left_container.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 8), pady=5)
        left_container.pack_propagate(False)  # Maintain consistent width
        
        # Create scrollable canvas for left panel
        left_canvas = tk.Canvas(left_container, bg=self.colors['surface'], highlightthickness=0)
        left_scrollbar = ttk.Scrollbar(left_container, orient="vertical", command=left_canvas.yview)
        left_scrollable_frame = tk.Frame(left_canvas, bg=self.colors['surface'])
        
        # Configure scrolling
        left_scrollable_frame.bind(
            "<Configure>",
            lambda e: left_canvas.configure(scrollregion=left_canvas.bbox("all"))
        )
        
        left_canvas.create_window((0, 0), window=left_scrollable_frame, anchor="nw")
        left_canvas.configure(yscrollcommand=left_scrollbar.set)
        
        # Pack scrollable components
        left_canvas.pack(side="left", fill="both", expand=True)
        left_scrollbar.pack(side="right", fill="y")
        
        # Add padding inside scrollable frame
        left_inner = tk.Frame(left_scrollable_frame, bg=self.colors['surface'])
        left_inner.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Mouse wheel scrolling: enable when the cursor is over the left panel
        def _on_mousewheel(event):
            # On Windows, event.delta is multiples of 120
            left_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        def _bind_to_mousewheel(_):
            left_canvas.bind_all("<MouseWheel>", _on_mousewheel)
        def _unbind_from_mousewheel(_):
            left_canvas.unbind_all("<MouseWheel>")
        left_scrollable_frame.bind("<Enter>", _bind_to_mousewheel)
        left_scrollable_frame.bind("<Leave>", _unbind_from_mousewheel)
        
        # Target configuration section
        target_section = tk.Frame(left_inner, bg=self.colors['surface'])
        target_section.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(target_section, 
                text="🎯 Target Configuration", 
                font=('Segoe UI', 12, 'bold'),
                fg=self.colors['primary'],
                bg=self.colors['surface']).pack(anchor=tk.W)
        
        tk.Label(target_section, 
                text="Host/Network:", 
                font=('Segoe UI', 9),
                fg=self.colors['text'],
                bg=self.colors['surface']).pack(anchor=tk.W, pady=(10, 5))
        
        self.host_var = tk.StringVar(value="localhost")
        host_entry = ttk.Entry(target_section, textvariable=self.host_var, 
                              style='Modern.TEntry', width=25)
        host_entry.pack(fill=tk.X)
        
        # Port configuration
        tk.Label(target_section, 
                text="Port Selection:", 
                font=('Segoe UI', 9),
                fg=self.colors['text'],
                bg=self.colors['surface']).pack(anchor=tk.W, pady=(15, 5))
        
        port_frame = tk.Frame(target_section, bg=self.colors['surface'])
        port_frame.pack(fill=tk.X)
        
        self.port_option = tk.StringVar(value="common")
        ttk.Radiobutton(port_frame, text="Common Ports", variable=self.port_option, 
                       value="common", style='Modern.TRadiobutton').pack(anchor=tk.W)
        ttk.Radiobutton(port_frame, text="Custom Ports", variable=self.port_option, 
                       value="custom", style='Modern.TRadiobutton').pack(anchor=tk.W, pady=(5, 0))
        
        self.custom_ports_var = tk.StringVar(value="3000,3001,8000,8080")
        self.custom_ports_entry = ttk.Entry(port_frame, textvariable=self.custom_ports_var, 
                                           style='Modern.TEntry', state="disabled")
        self.custom_ports_entry.pack(fill=tk.X, pady=(5, 0))
        
        # Bind radio button to enable/disable custom ports entry
        self.port_option.trace('w', self.on_port_option_change)
        
        # Advanced options section
        advanced_section = tk.Frame(left_inner, bg=self.colors['surface'])
        advanced_section.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(advanced_section, 
                text="⚙️ Advanced Options", 
                font=('Segoe UI', 12, 'bold'),
                fg=self.colors['primary'],
                bg=self.colors['surface']).pack(anchor=tk.W)
        
        # Settings grid
        settings_grid = tk.Frame(advanced_section, bg=self.colors['surface'])
        settings_grid.pack(fill=tk.X, pady=(10, 0))
        
        # Timeout
        tk.Label(settings_grid, text="Timeout (sec):", font=('Segoe UI', 9),
                fg=self.colors['text'], bg=self.colors['surface']).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.timeout_var = tk.DoubleVar(value=1.0)
        timeout_spin = ttk.Spinbox(settings_grid, from_=0.1, to=10.0, increment=0.1, 
                                  textvariable=self.timeout_var, width=8, style='Modern.TSpinbox')
        timeout_spin.grid(row=0, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        
        # Max workers
        tk.Label(settings_grid, text="Max Threads:", font=('Segoe UI', 9),
                fg=self.colors['text'], bg=self.colors['surface']).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.workers_var = tk.IntVar(value=100)
        workers_spin = ttk.Spinbox(settings_grid, from_=1, to=500, increment=10, 
                                  textvariable=self.workers_var, width=8, style='Modern.TSpinbox')
        workers_spin.grid(row=1, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        
        # Options checkboxes
        options_frame = tk.Frame(advanced_section, bg=self.colors['surface'])
        options_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.banner_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Enable Banner Grabbing", 
                       variable=self.banner_var, style='Modern.TCheckbutton').pack(anchor=tk.W)
        
        self.show_closed_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Show Closed/Filtered Ports", 
                       variable=self.show_closed_var, style='Modern.TCheckbutton').pack(anchor=tk.W, pady=(5, 0))
        
        # Control buttons section
        controls_section = tk.Frame(left_inner, bg=self.colors['surface'])
        controls_section.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(controls_section, 
                text="🚀 Scan Controls", 
                font=('Segoe UI', 12, 'bold'),
                fg=self.colors['primary'],
                bg=self.colors['surface']).pack(anchor=tk.W)
        
        button_grid = tk.Frame(controls_section, bg=self.colors['surface'])
        button_grid.pack(fill=tk.X, pady=(10, 0))
        
        self.scan_button = ttk.Button(button_grid, text="▶️ Start Scan", 
                                     command=self.start_scan, style='Primary.TButton')
        self.scan_button.pack(fill=tk.X, pady=2)
        
        self.stop_button = ttk.Button(button_grid, text="⏹️ Stop Scan", 
                                     command=self.stop_scan, style='Danger.TButton',
                                     state="disabled")
        self.stop_button.pack(fill=tk.X, pady=2)
        
        ttk.Button(button_grid, text="🗑️ Clear Results", 
                  command=self.clear_results, style='Secondary.TButton').pack(fill=tk.X, pady=2)
        
        ttk.Button(button_grid, text="💾 Export Results", 
                  command=self.export_results, style='Success.TButton').pack(fill=tk.X, pady=2)
        
        # Quick scan section
        quick_section = tk.Frame(left_inner, bg=self.colors['surface'])
        quick_section.pack(fill=tk.X)
        
        tk.Label(quick_section, 
                text="⚡ Quick Scans", 
                font=('Segoe UI', 12, 'bold'),
                fg=self.colors['primary'],
                bg=self.colors['surface']).pack(anchor=tk.W)
        
        quick_buttons = tk.Frame(quick_section, bg=self.colors['surface'])
        quick_buttons.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(quick_buttons, text="Port 3000", 
                  command=lambda: self.quick_scan("localhost", "3000"),
                  style='Secondary.TButton').pack(fill=tk.X, pady=1)
        ttk.Button(quick_buttons, text="Web Ports", 
                  command=lambda: self.quick_scan("localhost", "80,443,8000,8080,3000,5000"),
                  style='Secondary.TButton').pack(fill=tk.X, pady=1)
        ttk.Button(quick_buttons, text="Common Services", 
                  command=lambda: self.quick_scan("localhost", "common"),
                  style='Secondary.TButton').pack(fill=tk.X, pady=1)
        
        # Right panel for results
        right_panel = tk.Frame(content_frame, bg=self.colors['surface'], relief='solid', bd=1)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, pady=5)
        
        # Results header
        results_header = tk.Frame(right_panel, bg=self.colors['primary'], height=40)
        results_header.pack(fill=tk.X)
        results_header.pack_propagate(False)
        
        tk.Label(results_header, 
                text="📊 Scan Results", 
                font=('Segoe UI', 12, 'bold'),
                fg='white',
                bg=self.colors['primary']).pack(side=tk.LEFT, padx=15, pady=10)
        
        # Progress section
        progress_frame = tk.Frame(right_panel, bg=self.colors['surface'])
        progress_frame.pack(fill=tk.X, padx=15, pady=10)
        
        self.progress_var = tk.StringVar(value="Ready to scan")
        progress_label = tk.Label(progress_frame, textvariable=self.progress_var,
                                 font=('Segoe UI', 9),
                                 fg=self.colors['text'],
                                 bg=self.colors['surface'])
        progress_label.pack(anchor=tk.W)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='indeterminate',
                                          style='Modern.Horizontal.TProgressbar')
        self.progress_bar.pack(fill=tk.X, pady=(5, 0))
        
        # Results text area
        results_container = tk.Frame(right_panel, bg=self.colors['surface'])
        results_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        
        self.results_text = scrolledtext.ScrolledText(results_container, 
                                                     height=25, 
                                                     font=('Consolas', 10),
                                                     bg=self.colors['surface'],
                                                     fg=self.colors['text'],
                                                     selectbackground=self.colors['primary'],
                                                     selectforeground='white',
                                                     relief='flat',
                                                     bd=0,
                                                     wrap=tk.WORD)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure enhanced text tags for colored output
        self.results_text.tag_configure('open', 
                                       foreground=self.colors['success'], 
                                       font=('Consolas', 10, 'bold'))
        self.results_text.tag_configure('closed', 
                                       foreground=self.colors['danger'])
        self.results_text.tag_configure('filtered', 
                                       foreground=self.colors['warning'])
        self.results_text.tag_configure('header', 
                                       foreground=self.colors['primary'], 
                                       font=('Consolas', 11, 'bold'))
        self.results_text.tag_configure('error', 
                                       foreground=self.colors['danger'], 
                                       font=('Consolas', 10, 'bold'))
        self.results_text.tag_configure('info', 
                                       foreground=self.colors['text_light'],
                                       font=('Consolas', 9, 'italic'))
        
        # Add welcome message
        welcome_msg = """🔍 Advanced Port Scanner Ready!

Welcome to the Advanced Port Scanner - your comprehensive network security tool.

Getting Started:
• Enter a target host/IP or network range (e.g., 192.168.1.0/24)
• Choose between common ports or specify custom ports
• Adjust timeout and threading for optimal performance
• Use quick scan buttons for common scenarios

Features:
✓ Multi-threaded scanning for speed
✓ Service detection and banner grabbing
✓ Network range scanning support
✓ Export results to JSON/CSV
✓ Real-time progress tracking

Ready to scan! Click 'Start Scan' or use a Quick Scan button."""
        
        self.results_text.insert(tk.END, welcome_msg, 'info')
        
    def on_port_option_change(self, *args):
        """Handle port option radio button changes"""
        if self.port_option.get() == "custom":
            self.custom_ports_entry.config(state="normal")
        else:
            self.custom_ports_entry.config(state="disabled")
            
    def quick_scan(self, host, ports):
        """Perform a quick scan with predefined parameters"""
        self.host_var.set(host)
        if ports == "common":
            self.port_option.set("common")
        else:
            self.port_option.set("custom")
            self.custom_ports_var.set(ports)
        self.start_scan()
        
    def start_scan(self):
        """Start the port scan in a separate thread"""
        if self.scan_running:
            messagebox.showwarning("Warning", "A scan is already running!")
            return
            
        # Validate inputs
        host = self.host_var.get().strip()
        if not host:
            messagebox.showerror("Error", "Please enter a target host!")
            return
            
        # Get port list
        try:
            if self.port_option.get() == "common":
                ports = self.scanner.get_common_ports()
            else:
                port_str = self.custom_ports_var.get().strip()
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
        self.scanner.timeout = self.timeout_var.get()
        self.scanner.max_workers = self.workers_var.get()
        
        # Start scan thread
        self.scan_running = True
        self.scan_button.config(state="disabled")
        self.stop_button.config(state="normal")
        # Configure progress bar mode depending on target type
        if '/' in host:
            # Network scan -> unknown total, use indeterminate
            self.progress_bar.config(mode='indeterminate')
            self.progress_bar.start(10)
            self.progress_var.set("Scanning network range...")
        else:
            # Single host -> determinate
            self.progress_bar.stop()
            self.progress_bar.config(mode='determinate', maximum=len(ports))
            self.progress_bar['value'] = 0
            self.progress_var.set(f"Scanning... 0/{len(ports)} (0%)")
        
        self.scan_thread = threading.Thread(target=self.scan_worker, args=(host, ports))
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
    def scan_worker(self, host, ports):
        """Worker thread for scanning"""
        try:
            self.queue.put(("status", f"Starting scan of {host} on {len(ports)} ports..."))
            
            # Clear previous results
            self.scanner.results = []
            
            # Progress callback forwards updates to GUI via queue
            def progress_cb(completed, total, result):
                self.queue.put(("progress", completed, total))

            if '/' in host:  # Network scan
                results = self.scanner.scan_network_range(host, ports, progress_callback=progress_cb)
                for host_ip, host_results in results.items():
                    self.queue.put(("results", host_ip, host_results))
            else:  # Single host scan
                results = self.scanner.scan_host_ports(host, ports, show_progress=False, progress_callback=progress_cb)
                self.queue.put(("results", host, results))
                
            self.queue.put(("complete", "Scan completed successfully!"))
            
        except Exception as e:
            self.queue.put(("error", f"Scan failed: {str(e)}"))
        finally:
            self.scan_running = False
            
    def stop_scan(self):
        """Stop the current scan"""
        self.scan_running = False
        self.progress_bar.stop()
        self.progress_var.set("Scan stopped by user")
        self.scan_button.config(state="normal")
        self.stop_button.config(state="disabled")
        
    def process_queue(self):
        """Process messages from the scan thread"""
        try:
            while True:
                message = self.queue.get_nowait()
                
                if message[0] == "status":
                    self.progress_var.set(message[1])
                elif message[0] == "results":
                    self.display_results(message[1], message[2])
                elif message[0] == "progress":
                    completed, total = message[1], message[2]
                    if total > 0:
                        # Determinate progress
                        self.progress_bar.config(mode='determinate', maximum=total)
                        self.progress_bar['value'] = completed
                        pct = int((completed/total)*100)
                        self.progress_var.set(f"Scanning... {completed}/{total} ({pct}%)")
                elif message[0] == "complete":
                    self.progress_bar.stop()
                    self.progress_var.set(message[1])
                    self.scan_button.config(state="normal")
                    self.stop_button.config(state="disabled")
                elif message[0] == "error":
                    self.progress_bar.stop()
                    self.progress_var.set("Error occurred")
                    self.scan_button.config(state="normal")
                    self.stop_button.config(state="disabled")
                    self.results_text.insert(tk.END, f"ERROR: {message[1]}\n", 'error')
                    
        except queue.Empty:
            pass
            
        # Schedule next check
        self.root.after(100, self.process_queue)
        
    def display_results(self, host, results):
        """Display scan results with enhanced formatting"""
        # Clear welcome message if this is the first scan
        if "Welcome to the Advanced Port Scanner" in self.results_text.get(1.0, tk.END):
            self.results_text.delete(1.0, tk.END)
        
        # Header with modern styling
        self.results_text.insert(tk.END, f"\n{'='*90}\n", 'header')
        self.results_text.insert(tk.END, f"🎯 SCAN RESULTS FOR {host.upper()}\n", 'header')
        self.results_text.insert(tk.END, f"{'='*90}\n", 'header')
        self.results_text.insert(tk.END, f"{'PORT':<8} {'STATUS':<12} {'SERVICE':<20} {'BANNER':<40}\n", 'header')
        self.results_text.insert(tk.END, f"{'-'*90}\n", 'header')
        
        open_count = 0
        closed_count = 0
        filtered_count = 0
        
        for result in results:
            if result.status == "OPEN" or (self.show_closed_var.get() and result.status in ["CLOSED", "FILTERED"]):
                banner = result.banner[:40] + "..." if len(result.banner) > 40 else result.banner
                
                # Add status icons for better visual feedback
                status_icon = "🟢" if result.status == "OPEN" else ("🔴" if result.status == "CLOSED" else "🟡")
                line = f"{result.port:<8} {status_icon} {result.status:<10} {result.service:<20} {banner:<40}\n"
                
                if result.status == "OPEN":
                    self.results_text.insert(tk.END, line, 'open')
                    open_count += 1
                elif result.status == "CLOSED":
                    self.results_text.insert(tk.END, line, 'closed')
                    closed_count += 1
                else:
                    self.results_text.insert(tk.END, line, 'filtered')
                    filtered_count += 1
        
        # Enhanced summary with statistics
        self.results_text.insert(tk.END, f"{'-'*90}\n", 'header')
        summary = f"📊 SCAN SUMMARY:\n"
        summary += f"   • Open Ports: {open_count}\n"
        if self.show_closed_var.get():
            summary += f"   • Closed Ports: {closed_count}\n"
            summary += f"   • Filtered Ports: {filtered_count}\n"
        summary += f"   • Total Scanned: {len(results)}\n"
        summary += f"   • Target: {host}\n\n"
        
        self.results_text.insert(tk.END, summary, 'info')
        self.results_text.see(tk.END)
        
    def clear_results(self):
        """Clear the results text area"""
        self.results_text.delete(1.0, tk.END)
        self.scanner.results = []
        self.progress_var.set("Results cleared")
        
    def export_results(self):
        """Export results to file"""
        if not self.scanner.results:
            messagebox.showwarning("Warning", "No results to export!")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                format_type = "json" if filename.endswith('.json') else "csv"
                self.scanner.export_results(filename, format_type)
                messagebox.showinfo("Success", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export results: {e}")

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
