#!/usr/bin/env python3
"""
Port Scanner GUI
A user-friendly graphical interface for the advanced port scanner
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from tkinter import font as tkfont
import threading
import queue
from port_scanner import PortScanner, ScanResult
from config_loader import load_config, get_profile_config, list_profiles, config_loader
import json
import logging

class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 Advanced Port Scanner")
        self.root.geometry("1200x850")
        self.root.minsize(1000, 700)  # Set minimum window size
        self.root.resizable(True, True)
        
        # Enhanced color schemes with theme support
        self.themes = {
            'light': {
                'primary': '#3b82f6',      # Blue
                'primary_dark': '#2563eb', # Darker blue
                'primary_light': '#60a5fa', # Lighter blue
                'secondary': '#64748b',     # Gray
                'success': '#10b981',       # Green
                'danger': '#ef4444',        # Red
                'warning': '#f59e0b',       # Orange
                'info': '#06b6d4',          # Cyan
                'background': '#f8fafc',    # Light gray
                'surface': '#ffffff',       # White
                'text': '#1e293b',          # Dark gray
                'text_light': '#64748b',    # Light gray
                'text_muted': '#94a3b8',    # Muted gray
                'border': '#e2e8f0',        # Border gray
                'hover': '#f1f5f9',         # Hover gray
                'accent': '#8b5cf6'         # Purple accent
            },
            'dark': {
                'primary': '#3b82f6',
                'primary_dark': '#1e40af',
                'primary_light': '#60a5fa',
                'secondary': '#94a3b8',
                'success': '#10b981',
                'danger': '#ef4444',
                'warning': '#f59e0b',
                'info': '#06b6d4',
                'background': '#0f172a',
                'surface': '#1e293b',
                'text': '#f8fafc',
                'text_light': '#cbd5e1',
                'text_muted': '#94a3b8',
                'border': '#334155',
                'hover': '#334155',
                'accent': '#a78bfa'
            }
        }
        
        # Current theme
        self.current_theme = 'light'
        self.colors = self.themes[self.current_theme]
        
        # Statistics tracking
        self.scan_stats = {
            'total_scans': 0,
            'total_ports_scanned': 0,
            'total_open_ports': 0,
            'last_scan_duration': 0
        }
        
        # Set window background
        self.root.configure(bg=self.colors['background'])
        
        # Initialize configuration
        self.config = {}
        self.profiles = {}
        self.current_profile = None
        self.load_configuration()
        
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
        
        # Setup keyboard shortcuts
        self.setup_keyboard_shortcuts()
    
    def setup_keyboard_shortcuts(self):
        """Setup keyboard shortcuts for better UX"""
        self.root.bind('<Control-s>', lambda e: self.start_scan() if self.scan_button['state'] != 'disabled' else None)
        self.root.bind('<Control-q>', lambda e: self.stop_scan())
        self.root.bind('<Control-e>', lambda e: self.export_results())
        self.root.bind('<Control-l>', lambda e: self.clear_results())
        self.root.bind('<F5>', lambda e: self.reload_configuration())
        self.root.bind('<Control-t>', lambda e: self.toggle_theme())
    
    def toggle_theme(self):
        """Toggle between light and dark themes"""
        self.current_theme = 'dark' if self.current_theme == 'light' else 'light'
        self.colors = self.themes[self.current_theme]
        
        # Show notification
        theme_name = "Dark" if self.current_theme == 'dark' else "Light"
        
        # Recreate UI with new theme
        for widget in self.root.winfo_children():
            widget.destroy()
        
        self.setup_styles()
        self.create_widgets()
        
        # Show brief notification
        self.progress_var.set(f"Switched to {theme_name} theme")
    
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
        if hasattr(self, 'profile_combo'):
            profile_names = ["<Custom>"] + list(self.profiles.keys())
            self.profile_combo['values'] = profile_names
    
    def apply_profile_to_gui(self, profile_name):
        """Apply profile settings to GUI controls"""
        if profile_name == "<Custom>" or profile_name not in self.profiles:
            self.current_profile = None
            return
        
        try:
            # Get profile configuration
            profile_config = get_profile_config(profile_name, self.config)
            self.current_profile = profile_name
            
            # Apply settings to GUI controls
            if 'host' in profile_config and profile_config['host']:
                self.host_var.set(profile_config['host'])
            
            if 'timeout' in profile_config:
                self.timeout_var.set(profile_config['timeout'])
            
            if 'workers' in profile_config:
                self.workers_var.set(profile_config['workers'])
            
            if 'enable_banner' in profile_config:
                self.banner_var.set(profile_config['enable_banner'])
            
            if 'show_closed' in profile_config:
                self.show_closed_var.set(profile_config['show_closed'])
            
            if 'ping_sweep' in profile_config:
                self.ping_sweep_var.set(profile_config['ping_sweep'])
            
            if 'enable_udp' in profile_config:
                self.udp_scan_var.set(profile_config['enable_udp'])
            
            # Handle ports
            if 'ports' in profile_config and profile_config['ports']:
                ports = profile_config['ports']
                if isinstance(ports, list):
                    port_str = ','.join(map(str, ports))
                else:
                    port_str = str(ports)
                
                self.port_option.set("custom")
                self.custom_ports_var.set(port_str)
                self.on_port_option_change()
            
            logging.info(f"Applied profile '{profile_name}' to GUI")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to apply profile '{profile_name}': {e}")
            logging.error(f"Failed to apply profile '{profile_name}': {e}")
        
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
        
        # Configure combobox styles
        style.configure('Modern.TCombobox',
                       fieldbackground=self.colors['surface'],
                       borderwidth=2,
                       relief='solid',
                       bordercolor=self.colors['border'],
                       font=('Segoe UI', 10),
                       padding=(8, 6))
        
        style.map('Modern.TCombobox',
                 bordercolor=[('focus', self.colors['primary'])])
        
    def create_widgets(self):
        """Create and layout GUI widgets with modern styling"""
        # Main container with background and responsive padding
        main_container = tk.Frame(self.root, bg=self.colors['background'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Top navigation bar
        nav_bar = tk.Frame(main_container, bg=self.colors['primary'], height=60)
        nav_bar.pack(fill=tk.X, pady=(0, 15))
        nav_bar.pack_propagate(False)
        
        # Nav left side
        nav_left = tk.Frame(nav_bar, bg=self.colors['primary'])
        nav_left.pack(side=tk.LEFT, fill=tk.Y, padx=20)
        
        tk.Label(nav_left, 
                text="🔍 ADVANCED PORT SCANNER", 
                font=('Segoe UI', 14, 'bold'),
                fg='white',
                bg=self.colors['primary']).pack(side=tk.LEFT, pady=15)
        
        # Version badge
        version_frame = tk.Frame(nav_left, bg=self.colors['primary_dark'], bd=1, relief='solid')
        version_frame.pack(side=tk.LEFT, padx=(12, 0))
        tk.Label(version_frame,
                text="v2.0 Enhanced",
                font=('Segoe UI', 8, 'bold'),
                fg='white',
                bg=self.colors['primary_dark'],
                padx=8, pady=3).pack()
        
        # Nav right side with theme toggle
        nav_right = tk.Frame(nav_bar, bg=self.colors['primary'])
        nav_right.pack(side=tk.RIGHT, fill=tk.Y, padx=20)
        
        # Theme toggle button
        theme_icon = "🌙" if self.current_theme == 'light' else "☀️"
        theme_btn = tk.Button(nav_right,
                             text=theme_icon,
                             font=('Segoe UI', 12),
                             bg=self.colors['primary_dark'],
                             fg='white',
                             bd=0,
                             padx=12,
                             pady=8,
                             cursor='hand2',
                             command=self.toggle_theme,
                             activebackground=self.colors['primary_light'],
                             activeforeground='white')
        theme_btn.pack(side=tk.RIGHT, pady=12)
        
        # Keyboard shortcuts hint
        tk.Label(nav_right,
                text="Ctrl+T",
                font=('Segoe UI', 7),
                fg='#e0e0e0',
                bg=self.colors['primary']).pack(side=tk.RIGHT, padx=(0, 5))
        
        # Statistics Dashboard
        stats_frame = tk.Frame(main_container, bg=self.colors['background'])
        stats_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Create stat cards
        stats_data = [
            ("📊 Total Scans", "total_scans", self.colors['primary']),
            ("🔓 Open Ports", "total_open_ports", self.colors['success']),
            ("📈 Ports Scanned", "total_ports_scanned", self.colors['info']),
            ("⏱️ Last Duration", "last_scan_duration", self.colors['accent'])
        ]
        
        self.stat_labels = {}
        for i, (title, key, color) in enumerate(stats_data):
            stat_card = tk.Frame(stats_frame, bg=self.colors['surface'], relief='flat', bd=0, height=90)
            stat_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0 if i == 0 else 7, 0))
            
            # Color indicator
            tk.Frame(stat_card, bg=color, height=4).pack(fill=tk.X)
            
            # Content
            content = tk.Frame(stat_card, bg=self.colors['surface'])
            content.pack(fill=tk.BOTH, expand=True, padx=15, pady=12)
            
            tk.Label(content,
                    text=title,
                    font=('Segoe UI', 9),
                    fg=self.colors['text_muted'],
                    bg=self.colors['surface']).pack(anchor=tk.W)
            
            value_label = tk.Label(content,
                                  text=self.format_stat_value(key, 0),
                                  font=('Segoe UI', 20, 'bold'),
                                  fg=self.colors['text'],
                                  bg=self.colors['surface'])
            value_label.pack(anchor=tk.W, pady=(5, 0))
            self.stat_labels[key] = value_label
        
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
        
        # Profile selection section
        profile_section = tk.Frame(left_inner, bg=self.colors['surface'])
        profile_section.pack(fill=tk.X, pady=(0, 15))
        
        profile_header = tk.Frame(profile_section, bg=self.colors['surface'])
        profile_header.pack(fill=tk.X)
        
        tk.Label(profile_header, 
                text="📋 Configuration Profile", 
                font=('Segoe UI', 12, 'bold'),
                fg=self.colors['primary'],
                bg=self.colors['surface']).pack(side=tk.LEFT)
        
        reload_btn = ttk.Button(profile_header, text="🔄", 
                               command=self.reload_configuration,
                               style='Secondary.TButton', width=3)
        reload_btn.pack(side=tk.RIGHT)
        
        tk.Label(profile_section, 
                text="Profile:", 
                font=('Segoe UI', 9),
                fg=self.colors['text'],
                bg=self.colors['surface']).pack(anchor=tk.W, pady=(10, 5))
        
        profile_names = ["<Custom>"] + list(self.profiles.keys())
        self.profile_var = tk.StringVar(value="<Custom>")
        self.profile_combo = ttk.Combobox(profile_section, textvariable=self.profile_var,
                                         values=profile_names, state="readonly",
                                         style='Modern.TCombobox', width=23)
        self.profile_combo.pack(fill=tk.X)
        self.profile_combo.bind("<<ComboboxSelected>>", self.on_profile_change)
        
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
        # Disable mouse wheel to prevent accidental value changes when scrolling
        timeout_spin.bind("<MouseWheel>", lambda e: "break")
        
        # Max workers
        tk.Label(settings_grid, text="Max Threads:", font=('Segoe UI', 9),
                fg=self.colors['text'], bg=self.colors['surface']).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.workers_var = tk.IntVar(value=100)
        workers_spin = ttk.Spinbox(settings_grid, from_=1, to=500, increment=10, 
                                  textvariable=self.workers_var, width=8, style='Modern.TSpinbox')
        workers_spin.grid(row=1, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        # Disable mouse wheel to prevent accidental value changes when scrolling
        workers_spin.bind("<MouseWheel>", lambda e: "break")
        
        # Options checkboxes
        options_frame = tk.Frame(advanced_section, bg=self.colors['surface'])
        options_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.banner_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Enable Banner Grabbing", 
                       variable=self.banner_var, style='Modern.TCheckbutton').pack(anchor=tk.W)
        
        self.show_closed_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Show Closed/Filtered Ports", 
                       variable=self.show_closed_var, style='Modern.TCheckbutton').pack(anchor=tk.W, pady=(5, 0))
        
        self.ping_sweep_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Enable Ping Sweep (Network Scans)", 
                       variable=self.ping_sweep_var, style='Modern.TCheckbutton').pack(anchor=tk.W, pady=(5, 0))
        
        self.udp_scan_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Enable UDP Scanning", 
                       variable=self.udp_scan_var, style='Modern.TCheckbutton').pack(anchor=tk.W, pady=(5, 0))
        
        self.async_scan_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Use Async I/O (Better Performance)", 
                       variable=self.async_scan_var, style='Modern.TCheckbutton').pack(anchor=tk.W, pady=(5, 0))
        
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
        
        ttk.Button(button_grid, text="📄 Generate HTML Report", 
                  command=self.generate_html_report, style='Success.TButton').pack(fill=tk.X, pady=2)
        
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
        ttk.Button(quick_buttons, text="UDP Services", 
                  command=lambda: self.quick_scan_udp("localhost", "53,123,161,514,1900"),
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
                                                     wrap=tk.NONE)
        # Add horizontal scrollbar for wide content
        h_scrollbar = ttk.Scrollbar(results_container, orient="horizontal")
        # Link the scrollbar and the text widget for horizontal scrolling
        self.results_text.configure(xscrollcommand=h_scrollbar.set)
        h_scrollbar.config(command=self.results_text.xview)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Improve UX: hold Shift and use mouse wheel to scroll horizontally
        def _on_shift_mousewheel(event):
            try:
                self.results_text.xview_scroll(int(-1 * (event.delta / 120)), "units")
            except Exception:
                pass
            return "break"
        self.results_text.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        
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
        
        # Footer with shortcuts and credits
        footer = tk.Frame(main_container, bg=self.colors['surface'], height=45)
        footer.pack(fill=tk.X, pady=(10, 0))
        footer.pack_propagate(False)
        
        # Left side - shortcuts
        footer_left = tk.Frame(footer, bg=self.colors['surface'])
        footer_left.pack(side=tk.LEFT, padx=20, pady=10)
        
        shortcuts = "⌨️ Shortcuts: Ctrl+S (Start) | Ctrl+Q (Stop) | Ctrl+E (Export) | Ctrl+L (Clear) | Ctrl+T (Theme) | F5 (Reload)"
        tk.Label(footer_left,
                text=shortcuts,
                font=('Segoe UI', 8),
                fg=self.colors['text_muted'],
                bg=self.colors['surface']).pack(side=tk.LEFT)
        
        # Right side - signature
        footer_right = tk.Frame(footer, bg=self.colors['surface'])
        footer_right.pack(side=tk.RIGHT, padx=20, pady=10)
        
        tk.Label(footer_right,
                text="Made with 💜 by Eplisium",
                font=('Segoe UI', 9, 'italic'),
                fg=self.colors['accent'],
                bg=self.colors['surface']).pack(side=tk.RIGHT)
        
    def format_stat_value(self, key, value):
        """Format stat value for display"""
        if key == "last_scan_duration":
            if value == 0:
                return "0.0s"
            return f"{value:.1f}s"
        return str(value)
    
    def update_statistics(self, open_count, total_scanned, duration):
        """Update statistics after a scan"""
        self.scan_stats['total_scans'] += 1
        self.scan_stats['total_ports_scanned'] += total_scanned
        self.scan_stats['total_open_ports'] += open_count
        self.scan_stats['last_scan_duration'] = duration
        
        # Update UI labels if they exist
        if hasattr(self, 'stat_labels'):
            for key, value in self.scan_stats.items():
                if key in self.stat_labels:
                    self.stat_labels[key].config(text=self.format_stat_value(key, value))
    
    def on_port_option_change(self, *args):
        """Handle port option radio button changes"""
        if self.port_option.get() == "custom":
            self.custom_ports_entry.config(state="normal")
        else:
            self.custom_ports_entry.config(state="disabled")
    
    def on_profile_change(self, event=None):
        """Handle profile selection changes"""
        selected_profile = self.profile_var.get()
        if selected_profile and selected_profile != "<Custom>":
            self.apply_profile_to_gui(selected_profile)
        else:
            self.current_profile = None
            
    def quick_scan(self, host, ports):
        """Perform a quick scan with predefined parameters"""
        self.host_var.set(host)
        if ports == "common":
            self.port_option.set("common")
        else:
            self.port_option.set("custom")
            self.custom_ports_var.set(ports)
        # Disable UDP for regular quick scans
        self.udp_scan_var.set(False)
        self.start_scan()
    
    def quick_scan_udp(self, host, ports):
        """Perform a quick UDP scan with predefined parameters"""
        self.host_var.set(host)
        self.port_option.set("custom")
        self.custom_ports_var.set(ports)
        # Enable UDP for UDP quick scans
        self.udp_scan_var.set(True)
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
        self.scanner.reset_cancel()
        self.scanner.timeout = self.timeout_var.get()
        self.scanner.max_workers = self.workers_var.get()
        # Wire banner toggle from checkbox
        self.scanner.enable_banner = bool(self.banner_var.get())
        # Enable UDP scanning if requested
        self.scanner.enable_udp = bool(self.udp_scan_var.get())
        
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
            import time
            scan_start_time = time.time()
            
            self.queue.put(("status", f"Starting scan of {host} on {len(ports)} ports..."))
            
            # Clear previous results
            self.scanner.results = []
            
            # Progress callback forwards updates to GUI via queue
            def progress_cb(completed, total, result):
                # Avoid flooding updates if cancelled
                if not self.scanner.is_cancelled():
                    self.queue.put(("progress", completed, total))

            # Determine protocols to scan
            protocols = ["TCP"]
            if self.udp_scan_var.get():
                protocols.append("UDP")
            
            if '/' in host:  # Network scan
                ping_first = self.ping_sweep_var.get()
                results = self.scanner.scan_network_range(host, ports, protocols, ping_first=ping_first, progress_callback=progress_cb)
                for host_ip, host_results in results.items():
                    self.queue.put(("results", host_ip, host_results))
            else:  # Single host scan
                if self.async_scan_var.get():
                    # Use async scanning for better performance
                    import asyncio
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
        # Request cooperative cancellation
        self.scanner.cancel()
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
                elif message[0] == "stats":
                    open_count, total_scanned, duration = message[1], message[2], message[3]
                    self.update_statistics(open_count, total_scanned, duration)
                elif message[0] == "progress":
                    completed, total = message[1], message[2]
                    if self.scanner.is_cancelled():
                        # Do not show progress updates after cancellation
                        continue
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
                elif message[0] == "stopped":
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
        self.results_text.insert(tk.END, f"\n{'='*130}\n", 'header')
        self.results_text.insert(tk.END, f"🎯 SCAN RESULTS FOR {host.upper()}\n", 'header')
        self.results_text.insert(tk.END, f"{'='*130}\n", 'header')
        self.results_text.insert(tk.END, f"{'PORT':<8} {'PROTO':<6} {'STATUS':<12} {'SERVICE':<16} {'VERSION':<20} {'CONF':<6} {'LADDR':<16} {'ENV':<12} {'PROCESS(PID)':<20} {'BANNER':<24}\n", 'header')
        self.results_text.insert(tk.END, f"{'-'*130}\n", 'header')
        
        open_count = 0
        closed_count = 0
        filtered_count = 0
        
        for result in results:
            if result.status == "OPEN" or (self.show_closed_var.get() and result.status in ["CLOSED", "FILTERED"]):
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
                    self.results_text.insert(tk.END, line, 'open')
                    open_count += 1
                elif result.status == "CLOSED":
                    self.results_text.insert(tk.END, line, 'closed')
                    closed_count += 1
                else:
                    self.results_text.insert(tk.END, line, 'filtered')
                    filtered_count += 1
        
        # Enhanced summary with statistics
        self.results_text.insert(tk.END, f"{'-'*130}\n", 'header')
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
