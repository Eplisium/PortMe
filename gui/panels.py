#!/usr/bin/env python3
"""
GUI Panel Components for Port Scanner
Individual panel implementations
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
from typing import Dict, Callable
from gui.components import BaseComponent


class NavigationBar(BaseComponent):
    """Top navigation bar with title and theme toggle"""
    
    def __init__(self, parent, colors: Dict[str, str], on_theme_toggle: Callable, **kwargs):
        super().__init__(parent, colors, **kwargs)
        self.on_theme_toggle = on_theme_toggle
    
    def create(self) -> tk.Widget:
        nav_bar = tk.Frame(self.parent, bg=self.colors['primary'], height=60)
        nav_bar.pack(fill=tk.X, pady=(0, 15))
        nav_bar.pack_propagate(False)
        
        # Left side
        nav_left = tk.Frame(nav_bar, bg=self.colors['primary'])
        nav_left.pack(side=tk.LEFT, fill=tk.Y, padx=20)
        
        tk.Label(nav_left, text="🔍 ADVANCED PORT SCANNER", font=('Segoe UI', 14, 'bold'),
                fg='white', bg=self.colors['primary']).pack(side=tk.LEFT, pady=15)
        
        # Version badge
        version_frame = tk.Frame(nav_left, bg=self.colors['primary_dark'], bd=1, relief='solid')
        version_frame.pack(side=tk.LEFT, padx=(12, 0))
        tk.Label(version_frame, text="v2.0 Enhanced", font=('Segoe UI', 8, 'bold'),
                fg='white', bg=self.colors['primary_dark'], padx=8, pady=3).pack()
        
        # Right side with theme toggle
        nav_right = tk.Frame(nav_bar, bg=self.colors['primary'])
        nav_right.pack(side=tk.RIGHT, fill=tk.Y, padx=20)
        
        theme_icon = "🌙" if self.kwargs.get('current_theme') == 'light' else "☀️"
        theme_btn = tk.Button(nav_right, text=theme_icon, font=('Segoe UI', 12),
                             bg=self.colors['primary_dark'], fg='white', bd=0,
                             padx=12, pady=8, cursor='hand2', command=self.on_theme_toggle,
                             activebackground=self.colors['primary_light'], activeforeground='white')
        theme_btn.pack(side=tk.RIGHT, pady=12)
        
        tk.Label(nav_right, text="Ctrl+T", font=('Segoe UI', 7),
                fg='#e0e0e0', bg=self.colors['primary']).pack(side=tk.RIGHT, padx=(0, 5))
        
        self.container = nav_bar
        return nav_bar


class StatisticsPanel(BaseComponent):
    """Dashboard with statistics cards"""
    
    def __init__(self, parent, colors: Dict[str, str]):
        super().__init__(parent, colors)
        self.stat_labels = {}
    
    def create(self) -> tk.Widget:
        stats_frame = tk.Frame(self.parent, bg=self.colors['background'])
        stats_frame.pack(fill=tk.X, pady=(0, 15))
        
        stats_data = [
            ("📊 Total Scans", "total_scans", self.colors['primary']),
            ("🔓 Open Ports", "total_open_ports", self.colors['success']),
            ("📈 Ports Scanned", "total_ports_scanned", self.colors['info']),
            ("⏱️ Last Duration", "last_scan_duration", self.colors['accent'])
        ]
        
        for i, (title, key, color) in enumerate(stats_data):
            stat_card = tk.Frame(stats_frame, bg=self.colors['surface'], relief='flat', bd=0, height=90)
            stat_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0 if i == 0 else 7, 0))
            
            tk.Frame(stat_card, bg=color, height=4).pack(fill=tk.X)
            
            content = tk.Frame(stat_card, bg=self.colors['surface'])
            content.pack(fill=tk.BOTH, expand=True, padx=15, pady=12)
            
            tk.Label(content, text=title, font=('Segoe UI', 9),
                    fg=self.colors['text_muted'], bg=self.colors['surface']).pack(anchor=tk.W)
            
            value_label = tk.Label(content, text=self._format_stat_value(key, 0),
                                  font=('Segoe UI', 20, 'bold'),
                                  fg=self.colors['text'], bg=self.colors['surface'])
            value_label.pack(anchor=tk.W, pady=(5, 0))
            self.stat_labels[key] = value_label
        
        self.container = stats_frame
        return stats_frame
    
    def _format_stat_value(self, key: str, value) -> str:
        if key == "last_scan_duration":
            return "0.0s" if value == 0 else f"{value:.1f}s"
        return str(value)
    
    def update(self, **stats):
        for key, value in stats.items():
            if key in self.stat_labels:
                self.stat_labels[key].config(text=self._format_stat_value(key, value))


class ProfilePanel(BaseComponent):
    """Profile selection panel"""
    
    def __init__(self, parent, colors: Dict[str, str], profiles: Dict[str, str], 
                 on_profile_change: Callable, on_reload: Callable):
        super().__init__(parent, colors)
        self.profiles = profiles
        self.on_profile_change = on_profile_change
        self.on_reload = on_reload
        self.profile_var = None
        self.profile_combo = None
    
    def create(self) -> tk.Widget:
        profile_section = tk.Frame(self.parent, bg=self.colors['surface'])
        profile_section.pack(fill=tk.X, pady=(0, 15))
        
        profile_header = tk.Frame(profile_section, bg=self.colors['surface'])
        profile_header.pack(fill=tk.X)
        
        tk.Label(profile_header, text="📋 Configuration Profile", font=('Segoe UI', 12, 'bold'),
                fg=self.colors['primary'], bg=self.colors['surface']).pack(side=tk.LEFT)
        
        reload_btn = ttk.Button(profile_header, text="🔄", command=self.on_reload,
                               style='Secondary.TButton', width=3)
        reload_btn.pack(side=tk.RIGHT)
        
        tk.Label(profile_section, text="Profile:", font=('Segoe UI', 9),
                fg=self.colors['text'], bg=self.colors['surface']).pack(anchor=tk.W, pady=(10, 5))
        
        profile_names = ["<Custom>"] + list(self.profiles.keys())
        self.profile_var = tk.StringVar(value="<Custom>")
        self.profile_combo = ttk.Combobox(profile_section, textvariable=self.profile_var,
                                         values=profile_names, state="readonly",
                                         style='Modern.TCombobox', width=23)
        self.profile_combo.pack(fill=tk.X)
        self.profile_combo.bind("<<ComboboxSelected>>", self.on_profile_change)
        
        self.container = profile_section
        return profile_section
    
    def update_profiles(self, profiles: Dict[str, str]):
        self.profiles = profiles
        if self.profile_combo:
            profile_names = ["<Custom>"] + list(profiles.keys())
            self.profile_combo['values'] = profile_names


class TargetConfigPanel(BaseComponent):
    """Target and port configuration panel"""
    
    def __init__(self, parent, colors: Dict[str, str]):
        super().__init__(parent, colors)
        self.host_var = None
        self.port_option = None
        self.custom_ports_var = None
        self.custom_ports_entry = None
    
    def create(self) -> tk.Widget:
        target_section = tk.Frame(self.parent, bg=self.colors['surface'])
        target_section.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(target_section, text="🎯 Target Configuration", font=('Segoe UI', 12, 'bold'),
                fg=self.colors['primary'], bg=self.colors['surface']).pack(anchor=tk.W)
        
        tk.Label(target_section, text="Host/Network:", font=('Segoe UI', 9),
                fg=self.colors['text'], bg=self.colors['surface']).pack(anchor=tk.W, pady=(10, 5))
        
        self.host_var = tk.StringVar(value="localhost")
        host_entry = ttk.Entry(target_section, textvariable=self.host_var, 
                              style='Modern.TEntry', width=25)
        host_entry.pack(fill=tk.X)
        
        tk.Label(target_section, text="Port Selection:", font=('Segoe UI', 9),
                fg=self.colors['text'], bg=self.colors['surface']).pack(anchor=tk.W, pady=(15, 5))
        
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
        
        self.port_option.trace('w', self._on_port_option_change)
        
        self.container = target_section
        return target_section
    
    def _on_port_option_change(self, *args):
        if self.port_option.get() == "custom":
            self.custom_ports_entry.config(state="normal")
        else:
            self.custom_ports_entry.config(state="disabled")


class AdvancedOptionsPanel(BaseComponent):
    """Advanced scanning options panel"""
    
    def __init__(self, parent, colors: Dict[str, str]):
        super().__init__(parent, colors)
        self.timeout_var = None
        self.workers_var = None
        self.banner_var = None
        self.show_closed_var = None
        self.ping_sweep_var = None
        self.udp_scan_var = None
        self.async_scan_var = None
    
    def create(self) -> tk.Widget:
        advanced_section = tk.Frame(self.parent, bg=self.colors['surface'])
        advanced_section.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(advanced_section, text="⚙️ Advanced Options", font=('Segoe UI', 12, 'bold'),
                fg=self.colors['primary'], bg=self.colors['surface']).pack(anchor=tk.W)
        
        settings_grid = tk.Frame(advanced_section, bg=self.colors['surface'])
        settings_grid.pack(fill=tk.X, pady=(10, 0))
        
        tk.Label(settings_grid, text="Timeout (sec):", font=('Segoe UI', 9),
                fg=self.colors['text'], bg=self.colors['surface']).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.timeout_var = tk.DoubleVar(value=1.0)
        timeout_spin = ttk.Spinbox(settings_grid, from_=0.1, to=10.0, increment=0.1, 
                                  textvariable=self.timeout_var, width=8, style='Modern.TSpinbox')
        timeout_spin.grid(row=0, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        timeout_spin.bind("<MouseWheel>", lambda e: "break")
        
        tk.Label(settings_grid, text="Max Threads:", font=('Segoe UI', 9),
                fg=self.colors['text'], bg=self.colors['surface']).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.workers_var = tk.IntVar(value=100)
        workers_spin = ttk.Spinbox(settings_grid, from_=1, to=500, increment=10, 
                                  textvariable=self.workers_var, width=8, style='Modern.TSpinbox')
        workers_spin.grid(row=1, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        workers_spin.bind("<MouseWheel>", lambda e: "break")
        
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
        
        self.container = advanced_section
        return advanced_section


class ControlsPanel(BaseComponent):
    """Scan control buttons panel"""
    
    def __init__(self, parent, colors: Dict[str, str], 
                 on_start: Callable, on_stop: Callable, on_clear: Callable,
                 on_export: Callable, on_html_report: Callable):
        super().__init__(parent, colors)
        self.on_start = on_start
        self.on_stop = on_stop
        self.on_clear = on_clear
        self.on_export = on_export
        self.on_html_report = on_html_report
        self.scan_button = None
        self.stop_button = None
    
    def create(self) -> tk.Widget:
        controls_section = tk.Frame(self.parent, bg=self.colors['surface'])
        controls_section.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(controls_section, text="🚀 Scan Controls", font=('Segoe UI', 12, 'bold'),
                fg=self.colors['primary'], bg=self.colors['surface']).pack(anchor=tk.W)
        
        button_grid = tk.Frame(controls_section, bg=self.colors['surface'])
        button_grid.pack(fill=tk.X, pady=(10, 0))
        
        self.scan_button = ttk.Button(button_grid, text="▶️ Start Scan", 
                                     command=self.on_start, style='Primary.TButton')
        self.scan_button.pack(fill=tk.X, pady=2)
        
        self.stop_button = ttk.Button(button_grid, text="⏹️ Stop Scan", 
                                     command=self.on_stop, style='Danger.TButton', state="disabled")
        self.stop_button.pack(fill=tk.X, pady=2)
        
        ttk.Button(button_grid, text="🗑️ Clear Results", 
                  command=self.on_clear, style='Secondary.TButton').pack(fill=tk.X, pady=2)
        
        ttk.Button(button_grid, text="💾 Export Results", 
                  command=self.on_export, style='Success.TButton').pack(fill=tk.X, pady=2)
        
        ttk.Button(button_grid, text="📄 Generate HTML Report", 
                  command=self.on_html_report, style='Success.TButton').pack(fill=tk.X, pady=2)
        
        self.container = controls_section
        return controls_section
    
    def set_scanning_state(self, is_scanning: bool):
        if is_scanning:
            self.scan_button.config(state="disabled")
            self.stop_button.config(state="normal")
        else:
            self.scan_button.config(state="normal")
            self.stop_button.config(state="disabled")


class QuickScanPanel(BaseComponent):
    """Quick scan buttons panel"""
    
    def __init__(self, parent, colors: Dict[str, str], on_quick_scan: Callable, on_quick_scan_udp: Callable):
        super().__init__(parent, colors)
        self.on_quick_scan = on_quick_scan
        self.on_quick_scan_udp = on_quick_scan_udp
    
    def create(self) -> tk.Widget:
        quick_section = tk.Frame(self.parent, bg=self.colors['surface'])
        quick_section.pack(fill=tk.X)
        
        tk.Label(quick_section, text="⚡ Quick Scans", font=('Segoe UI', 12, 'bold'),
                fg=self.colors['primary'], bg=self.colors['surface']).pack(anchor=tk.W)
        
        quick_buttons = tk.Frame(quick_section, bg=self.colors['surface'])
        quick_buttons.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(quick_buttons, text="Port 3000", 
                  command=lambda: self.on_quick_scan("localhost", "3000"),
                  style='Secondary.TButton').pack(fill=tk.X, pady=1)
        ttk.Button(quick_buttons, text="Web Ports", 
                  command=lambda: self.on_quick_scan("localhost", "80,443,8000,8080,3000,5000"),
                  style='Secondary.TButton').pack(fill=tk.X, pady=1)
        ttk.Button(quick_buttons, text="UDP Services", 
                  command=lambda: self.on_quick_scan_udp("localhost", "53,123,161,514,1900"),
                  style='Secondary.TButton').pack(fill=tk.X, pady=1)
        ttk.Button(quick_buttons, text="Common Services", 
                  command=lambda: self.on_quick_scan("localhost", "common"),
                  style='Secondary.TButton').pack(fill=tk.X, pady=1)
        
        self.container = quick_section
        return quick_section


class ResultsPanel(BaseComponent):
    """Results display panel with progress tracking"""
    
    def __init__(self, parent, colors: Dict[str, str]):
        super().__init__(parent, colors)
        self.results_text = None
        self.progress_bar = None
        self.progress_var = None
    
    def create(self) -> tk.Widget:
        right_panel = tk.Frame(self.parent, bg=self.colors['surface'], relief='solid', bd=1)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, pady=5)
        
        # Results header
        results_header = tk.Frame(right_panel, bg=self.colors['primary'], height=40)
        results_header.pack(fill=tk.X)
        results_header.pack_propagate(False)
        
        tk.Label(results_header, text="📊 Scan Results", font=('Segoe UI', 12, 'bold'),
                fg='white', bg=self.colors['primary']).pack(side=tk.LEFT, padx=15, pady=10)
        
        # Progress section
        progress_frame = tk.Frame(right_panel, bg=self.colors['surface'])
        progress_frame.pack(fill=tk.X, padx=15, pady=10)
        
        self.progress_var = tk.StringVar(value="Ready to scan")
        progress_label = tk.Label(progress_frame, textvariable=self.progress_var,
                                 font=('Segoe UI', 9), fg=self.colors['text'],
                                 bg=self.colors['surface'])
        progress_label.pack(anchor=tk.W)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='indeterminate',
                                          style='Modern.Horizontal.TProgressbar')
        self.progress_bar.pack(fill=tk.X, pady=(5, 0))
        
        # Results text area
        results_container = tk.Frame(right_panel, bg=self.colors['surface'])
        results_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        
        self.results_text = scrolledtext.ScrolledText(results_container, height=25, 
                                                     font=('Consolas', 10),
                                                     bg=self.colors['surface'],
                                                     fg=self.colors['text'],
                                                     selectbackground=self.colors['primary'],
                                                     selectforeground='white',
                                                     relief='flat', bd=0, wrap=tk.NONE)
        
        # Horizontal scrollbar
        h_scrollbar = ttk.Scrollbar(results_container, orient="horizontal")
        self.results_text.configure(xscrollcommand=h_scrollbar.set)
        h_scrollbar.config(command=self.results_text.xview)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Shift+MouseWheel for horizontal scroll
        def _on_shift_mousewheel(event):
            try:
                self.results_text.xview_scroll(int(-1 * (event.delta / 120)), "units")
            except Exception:
                pass
            return "break"
        self.results_text.bind("<Shift-MouseWheel>", _on_shift_mousewheel)
        
        # Configure text tags
        self.results_text.tag_configure('open', foreground=self.colors['success'], 
                                       font=('Consolas', 10, 'bold'))
        self.results_text.tag_configure('closed', foreground=self.colors['danger'])
        self.results_text.tag_configure('filtered', foreground=self.colors['warning'])
        self.results_text.tag_configure('header', foreground=self.colors['primary'], 
                                       font=('Consolas', 11, 'bold'))
        self.results_text.tag_configure('error', foreground=self.colors['danger'], 
                                       font=('Consolas', 10, 'bold'))
        self.results_text.tag_configure('info', foreground=self.colors['text_light'],
                                       font=('Consolas', 9, 'italic'))
        
        # Welcome message
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
        
        self.container = right_panel
        return right_panel


class FooterPanel(BaseComponent):
    """Footer with shortcuts and credits"""
    
    def __init__(self, parent, colors: Dict[str, str]):
        super().__init__(parent, colors)
    
    def create(self) -> tk.Widget:
        footer = tk.Frame(self.parent, bg=self.colors['surface'], height=45)
        footer.pack(fill=tk.X, pady=(10, 0))
        footer.pack_propagate(False)
        
        # Left side - shortcuts
        footer_left = tk.Frame(footer, bg=self.colors['surface'])
        footer_left.pack(side=tk.LEFT, padx=20, pady=10)
        
        shortcuts = "⌨️ Shortcuts: Ctrl+S (Start) | Ctrl+Q (Stop) | Ctrl+E (Export) | Ctrl+L (Clear) | Ctrl+T (Theme) | F5 (Reload)"
        tk.Label(footer_left, text=shortcuts, font=('Segoe UI', 8),
                fg=self.colors['text_muted'], bg=self.colors['surface']).pack(side=tk.LEFT)
        
        # Right side - signature
        footer_right = tk.Frame(footer, bg=self.colors['surface'])
        footer_right.pack(side=tk.RIGHT, padx=20, pady=10)
        
        tk.Label(footer_right, text="Made with 💜 by Eplisium", font=('Segoe UI', 9, 'italic'),
                fg=self.colors['accent'], bg=self.colors['surface']).pack(side=tk.RIGHT)
        
        self.container = footer
        return footer
