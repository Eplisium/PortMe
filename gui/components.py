#!/usr/bin/env python3
"""
GUI Components for Port Scanner
Modular UI components for better maintainability
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
from typing import Dict, Any, Callable, Optional


class BaseComponent:
    """Base class for all GUI components"""
    
    def __init__(self, parent, colors: Dict[str, str], **kwargs):
        self.parent = parent
        self.colors = colors
        self.container = None
        self.kwargs = kwargs
    
    def create(self) -> tk.Widget:
        """Create and return the component's main widget"""
        raise NotImplementedError("Subclasses must implement create()")
    
    def update(self, **kwargs):
        """Update component with new data/state"""
        pass
    
    def destroy(self):
        """Clean up the component"""
        if self.container:
            self.container.destroy()


class ThemeManager:
    """Manages theme configuration and switching"""
    
    THEMES = {
        'light': {
            'primary': '#3b82f6', 'primary_dark': '#2563eb', 'primary_light': '#60a5fa',
            'secondary': '#64748b', 'success': '#10b981', 'danger': '#ef4444',
            'warning': '#f59e0b', 'info': '#06b6d4', 'background': '#f8fafc',
            'surface': '#ffffff', 'text': '#1e293b', 'text_light': '#64748b',
            'text_muted': '#94a3b8', 'border': '#e2e8f0', 'hover': '#f1f5f9',
            'accent': '#8b5cf6'
        },
        'dark': {
            'primary': '#3b82f6', 'primary_dark': '#1e40af', 'primary_light': '#60a5fa',
            'secondary': '#94a3b8', 'success': '#10b981', 'danger': '#ef4444',
            'warning': '#f59e0b', 'info': '#06b6d4', 'background': '#0f172a',
            'surface': '#1e293b', 'text': '#f8fafc', 'text_light': '#cbd5e1',
            'text_muted': '#94a3b8', 'border': '#334155', 'hover': '#334155',
            'accent': '#a78bfa'
        }
    }
    
    def __init__(self, initial_theme: str = 'light'):
        self.current_theme = initial_theme
        self.colors = self.THEMES[initial_theme]
    
    def toggle(self) -> str:
        """Toggle between light and dark themes"""
        self.current_theme = 'dark' if self.current_theme == 'light' else 'light'
        self.colors = self.THEMES[self.current_theme]
        return self.current_theme
    
    def get_theme_name(self) -> str:
        return "Dark" if self.current_theme == 'dark' else "Light"
    
    def setup_styles(self):
        """Configure ttk styles for current theme"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Primary button
        style.configure('Primary.TButton', background=self.colors['primary'],
                       foreground='white', font=('Segoe UI', 10, 'bold'),
                       borderwidth=0, focuscolor='none', relief='flat', padding=(15, 8))
        style.map('Primary.TButton', background=[('active', self.colors['primary_dark'])])
        
        # Success, Danger, Secondary, Info buttons
        for btn_type, color, active in [('Success', self.colors['success'], '#047857'),
                                         ('Danger', self.colors['danger'], '#b91c1c'),
                                         ('Secondary', self.colors['secondary'], '#475569'),
                                         ('Info', self.colors['info'], '#0891b2')]:
            style.configure(f'{btn_type}.TButton', background=color, foreground='white',
                           font=('Segoe UI', 9), borderwidth=0, focuscolor='none',
                           relief='flat', padding=(12, 6))
            style.map(f'{btn_type}.TButton', background=[('active', active)])
        
        # Entry, Spinbox, Combobox styles
        for widget in ['Entry', 'Spinbox', 'Combobox']:
            style.configure(f'Modern.T{widget}', fieldbackground=self.colors['surface'],
                           borderwidth=2, relief='solid', bordercolor=self.colors['border'],
                           font=('Segoe UI', 10 if widget != 'Spinbox' else 9),
                           padding=(10, 8) if widget == 'Entry' else (8, 6))
            style.map(f'Modern.T{widget}', bordercolor=[('focus', self.colors['primary'])])
        
        # Checkbox and Radiobutton
        for widget in ['Checkbutton', 'Radiobutton']:
            style.configure(f'Modern.T{widget}', background=self.colors['background'],
                           foreground=self.colors['text'], font=('Segoe UI', 9), focuscolor='none')
        
        # Progressbar
        style.configure('Modern.Horizontal.TProgressbar', background=self.colors['primary'],
                       troughcolor=self.colors['border'], borderwidth=0)
