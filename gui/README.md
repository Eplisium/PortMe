# GUI Package

This directory contains all GUI components for the Port Scanner application.

## Structure

```
gui/
├── __init__.py       # Package initialization and exports
├── components.py     # Base components and theme manager
├── panels.py         # Individual panel implementations
└── README.md         # This file
```

## Components

### Base Components (`components.py`)

- **BaseComponent**: Abstract base class for all GUI components
  - Provides standard interface with `create()`, `update()`, and `destroy()` methods
  - Handles parent widget and color scheme management

- **ThemeManager**: Manages light/dark theme configuration
  - Provides theme toggle functionality
  - Configures all ttk styles for consistent appearance
  - Supports dynamic theme switching

### Panel Components (`panels.py`)

All panels inherit from `BaseComponent` and provide specific UI functionality:

1. **NavigationBar**: Top navigation with title and theme toggle button
2. **StatisticsPanel**: Dashboard displaying scan statistics (total scans, open ports, etc.)
3. **ProfilePanel**: Configuration profile selection and reload
4. **TargetConfigPanel**: Target host/network and port configuration
5. **AdvancedOptionsPanel**: Advanced scanning options (timeout, workers, flags)
6. **ControlsPanel**: Scan control buttons (start, stop, clear, export, report)
7. **QuickScanPanel**: Quick scan preset buttons
8. **ResultsPanel**: Results display with progress tracking
9. **FooterPanel**: Footer with keyboard shortcuts and credits

## Usage

Import components from the gui package:

```python
from gui.components import ThemeManager
from gui.panels import NavigationBar, StatisticsPanel, ResultsPanel
# or import all
from gui import *
```

### Creating a Component

```python
# Initialize theme manager
theme_manager = ThemeManager('light')
colors = theme_manager.colors

# Create a panel
nav_bar = NavigationBar(parent_frame, colors, on_theme_toggle_callback, current_theme='light')
nav_bar.create()

# Update a panel (if supported)
stats_panel.update(total_scans=10, total_open_ports=5)
```

## Design Philosophy

- **Modularity**: Each panel is self-contained and reusable
- **Separation of Concerns**: UI logic separated from business logic
- **Theming**: Centralized theme management for consistent styling
- **Component Pattern**: All panels follow the same base interface
- **Callbacks**: Parent-child communication via callback functions

## Color Scheme

Both light and dark themes include:
- Primary colors (primary, primary_dark, primary_light)
- Semantic colors (success, danger, warning, info)
- UI colors (background, surface, text variants, border, hover)
- Accent color for highlights

## Adding New Components

1. Create a new class inheriting from `BaseComponent`
2. Implement the `create()` method to build the UI
3. Optionally implement `update()` and `destroy()` methods
4. Add to `__init__.py` exports
5. Update this README

## Example

See `port_scanner_gui.py` for complete usage example of all components.
