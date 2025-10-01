# Port Scanner GUI - Component Architecture

## Overview
```
┌─────────────────────────────────────────────────────────┐
│                   PortScannerGUI                        │
│                  (Main Application)                      │
└─────────────────────────────────────────────────────────┘
                           │
                           │ orchestrates
                           ▼
    ┌──────────────────────────────────────────────┐
    │          Component Architecture               │
    │              (gui/ package)                   │
    └──────────────────────────────────────────────┘
                           │
         ┌─────────────────┴─────────────────┐
         │                                   │
         ▼                                   ▼
┌──────────────────┐              ┌──────────────────┐
│ gui/components.py│              │  gui/panels.py   │
├──────────────────┤              ├──────────────────┤
│ • BaseComponent  │              │ 9 Panel Classes  │
│ • ThemeManager   │              │                  │
└──────────────────┘              └──────────────────┘
```

## Component Hierarchy

```
BaseComponent (Abstract)
│
├── NavigationBar
│   ├── Title & Branding
│   ├── Version Badge
│   └── Theme Toggle Button
│
├── StatisticsPanel
│   ├── Total Scans Card
│   ├── Open Ports Card
│   ├── Ports Scanned Card
│   └── Last Duration Card
│
├── ProfilePanel
│   ├── Profile Selector
│   └── Reload Button
│
├── TargetConfigPanel
│   ├── Host Input
│   ├── Port Option (Common/Custom)
│   └── Custom Ports Entry
│
├── AdvancedOptionsPanel
│   ├── Timeout Spinbox
│   ├── Max Threads Spinbox
│   └── Options Checkboxes
│       ├── Banner Grabbing
│       ├── Show Closed
│       ├── Ping Sweep
│       ├── UDP Scan
│       └── Async I/O
│
├── ControlsPanel
│   ├── Start Scan Button
│   ├── Stop Scan Button
│   ├── Clear Results Button
│   ├── Export Results Button
│   └── Generate HTML Report Button
│
├── QuickScanPanel
│   ├── Port 3000 Button
│   ├── Web Ports Button
│   ├── UDP Services Button
│   └── Common Services Button
│
├── ResultsPanel
│   ├── Progress Bar
│   ├── Progress Label
│   └── Results Text Area
│       ├── Horizontal Scroll
│       └── Text Tags (open, closed, filtered, etc.)
│
└── FooterPanel
    ├── Keyboard Shortcuts
    └── Credits
```

## File Structure

```
 PortMe/
│
├── port_scanner.py              # Backend scanner logic
├── config_loader.py             # Configuration management
├── config.yaml                  # Configuration file
│
├── gui/                         # GUI Package
│   ├── __init__.py              # Package initialization & exports
│   ├── README.md                # GUI package documentation
│   │
│   ├── components.py            # Base classes & theme
│   │   ├── BaseComponent        # Abstract base class
│   │   └── ThemeManager         # Theme & style management
│   │
│   └── panels.py                # UI panel components
│       ├── NavigationBar        # Top navigation
│       ├── StatisticsPanel      # Stats dashboard
│       ├── ProfilePanel         # Profile selector
│       ├── TargetConfigPanel    # Target configuration
│       ├── AdvancedOptionsPanel # Advanced options
│       ├── ControlsPanel        # Control buttons
│       ├── QuickScanPanel       # Quick scan buttons
│       ├── ResultsPanel         # Results display
│       └── FooterPanel          # Footer
│
└── port_scanner_gui.py          # Main application
    └── PortScannerGUI           # Orchestrates all components
```

## Data Flow

```
User Input
    │
    ▼
┌─────────────────────┐
│  UI Panel Component │
│  (e.g., TargetPanel)│
└─────────────────────┘
    │
    │ updates tkinter vars
    ▼
┌─────────────────────┐
│  PortScannerGUI     │
│  (Main Controller)  │
└─────────────────────┘
    │
    │ configures
    ▼
┌─────────────────────┐
│   PortScanner       │
│   (Backend)         │
└─────────────────────┘
    │
    │ via queue
    ▼
┌─────────────────────┐
│  ResultsPanel       │
│  (Display Results)  │
└─────────────────────┘
    │
    ▼
User Views Results
```

## Component Communication

### 1. Component → Main GUI
- Components expose `tkinter.Variable` objects
- Main GUI reads from these variables when needed
- Example: `self.target_panel.host_var.get()`

### 2. Main GUI → Component
- Main GUI calls component methods
- Main GUI updates component state directly
- Example: `self.stats_panel.update(**stats)`

### 3. Component → Component (via Main GUI)
- No direct component-to-component communication
- All communication goes through PortScannerGUI
- Maintains loose coupling

### 4. Threading Communication
```
Scan Worker Thread
    │
    │ queue.put()
    ▼
Queue
    │
    │ process_queue() (main thread)
    ▼
PortScannerGUI
    │
    │ updates components
    ▼
UI Components
```

## Theme System

```
ThemeManager
    │
    ├── THEMES = {
    │       'light': {...},
    │       'dark': {...}
    │   }
    │
    ├── current_theme: str
    ├── colors: Dict[str, str]
    │
    └── Methods:
        ├── toggle() → str
        ├── get_theme_name() → str
        └── setup_styles() → None
```

### Theme Color Palette

Each theme defines:
- `primary`, `primary_dark`, `primary_light` - Main brand colors
- `secondary` - Secondary actions
- `success`, `danger`, `warning`, `info` - Status colors
- `background`, `surface` - Container colors
- `text`, `text_light`, `text_muted` - Text colors
- `border`, `hover` - UI element colors
- `accent` - Accent highlights

## Component Lifecycle

```
1. __init__(parent, colors, **kwargs)
   │ Initialize component
   │ Store parent and colors
   │ Store additional kwargs
   │
2. create() → tk.Widget
   │ Build UI elements
   │ Pack/grid elements
   │ Configure bindings
   │ Store reference in self.container
   │ Return main widget
   │
3. update(**kwargs) [optional]
   │ Update component state
   │ Refresh displayed data
   │
4. destroy() [optional]
   │ Clean up resources
   │ Destroy container
```

## Key Design Patterns

### 1. **Component Pattern**
Each UI section is encapsulated in a self-contained component.

### 2. **Observer Pattern**
Queue-based communication for thread-safe UI updates.

### 3. **Template Method**
BaseComponent defines structure, subclasses implement specifics.

### 4. **Strategy Pattern**
ThemeManager allows switching visual strategies at runtime.

### 5. **Facade Pattern**
PortScannerGUI provides simplified interface to complex subsystems.

## Thread Safety

```
┌─────────────────┐
│  Main Thread    │ ◄─── UI Operations (Tkinter)
└─────────────────┘
        ▲
        │ queue
        │
┌─────────────────┐
│  Worker Thread  │ ◄─── Scanning Operations
└─────────────────┘
```

- **Main Thread**: All UI updates
- **Worker Thread**: All scanning operations
- **Communication**: Thread-safe queue
- **Synchronization**: `process_queue()` polls every 100ms

## Extension Points

### Adding a New Component
1. Create class in `gui/panels.py` inheriting from `BaseComponent`
2. Implement `create()` method
3. Add to `gui/__init__.py` exports
4. Import in `port_scanner_gui.py`
5. Instantiate in `PortScannerGUI.create_widgets()`
6. Access via `self.my_component` in main GUI
7. Update `gui/README.md` documentation

### Adding a New Theme
1. Add theme dict to `ThemeManager.THEMES`
2. Define all required color keys
3. Theme automatically available via toggle

### Adding a New Feature
1. Add UI component (if needed)
2. Add backend logic to `PortScanner`
3. Wire up in `PortScannerGUI`
4. Update configuration (if needed)

## Performance Considerations

- **Lazy Loading**: Components created only when needed
- **Event Throttling**: Queue processing at 100ms intervals
- **Progressive Rendering**: Results displayed as they arrive
- **Responsive Design**: Scrollable panels prevent overflow
- **Efficient Updates**: Only changed statistics are updated

## Testing Strategy

### Unit Tests (Recommended)
- Test each component's `create()` method
- Test ThemeManager color switching
- Test component state updates

### Integration Tests
- Test main GUI initialization
- Test component communication
- Test theme switching flow

### Manual Tests
- Verify all buttons work
- Test keyboard shortcuts
- Verify scrolling behavior
- Test theme switching
- Run actual scans

---

**Architecture designed with ❤️ for maintainability and extensibility**
