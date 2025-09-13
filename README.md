# Advanced Port Scanner

A comprehensive, cross-platform port scanning tool designed for Windows and WSL environments. Features multi-threading, service detection, banner grabbing, and both CLI and GUI interfaces.

## 🚀 Features

- **Multi-threaded scanning** for fast performance
- **Service detection** and banner grabbing
- **Cross-platform** compatibility (Windows & WSL)
- **GUI and CLI interfaces** for different use cases
- **Configuration profiles** with YAML/JSON support
- **Profile-based scanning** (quick-dev, web-audit, full-tcp, local-deep)
- **Hierarchical config management** with auto-discovery
- **Network range scanning** (CIDR notation support) with bounded host concurrency
- **Export results** to JSON/CSV/HTML/Markdown/XLSX formats
- **Optional gzip compression** for large JSON exports (.json.gz)
- **Real-time progress tracking**
- **Comprehensive logging**
- **Built-in common port definitions**
- **Special focus on development ports** (3000, 8000, etc.)

## 📋 Requirements

- Python 3.7 or higher
- PyYAML (for configuration file support) - install with `pip install PyYAML`
- tkinter for GUI (included with Python on Windows)
- No other external dependencies required (uses Python standard library)

## 🔧 Installation

### Windows
```powershell
# Clone or download the files to your desired directory
cd E:\Projects\Dev\Python\Important\PortMe

# Verify Python installation
python --version

# Install required dependencies
pip install PyYAML

# Run directly (no installation required)
python port_scanner.py --help
```

### WSL (Windows Subsystem for Linux)
```bash
# Navigate to your project directory
cd /mnt/e/Projects/Dev/Python/Important/PortMe

# Ensure Python3 is available
python3 --version

# Install dependencies
pip3 install PyYAML

# Run directly
python3 port_scanner.py --help
```

## 💻 Usage

### Command Line Interface

#### Configuration & Profile Management
```bash
# List available profiles
python port_scanner.py --list-profiles

# Create a sample configuration file
python port_scanner.py --create-config config.yaml

# Use a specific profile for scanning
python port_scanner.py -P quick-dev

# Use custom configuration file
python port_scanner.py -c /path/to/config.yaml -P web-audit

# Use profile with host override
python port_scanner.py -P local-deep -H 192.168.1.100
```

#### Basic Usage
```bash
# Scan common ports on localhost
python port_scanner.py -H localhost --common

# Scan specific ports
python port_scanner.py -H 192.168.1.1 -p 80,443,22,3000

# Scan port range
python port_scanner.py -H example.com -p 1-1000

# Quick check for your development server (port 3000) with banner grabbing
python port_scanner.py -H localhost -p 3000 --banner

# Scan with custom timeout and threading
python port_scanner.py -H 127.0.0.1 -p 3000-3010 --timeout 2 -w 50
```

#### Advanced Usage
```bash
# Scan network range with bounded parallelism across hosts (16 by default)
python port_scanner.py -H 192.168.1.0/24 -p 22,80,443 --host-concurrency 16

# Export results to JSON
python port_scanner.py -H localhost --common -o results.json

# Export results to Markdown
python port_scanner.py -H localhost --common -o results.md

# Export results to Excel (XLSX)
python port_scanner.py -H localhost --common -o results.xlsx

# Export gzipped JSON (either extension or --gzip flag)
python port_scanner.py -H localhost --common -o results.json.gz
# or
python port_scanner.py -H localhost --common -o results.json --gzip

# Verbose logging with banner grabbing (banners only fetched when --banner is set)
python port_scanner.py -H target.com -p 80,443,8080 --banner -v

# Show closed ports in results
python port_scanner.py -H localhost -p 3000-3005 --show-closed
```

### Graphical User Interface

Launch the GUI:
```bash
# Windows
python port_scanner_gui.py

# WSL (requires X11 forwarding)
python3 port_scanner_gui.py
```

#### GUI Features
- **Profile management**: Dropdown to select configuration profiles
- **Configuration reload**: 🔄 button to refresh configuration without restart
- **Target configuration**: Enter hostname or IP address (auto-populated from profiles)
- **Port selection**: Choose common ports or specify custom ranges
- **Advanced options**: Adjust timeout, thread count, banner grabbing
- **Quick scan buttons**: One-click scans for common scenarios
- **Real-time results**: Color-coded output with progress tracking
- **Export functionality**: Save results to JSON/CSV/HTML/Markdown/XLSX (JSON supports gzip)

## ⚙️ Configuration System

The Advanced Port Scanner now supports a comprehensive configuration and profile system that allows you to save common scanning configurations and reuse them easily.

### Configuration File Locations

The scanner automatically searches for configuration files in this order of precedence:

1. **Current Directory**: `./config.yaml` or `./config.json`
2. **User Config Directory**: 
   - **Windows**: `%APPDATA%/AdvancedPortScanner/config.yaml`
   - **Linux/WSL**: `~/.config/AdvancedPortScanner/config.yaml`

### Built-in Profiles

The scanner comes with several predefined profiles:

| Profile | Description | Ports | Features |
|---------|-------------|-------|----------|
| `quick-dev` | Development ports scan | 3000, 3001, 5000, 8000, 8080, 9000 | Banner grabbing enabled |
| `web-audit` | Web server audit | 80, 443, 8080, 8443, 8000, 3000, 22, 21, 23 | 2s timeout, banner grabbing |
| `full-tcp` | Complete TCP scan | 1-65535 (all ports) | Slow scan, 50 workers, 3s timeout |
| `local-deep` | Deep localhost scan | 1-10000 | Shows closed ports, banner grabbing |

### Sample Configuration File

Create a `config.yaml` file with:

```yaml
defaults:
  timeout: 1.5
  workers: 200
  host_concurrency: 20
  enable_banner: true
  show_closed: false
  ping_sweep: true
  output_format: json
  log_level: INFO

profiles:
  quick-dev:
    description: "Quick scan for common development ports"
    ports: [3000, 3001, 5000, 8000, 8080, 9000]
    enable_banner: true
    
  web-audit:
    description: "Scan for common web server and management ports"
    ports: [80, 443, 8080, 8443, 8000, 3000, 22, 21, 23]
    timeout: 2.0
    enable_banner: true
    
  custom-local:
    description: "Custom localhost scan"
    host: "localhost"
    ports: "22,80,443,3000-3010"
    enable_banner: true
    show_closed: true
```

### Configuration Priority

Settings are applied in this priority order (highest to lowest):

1. **Command Line Arguments** (highest priority)
2. **Profile Settings** 
3. **Configuration File Defaults**
4. **Hard-coded Defaults** (lowest priority)

This means you can set defaults in your config file, override them with a profile, and still override specific settings with command-line flags.

## 🔍 Troubleshooting Port 3000

If you're experiencing issues with port 3000 (common development port), try these solutions:

### Check if Port 3000 is in Use
```bash
# Windows
netstat -an | findstr :3000

# WSL/Linux
netstat -tlnp | grep :3000
# or
ss -tlnp | grep :3000
```

### Quick Port 3000 Diagnostic
```bash
# Test with the port scanner
python port_scanner.py -H localhost -p 3000 --banner --timeout 5

# Or use the GUI "Scan Port 3000" button
```

### Common Port 3000 Issues
1. **Service not running**: Start your development server
2. **Firewall blocking**: Check Windows Firewall/WSL firewall rules
3. **Binding issues**: Service might be bound to 127.0.0.1 vs 0.0.0.0
4. **Port already in use**: Another process might be using port 3000

### WSL-Specific Port 3000 Issues
```bash
# Check WSL port forwarding (Windows 11)
netsh interface portproxy show all

# Add port forwarding if needed (run as Administrator in Windows)
netsh interface portproxy add v4tov4 listenport=3000 listenaddress=0.0.0.0 connectport=3000 connectaddress=127.0.0.1
```

## 🎯 Quick Start Examples

### Example 1: Check Development Environment
```bash
python port_scanner.py -H localhost -p 3000,3001,8000,8080,5000 --banner
```

### Example 2: Network Security Audit
```bash
python port_scanner.py -H 192.168.1.0/24 --common -o network_audit.json
```

### Example 3: Service Investigation
```bash
python port_scanner.py -H target.com -p 80,443,22,21,25 --banner -v
```

## 📊 Output Formats

### Console Output
```
================================================================================
SCAN RESULTS FOR localhost
================================================================================
PORT     STATUS       SERVICE              BANNER                        
--------------------------------------------------------------------------------
22       OPEN         SSH                  SSH-2.0-OpenSSH_8.2p1        
80       OPEN         HTTP                 HTTP/1.1 200 OK              
3000     OPEN         Node.js/Development  HTTP/1.1 200 OK              
443      FILTERED     HTTPS                                              

Summary: 3 open ports found out of 4 scanned
```

### JSON Export
```json
[
  {
    "host": "localhost",
    "port": 3000,
    "status": "OPEN",
    "service": "Node.js/Development",
    "banner": "HTTP/1.1 200 OK",
    "response_time": 0.023
  }
]
```

### Markdown Export

```md
# Scan Results
_Generated: 2025-01-01 12:34:56_

Made with loveee <3 :3

| Host | Port | Proto | Status | Service | ServiceVersion | Conf | Banner | RespTime | PID | Process | LocalAddr | WSL | Docker |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| localhost | 3000 | TCP | OPEN | Node.js/Development |  | 0.90 | HTTP/1.1 200 OK | 0.023 | 12345 | node | 127.0.0.1 | no |  |
```

### Excel (XLSX) Export

- Produces a `Results` worksheet with a bold, centered title: “Scan Results - Made with loveee <3 :3”.
- Columns include: Host, Port, Protocol, Status, Service, ServiceVersion, Confidence, Banner, ResponseTime, PID, Process, ProcessPath, LocalAddress, IsWSL, WSLDistro, WSLProcess, WSLPath, DockerContainer, DockerImage, DockerContainerID.
- Columns are auto-sized (capped) and headers are frozen for easy scrolling.

### Gzipped JSON Export (.json.gz)

- Use a filename ending with `.json.gz` (or `.gz`) or pass `--gzip` with a `.json` filename.
- Useful for reducing file size for large scans.

## ⚙️ Configuration Options

### Configuration & Profile Arguments
| Parameter | Description | Default |
|-----------|-------------|---------|
| `-c, --config` | Path to configuration file | Auto-detect |
| `-P, --profile` | Configuration profile to use | None |
| `--list-profiles` | List available profiles and exit | - |
| `--create-config` | Create sample configuration file and exit | - |

### Scanning Arguments
| Parameter | Description | Default |
|-----------|-------------|---------|
| `-H, --host` | Target host or network | Required (or from profile) |
| `-p, --ports` | Ports to scan | Common ports |
| `--common` | Scan common ports only | False |
| `-t, --timeout` | Socket timeout (seconds) | 1.0 (or from config) |
| `-w, --workers` | Max worker threads | 100 (or from config) |
| `--host-concurrency` | Max concurrent host scans for network ranges | 16 (or from config) |
| `--banner` | Enable banner grabbing | False (or from config) |
| `--show-closed` | Show closed/filtered ports in results | False (or from config) |
| `--no-ping` | Skip ping sweep for network scans | False (or from config) |
| `--udp` | Enable UDP scanning in addition to TCP | False (or from config) |
| `-o, --output` | Export file (supports .json, .json.gz, .csv, .html, .md, .xlsx) | None |
| `--gzip` | Compress JSON output (implied when `-o` ends with `.gz`) | False |
| `-v, --verbose` | Enable verbose logging | False |
| `--async` | Use async I/O for better performance | False |

## ✅ Behavior Notes

- Banners are fetched only when `--banner` is specified (CLI) or the "Enable Banner Grabbing" checkbox is checked (GUI). This avoids unnecessary I/O when disabled.
- The GUI features a real Stop Scan button that cooperatively cancels ongoing scans. Scans halt shortly after pressing stop and the UI returns to an idle state.
- Network range scans are parallelized across hosts with a bounded level of concurrency to avoid overwhelming the system. Use `--host-concurrency` to tune.
- Total concurrency during network scans is approximately `host_concurrency * workers` (per-host threads). Choose balanced values to keep CPU and the target stable.
- macOS (Darwin) ping sweep uses `-W` in milliseconds; Linux uses seconds; Windows uses `-w` in milliseconds. If `ping` is not available, hosts are treated as offline without crashing.
- CSV exports open files with `newline=''` to prevent extra blank lines on Windows.

## 🔐 Security Notes

- This tool is for legitimate network analysis and debugging
- Always obtain proper authorization before scanning networks
- Be mindful of thread count to avoid overwhelming target systems
- Logs are created in the current directory (`port_scanner.log`)

## 🐛 Common Issues

### Permission Errors
- Run as Administrator on Windows if scanning privileged ports (< 1024)
- Use `sudo` on Linux/WSL for privileged operations

### Threading Issues
- Reduce worker thread count (`-w 50`) for slower systems
- Increase timeout (`-t 2.0`) for slow networks

### GUI Issues on WSL
- Ensure X11 forwarding is enabled
- Install X server on Windows (like VcXsrv)
- Set DISPLAY environment variable

## 📝 Logging

Logs are automatically created as `port_scanner.log` with:
- Scan start/end times
- Error messages
- Debug information (with `-v` flag)

## 🤝 Contributing

Feel free to enhance this tool with:
- Additional service detection
- More export formats
- Enhanced GUI features
- Performance optimizations

## 📄 License

This project is provided as-is for educational and legitimate network analysis purposes.
