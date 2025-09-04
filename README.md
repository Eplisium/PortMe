# Advanced Port Scanner

A comprehensive, cross-platform port scanning tool designed for Windows and WSL environments. Features multi-threading, service detection, banner grabbing, and both CLI and GUI interfaces.

## 🚀 Features

- **Multi-threaded scanning** for fast performance
- **Service detection** and banner grabbing
- **Cross-platform** compatibility (Windows & WSL)
- **GUI and CLI interfaces** for different use cases
- **Network range scanning** (CIDR notation support)
- **Export results** to JSON/CSV formats
- **Real-time progress tracking**
- **Comprehensive logging**
- **Built-in common port definitions**
- **Special focus on development ports** (3000, 8000, etc.)

## 📋 Requirements

- Python 3.7 or higher
- No external dependencies required (uses Python standard library only)
- tkinter for GUI (included with Python on Windows)

## 🔧 Installation

### Windows
```powershell
# Clone or download the files to your desired directory
cd E:\Projects\Dev\Python\Important\PortMe

# Verify Python installation
python --version

# Run directly (no installation required)
python port_scanner.py --help
```

### WSL (Windows Subsystem for Linux)
```bash
# Navigate to your project directory
cd /mnt/e/Projects/Dev/Python/Important/PortMe

# Ensure Python3 is available
python3 --version

# Run directly
python3 port_scanner.py --help
```

## 💻 Usage

### Command Line Interface

#### Basic Usage
```bash
# Scan common ports on localhost
python port_scanner.py -H localhost --common

# Scan specific ports
python port_scanner.py -H 192.168.1.1 -p 80,443,22,3000

# Scan port range
python port_scanner.py -H example.com -p 1-1000

# Quick check for your development server (port 3000)
python port_scanner.py -H localhost -p 3000 --banner

# Scan with custom timeout and threading
python port_scanner.py -H 127.0.0.1 -p 3000-3010 --timeout 2 -w 50
```

#### Advanced Usage
```bash
# Scan network range
python port_scanner.py -H 192.168.1.0/24 -p 22,80,443

# Export results to JSON
python port_scanner.py -H localhost --common -o results.json

# Verbose logging with banner grabbing
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
- **Target configuration**: Enter hostname or IP address
- **Port selection**: Choose common ports or specify custom ranges
- **Advanced options**: Adjust timeout, thread count, banner grabbing
- **Quick scan buttons**: One-click scans for common scenarios
- **Real-time results**: Color-coded output with progress tracking
- **Export functionality**: Save results to JSON/CSV

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

## ⚙️ Configuration Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-H, --host` | Target host or network | Required |
| `-p, --ports` | Ports to scan | Common ports |
| `--common` | Scan common ports only | False |
| `-t, --timeout` | Socket timeout (seconds) | 1.0 |
| `-w, --workers` | Max worker threads | 100 |
| `--banner` | Enable banner grabbing | False |
| `--show-closed` | Show closed ports | False |
| `-o, --output` | Export file | None |
| `-v, --verbose` | Verbose logging | False |

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
