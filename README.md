# HackingTool - Security Testing Suite for VS Code

![Version](https://img.shields.io/badge/version-0.2.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A comprehensive pentesting and OSINT toolkit for Visual Studio Code, providing access to 183+ security tools including nmap, nuclei, amass, subfinder, sherlock, maigret, trufflehog, sqlmap, impacket, and more. Runs locally via native Bash, WSL, or Docker with automatic backend selection.

## Features

- **183+ Security Tools** - Complete toolkit from Z4nzu/hackingtool
- **Multi-Backend Support** - Runs on Linux/macOS (native), Windows (WSL or Docker), any OS with Docker
- **Smart Execution** - Automatic backend selection and tool-specific Docker images
- **Visual Tool Explorer** - Browse tools by category in the sidebar
- **Integrated Terminal** - Execute tools directly in VS Code terminals
- **Quick Search** - Find tools by name, category, tag, or description
- **Preflight Checks** - Verify environment setup before running tools
- **Tool Information** - View detailed info, install commands, and capabilities

## Tool Categories

- **Active Directory** - BloodHound, NetExec, Impacket
- **Network Scanning** - Nmap, Masscan, Naabu
- **Subdomain Enumeration** - Subfinder, Amass, Assetfinder
- **Web Scanning** - Nuclei, Httpx, Nikto, Dirb, Ffuf
- **OSINT** - Sherlock, Maigret, Holehe, TheHarvester
- **Secret Scanning** - TruffleHog, Gitleaks
- **Password Attacks** - Hashcat, John, Hydra
- **Wireless** - Aircrack-ng, Reaver
- **And many more...**

## Installation

### From VSIX
1. Download the `.vsix` file
2. Open VS Code
3. Run: `Extensions: Install from VSIX...`
4. Select the downloaded file

### From Source
```bash
git clone https://github.com/AKCodez/hackingtool-plugin.git
cd hackingtool-plugin
npm install -g @vscode/vsce
vsce package
code --install-extension hackingtool-0.2.0.vsix
```

## Prerequisites

Choose one of these execution backends:

### Option 1: Native (Linux/macOS)
- Python 3.7+
- Bash shell
- Individual tools installed (or use Docker fallback)

### Option 2: WSL (Windows)
- Windows Subsystem for Linux (WSL 2 recommended)
- Python 3.7+ in WSL
- Ubuntu, Debian, or Kali Linux distro

### Option 3: Docker (Any OS)
- Docker Desktop installed and running
- No other dependencies needed
- Uses purpose-built images (`instrumentisto/nmap`, `projectdiscovery/nuclei`, etc.)

## Quick Start

1. **Run Preflight Check**
   - Open Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
   - Run: `HackingTool: Run Preflight Check`
   - Review environment status and backend selection

2. **Browse Tools**
   - Open HackingTool sidebar (click shield icon)
   - Expand categories to see available tools
   - Click tool to view info or run

3. **Search & Execute**
   - Command Palette → `HackingTool: Search Tools`
   - Enter query (e.g., "nmap", "subdomain", "osint")
   - Select tool and provide arguments
   - View results in integrated terminal

## Usage Examples

### Example 1: Subdomain Enumeration
```bash
# Command Palette → HackingTool: Run Tool
# Select: Subfinder
# Args: -d example.com -all
```

### Example 2: Port Scanning
```bash
# Command Palette → HackingTool: Run Tool
# Select: NMAP
# Args: -sV -sC target.com
```

### Example 3: Web Vulnerability Scan
```bash
# Command Palette → HackingTool: Run Tool
# Select: Nuclei
# Args: -u https://example.com -severity medium,high,critical
```

### Example 4: OSINT Username Investigation
```bash
# Command Palette → HackingTool: Run Tool
# Select: Sherlock
# Args: username123
```

## Commands

- `HackingTool: Run Preflight Check` - Verify environment and backend
- `HackingTool: Search Tools` - Search and run tools
- `HackingTool: Run Tool` - Browse and execute tools
- `HackingTool: Show Environment Info` - Display system details
- `HackingTool: Refresh Tool Index` - Rebuild tool database

## Configuration

Settings available in `Settings → Extensions → HackingTool`:

```json
{
  "hackingtool.pythonPath": "python3",
  "hackingtool.defaultTimeout": 180,
  "hackingtool.preferredBackend": "auto",
  "hackingtool.showOutputChannel": true
}
```

## Legal & Ethical Notice

⚠️ **IMPORTANT**: This extension provides access to powerful security testing tools. You must:

- Only test systems you own or have explicit written permission to test
- Comply with all applicable laws and regulations
- Follow responsible disclosure practices
- Respect privacy and data protection laws
- Use tools ethically and legally

**Unauthorized access to computer systems is illegal.** The authors assume no liability for misuse.

## License

MIT License - See [LICENSE](LICENSE) file for details

---

**Happy Hacking! 🛡️**
