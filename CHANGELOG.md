# Change Log

All notable changes to the "hackingtool" extension will be documented in this file.

## [0.2.0] - 2024-01-XX

### Added
- Initial VS Code extension release
- Converted from Claude Code plugin to VS Code extension
- Tool Explorer sidebar with category browsing
- Command Palette integration for all tools
- Preflight check command
- Tool search functionality
- Environment detection (native, WSL, Docker)
- Integrated terminal execution
- Tool information webview panels
- 183+ security tools support
- Multi-backend execution (native Bash, WSL, Docker)
- Purpose-built Docker image overrides for common tools
- Configuration settings for Python path, timeout, backend preference
- Output channel for execution logs

### Features
- **Commands**:
  - Run Preflight Check
  - Search Tools
  - Run Tool
  - Show Environment Info
  - Refresh Tool Index
  
- **Views**:
  - Tool Explorer with categories
  - Tool info panels with capabilities
  
- **Backends**:
  - Native Linux/macOS execution
  - WSL on Windows
  - Docker fallback (any OS)

### Dependencies
- Python 3.7+ (for script execution)
- Optional: Docker Desktop (for Docker backend)
- Optional: WSL 2 (for Windows users)

## [0.1.0] - 2024-XX-XX

### Initial Development
- Original Claude Code plugin by AKCodez
- Python backend scripts (ht_run.py, ht_env.py, ht_preflight.py, ht_search.py, ht_index.py)
- Tool database (tools.json) with 183 tools
- Multi-runtime support
