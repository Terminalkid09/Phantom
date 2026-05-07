# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-05-07

### Added
- **Plugin System**: Dynamic loading of custom Python modules from `~/.phantom/plugins/`.
- **Scan History Diff**: New `scan-diff` command to compare results between different scan sessions.
- **Profile Management**: Added `save-profile` and `load-profile` to persist settings (target, mode, scope) independently of sessions.
- **Advanced Wordlist Manager**: Interactive indexing, searching, and categorization of wordlists from system paths.
- **Tool Existence Check**: Framework now verifies if external dependencies (nmap, sqlmap, etc.) are installed before execution, providing installation tips.
- **Exploitability Scoring**: Enhanced `exploit` module with a dynamic scoring algorithm based on CVE data, MSF modules, and GitHub PoCs.
- **Interactive Notes**: Timestamped inline note-taking during sessions.
- **Improved Report Export**: Added PDF and HTML export support via `reportlab`.

### Changed
- **Modular Refactoring**: Core logic separated from shell interface for better maintainability.
- **Enhanced Banner**: Redesigned ASCII splash screen for better Kali Linux terminal compatibility.
- **Executor Logic**: Improved subprocess management with better timeout handling and real-time output streaming.
- **Safety Layer**: Strengthened scope enforcement and target sanitization.

### Fixed
- Fixed race condition in real-time output reading during command execution.
- Corrected Nmap XML parsing errors for services with missing versions.
- Resolved path issues for plugin loading on Windows.

## [1.0.0] - 2025-01-15
- Initial release of Phantom Offensive Security Framework.
- Basic interactive shell.
- 10 core modules: scan, osint, web, brute, exploit, payload, handler, pivot, analyzer, report.
- Target and scope management.
- JSON session persistence.
