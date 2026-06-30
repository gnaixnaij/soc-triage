# Changelog

## v1.1.0 (2026-06-30)

### Added

- Watch mode (`-w`): continuous monitoring with change detection
- Quiet mode for watch mode repeated checks
- JSON output (`--json`): structured data for automation/SIEM integration

## v1.0.0 (2026-06-29)

### Initial Release

- Host information collection (hostname, OS, kernel, uptime)
- Listening port detection
- Established connection monitoring
- Suspicious process detection (reverse shells, netcat, cryptominers)
- Recent login history
- SUID binary enumeration
- Cron job listing (user and system)
- Color-coded terminal output
- File output with `.txt` reports and `.tar.gz` archive
