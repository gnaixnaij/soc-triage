# soc-triage

[![Ko-fi](https://img.shields.io/badge/Sponsor-Ko--fi-FF5E5B?style=flat-square&logo=ko-fi)](https://ko-fi.com/gnaixnaij)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Lint](https://img.shields.io/github/actions/workflow/status/gnaixnaij/soc-triage/lint.yml?branch=main&label=lint&logo=github)](https://github.com/gnaixnaij/soc-triage/actions)
[![Release](https://img.shields.io/github/v/release/gnaixnaij/soc-triage?logo=github)](https://github.com/gnaixnaij/soc-triage/releases)
[![Python](https://img.shields.io/badge/python-3.6+-3776AB?logo=python&logoColor=white)](https://python.org)

Quick host triage toolkit for incident response. Collects system state information for initial compromise assessment.

## What it checks

| Section | Data Collected |
|---------|---------------|
| Host Information | Hostname, OS, kernel, uptime |
| Listening Ports | All TCP listening ports with processes |
| Established Connections | Active outbound connections |
| Suspicious Processes | Reverse shells, netcat, cryptominers |
| Recent Logins | Last 20 login records |
| SUID Binaries | Binaries with setuid bit set |
| Cron Jobs | User and system scheduled tasks |

## Usage

```bash
# Terminal output only
python3 soc_triage.py

# Save reports + archive
python3 soc_triage.py -o ./reports

# Watch mode — monitor for changes every N seconds
python3 soc_triage.py -w 60

# JSON output (for automation / SIEM integration)
python3 soc_triage.py --json

# Save reports and output JSON
python3 soc_triage.py -o ./reports --json

# Watch mode with JSON output
python3 soc_triage.py -w 300 --json -o ./monitor
```

## Output

- **Terminal:** Color-coded output for rapid visual triage
- **JSON:** Structured data for automation, SIEM ingestion, or further processing
- **Files:** Individual `.txt` reports per section + `.tar.gz` archive for exfiltration

## JSON Output Example

```json
{
  "timestamp": "2026-06-29 22:50:27",
  "host_info": {
    "hostname": "kali",
    "os": "Kali GNU/Linux Rolling",
    "kernel": "6.18.12+kali-amd64",
    "uptime": "up 2 hours, 1 minute"
  },
  "listening_ports": [
    {"address": "127.0.0.1:11434", "process": ""},
    {"address": "0.0.0.0:22", "process": "sshd"}
  ],
  "suid_binaries": ["/usr/bin/sudo", "/usr/bin/passwd", "..."]
}
```

## Use Case

Designed for SOC analysts and incident responders who need a fast snapshot of a potentially compromised Linux host. Run it, grab the archive, and analyze offline.

## Requirements

- Python 3.6+
- Linux with `ss`, `ps`, `last`, `find`, `crontab`

## Support

If this tool helps in your IR work, [buy me a coffee](https://ko-fi.com/gnaixnaij).

## License

MIT
