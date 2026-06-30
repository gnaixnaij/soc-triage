# soc-triage

Quick host triage toolkit for incident response. Collects system state information for initial compromise assessment.

## What it checks

| Section | Data Collected |
|---------|---------------|
| Host Information | Hostname, OS, kernel, uptime, timestamp |
| Listening Ports | All TCP listening ports with processes |
| Established Connections | Active outbound connections |
| Suspicious Processes | Reverse shells, netcat, cryptominers, etc. |
| Recent Logins | Last 20 login records |
| SUID Binaries | Binaries with setuid bit set |
| Cron Jobs | User and system scheduled tasks |

## Usage

```bash
# Quick triage (stdout only)
python3 soc_triage.py

# Save reports to directory (also creates .tar.gz archive)
python3 soc_triage.py -o ./reports
```

## Output

- Color-coded terminal output for rapid visual triage
- Individual `.txt` reports per section when using `-o`
- Tarball archive for easy exfiltration or evidence preservation

## Use Case

Designed for SOC analysts and incident responders who need a fast snapshot of a potentially compromised Linux host. Run it, grab the archive, and analyze offline.

## Requirements

- Python 3.6+
- Linux with `ss`, `ps`, `last`, `find`, `crontab` (standard on any Linux distro)

## License

MIT
