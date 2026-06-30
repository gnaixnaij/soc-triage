#!/usr/bin/env python3
"""soc-triage — Quick host triage for incident response."""

import subprocess
import json
import os
import sys
import shutil
import argparse
from datetime import datetime
from pathlib import Path

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

REPORT_DIR = None
JSON_MODE = False
DATA = {}


def c(text, color=None, bold=False):
    parts = []
    if color: parts.append(color)
    if bold: parts.append(BOLD)
    if parts: return "".join(parts) + text + RESET
    return text


def section(title):
    if not JSON_MODE:
        print(f"\n{c('━' * 60, CYAN)}")
        print(f"{c(f'  {title}', CYAN, bold=True)}")
        print(f"{c('━' * 60, CYAN)}")


def out(text):
    if not JSON_MODE:
        print(text)


def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except FileNotFoundError:
        return "(tool not found)", -1
    except subprocess.TimeoutExpired:
        return "(timed out)", -1


def check_tool(name):
    return shutil.which(name) is not None


def host_info():
    section("Host Information")
    hostname, _ = run(["uname", "-n"])
    kernel, _ = run(["uname", "-a"])
    uptime, _ = run(["uptime", "-p"])
    os_release = "(unknown)"
    if os.path.exists("/etc/os-release"):
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    os_release = line.split("=", 1)[1].strip().strip('"')
    info = {
        "hostname": hostname,
        "os": os_release,
        "kernel": kernel.split()[2] if kernel else "N/A",
        "uptime": uptime,
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }
    DATA["host_info"] = info
    lines = [
        f"  Hostname:    {c(hostname, YELLOW)}",
        f"  OS:          {os_release}",
        f"  Kernel:      {kernel.split()[2] if kernel else 'N/A'}",
        f"  Uptime:      {uptime}",
        f"  Date:        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    ]
    return "\n".join(lines)


def listening_ports():
    section("Listening Ports")
    if check_tool("ss"):
        raw, _ = run(["ss", "-tlnp4"])
    elif check_tool("netstat"):
        raw, _ = run(["netstat", "-tlnp4"])
    else:
        DATA["listening_ports"] = []
        return c("  Neither ss nor netstat available", RED)
    lines = raw.split("\n")
    ports = []
    result = []
    for line in lines[1:]:
        if line.strip():
            parts = line.split()
            if len(parts) >= 4:
                addr = parts[3]
                proc = " ".join(parts[4:]) if len(parts) > 4 else ""
                ports.append({"address": addr, "process": proc})
                result.append(f"  {c(addr, GREEN)}  {c(proc, YELLOW)}")
    DATA["listening_ports"] = ports
    if not result:
        return c("  No listening ports found", YELLOW)
    return "\n".join(result[:30])


def established_connections():
    section("Established Connections")
    if not check_tool("ss"):
        DATA["established_connections"] = []
        return c("  ss not available", RED)
    raw, _ = run(["ss", "-tenp4", "state", "established"])
    lines = raw.split("\n")
    conns = []
    result = []
    for line in lines[1:]:
        if line.strip():
            parts = line.split()
            if len(parts) >= 5:
                local = parts[3]
                remote = parts[4]
                proc = " ".join(parts[6:]) if len(parts) > 6 else ""
                conns.append({"local": local, "remote": remote, "process": proc})
                result.append(f"  {c(local, GREEN)} -> {c(remote, YELLOW)}  {c(proc, CYAN)}")
    DATA["established_connections"] = conns
    if not result:
        return c("  No established connections", YELLOW)
    return "\n".join(result[:20])


def suspicious_processes():
    section("Suspicious Processes")
    raw, _ = run(["ps", "aux"])
    lines = raw.split("\n")
    keywords = ["nc -", "ncat", "socat", "mkfifo", "bash -i", "sh -i",
                "python -c", "perl -e", "nmap", "cryptominer", "xmrig"]
    matches = []
    result = []
    for line in lines[1:]:
        lower = line.lower()
        for kw in keywords:
            if kw.lower() in lower:
                parts = line.split(None, 10)
                cmd = parts[10] if len(parts) > 10 else line
                matches.append({"command": cmd.strip()[:80], "match": kw})
                result.append(f"  {c(cmd[:80], RED)}")
                break
    DATA["suspicious_processes"] = matches
    if not result:
        return c("  No obviously suspicious processes detected", GREEN)
    return "\n".join(result)


def recent_logins():
    section("Recent Logins")
    DATA["recent_logins"] = []
    if check_tool("last"):
        raw, _ = run(["last", "-n", "20"])
        lines = raw.split("\n")
        result = []
        for line in lines:
            if line.strip() and "wtmp" not in line:
                result.append(f"  {line}")
                DATA["recent_logins"].append(line.strip())
        if result:
            return "\n".join(result)
    return c("  No login history available", YELLOW)


def sudi_binaries():
    section("SUID Binaries")
    raw, _ = run(["/usr/bin/find", "/", "-perm", "-4000", "-type", "f",
                  "-not", "-path", "*/snap/*", "-not", "-path", "*/proc/*"], timeout=30)
    binaries = []
    result = []
    for line in raw.split("\n"):
        line = line.strip()
        if line:
            binaries.append(line)
            result.append(f"  {line}")
    DATA["suid_binaries"] = binaries[:40]
    if not result:
        return c("  No SUID binaries found", YELLOW)
    return "\n".join(result[:40])


def cron_jobs():
    section("Cron Jobs")
    entries = []
    result = []
    for user in ["root"] + [x for x in os.listdir("/home") if os.path.isdir(f"/home/{x}")]:
        raw, rc = run(["crontab", "-l", "-u", user], timeout=5)
        if rc == 0 and raw.strip():
            for line in raw.split("\n"):
                if line.strip() and not line.startswith("#"):
                    entries.append({"type": "user", "user": user, "entry": line.strip()})
                    result.append(f"  [{c(user, YELLOW)}] {line}")
    for d in ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly"]:
        if os.path.isdir(d):
            for f in sorted(os.listdir(d)):
                entries.append({"type": "system", "path": f"{d}/{f}"})
                result.append(f"  [{c('system', CYAN)}] {d}/{f}")
    DATA["cron_jobs"] = entries
    if not result:
        return c("  No crons found", YELLOW)
    return "\n".join(result[:30])


def save_report(target_dir):
    global DATA
    Path(target_dir).mkdir(parents=True, exist_ok=True)

    # Save JSON
    json_path = f"{target_dir}/soc-triage.json"
    with open(json_path, "w") as f:
        json.dump(DATA, f, indent=2)

    # Save individual text reports
    for name, func in [
        ("host_info", host_info),
        ("listening_ports", listening_ports),
        ("established_connections", established_connections),
        ("suspicious_processes", suspicious_processes),
        ("recent_logins", recent_logins),
        ("suid_binaries", sudi_binaries),
        ("cron_jobs", cron_jobs),
    ]:
        raw = func()
        with open(f"{target_dir}/{name}.txt", "w") as f:
            f.write(raw + "\n")

    # Create archive
    archive = f"{target_dir}/soc-triage-{datetime.now().strftime('%Y%m%d_%H%M%S')}.tar.gz"
    subprocess.run(["tar", "-czf", archive, "-C", target_dir, "."], capture_output=True)
    return json_path, archive


def run_all(target_dir=None, json_mode=False):
    global JSON_MODE, REPORT_DIR, DATA
    JSON_MODE = json_mode
    REPORT_DIR = target_dir
    DATA = {"timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

    sections_list = [
        ("host_info", host_info),
        ("listening_ports", listening_ports),
        ("established_connections", established_connections),
        ("suspicious_processes", suspicious_processes),
        ("recent_logins", recent_logins),
        ("sudi_binaries", sudi_binaries),
        ("cron_jobs", cron_jobs),
    ]

    if not JSON_MODE:
        print(c(f"\n{'=' * 60}", BOLD))
        print(c("  SOC TRIAGE REPORT", BOLD))
        print(c(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", BOLD))
        print(c(f"{'=' * 60}", BOLD))

    for name, func in sections_list:
        result = func()
        out(result)

    if JSON_MODE:
        print(json.dumps(DATA, indent=2))

    if not JSON_MODE:
        print()
        print(c("─" * 60, CYAN))
        print(c("  Triage complete.", GREEN))

    if target_dir:
        json_path, archive = save_report(target_dir)
        if not JSON_MODE:
            print(c(f"  JSON:   {json_path}", CYAN))
            print(c(f"  Archive: {archive}", YELLOW))

    return DATA


def main():
    parser = argparse.ArgumentParser(
        description="Quick host triage for incident response",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  soc_triage.py                          # Terminal output only
  soc_triage.py -o ./reports             # Save reports to directory
  soc_triage.py --json                   # JSON output to stdout
  soc_triage.py -o ./reports --json      # Both JSON file and terminal output
""")
    parser.add_argument("-o", "--output", help="Output directory for report files")
    parser.add_argument("--json", action="store_true", help="Output as JSON to stdout")
    args = parser.parse_args()
    run_all(target_dir=args.output, json_mode=args.json)


if __name__ == "__main__":
    main()
