#!/usr/bin/env python3
"""soc-triage — Quick host triage for incident response."""

import subprocess
import json
import os
import sys
import shutil
from datetime import datetime
from pathlib import Path

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

REPORT_DIR = None

def c(text, color=None, bold=False):
    parts = []
    if color: parts.append(color)
    if bold: parts.append(BOLD)
    if parts: return "".join(parts) + text + RESET
    return text

def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except FileNotFoundError:
        return "(tool not found)", -1
    except subprocess.TimeoutExpired:
        return "(timed out)", -1

def section(title):
    print(f"\n{c('━'*60, CYAN)}")
    print(f"{c(f'  {title}', CYAN, bold=True)}")
    print(f"{c('━'*60, CYAN)}")

def check_tool(name):
    return shutil.which(name) is not None

def host_info():
    section("Host Information")
    out = []
    hostname, _ = run(["uname", "-n"])
    kernel, _ = run(["uname", "-a"])
    uptime, _ = run(["uptime", "-p"])
    os_release = "(unknown)"
    if os.path.exists("/etc/os-release"):
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    os_release = line.split("=", 1)[1].strip().strip('"')
    out.append(f"  Hostname:    {c(hostname, YELLOW)}")
    out.append(f"  OS:          {os_release}")
    out.append(f"  Kernel:      {kernel.split()[2] if kernel else 'N/A'}")
    out.append(f"  Uptime:      {uptime}")
    out.append(f"  Date:        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    return "\n".join(out)

def listening_ports():
    section("Listening Ports")
    if check_tool("ss"):
        out, _ = run(["ss", "-tlnp4"])
    elif check_tool("netstat"):
        out, _ = run(["netstat", "-tlnp4"])
    else:
        return c("  Neither ss nor netstat available", RED)
    lines = out.split("\n")
    result = []
    for line in lines[1:]:
        if line.strip():
            parts = line.split()
            if len(parts) >= 4:
                addr = parts[3]
                proc = " ".join(parts[4:]) if len(parts) > 4 else ""
                result.append(f"  {c(addr, GREEN)}  {c(proc, YELLOW)}")
    if not result:
        return c("  No listening ports found", YELLOW)
    return "\n".join(result[:30])

def established_connections():
    section("Established Connections")
    if check_tool("ss"):
        out, _ = run(["ss", "-tenp4", "state", "established"])
    else:
        return c("  ss not available", RED)
    lines = out.split("\n")
    result = []
    for line in lines[1:]:
        if line.strip():
            parts = line.split()
            if len(parts) >= 4:
                local = parts[3]
                remote = parts[4]
                proc = " ".join(parts[6:]) if len(parts) > 6 else ""
                result.append(f"  {c(local, GREEN)} -> {c(remote, YELLOW)}  {c(proc, CYAN)}")
    if not result:
        return c("  No established connections", YELLOW)
    return "\n".join(result[:20])

def suspicious_processes():
    section("Suspicious Processes")
    out, _ = run(["ps", "aux"])
    lines = out.split("\n")
    keywords = ["nc -", "ncat", "socat", "mkfifo", "bash -i", "sh -i", "python -c", "perl -e", "nmap", "cryptominer", "xmrig"]
    result = []
    for line in lines[1:]:
        lower = line.lower()
        for kw in keywords:
            if kw.lower() in lower:
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    result.append(f"  {c(parts[10][:80], RED)}")
                elif len(parts) >= 2:
                    result.append(f"  {c(' '.join(parts[10:])[:80], RED)}")
                break
    if not result:
        result.append(c("  No obviously suspicious processes detected", GREEN))
    return "\n".join(result)

def recent_logins():
    section("Recent Logins")
    if check_tool("last"):
        out, _ = run(["last", "-n", "20"])
        lines = out.split("\n")
        result = []
        for line in lines:
            if line.strip() and "wtmp" not in line:
                result.append(f"  {line}")
        if result:
            return "\n".join(result)
    return c("  No login history available", YELLOW)

def sudi_binaries():
    section("SUID Binaries")
    out, _ = run(["/usr/bin/find", "/", "-perm", "-4000", "-type", "f", "-not", "-path", "*/snap/*", "-not", "-path", "*/proc/*"], timeout=30)
    result = []
    for line in out.split("\n"):
        line = line.strip()
        if line:
            result.append(f"  {line}")
    if not result:
        return c("  No SUID binaries found (unlikely — check permissions)", YELLOW)
    return "\n".join(result[:40])

def cron_jobs():
    section("Cron Jobs")
    result = []
    for user in ["root"] + [x for x in os.listdir("/home") if os.path.isdir(f"/home/{x}")]:
        out, rc = run(["crontab", "-l", "-u", user], timeout=5)
        if rc == 0 and out.strip():
            for line in out.split("\n"):
                if line.strip() and not line.startswith("#"):
                    result.append(f"  [{c(user, YELLOW)}] {line}")
    for d in ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly"]:
        if os.path.isdir(d):
            for f in sorted(os.listdir(d)):
                result.append(f"  [{c('system', CYAN)}] {d}/{f}")
    if not result:
        result.append(c("  No crons found", YELLOW))
    return "\n".join(result[:30])

def run_all(target_dir=None):
    global REPORT_DIR
    REPORT_DIR = target_dir
    if REPORT_DIR:
        Path(REPORT_DIR).mkdir(parents=True, exist_ok=True)

    print(c(f"\n{'='*60}", BOLD))
    print(c("  SOC TRIAGE REPORT", BOLD))
    print(c(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", BOLD))
    print(c(f"{'='*60}", BOLD))

    sections_list = [
        ("host_info", host_info),
        ("listening_ports", listening_ports),
        ("established_connections", established_connections),
        ("suspicious_processes", suspicious_processes),
        ("recent_logins", recent_logins),
        ("sudi_binaries", sudi_binaries),
        ("cron_jobs", cron_jobs),
    ]

    full = ""
    for name, func in sections_list:
        result = func()
        full += result + "\n"
        print(result)
        if REPORT_DIR:
            with open(f"{REPORT_DIR}/{name}.txt", "w") as f:
                f.write(result)

    print()
    print(c("─" * 60, CYAN))
    print(c("  Triage complete.", GREEN))

    if REPORT_DIR:
        print(c(f"  Reports saved to: {REPORT_DIR}", CYAN))
        archive = f"{REPORT_DIR}/soc-triage-{datetime.now().strftime('%Y%m%d_%H%M%S')}.tar.gz"
        subprocess.run(["tar", "-czf", archive, "-C", REPORT_DIR, "."], capture_output=True)
        print(c(f"  Archive: {archive}", YELLOW))

def main():
    parser = argparse.ArgumentParser(description="Quick host triage for incident response")
    parser.add_argument("-o", "--output", help="Output directory for report files")
    args = parser.parse_args()
    run_all(target_dir=args.output)

if __name__ == "__main__":
    import argparse
    main()
