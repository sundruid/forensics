#!/usr/bin/env python3

import argparse
import subprocess
import os
import datetime
import hashlib
import tarfile
from pathlib import Path

print("Forensics Collector v1.3 updated 08/2024")
print("Go Blue Team")
print()

# Variables
SSH_USER = "your_username"  # Replace with your SSH username
SSH_KEY = "your_ssh_key_path"  # Replace with the path to your SSH key

def run_remote_command(remote_host, command, use_sudo=False):
    ssh_command = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-i", os.path.expanduser(SSH_KEY),
        f"{SSH_USER}@{remote_host}"
    ]
    
    if use_sudo:
        command = f"sudo {command}"
    
    full_command = ssh_command + [command]
    
    try:
        result = subprocess.run(full_command, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        if "command not found" in e.stderr:
            return "Command not available on the system"
        elif "syntax error" in e.stderr:
            return "Command execution failed due to syntax error"
        elif "sudo: a password is required" in e.stderr or "sudo: no tty present and no askpass program specified" in e.stderr:
            return "SUDO_PERMISSION_DENIED"
        else:
            return f"Command execution failed: {e.stderr.strip()}"

def collect_forensics(remote_host):
    print(f"Starting forensic data collection from {remote_host}...")

    # Validate the hostname format
    if not remote_host.replace(".", "").replace("-", "").isalnum():
        print(f"Error: hostname {remote_host} contains invalid characters")
        return False

    # Test if sudo requires a password
    sudo_test = run_remote_command(remote_host, "sudo -n true 2>&1")
    if sudo_test == "SUDO_PERMISSION_DENIED":
        print(f"Sudo requires a password for {remote_host}. Skipping this host.")
        return False

    # Create directory for the host
    host_dir = Path(remote_host)
    host_dir.mkdir(exist_ok=True)
    os.chdir(host_dir)

    # Create or clear the local forensics output files
    with open("forensics.out", "w") as f:
        f.write(f"DATE\n{datetime.datetime.now()}\n\n")

    commands = [
        ("UNAME", "uname -a"),
        ("SUDOERS", "getent group sudo | cut -d: -f4"),
        ("CRONTAB", "for user in $(cut -f1 -d: /etc/passwd); do echo $user; crontab -u $user -l 2>/dev/null; done"),
        ("LOGGED_IN_USERS", "who -a"),
        ("NETWORK_INTERFACES", "ip -o addr show"),
        ("LISTENING_PORTS", "ss -tuln"),
        ("OPEN_FILES", "lsof -n"),
        ("PROCESSES", "ps auxf"),
        ("MOUNTED_FILESYSTEMS", "mount"),
        ("DISK_USAGE", "df -h"),
        ("LOADED_MODULES", "lsmod"),
        ("LOGIN_HISTORY", "last -Faiwx"),
        ("FAILED_LOGINS", "lastb -Faiwx"),
        ("PASSWD_FILE", "cat /etc/passwd"),
        ("GROUP_FILE", "cat /etc/group"),
        ("SHADOW_FILE", "cat /etc/shadow"),
        ("LOG_SIZE", "du -sh /var/log"),
        ("DOCKER_CONTAINERS", "docker ps -a --format '{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}'"),
        ("IPTABLES_RULES", "iptables-save"),
        ("SSH_HOST_KEYS", "find /etc/ssh/ -name 'ssh_host_*_key.pub' -exec cat {} +"),
        ("INSTALLED_PACKAGES", "if command -v dpkg > /dev/null; then dpkg -l; elif command -v rpm > /dev/null; then rpm -qa; fi"),
        ("SYSTEM_SERVICES", "systemctl list-units --type=service --all"),
        ("NETWORK_CONNECTIONS", "netstat -antup"),
        ("ARP_CACHE", "arp -e"),
        ("ROUTING_TABLE", "route -n"),
        ("DNS_RESOLV_CONF", "cat /etc/resolv.conf"),
        ("HOSTS_FILE", "cat /etc/hosts"),
        ("SYSLOG_CONF", "cat /etc/syslog.conf /etc/rsyslog.conf 2>/dev/null"),
        ("AUDITD_CONF", "cat /etc/audit/auditd.conf 2>/dev/null"),
        ("SSHD_CONFIG", "cat /etc/ssh/sshd_config"),
        ("SUDOERS_FILE", "cat /etc/sudoers"),
        ("KERNEL_PARAMETERS", "sysctl -a"),
        ("SCHEDULED_TASKS", "find /etc/cron* -type f -exec ls -l {} +"),
        ("USER_BASH_HISTORY", "for user in $(cut -f1 -d: /etc/passwd); do echo $user; cat /home/$user/.bash_history 2>/dev/null; done"),
    ]

    with open("forensics.out", "a") as f:
        for label, cmd in commands:
            f.write(f"{label}\n")
            output = run_remote_command(remote_host, cmd, use_sudo=True)
            if output == "SUDO_PERMISSION_DENIED":
                f.write("Sudo permission denied. Skipping further commands.\n")
                print(f"Sudo permission denied for {remote_host}. Skipping further commands.")
                os.chdir("..")
                return False
            f.write(output if output else "No output or command not available\n")
            f.write("\n")

    # Check and collect iptables rules
    iptables_check = run_remote_command(remote_host, "command -v iptables")
    if iptables_check:
        with open("iptables.out", "w") as f:
            f.write("Collecting iptables rules...\n")
            iptables_output = run_remote_command(remote_host, "iptables-save", use_sudo=True)
            f.write(iptables_output if iptables_output else "Failed to collect iptables rules\n")

    # Check and collect nftables rules
    nft_check = run_remote_command(remote_host, "command -v nft")
    if nft_check:
        with open("nftables.out", "w") as f:
            f.write("Collecting nftables rules...\n")
            nft_output = run_remote_command(remote_host, "nft list ruleset", use_sudo=True)
            f.write(nft_output if nft_output else "Failed to collect nftables rules\n")

    # Check for and collect system logs
    journalctl_check = run_remote_command(remote_host, "command -v journalctl")
    syslog_check = run_remote_command(remote_host, "test -f /var/log/syslog && echo exists")
    authlog_check = run_remote_command(remote_host, "test -f /var/log/auth.log && echo exists")

    if journalctl_check and "not available" not in journalctl_check:
        with open("journalctl.out", "w") as f:
            f.write("Collecting journalctl logs from the last 14 days...\n")
            journalctl_logs = run_remote_command(remote_host, 'journalctl --since="14 days ago"', use_sudo=True)
            f.write(journalctl_logs if journalctl_logs else "Failed to collect journalctl logs\n")
    else:
        # Check for traditional syslog and auth.log
        syslog_check = run_remote_command(remote_host, "test -f /var/log/syslog && echo exists")
        authlog_check = run_remote_command(remote_host, "test -f /var/log/auth.log && echo exists")
        
        if syslog_check:
            with open("syslog.out", "w") as f:
                f.write("Collecting syslog entries from the last 14 days...\n")
                syslog_entries = run_remote_command(remote_host, 'tail -n 10000 /var/log/syslog', use_sudo=True)
                f.write(syslog_entries if syslog_entries else "Failed to collect syslog entries\n")
        
        if authlog_check:
            with open("authlog.out", "w") as f:
                f.write("Collecting auth.log entries from the last 14 days...\n")
                authlog_entries = run_remote_command(remote_host, 'tail -n 10000 /var/log/auth.log', use_sudo=True)
                f.write(authlog_entries if authlog_entries else "Failed to collect auth.log entries\n")

    # Collect new files
    with open("new_files.out", "w") as f:
        f.write("Collecting new files created in the last 14 days (excluding /proc, /sys, /var/cache, /run, /dev)...\n")
        new_files_cmd = """find / -type f -mtime -14 ! -path '/proc/*' ! -path '/sys/*' ! -path '/run/*' ! -path '/dev/*' ! -path '/var/lib/*' -printf '%T+ %u:%g %m %s %Y %f %p\\n' | sort -r"""
        new_files = run_remote_command(remote_host, new_files_cmd, use_sudo=True)
        f.write(new_files if new_files else "Failed to collect new files information\n")

    # Generate hash values
    def get_file_hash(filename):
        try:
            with open(filename, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            return f"Error generating hash: {e}"

    forensics_hash = get_file_hash("forensics.out")
    newfiles_hash = get_file_hash("new_files.out")
    iptables_hash = get_file_hash("iptables.out") if iptables_check else "N/A"
    nftables_hash = get_file_hash("nftables.out") if nft_check else "N/A"
    journalctl_hash = get_file_hash("journalctl.out") if journalctl_check else "N/A"
    syslog_hash = get_file_hash("syslog.out") if syslog_check else "N/A"
    authlog_hash = get_file_hash("authlog.out") if authlog_check else "N/A"

    # Write hash values to a summary file
    with open("hash_summary.out", "w") as f:
        f.write("Forensics SHA256 HASHES:\n")
        f.write(f"forensics.out: {forensics_hash}\n")
        f.write(f"new_files.out: {newfiles_hash}\n")
        f.write(f"iptables.out: {iptables_hash}\n")
        f.write(f"nftables.out: {nftables_hash}\n")
        f.write(f"journalctl.out: {journalctl_hash}\n")
        f.write(f"syslog.out: {syslog_hash}\n")
        f.write(f"authlog.out: {authlog_hash}\n")

    # Archive all files locally
    tar_filename = f"{remote_host}.{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.infosec.forensics.tar.gz"
    try:
        with tarfile.open(tar_filename, "w:gz") as tar:
            for file in ["forensics.out", "new_files.out", "iptables.out", "nftables.out", 
                         "journalctl.out", "syslog.out", "authlog.out", "hash_summary.out"]:
                if os.path.exists(file):
                    tar.add(file)
        print(f"Files successfully archived locally as {tar_filename}")
    except Exception as e:
        print(f"Error: Failed to create the tar.gz archive. {e}")
        os.chdir("..")
        return False

    print(f"Forensic data collection from {remote_host} completed.")
    os.chdir("..")
    return True

def analyze_forensics(host):
    host_dir = Path(host)
    os.chdir(host_dir)

    with open("forensics.out", "r") as f:
        content = f.read()

    os.chdir("..")

def main():
    parser = argparse.ArgumentParser(description="Forensics Collector")
    parser.add_argument("target", help="Remote IP, hostname, or path to hosts file")
    parser.add_argument("-file", action="store_true", help="Indicates that the target is a file containing host list")
    args = parser.parse_args()

    if args.file:
        with open(args.target, "r") as hosts_file:
            hosts = hosts_file.read().splitlines()
        print(f"Processing hosts from file: {args.target}")
        for host in hosts:
            if host.strip():
                print(f"Starting to process host: {host}")
                success = collect_forensics(host.strip())
                if success:
                    analyze_forensics(host.strip())
                print(f"Finished processing host: {host}")
        print(f"Finished processing all hosts from {args.target}")
    else:
        success = collect_forensics(args.target)
        if success:
            analyze_forensics(args.target)

if __name__ == "__main__":
    main()