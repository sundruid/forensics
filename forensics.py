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
SSH_USER = "your-user"  # Replace with your SSH username
SSH_KEY = "your-key"  # Replace with the path to your SSH key

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
        print(f"Error running command on {remote_host}: {e}")
        return None

def collect_forensics(remote_host):
    print(f"Starting forensic data collection from {remote_host}...")

    # Validate the hostname format
    if not remote_host.replace(".", "").replace("-", "").isalnum():
        print(f"Error: hostname {remote_host} contains invalid characters")
        return False

    # Test if sudo requires a password
    sudo_test = run_remote_command(remote_host, "sudo -n true 2>&1")
    if sudo_test and "password" in sudo_test.lower():
        print(f"Sudo requires a password for {remote_host}. Please rerun the script with your SSH password.")
        return False

    # Create directory for the host
    host_dir = Path(remote_host)
    host_dir.mkdir(exist_ok=True)
    os.chdir(host_dir)

    # Create or clear the local forensics output files
    with open("forensics.out", "w") as f:
        f.write(f"DATE\n{datetime.datetime.now()}\n\n")

    commands = [
        ("UNAME -A", "uname -a"),
        ("SUDOERS", "getent group sudo | cut -d: -f4"),
        ("CRONTAB -L", "command -v crontab > /dev/null && crontab -l || echo 'crontab command not found'"),
        ("WHO -A", "who -a"),
        ("IP ADDR SHOW", "ip addr show"),
        ("SS -TULN", "ss -tuln"),
        ("LSOF -V", "command -v lsof > /dev/null && lsof -V || echo 'lsof command not found'"),
        ("PS -AUX -EF", "ps -eo user,pid,ppid,%cpu,%mem,vsz,rss,tty,stat,start,time,cmd"),
        ("MOUNT", "mount"),
        ("DF", "df"),
        ("LSMOD", "lsmod"),
        ("LAST", "last"),
        ("LASTB", "lastb"),
        ("PASSWD", "cat /etc/passwd"),
        ("GROUP", "cat /etc/group"),
        ("SHADOW", "cat /etc/shadow"),
        ("DU -HC", "du -hc /var/log"),
        ("DOCKER PS", "docker ps"),
        ("IPTABLES -L -n -v", "iptables -L -n -v"),
        ("SSH_host_*_key.pub", "cat /etc/ssh/ssh_host_*_key.pub"),
    ]

    with open("forensics.out", "a") as f:
        for label, cmd in commands:
            f.write(f"{label}\n")
            output = run_remote_command(remote_host, cmd, use_sudo=True)
            f.write(output if output else "Command failed or returned no output\n")
            f.write("\n")

    # Check for nftables
    nft_check = run_remote_command(remote_host, "command -v nft")
    if nft_check:
        with open("forensics.out", "a") as f:
            f.write("NFTABLES CONFIGURATION\n")
            nft_output = run_remote_command(remote_host, "nft list ruleset", use_sudo=True)
            f.write(nft_output if nft_output else "Failed to get nftables configuration\n")
            f.write("\n")

    # Collect new files
    with open("new_files.out", "w") as f:
        f.write("Collecting new files created in the last 14 days (excluding /proc, /sys, /var/cache, /run, /dev)...\n")
        new_files = run_remote_command(remote_host, 'find / -executable -mtime -14 2>/dev/null | grep -v "/sys\|/proc\|/var/cache\|/run\|/dev"', use_sudo=True)
        f.write(new_files if new_files else "Failed to collect new files information\n")

    # Collect journalctl logs
    with open("journalctl.out", "w") as f:
        f.write("Collecting journalctl logs from the last 14 days...\n")
        journalctl_logs = run_remote_command(remote_host, 'journalctl --since="14 days ago"', use_sudo=True)
        f.write(journalctl_logs if journalctl_logs else "Failed to collect journalctl logs\n")

    # Generate hash values
    def get_file_hash(filename):
        try:
            with open(filename, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            return f"Error generating hash: {e}"

    forensics_hash = get_file_hash("forensics.out")
    newfiles_hash = get_file_hash("new_files.out")
    journalctl_hash = get_file_hash("journalctl.out")

    # Write hash values to a summary file
    with open("hash_summary.out", "w") as f:
        f.write("Forensics SHA256 HASHES:\n")
        f.write(f"forensics.out: {forensics_hash}\n")
        f.write(f"new_files.out: {newfiles_hash}\n")
        f.write(f"journalctl.out: {journalctl_hash}\n")

    # Archive all files locally
    tar_filename = f"{remote_host}.{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.infosec.forensics.tar.gz"
    try:
        with tarfile.open(tar_filename, "w:gz") as tar:
            for file in ["forensics.out", "new_files.out", "journalctl.out", "hash_summary.out"]:
                tar.add(file)
        print(f"Files successfully archived locally as {tar_filename}")
    except Exception as e:
        print(f"Error: Failed to create the tar.gz archive. {e}")
        os.chdir("..")
        return False

    print(f"Forensic data collection from {remote_host} completed.")
    os.chdir("..")
    return True

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
                collect_forensics(host.strip())
                print(f"Finished processing host: {host}")
        print(f"Finished processing all hosts from {args.target}")
    else:
        collect_forensics(args.target)

if __name__ == "__main__":
    main()