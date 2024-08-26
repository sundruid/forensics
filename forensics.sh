#!/bin/bash

echo "Forensics Collector v0.8 updated 08/2024"
echo "Go Blue Team"
echo ""
echo "  Example SCP command to download files later:"
echo "    scp -i \"~/.ssh/your_key.pem\" your_login@your_remote_server:/home/location_of_files/*.gz ."

usage() {
    echo "Usage:"
    echo "  Run without options to collect forensic data:"
    echo "    sudo ./forensics_collector.sh"
}

if [ `id -u` -ne 0 ]; then
    echo "Error: Must be run as root or sudo."
    usage
    exit 1
fi

echo "Starting forensic data collection..."

# Create or clear the forensics output file
echo "DATE" > forensics.out
date >> forensics.out
echo "" >> forensics.out

# Collect system information
commands=(
    "UNAME -A" "uname -a"
    "SUDOERS" "getent group sudo | cut -d: -f4"
    "CRONTAB -L" "crontab -l"
    "WHO -A" "who -a"
    "IP ADDR SHOW" "ip addr show"
    "SS -TULN" "ss -tuln"
    "LSOF -V" "lsof -V"
    "PS -AUX -EF" "ps -eo user,pid,ppid,%cpu,%mem,vsz,rss,tty,stat,start,time,cmd"
    "MOUNT" "mount"
    "DF" "df"
    "LSMOD" "lsmod"
    "LAST" "last"
    "LASTB" "lastb"
    "PASSWD" "cat /etc/passwd"
    "GROUP" "cat /etc/group"
    "SHADOW" "cat /etc/shadow"
    "DU -HC" "du -hc /var/log"
    "DOCKER PS" "docker ps /dev/null 2>&1"
    "IPTABLES -L -n -v" "iptables -L -n -v"
    "SSH_host_*_key.pub" "cat /etc/ssh/ssh_host_*_key.pub"
)

# Loop through and collect output
for ((i=0; i<${#commands[@]}; i+=2)); do
    echo "${commands[i]}" >> forensics.out
    eval "${commands[i+1]}" >> forensics.out
    echo "" >> forensics.out
done

# Check if nftables exists and collect its configuration
if command -v nft > /dev/null 2>&1; then
    echo "NFTABLES CONFIGURATION" >> forensics.out
    nft list ruleset >> forensics.out
    echo "" >> forensics.out
else
    echo "NFTABLES not found on this system." >> forensics.out
    echo "" >> forensics.out
fi

# Collect new files created in the last 14 days
echo "NEW FILES created in last 14 days exclude: /proc /sys /var/cache /run /dev"
find / -executable -mtime -14 2>/dev/null | grep -v "/sys\|/proc\|/var/cache\|/run\|/dev" >> new_files.out

# Collect journalctl logs for the last 14 days
echo "Collecting journalctl logs from the last 14 days..."
journalctl --since="14 days ago" > journalctl.out

# Generate hash values
forensics_hash=$(sha256sum forensics.out | awk '{print $1}')
newfiles_hash=$(sha256sum new_files.out | awk '{print $1}')
journalctl_hash=$(sha256sum journalctl.out | awk '{print $1}')

logger "Forensics sha256 HASH for forensics.out is $forensics_hash"
logger "Forensics sha256 HASH for new_files.out is $newfiles_hash"
logger "Forensics sha256 HASH for journalctl.out is $journalctl_hash"

# Archive all files
tar_filename="`hostname`.`date +%Y%m%d-%H%M%S`.infosec.forensics.tar.gz"
tar -czf $tar_filename forensics.out new_files.out journalctl.out

# Check if tar was successful
if [ $? -eq 0 ]; then
    echo "Files successfully archived as $tar_filename"
    echo "Move them to a safe location for future analysis."
else
    echo "Error: Failed to create the tar.gz archive."
    exit 1
fi
