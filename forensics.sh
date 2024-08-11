echo "Forensics Collector v0.5 updated 11/2023"
echo "Go Blue Team"
echo ""

uploader(){
    
    if [ -e forensics.out -o -e new_files.out ]; then
        echo "packing and uploading to forensics server"
        tar -czf - /var/log new_files.out forensics.out | ssh drop@<your.host> "cat > `hostname`.`date +%Y%m%d-%H%M%S`.infosec.forensics.tar.gz"
        wait $!
        echo "Transfer complete"
        exit 0
    else
        echo "Collection files do not exist. If you are running with -u option, try it without."
        exit 0
    fi

}


if [ `id -u` -ne 0 ]
   then echo "Must be run as root or sudo"
   exit 0
fi


if [ "$1" = "-u" ]

then
    uploader
    exit 0
fi


echo "DATE" >> forensics.out
date > forensics.out
echo "" >> forensics.out

echo "UNAME -A" >> forensics.out
uname -a >> forensics.out
echo "" >> forensics.out

echo "SUDOERS" >> forensics.out
getent group sudo | cut -d: -f4
echo "" >> forensics.out

echo "CRONTAB -L" >> forensics.out
crontab -l >> forensics.out
echo "" >> forensics.out

echo "WHO -A" >> forensics.out
who -a >> forensics.out
echo "" >> forensics.out

echo "IP ADDR SHOW" >> forensics.out
ip addr show >> forensics.out
echo "" >> forensics.out

echo "SS -TULN" >> forensics.out
ss -tuln >> forensics.out
echo "" >> forensics.out

echo "LSOF -V" >> forensics.out
lsof -V >> forensics.out
echo "" >> forensics.out

echo "PS -AUX -EF" >> forensics.out
ps -eo user,pid,ppid,%cpu,%mem,vsz,rss,tty,stat,start,time,cmd >> forensics.out
echo "" >> forensics.out

echo "MOUNT" >> forensics.out
mount >> forensics.out
echo "" >> forensics.out

echo "DF" >> forensics.out
df >> forensics.out
echo "" >> forensics.out

echo "LSMOD" >> forensics.out
lsmod >> forensics.out
echo "" >> forensics.out

echo "LAST" >> forensics.out
last >> forensics.out
echo "" >> forensics.out

echo "LASTB" >> forensics.out
lastb >> forensics.out
echo "" >> forensics.out

echo "PASSWD" >> forensics.out
cat /etc/passwd >> forensics.out
echo "" >> forensics.out

echo "GROUP" >> forensics.out
cat /etc/group >> forensics.out
echo "" >> forensics.out

echo "SHADOW" >> forensics.out
cat /etc/shadow >> forensics.out
echo "" >> forensics.out

echo "DU -HC" >> forensics.out
du -hc /var/log >> forensics.out
echo "" >> forensics.out

echo "DOCKER PS" >> forensics.out
docker ps /dev/null 2>&1 >> forensics.out
echo "" >> forensics.out

echo "IPTABLES -L -n -v" >> forensics.out
iptables -L -n -v >> forensics.out
echo "" >> forensics.out

echo "SSH_host_*_key.pub" >> forensics.out
cat /etc/ssh/ssh_host_*_key.pub >> forensics.out
echo "" >> forensics.out

echo "NEW FILES created in last 14 days exclude: /proc /sys /var/cache /run /dev"
find / -executable -mtime -14 |grep -v "Permission denied" |grep -v /sys |grep -v /proc |grep -v /var/cache |grep -v /run |grep -v /dev >> new_files.out

forensics_hash=$(sha256sum forensics.out | awk '{print $1}')
newfiles_hash=$(sha256sum new_files.out | awk '{print $1}')
logger "Forensics sha256 HASH calculation for forensics.out is $forensics_hash"
logger "Forensics sha256 HASH calculation for new_files.out is $newfiles_hash"

read -p "Do you have a password to upload this file to the forensics server? (yes/no) " answer

if [ "$answer" = "yes" ]
then
    uploader
fi

echo "Output files are contained in this directory. Move them to a safe location for future analysis. If you obtain a password for upload, execute this script with a -u option to upload without recollecting."
