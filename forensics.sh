#Ken Webster kenneth.webster@imperva.com 10/2021

echo "Forensics Collector v0.3"
echo ""

if [ `id -u` -ne 0 ]
   then echo "Must be run as root or sudo"
   exit
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

echo "IFCONFIG -A" >> forensics.out
ifconfig -a >> forensics.out
echo "" >> forensics.out

echo "NETSTAT -ANP" >> forensics.out
netstat -anp >> forensics.out
echo "" >> forensics.out

echo "LSOF -V" >> forensics.out
lsof -V >> forensics.out
echo "" >> forensics.out

echo "PS -AUX" >> forensics.out
ps -aux >> forensics.out
echo "" >> forensics.out

echo "PS -EF" >> forensics.out
ps -ef >> forensics.out
echo "" >> forensics.out

echo "NETSTAT -RN" >> forensics.out
netstat -rn >> forensics.out
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

tar -czf - /var/log new_files.out forensics.out | ssh drop@vuser.imperva.local "cat > `hostname`.`date +%Y%m%d-%H%M%S`.infosec.forensics.tar.gz"

wait $!

echo "Transfer complete"

#If you want to use scp do this: "scp *.forensics.tar.gz drop@35.165.222.145:."


