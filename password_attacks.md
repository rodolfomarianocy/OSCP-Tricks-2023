# Password Attacks
## Generating Wordlists
### Cewl - Custom Word List generator

-> generating wordlist based on information from a website
```
cewl <domain> -w wordlist.txt
```

### Crunch - Wordlist Generator
-> Character Translation  
`@ = Lower case alpha characters`  
`, = Upper case alpha characters`  
`% = Numeric characters`  
`^ = Special characters including space`  

-> Usage
```
./crunch <min-len> <max-len> [charset]
```

-> basic examples
```
crunch 9 9 -t ,@@@@^%%%
```
```
crunch 4 6 0123456789abcdef -o wordlist.txt
```

### John Mutation
-> Add the rules you want in the /etc/john/john.conf file inside the rules module [List.Rules:Wordlist] to modify your wordlists  
-> basic rule example `$@$[1-2]$[0-9]$[0-9]$[0-9]`
```
john --wordlist=wordlist.txt --rules --stdout > mutated.txt
```
https://www.openwall.com/john/doc/RULES.shtml

## Cracking Password
### Identifying Hash Type
```
hashid <hash>
```
https://www.tunnelsup.com/hash-analyzer/
https://hashes.com/en/tools/hash_identifier

### Hashing different file types for cracking with 2john
- [ssh2john](https://github.com/piyushcse29/john-the-ripper/blob/master/src/ssh2john.c)  
- [rar2john](https://github.com/piyushcse29/john-the-ripper/blob/master/src/rar2john.c)  
- [zip2john](https://github.com/piyushcse29/john-the-ripper/blob/master/src/zip2john.c)  
- [keepass2john](https://github.com/piyushcse29/john-the-ripper/blob/master/src/keepass2john.c)  
- [office2john](https://github.com/piyushcse29/john-the-ripper/blob/master/src/office2john.c)  
- [pdf2john](https://github.com/piyushcse29/john-the-ripper/blob/master/src/pdf2john.c)  
- [pwsafe2john](https://github.com/piyushcse29/john-the-ripper/blob/master/src/pwsafe2john.c)  
- [racf2john](https://github.com/piyushcse29/john-the-ripper/blob/master/src/racf2john.c)  
- [vncpcap2john](https://github.com/piyushcse29/john-the-ripper/blob/master/src/vncpcap2john.cpp)  
- [hccap2jjohn](https://github.com/piyushcse29/john-the-ripper/blob/master/src/hccap2john.c)  
- [keychain2john](https://github.com/piyushcse29/john-the-ripper/blob/master/src/keychain2john.c)  
- [mozilla2john](https://github.com/piyushcse29/john-the-ripper/blob/master/src/mozilla2john.c)  

### Password Manager
-> Search KeePass database files
```
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

-> Hashing the .kdbx file
```
keepass2john Database.kdbx > keepass.hash   
```

-> Finding Hash-Mode ID of hashcat
```
hashcat --help | grep -i "KeePass"
```

-> Cracking
```
hashcat -m 13400 keepass.hash
```

## Brute Force Attacks
### RDP Brute Force - Hydra
```
hydra -L /usr/share/wordlists/rockyou.txt t -p "<password" rdp://<IP>
```

### RDP Brute Force - Crowbar
```
crowbar -b rdp -s X.X.X.X/32 -u admin -C /usr/share/wordlists/rockyou.txt -n 1
```

### SMB Brute Force - Hydra
```
hydra -L /root/Desktop/user.txt -P /usr/share/wordlists/rockyou.txt <IP> smb
```

### SSH Brute Force - Hydra
```
hydra -l <user> -P /usr/share/wordlists/rockyou.txt ssh://<IP>
```

### HTTP POST Login Form Brute Force - Hydra
```
hydra -l <user> -P /usr/share/wordlists/rockyou.txt <IP> http-post-form "/login.php:user=admin&pass=^PASS^:Invalid Login" -vV -f
```

### HTTP GET Login Form Brute Force - Hydra
```
hydra -l <username> -P /usr/share/wordlists/rockyou.txt -f <IP> http-get /login
```
