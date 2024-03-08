# Reconnaissance
## Host Discovery
-> nmap
```
nmap -sn 10.10.0.0/16
```
https://github.com/andrew-d/static-binaries/tree/master/binaries  

-> crackmapexec  
```
crackmapexec smb 192.168.0.20/24
```

-> Ping Sweep - PowerShell
```
for ($i=1;$i -lt 255;$i++) { ping -n 1 192.168.0.$i| findstr "TTL"}
```

-> Ping Sweep - Bash
```
for i in {1..255};do (ping -c 1 192.168.0.$i | grep "bytes from" &); done
```

-> Port Scanning - Bash
```
for i in {1..65535}; do (echo > /dev/tcp/192.168.1.1/$i) >/dev/null 2>&1 && echo $i is open; done
```
-> Port Scanning - NetCat
```
nc -zvn <ip> 1-1000
```
https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/ncat

## Port Scanning
### nmap  
```
nmap -sC -sV -A -Pn -T5 -p- <ip>
```

### rustscan
-> install
```
sudo docker pull rustscan/rustscan:2.1.1
alias rustscan='sudo docker run -it --rm --name rustscan rustscan/rustscan:2.1.1'
```
-> scan
```
rustscan -a <ip> -- -A -Pn
```

## DNS Enumeration
-> Locating the host records for the domain
```
host <domain>
host -t mx megacorpone.com
host -t txt <domain>
```

-> Forward Lookup Brute Force
```
for ip in $(cat wordlist.txt); do host $ip.<domain>; done
```

-> Reverse Lookup Brute Force
```
for ip in $(seq  50 100); do host 192.168.0.$ip; done | grep -v "not found"
```

-> Get DNS servers for a given domain
```
host -t ns megacorpone.com | cut -d " " -f 4
```

-> DNS Zone Transfers
```
host -l <domain name> <dns server address>
```
-> Automation DNS Zone Transfer
```
for ns in $(host -t ns $1 | cut -d ' ' -f 4 | cut -d '.' -f 1); do host -l $1 $ns.$1; done
```
-> DNS Zone Transfer - dnsrecon
```
dnsrecon -d <domain -t axfr
dnsrecon -d megacorpone.com -D wordlist.txt -t brt
```

## SMB Enumeration
```
nmap -v -p 139,445 -oG smb.txt 10.11.1.1-254
```
```
sudo nbtscan -r 10.11.1.0/24
```
-> enum4linux
```
enum4linux <ip>
enum4linux -a -u "" -p "" <ip> && enum4linux -a -u "guest" -p "" <ip>
``` 

## NFS Enumeration

-> see nfs version  
```
nmap -sV -p 111 --script=rpcinfo 10.11.1.1-254
```
or  
```
rpcinfo <IP> | grep nfs
```

-> View NFS shared directories
```
nmap -p 111 --script nfs* <IP>
```
or  
```
showmount -e <ip>
```

-> mount
```
mkdir /tmp/ok
sudo mount -t nfs -o vers=4 <IP>:/folder /tmp/ok -o nolock
```

-> Config files
```
/etc/exports
/etc/lib/nfs/etab
```

## LDAP Enumeration
```
nmap -n -sV --script "ldap* and not brute" <IP>
```

```
ldapsearch -h <IP> -bx "DC=domain,DC=com"
```

## SNMP Enumeration
```
sudo nmap -sU --open -p 161 10.11.1.1-254 -oG open-snmp.txt
```
```
echo public > community
echo private >> community
echo manager >> community
```

```
for ip in $(seq 1 243); do echo 192.168.0.$ip; done > ips
onesixtyone -c community -i ips
```

```
onesixtyone -c community -i ips
```

-> Enumerate the entire MIB tree

```
snmpwalk -c public -v1 -t <ip>
```

-> Enumerate windows users

```
snmpwalk -c public -v1 <ip> 1.3.6.1.4.1.77.1.2.25
```

-> Lists running processes
```
snmpwalk -c public -v1 <ip> 1.3.6.1.2.1.25.4.2.1.2
```

-> Lists open TCP ports
```
snmpwalk -c public -v1 <ip> 1.3.6.1.2.1.6.13.1.3
```

-> Enumerate installed software
```
snmpwalk -c public -v1 <ip> 1.3.6.1.2.1.25.6.3.1.2
```

## FTP
-> credentials default  
anonymous : anonymous  
-> get version
```
nc <IP> <PORT>
```

-> scan ftp service
```
nmap --script ftp-* -p 21 <ip>
```

-> binary transfer
```
ftp user@port
binary
```

-> ascii transfer
```
ftp user@port
ascii
```

## RDP
-> RDP enumeration
```
nmap --script rdp-ntlm-info,rdp-enum-encryption,rdp-vuln-ms12-020 -p 3389 -T4 <IP>
```

-> Connect to RDP
```
rdesktop -u <username> <IP>
xfreerdp /d:<domain> /u:<username> /p:<password> /v:<IP>
```

-> Check valid credentials in RDP
```
rdp_check <domain>/<name>:<password>@<IP>
```

## POP 
-> POP enumeration
```
nmap --script pop3-capabilities,pop3-ntlm-info -sV -port <IP>
```

-> login
```
telnet <IP> 110
USER user1
PASS password
```

-> list messages 
```
list
```

->  Show message number 1
```
retr 1
```

## SMTP
-> SMTP enumeration
```
nmap -p25 --script smtp-commands,smtp-open-relay 10.10.10.10
```
-> send email via SMTP
```
nc -C <IP> 25
HELO
MAIL FROM:user@local
RCPT TO:user2@local
DATA
Subject: approved in the job

http://<IP>/malware.exe

.
QUIT
```

hydra smtp-enum://192.168.0.1/vrfy -l john -p localhost
-> username enumeration
```
telnet 10.0.0.1 25
HELO
hydra smtp-enum://<IP>/vrfy -L "/usr/share/seclists/Usernames/top-usernames-shortlist.txt" 
```

## Recon Web
### Wappalyzer
https://www.wappalyzer.com/

### What is that Website
```
./whatweb site.com
```

### ffuf
-> fuzzing
```
ffuf -u http://site.com/FUZZ -w /usr/share/wordlists/dirb/big.txt
```
or
```
gobuster dir -u <IP> -w /usr/share/wordlists/dirb/common.txt -t 5
```

-> Fuzzing File Extension
```
ffuf -u "https://site.com/indexFUZZ" -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt -fs xxx
```

-> Fuzzing Parameter GET
```
ffuf -u "https://site.com/index.php?FUZZ=ok" -w wordlist.txt -fs xxx
```

-> Fuzzing Parameter POST
```
ffuf -u "https://site.com/index.php" -X POST -d 'FUZZ=ok' -H 'Content-Type: application/x-www-form-urlencoded' -w wordlist.txt -fs xxx
```
https://github.com/danielmiessler/SecLists

### Nikto - Web Server Scanner 
```
nikto -h http://site.com
```

### HTTP Enum Nmap
```
nmap -p80 --script=http-enum <IP>
```

### CMS
#### Wordpress
-> wpscan
```
wpscan --url http://site.com/wordpress --api-token <your_token> --enumerate u,vp --plugins-detection aggressive
wpscan --url http://site.com/wordpress --api-token <your_token> --enumerate u,ap
```

#### Joomla
-> juumla
```
python main.py -u <target>
```
https://github.com/oppsec/juumla

#### Drupal
-> droopescan
```
droopescan scan drupal -u <target> -t 32
```
https://github.com/SamJoan/droopescan

#### Magento
-> magescan
```
php magescan.phar scan:all www.example.com
```
https://github.com/steverobbins/magescan
