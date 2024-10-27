# Reconnaissance
## Host Discovery
-> nmap
```bash
nmap -sn 10.10.0.0/16
```
- https://github.com/andrew-d/static-binaries/tree/master/binaries  

-> crackmapexec  
```bash
crackmapexec smb 192.168.0.20/24
```

-> Ping Sweep - PowerShell
```bash
for ($i=1;$i -lt 255;$i++) { ping -n 1 192.168.0.$i| findstr "TTL"}
```

-> Ping Sweep - Bash
```bash
for i in {1..255};do (ping -c 1 192.168.0.$i | grep "bytes from" &); done
```

-> Port Scanning - Bash
```bash
for i in {1..65535}; do (echo > /dev/tcp/192.168.1.1/$i) >/dev/null 2>&1 && echo $i is open; done
```
-> Port Scanning - NetCat
```bash
nc -zvn <ip> 1-1000
```
- https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/ncat

## Port Scanning
### nmap  
```bash
nmap -sC -sV -A -Pn -T5 -p- <ip>
```

### rustscan
-> install
```bash
sudo docker pull rustscan/rustscan:2.1.1
alias rustscan='sudo docker run -it --rm --name rustscan rustscan/rustscan:2.1.1'
```
-> scan
```bash
rustscan -a <ip> -- -A -Pn
```

## DNS Enumeration
-> Locating the host records for the domain
```bash
host <domain>
host -t mx megacorpone.com
host -t txt <domain>
```

-> Forward Lookup Brute Force
```bash
for ip in $(cat wordlist.txt); do host $ip.<domain>; done
```

-> Reverse Lookup Brute Force
```bash
for ip in $(seq  50 100); do host 192.168.0.$ip; done | grep -v "not found"
```

-> Get DNS servers for a given domain
```bash
host -t ns megacorpone.com | cut -d " " -f 4
```

-> DNS Zone Transfers
```bash
host -l <domain name> <dns server address>
```
-> Automation DNS Zone Transfer
```bash
for ns in $(host -t ns $1 | cut -d ' ' -f 4 | cut -d '.' -f 1); do host -l $1 $ns.$1; done
```
-> DNS Zone Transfer - dnsrecon
```bash
dnsrecon -d <domain -t axfr
dnsrecon -d megacorpone.com -D wordlist.txt -t brt
```

## SMB Enumeration
```bash
nmap -v -p 139,445 -oG smb.txt 10.11.1.1-254
```
```bash
sudo nbtscan -r 10.11.1.0/24
```
-> enum4linux
```bash
enum4linux <ip>
enum4linux -a -u "" -p "" <ip> && enum4linux -a -u "guest" -p "" <ip>
``` 

## NFS Enumeration

-> see nfs version  
```bash
nmap -sV -p 111 --script=rpcinfo 10.11.1.1-254
```
or  
```bash
rpcinfo <IP> | grep nfs
```

-> View NFS shared directories
```bash
nmap -p 111 --script nfs* <IP>
```
or  
```bash
showmount -e <ip>
```

-> mount
```bash
mkdir /tmp/ok
sudo mount -t nfs -o vers=4 <IP>:/folder /tmp/ok -o nolock
```

-> Config files
```bash
/etc/exports
/etc/lib/nfs/etab
```

## LDAP Enumeration
```bash
nmap -n -sV --script "ldap* and not brute" <IP>
```

```bash
ldapsearch -h <IP> -bx "DC=domain,DC=com"
```

## SNMP Enumeration
```bash
sudo nmap -sU --open -p 161 10.11.1.1-254 -oG open-snmp.txt
```
```bash
echo public > community
echo private >> community
echo manager >> community
```

```bash
for ip in $(seq 1 243); do echo 192.168.0.$ip; done > ips
onesixtyone -c community -i ips
```

```bash
onesixtyone -c community -i ips
```

-> Enumerate the entire MIB tree
```bash
snmpwalk -c public -v1 -t <ip>
```

-> Enumerate windows users
```bash
snmpwalk -c public -v1 <ip> 1.3.6.1.4.1.77.1.2.25
```

-> Lists running processes
```bash
snmpwalk -c public -v1 <ip> 1.3.6.1.2.1.25.4.2.1.2
```

-> Lists open TCP ports
```bash
snmpwalk -c public -v1 <ip> 1.3.6.1.2.1.6.13.1.3
```

-> Enumerate installed software
```bash
snmpwalk -c public -v1 <ip> 1.3.6.1.2.1.25.6.3.1.2
```

## FTP
-> credentials default  
anonymous : anonymous  
-> get version
```bash
nc <IP> <PORT>
```

-> scan ftp service
```bash
nmap --script ftp-* -p 21 <ip>
```

-> binary transfer
```bash
ftp user@port
binary
```

-> ascii transfer
```bash
ftp user@port
ascii
```

## RDP
-> RDP enumeration
```bash
nmap --script rdp-ntlm-info,rdp-enum-encryption,rdp-vuln-ms12-020 -p 3389 -T4 <IP>
```

-> Connect to RDP
```bash
rdesktop -u <username> <IP>
xfreerdp /d:<domain> /u:<username> /p:<password> /v:<IP>
```

-> Check valid credentials in RDP
```bash
rdp_check <domain>/<name>:<password>@<IP>
```

## POP 
-> POP enumeration
```bash
nmap --script pop3-capabilities,pop3-ntlm-info -sV -port <IP>
```

-> login
```bash
telnet <IP> 110
USER user1
PASS password
```

-> list messages 
```bash
list
```

->  Show message number 1
```bash
retr 1
```

## SMTP
-> SMTP enumeration
```bash
nmap -p25 --script smtp-commands,smtp-open-relay 10.10.10.10
```
-> send email via SMTP
```bash
nc -C <IP> 25
HELO
MAIL FROM:user@local
RCPT TO:user2@local
DATA
Subject: Approved in the job

http://<IP>/malware.exe

.
QUIT
```

hydra smtp-enum://192.168.0.1/vrfy -l john -p localhost
-> username enumeration
```bash
telnet <IP>
HELO
hydra smtp-enum://<IP>/vrfy -L "/usr/share/seclists/Usernames/top-usernames-shortlist.txt" 
```

## Recon Web
### Wappalyzer
- https://www.wappalyzer.com/

### What is that Website
```bash
./whatweb site.com
```

### ffuf
-> fuzzing
```bash
ffuf -u http://site.com/FUZZ -w /usr/share/wordlists/dirb/big.txt
```
or
```bash
gobuster dir -u <IP> -w /usr/share/wordlists/dirb/common.txt -t 5
```

-> Fuzzing File Extension
```bash
ffuf -u "https://site.com/indexFUZZ" -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt -fs xxx
```

-> Fuzzing Parameter GET
```bash
ffuf -u "https://site.com/index.php?FUZZ=ok" -w wordlist.txt -fs xxx
```

-> Fuzzing Parameter POST
```bash
ffuf -u "https://site.com/index.php" -X POST -d 'FUZZ=ok' -H 'Content-Type: application/x-www-form-urlencoded' -w wordlist.txt -fs xxx
```
- https://github.com/danielmiessler/SecLists

### Nikto - Web Server Scanner 
```bash
nikto -h http://site.com
```

### HTTP Enum Nmap
```bash
nmap -p80 --script=http-enum <IP>
```

### CMS
#### Wordpress
-> wpscan
```bash
wpscan --url http://site.com/wordpress --api-token <your_token> --enumerate u,vp --plugins-detection aggressive
wpscan --url http://site.com/wordpress --api-token <your_token> --enumerate u,ap
```

#### Joomla
-> juumla
```bash
python main.py -u <target>
```
- https://github.com/oppsec/juumla

#### Drupal
-> droopescan
```bash
droopescan scan drupal -u <target> -t 32
```
- https://github.com/SamJoan/droopescan

#### Magento
-> magescan
```bash
php magescan.phar scan:all www.example.com
```
- https://github.com/steverobbins/magescan
