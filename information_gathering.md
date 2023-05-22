# Reconnaissance
## Host Discovery
### nmap
```
nmap -sn 10.10.0.0./16
```
https://github.com/andrew-d/static-binaries/tree/master/binaries  

### crackmapexec  
```
crackmapexec smb 192.168.0.20/24
```

## Port Scanning
### nmap  
```
nmap -sC -sV -A -Pn -T5 -p- <ip>
```

### rustscan
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
```
nmap -v -p 111 10.11.1.1-254
```
```
nmap -sV -p 111 --script=rpcinfo 10.11.1.1-254
```

-> View NFS shared directories
```
nmap -p 111 --script nfs* <ip>
```
or  
```
showmount -e <ip>
```
-> mount
```
mkdir /tmp/ok
sudo mount -o nolock <ip>:/home /tmp/ok
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

## Recon Web
### What is that Website
```
 ./whatweb site.com
```

### ffuf
-> fuzzing
```
ffuf -u http://site.com/FUZZ -w /usr/share/wordlists/dirb/big.txt
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
