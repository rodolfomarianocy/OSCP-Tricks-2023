## Recon Active
### Host Discovery
-> nmap
```
nmap -sn 10.10.0.0./16
```
https://github.com/andrew-d/static-binaries/tree/master/binaries  
-> crackmapexec  
```
crackmapexec smb 192.168.0.20/24
```

### Capturing Information
-> nmap  
```
nmap -sC -sV -A -Pn -T5 -p- <ip>
```

-> rustscan
```
rustscan -a <ip> -- -A -Pn
```

-> enum4linux  
```
enum4linux <ip>
```
```
enum4linux -a -u "" -p "" <ip> && enum4linux -a -u "guest" -p "" <ip>
```
