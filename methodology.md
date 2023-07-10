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
