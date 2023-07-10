* [Passive Information Gathering](passive-information-gathering)
  - [WHOIS](#whois)
  - [DNS](#dns)
  - [Passive Subdomain Enumeration](#passive-subdomain-enumeration)
  - [Passive Infrastructure Identification](#passive-infrastructure-identification)
* [Active Information Gathering](#active-information-gathering)
  - [Active Infrastructure Identifcation](#active-infrastructure-identification)
  - [Active Subdomain Enumeration](#active-subdomain-enumeration)
  - [Virtual Hosts](#virtual-hosts)
  - [Crawling](#crawling)

# Passive Information Gathering

## WHOIS
Linux
```
export TARGET="facebook.com" # Assign our target to an environment variable
whois $TARGET
```
Windows
```
whois.exe facebook.com
```

## DNS
### Query A record
```
export TARGET="facebook.com"
nslookup $TARGET
```
```
dig facebook.com @1.1.1.1
```
Subdomain
```
export TARGET=www.facebook.com
nslookup -query=A $TARGET
```
```
dig a www.facebook.com @1.1.1.1
```

### PTR Record

```
nslookup -query=PTR 31.13.92.36
```
```
dig -x 31.13.92.36 @1.1.1.1
```
### ANY existin record
```
export TARGET="google.com"
nslookup -query=ANY $TARGET
```
```
dig any google.com @8.8.8.8
```
###  TXT Record
```
export TARGET="facebook.com"
nslookup -query=TXT $TARGET
```
```
dig txt facebook.com @1.1.1.1
```
### MX Record
```
export TARGET="facebook.com"
nslookup -query=MX $TARGET
```
```
dig mx facebook.com @1.1.1.1
```

## Passive Subdomain Enumeration
> Virustotal
> crt.sh
> censys.io
### Certificate Transparency
```
export TARGET="facebook.com"
curl -s "https://crt.sh/?q=${TARGET}&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u > "${TARGET}_crt.sh.txt"
```
```
head -n20 facebook.com_crt.sh.txt
```
```
export TARGET="facebook.com"
export PORT="443"
openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' -connect "${TARGET}:${PORT}" | openssl x509 -noout -text -in - | grep 'DNS' | sed -e 's|DNS:|\n|g' -e 's|^\*.*||g' | tr -d ',' | sort -u
```

**cat sources.txt**
---
baidu
bufferoverun
crtsh
hackertarget
otx
projecdiscovery
rapiddns
sublist3r
threatcrowd
trello
urlscan
vhost
virustotal
zoomeye
---
### The Harvester
```
export TARGET="facebook.com"
cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}_${TARGET}";done
```
```
cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > "${TARGET}_theHarvester.txt"
```
```
cat facebook.com_*.txt | sort -u > facebook.com_subdomains_passive.txt
cat facebook.com_subdomains_passive.txt | wc -l
```
## Passive Infrastructure Identification
[Netcraft](https://sitereport.netcraft.com)
[Wayback Machine](http://web.archive.org/)
[Wayback URL](https://github.com/tomnomnom/waybackurls)

# Active Information Gathering
## Active Infrastructure Identification
### HTTP Headers
```
curl -I "http://${TARGET}"
```
## WhatWeb
```
whatweb -a3 https://www.facebook.com -v
```
**Wappalyzer**
### WafW00f
```
sudo apt install wafw00f -y
```
```
wafw00f -v https://www.tesla.com
```
### Aquatone
```
sudo apt install golang chromium-driver
go get github.com/michenriksen/aquatone
export PATH="$PATH":"$HOME/go/bin"
```
```
cat facebook_aquatone.txt | aquatone -out ./aquatone -screenshot-timeout 1000
```
## Active Subdomain Enumeration
### Zone Transfer
[Hacker Target](https://hackertarget.com/zone-transfer/)
### Gobuster - DNS
```
export TARGET="facebook.com"
export NS="d.ns.facebook.com"
export WORDLIST="numbers.txt"
gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"
```

## Virtual Hosts
### Name-based Virtual Hosting
```
curl -s http://192.168.10.10
```
```
curl -s http://192.168.10.10 -H "Host: randomtarget.com"
```
/opt/useful/SecLists/Discovery/DNS/namelist.txt
### vHost Fuzzing
```
cat ./vhosts | while read vhost;do echo "\n********\nFUZZING: ${vhost}\n********";curl -s -I http://192.168.10.10 -H "HOST: ${vhost}.randomtarget.com" | grep "Content-Length: ";done
```
```
curl -s http://192.168.10.10 -H "Host: dev-admin.randomtarget.com"
```
### ffuf
```
ffuf -w ./vhosts -u http://192.168.10.10 -H "HOST: FUZZ.randomtarget.com" -fs 612
```
## Crawling
Use OWASPZAP
### ffuf Crawling
```
ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt
```
```
cewl -m5 --lowercase -w wordlist.txt http://192.168.10.10
```
```
ffuf -w ./folders.txt:FOLDERS,./wordlist.txt:WORDLIST,./extensions.txt:EXTENSIONS -u http://192.168.10.10/FOLDERS/WORDLISTEXTENSIONS

```

