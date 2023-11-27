## Application Discovery & Enumeration
Add vhosts or list of hosts or subdomains to a scope list, which can be used to perform nmap scans.
```
sudo  nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list
```
Tools like eyewitness and aquatone can be used with the results of the nmap scan to take screenshots of all the webpages and make a report.
```
eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness
```
```
 cat web_discovery.xml | ./aquatone -nmap
```
### WordPress
## Discovery
