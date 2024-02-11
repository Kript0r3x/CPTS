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

