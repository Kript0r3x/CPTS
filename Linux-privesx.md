### Look for 
- OS Version ```cat /etc/os-release```
- Kernel Version ```cat /proc/version``` or ```unmae -a```
- Running Services \
### Basic commands to orient ourselves
- whoami - what user are we running as
- id - what groups does our user belong to?
- hostname - what is the server named. can we gather anything from the naming convention?
- ifconfig or ip -a - what subnet did we land in, does the host have additional NICs in other subnets?
- sudo -l - can our user run anything with sudo (as another user as root) without needing a password? This can sometimes be the easiest win and we can do something like sudo su and drop right into a root shell. \ 
### Check for current users
- PATH ```echo $PATH```
- Environment variables ```env```
- CPU info ```lscpu```
- Shells available ```cat /etc/shells```
- Block devices on system ```lsblk```
- Printers (Queued print jobs) ```lpstat```
- Mounted or unmounted drives and username, passwords for the same ```cat /etc/fstab```
- Routing table ```route``` or ```netstat -rn```
- arp table ```arp -a```
- User accounts info ```cat /etc/passwd```
- Users login shells ```grep "*sh$" /etc/passwd```
- Groups ```cat /etc/group```
- Group members ```getent group sudo```
- Mounted files ```df -h```
- Unmounted file systems ```cat /etc/fstab | grep -v "#" | column -t```
- All hidden files ```find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep htb-student```
- All hidden directories ```find / -type d -name ".*" -ls 2>/dev/null```
- Temp files ```ls -l /tmp /var/tmp /dev/shm``` \
### We should also check to see if any defenses are in place and we can enumerate any information about them. Some things to look for include:
- Exec Shield
- iptables
- AppArmor
- SELinux
- Fail2ban
- Snort
- Uncomplicated Firewall (ufw) \
In a domain environment we'll definitely want to check **/etc/resolv.conf** if the host is configured to use internal DNS we may be able to use this as a starting point to query the Active Directory environment.

**Password Hashes**
| Algorithm | Hash |
| --- | --- |
| Salted MD5 | $1$... |
| SHA-256 | $5$... |
| SHA-512 | $6$... |
| BCrypt | $2a$... |
| Scrypt | $7$... |
| Argon2 | $argon2i$... |

Checkout /home directory for users and .bash_history and hidden files and directories.  Check the ARP cache to see what other hosts are being accessed and cross-reference these against any useable SSH private keys\
Look for config files, such as files ending with .conf and .config for usernames, passwords and secrets.
