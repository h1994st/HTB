# Cap

## Port Scanning

```bash
sudo nmap -vv -n -sS -T4 --top-ports 6000 10.10.10.245
sudo nmap -vv -sC -sV -T4 -A --top-ports 80 10.10.10.245
```

Actually, no need to specify a large number like 6000. Using the default 1000 should be sufficient.

Results:

```txt
...
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2vrva1a+HtV5SnbxxtZSs+D8/EXPL2wiqOUG2ngq9zaPlF6cuLX3P2QYvGfh5bcAIVjIqNUmmc1eSHVxtbmNEQjyJdjZOP4i2IfX/RZUA18dWTfEWlNaoVDGBsc8zunvFk3nkyaynnXmlH7n3BLb1nRNyxtouW+q7VzhA6YK3ziOD6tXT7MMnDU7CfG1PfMqdU297OVP35BODg1gZawthjxMi5i5R1g3nyODudFoWaHu9GZ3D/dSQbMAxsly98L1Wr6YJ6M6xfqDurgOAl9i6TZ4zx93c/h1MO+mKH7EobPR/ZWrFGLeVFZbB6jYEflCty8W8Dwr7HOdF1gULr+Mj+BcykLlzPoEhD7YqjRBm8SHdicPP1huq+/3tN7Q/IOf68NNJDdeq6QuGKh1CKqloT/+QZzZcJRubxULUg8YLGsYUHd1umySv4cHHEXRl7vcZJst78eBqnYUtN3MweQr4ga1kQP4YZK5qUQCTPPmrKMa9NPh1sjHSdS8IwiH12V0=
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDqG/RCH23t5Pr9sw6dCqvySMHEjxwCfMzBDypoNIMIa8iKYAe84s/X7vDbA9T/vtGDYzS+fw8I5MAGpX8deeKI=
|   256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPbLTiQl+6W0EOi8vS+sByUiZdBsuz0v/7zITtSuaTFH
80/tcp open  http    syn-ack Gunicorn
|_http-server-header: gunicorn
|_http-title: Security Dashboard
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
...
```

## PCAP Analysis

We need to download all available pcaps. After several tries, we find out there are 24 pcap files in total. All of them can be downloaded via `/download/{id}` endpoint.

```bash
wget -O 0.pcap http://10.10.10.245/download/0
```

Luckily, `0.pcap` contains the sensitive information. The FTP traffice exposes the password of `nathan`.

## Exploit

After getting the password of `nathan`, we can try to ssh into the box, as the port 22 is available. It is not difficult to get the user's flag. The remainnig question is how to obtain the root permission.

Randomly running two available bash scripts under the home directory of `nathan`, we notice that `/usr/bin/python3.8` has `CAP_SETUID` capability, allowing us to execute arbitrary commands via `os.setuid(0)`. Then, simply listing files under `/root` will lead to the root flag.
