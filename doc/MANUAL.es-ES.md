# Manual de uso de localSIEM

Este MANUAL también está disponible en:\
[en-GB](MANUAL.en-GB.md), [en-US](MANUAL.md), [es-AR](MANUAL.es-AR.md), es-ES

[Instalación](README.es-ES.md) · [Referencia técnica](CODE.es-ES.md)

## Contenido

1. [Qué hace localSIEM](#what)
2. [Instalación](#installation)
3. [Requisitos de Apache y ModSecurity](#requirements)
4. [El doctor](#doctor)
5. [Conexión con el SOC](#soc)
6. [Inicio de sesión y cuentas](#signin)
7. [Los dos paneles](#dashboards)
8. [Resumen](#overview)
9. [Búsqueda](#search)
10. [La ficha de la petición y los pivotes](#card)
11. [Vista en directo](#live)
12. [Alertas](#alerts)
13. [Módulos](#modules)
14. [Administración](#administration)
15. [Avisos de salud y qué hacer](#health)
16. [Retención y disco](#retention)
17. [Línea de comandos](#cli)

<a id="what"></a>
## 1. Qué hace localSIEM

localSIEM vigila los servicios del servidor en el que está instalado mediante **módulos**, uno por cada servicio. Solo lee los logs de ese servidor: no recibe logs de otras máquinas. El módulo **Apache + ModSecurity** vigila la web de Apache: para cada petición junta tres registros, la línea de `access.log`, las líneas de `error.log` y el registro del log de auditoría de ModSecurity, usando el `UNIQUE_ID` de la petición. Todo se guarda para poder buscarlo. Después localSIEM decide qué tiene que ir al SOC.

**Al SOC solo va lo que todavía nadie ha resuelto.**

| Situación | ¿Va al SOC? |
|---|---|
| ModSecurity bloqueó la petición en las fases 1–2 (antes de que la recibiera la aplicación) | **No.** Se queda en localSIEM, se puede buscar y aparece como recuento en la siguiente alerta de esa IP. |
| ModSecurity bloqueó la respuesta en las fases 3–4 (la aplicación ya había ejecutado la petición) | Sí |
| Coincidencias de reglas con ModSecurity en `DetectionOnly` (no se bloquea nada) | Sí |
| Coincidencias de reglas por debajo del umbral de bloqueo | Sí, con severidad `low` |
| Señales de las reglas de localSIEM (fuerza bruta, web shell, archivo sensible, enumeración, error de base de datos) | Sí |
| Problemas de salud y posible borrado de rastros | Sí |

**Severidad de lo que va al SOC**

| Situación | Severidad |
|---|---|
| Coincidencias de reglas no bloqueadas, respuesta 3xx, 4xx o 5xx | media |
| Coincidencias de reglas no bloqueadas, respuesta 2xx | alta |
| Bloqueada en las fases 3–4 | alta |
| Indicios de éxito: regla de fuga de datos o de web shell (950–955) no bloqueada, error SQL justo después, POST con 2xx a un `.php` nuevo | crítica |
| Por debajo del umbral de bloqueo (a menudo falsos positivos de la aplicación) | baja (configurable en Ajustes) |

**Agrupación.** Una alerta por módulo, vhost, IP, categoría y severidad en una ventana de 10 minutos. Una alerta crítica sale en el acto; las demás esperan 60 segundos para reunir la ráfaga y salen con el recuento. Un escáner que envía miles de peticiones produce unas pocas alertas, no miles. Si la severidad sube (por ejemplo, el mismo ataque ahora recibe respuestas 200), es otra alerta.

**Lo que nunca va al SOC:** los cuerpos de las peticiones o de las respuestas, las cookies, las cabeceras `Authorization`, las contraseñas ni los tokens —ni siquiera enmascarados— y lo que ya se bloqueó en las fases 1–2 (solo como recuento). localSIEM enmascara los valores sensibles (`password`, `pass`, `pwd`, `passwd`, `token`, `secret`, `api_key`, `apikey`, `auth`, `session` y las cabeceras `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `Proxy-Authorization`) con `***` antes de guardar nada.

**Módulos.** El núcleo de localSIEM (almacenamiento, búsqueda, reglas, agrupación, envío al SOC, salud) es el mismo para todos los servicios; cada módulo añade lo que es específico de un servicio. El módulo Apache + ModSecurity (`apache2`) viene del repositorio `localSIEM-modules` (GitHub) y se instala, actualiza y desinstala solo desde la web, nunca con el instalador de localSIEM; instalarlo nunca instala Apache ni ModSecurity. Todos los módulos se instalan, actualizan y desinstalan del mismo modo, desde la web. La sección 13 explica cómo instalarlos y actualizarlos, ver su estado, activarlos, desactivarlos y configurarlos.

<a id="installation"></a>
## 2. Instalación

La instalación tiene dos pasos: el núcleo de localSIEM y, después, sus módulos (el paso 2, más abajo). Ejecuta como root, directamente desde GitHub:

```bash
# Debian 13
curl -fsSL -H 'Accept: application/vnd.github.raw+json' https://api.github.com/repos/PYMEHackers/localSIEM/contents/deploy/install-update-reinstall-debian.sh | bash -s -- --install --allow-from 203.0.113.10 --soc-token TOKEN
# Alpine 3.24 (primero: apk add bash curl)
curl -fsSL -H 'Accept: application/vnd.github.raw+json' https://api.github.com/repos/PYMEHackers/localSIEM/contents/deploy/install-update-reinstall-alpine.sh | bash -s -- --install --allow-from 203.0.113.10 --soc-token TOKEN
```

La web de localSIEM siempre escucha en el **puerto 10443 con HTTPS**: el instalador comprueba que el puerto esté libre y se detiene si otro servicio lo usa. La acción y las opciones van después de `bash -s --`. El instalador comprueba lo que necesita (Python 3.13 con `venv`, OpenSSL, los certificados de las CA, las herramientas de ACL, logrotate, curl, tar) e instala lo que falta. Ejecutado así, con una tubería, descarga la rama `main` de `https://github.com/PYMEHackers/localSIEM`; si se ejecuta desde una copia del proyecto (`bash deploy/install-update-reinstall-debian.sh --install`), instala esa copia.

**La acción.** El instalador siempre necesita una acción; sin ella se detiene y las enumera:

| Acción | Uso |
|---|---|
| `--install` | Instala localSIEM en un servidor que no lo tiene. Si encuentra cualquier cosa de localSIEM (`/opt/localsiem`, sus servicios o su usuario `localsiem`, también de una instalación que falló a medias), se detiene e indica `--update` y `--reinstall`. |
| `--update` | Actualiza el localSIEM instalado: conserva sus datos, cuentas, ajustes, módulos y las opciones que se dieron antes (más abajo). |
| `--reinstall [--yes]` | Borra el localSIEM instalado con todos sus datos, como `--uninstall` (más abajo), y lo vuelve a instalar desde cero, con contraseñas nuevas. Antes pide que escribas `yes` (`--yes` no lo pide; hace falta cuando no hay terminal) y no borra nada hasta haber descargado la copia nueva y comprobado las opciones. Las opciones de la instalación anterior no se conservan: hay que volver a darlas. |
| `--uninstall [--yes]` | Borra localSIEM y todos sus datos del servidor (más abajo). Va sola. |

`--update` y `--reinstall` se detienen si localSIEM no está instalado: usa `--install`.

Opciones de `--install`, `--update` y `--reinstall`:

| Opción | Uso |
|---|---|
| `--allow-from LIST` | IPs y CIDR a los que se permite abrir la web, separados por comas: el SOC y tus administradores |
| `--soc-url URL` | Por defecto, `https://soc.pymehackers.com` |
| `--soc-token TOKEN` | Token de ingesta de este cliente en el SOC. Opcional: sin SOC, localSIEM funciona por su cuenta (sección 5) |
| `--soc-ca-file PATH` | Solo para un SOC con certificado privado (servidores de prueba) |
| `--domain NAME` | Nombre del servidor, para el certificado y la Dirección del SIEM (por defecto: su nombre de host) |
| `--certificate PATH --private-key PATH` | Certificado que se va a usar. Sin estas opciones, localSIEM copia el certificado de Let's Encrypt de `--domain` si existe (y lo vuelve a copiar en cada renovación), o crea uno autofirmado. |
| `--retention-days N`, `--max-disk SIZE` | Retención (sección 16) |
| `--enable-mfa`, `--disable-mfa` | Verificación en dos pasos activada (obligatoria para todas las cuentas) o desactivada. Sin ellas, una instalación nueva la tiene desactivada y una actualización conserva lo que se eligió en Administración › Ajustes (sección 14). |
| `--rotate-credentials` | Crea un secreto de firma JWT nuevo y lo escribe en `/root/webapp-credentials.txt` |
| `--ref REF` | Rama o etiqueta de localSIEM que se descarga (por defecto, `main`) |
| `--source-url URL` | Archivo (`.tar.gz`) de localSIEM que se instala en lugar del de GitHub (una réplica) |
| `--modules-repository URL`, `--modules-ref REF` | Repositorio (o archivo `.tar.gz`) y rama o etiqueta desde los que la web instala y actualiza módulos (sección 13). Por defecto: `https://github.com/PYMEHackers/localSIEM-modules`, rama `main`. |

**Siempre la última versión.** GitHub guarda los archivos de `raw.githubusercontent.com` en una caché durante hasta 5 minutos después de cada cambio, así que los comandos de arriba leen el instalador a través de la API de GitHub, que no tiene caché; después, el instalador pregunta a esa API qué commit es la rama y descarga exactamente ese commit, y pide a todos los servidores del camino que no respondan con una copia guardada en caché. Sin token, GitHub permite 60 peticiones a su API por hora desde cada dirección IP: si la rechaza, el comando falla con `403` (espera y vuelve a ejecutarlo); si solo falla la pregunta del instalador, el instalador lo avisa y descarga la rama.

Las opciones se recuerdan: `--update` sin opciones las conserva. Para actualizar:

```bash
# Debian 13 (en Alpine: install-update-reinstall-alpine.sh)
curl -fsSL -H 'Accept: application/vnd.github.raw+json' https://api.github.com/repos/PYMEHackers/localSIEM/contents/deploy/install-update-reinstall-debian.sh | bash -s -- --update
```

El log del instalador es `/root/webapp-install.log` y las contraseñas que crea están en `/root/webapp-credentials.txt` (ambos con modo 600). Al final ejecuta el doctor de cada módulo activado (sección 4) y muestra la Dirección del SIEM que hay que dar al SOC.

**Desinstalar.** `--uninstall` borra localSIEM del servidor: detiene y elimina sus servicios y borra `/opt/localsiem` (código, ajustes, la base de datos con todos los eventos y alertas, certificados y módulos), el usuario `localsiem`, el permiso de lectura de los logs que dio `setup-modules`, la configuración de Apache de `--configure-apache` (`localsiem.conf`, con un configtest y una recarga de Apache), el archivo de logrotate, el hook de Let's Encrypt y las entradas de localSIEM de `/root/webapp-credentials.txt` (el archivo se borra si no queda nada más en él). Antes pide que escribas `yes` (`--yes` no lo pide; hace falta cuando no hay terminal). Se conservan el log del instalador, los paquetes que añadió el instalador, `mod_unique_id` (Debian) y los logs de Apache, también el `localsiem_access.log` de `--configure-apache` y `modsec_audit.log`: localSIEM nunca cambia ni borra un log de Apache. Para desinstalarlo:

```bash
# Debian 13 (en Alpine: install-update-reinstall-alpine.sh)
curl -fsSL -H 'Accept: application/vnd.github.raw+json' https://api.github.com/repos/PYMEHackers/localSIEM/contents/deploy/install-update-reinstall-debian.sh | bash -s -- --uninstall
```

**Reinstalar.** Para empezar de cero en un solo paso, `--reinstall` lo borra todo del mismo modo y vuelve a instalar localSIEM (vuelve a dar las opciones):

```bash
# Debian 13 (en Alpine: install-update-reinstall-alpine.sh)
curl -fsSL -H 'Accept: application/vnd.github.raw+json' https://api.github.com/repos/PYMEHackers/localSIEM/contents/deploy/install-update-reinstall-debian.sh | bash -s -- --reinstall --allow-from 203.0.113.10 --soc-token TOKEN
```

**2. Los módulos.** El instalador de localSIEM **no instala ningún módulo**: deja localSIEM preparado para ellos, y una actualización conserva los que ya estaban instalados (y el acceso de lectura a sus logs). Los módulos se instalan **solo desde la web**: Módulos › Instalables (sección 13), que lista los módulos del repositorio `localSIEM-modules` que todavía no están instalados; ese repositorio no tiene instalador propio. localSIEM descarga el módulo de él, copia su carpeta (`mod-<name>/` en ese repositorio) en `/opt/localsiem/modules/<name>/` (las carpetas `tests/` no se copian; un módulo que se vuelve a instalar recupera los ajustes que tenía) y reinicia el colector. Los módulos también se actualizan y desinstalan desde la web: **Actualizar**, cuando el repositorio tiene una versión más nueva, y **Desinstalar**, los dos en Módulos › Instalados (sección 13).

Leer los logs de un módulo requiere root, así que, una vez instalado el módulo, la web muestra en un cuadro de diálogo el comando que hay que ejecutar como root en el servidor:

```bash
/opt/localsiem/venv/bin/python /opt/localsiem/webapp/backend/manage.py setup-modules
```

Da al usuario `localsiem` acceso de lectura a las carpetas de logs que declara cada módulo instalado (`/var/log/apache2` para el módulo de Apache; sección 3.7), también a los archivos de las siguientes rotaciones, reinicia localSIEM y ejecuta el doctor como `localsiem`. Añade la opción de preparación que sugiere la web (`--configure-apache` para el módulo de Apache, sección 3) para aplicar además los requisitos del módulo a su servicio. Se puede volver a ejecutar en cualquier momento. El instalador de localSIEM rechaza `--configure-apache`: esa opción solo va en este comando.

**Instalar un módulo nunca instala el software que vigila.** Un módulo nuevo empieza activado o desactivado según lo haya decidido su autor, salvo cuando al servidor le falta lo que necesita (para el módulo de Apache: Apache y ModSecurity 2): entonces se instala **desactivado**, la web indica qué falta y su interruptor sigue bloqueado hasta que **Reconfigurar** lo encuentra (sección 13). Su estado está en **Módulos › Instalados** (sección 13).

<a id="requirements"></a>
## 3. Requisitos de Apache y ModSecurity

Estos son los requisitos del módulo Apache + ModSecurity. Antes tienen que estar instalados el propio Apache y ModSecurity 2: sin ellos, el módulo no se puede activar (sección 13). localSIEM nunca cambia por su cuenta la configuración de Apache. El doctor del módulo (sección 4) comprueba cada requisito y muestra el fragmento exacto para cada uno que falte. Con `--configure-apache`, añadido al comando para root de la sección 2 (`manage.py setup-modules --configure-apache`), el módulo de Apache los aplica por ti: escribe un archivo propio (`/etc/apache2/conf-available/localsiem.conf` en Debian, `/etc/apache2/conf.d/localsiem.conf` en Alpine), habilita `mod_unique_id`, ejecuta `apache2ctl configtest` y **lo deshace todo si falla**; si funciona, recarga Apache (nunca lo reinicia). Para deshacerlo más adelante, borra ese archivo (Debian: `a2disconf localsiem`) y recarga Apache.

1. **ModSecurity 2 con OWASP CRS**, con `SecRuleEngine On` o `DetectionOnly`. Ambos funcionan: con `DetectionOnly` no se bloquea nada, así que todas las coincidencias van al SOC.
2. **`mod_unique_id`**, que ModSecurity 2 necesita para funcionar (sin él no inspecciona nada; Alpine no lo carga por defecto) y con el que se juntan los tres registros de cada petición.
3. **Un log de acceso**. Bastan los que Apache escribe por defecto (`combined`, `vhost_combined`, `common`, o cualquier `LogFormat` de la configuración): cada línea se junta con su petición por IP de cliente, método, URI, estado y hora («correlación débil»), y el vhost sale de `%v` o, si no lo tiene, de la cabecera Host y el puerto del registro de auditoría. De forma opcional, para tener milisegundos, duración y la unión por `UNIQUE_ID`, este formato:

   ```apache
   LogFormat "%a %l %u [%{%d/%b/%Y:%H:%M:%S}t.%{msec_frac}t %{%z}t] \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\" %v %D %{UNIQUE_ID}e" localsiem_combined
   GlobalLog ${APACHE_LOG_DIR}/localsiem_access.log localsiem_combined
   ```

   `GlobalLog` lo escribe para todos los vhosts, sin tocar sus propios logs. `%a` es la IP real del cliente cuando se usa `mod_remoteip`.
4. **`mod_remoteip`** si la web está detrás de un proxy o de un balanceador de carga; sin él, todas las peticiones parecen venir del proxy:

   ```apache
   RemoteIPHeader X-Forwarded-For
   RemoteIPInternalProxy 10.0.0.1
   ```
5. **El log de auditoría de ModSecurity**, en serie y preferiblemente en JSON:

   ```apache
   SecAuditEngine RelevantOnly
   SecAuditLogRelevantStatus "^(?:5|4(?!04))"
   SecAuditLogType Serial
   SecAuditLogFormat JSON
   SecAuditLogParts ABIJFHKZ
   SecAuditLog /var/log/apache2/modsec_audit.log
   ```

   La parte `E` (cuerpo de la respuesta) no se registra: es voluminosa, sensible e innecesaria. La parte `K` lista el texto completo de cada regla ejecutada y hace que cada registro ocupe mucho en el disco del servidor; localSIEM no la necesita ni la guarda, así que puedes quitarla. Si tu ModSecurity no admite JSON, usa el formato nativo: localSIEM lee los dos.
6. **Enmascaramiento en origen**, para que el log de auditoría en disco tampoco guarde contraseñas:

   ```apache
   SecAction "id:77001,phase:5,nolog,pass,sanitiseArg:password,sanitiseArg:pass,sanitiseArg:pwd,sanitiseArg:passwd,sanitiseArg:token,sanitiseArg:secret,sanitiseArg:api_key,sanitiseArg:apikey,sanitiseArg:auth,sanitiseArg:session,sanitiseRequestHeader:Authorization,sanitiseRequestHeader:Cookie,sanitiseRequestHeader:Proxy-Authorization,sanitiseRequestHeader:X-Api-Key,sanitiseResponseHeader:Set-Cookie"
   ```
7. **Acceso de lectura a los logs para el usuario `localsiem`**. Lo hace el comando para root de la sección 2 (`manage.py setup-modules`) para las carpetas que declaran los módulos instalados (`/var/log/apache2` para el módulo de Apache), y el instalador de localSIEM lo vuelve a hacer en cada actualización: en Debian añade `localsiem` al grupo `adm` y, como en Alpine, da a `localsiem` acceso de lectura a esas carpetas mediante ACL, incluida una ACL por defecto para que los archivos de las siguientes rotaciones también se puedan leer. Los logs que añadas a mano en otra carpeta (sección 13) también necesitan ese acceso, por ejemplo `setfacl -m g:localsiem:rx /srv/logs`, `setfacl -d -m g:localsiem:r /srv/logs` y `setfacl -m g:localsiem:r /srv/logs/*.log`. localSIEM solo lee los logs: nunca escribe en ellos, ni los rota, trunca, mueve o borra. Cuando empieza a seguir un log (en el primer arranque, al instalar o activar un módulo, o cuando root le da acceso de lectura) empieza por su final: lo que el log ya tenía es historial y nunca se alerta; solo el log de un vhost creado después se lee desde su principio (si ocupa hasta 5 MB).

<a id="doctor"></a>
## 4. El doctor

Cada módulo tiene su propio doctor. El doctor del módulo de Apache comprueba cada requisito de la sección 3, lista las fuentes encontradas (y las que no puede leer, como los logs por tubería) y muestra el fragmento que corrige cada elemento que falta. Se ejecuta al final de cada instalación de localSIEM y del comando para root de la sección 2, aparece en la página de cada módulo (**Módulos › Instalados › Configurar**, sección 13, con el botón «Descubrir de nuevo y pasar el doctor») y se puede ejecutar en cualquier momento para todos los módulos activados:

```bash
runuser -u localsiem -- /opt/localsiem/venv/bin/python /opt/localsiem/webapp/backend/manage.py doctor   # Debian
su -s /bin/sh localsiem -c "/opt/localsiem/venv/bin/python /opt/localsiem/webapp/backend/manage.py doctor"   # Alpine
```

`[ OK ]` está bien, `[WARN]` funciona con limitaciones, `[FAIL]` hay que corregirlo, `[INFO]` solo se aplica en algunas situaciones. Un módulo que no se puede cargar se muestra primero como `[FAIL] Module <name> not loaded: <reason>`. Un módulo desactivado no tiene doctor: si tiene requisitos (sección 13), el doctor muestra esos requisitos en su lugar, para que sepas si se puede activar.

<a id="soc"></a>
## 5. Conexión con el SOC

Conectar localSIEM con un SOC es opcional. Sin SOC (sin token, o con **Enviar las alertas al SOC** desactivado), localSIEM funciona por su cuenta: guarda cada alerta en la pestaña **Alertas** como «No enviada» y no la envía después, ni siquiera cuando más tarde se configura un SOC: desde entonces solo le llegan las alertas nuevas. Los canales (Telegram) funcionan con SOC o sin él.

El administrador del SOC:

1. Crea un token de ingesta para el cliente (solo se muestra una vez) y te lo da. Configúralo con `--soc-token` o en **Administración › SOC**.
2. Pone como **Dirección del SIEM** del cliente `https://<server>:<port of localSIEM>` (la muestran el instalador y Administración › SOC). El analista responsable de una alerta usa ese enlace para venir a investigar.
3. Te da las IPs de salida del SOC: añádelas a las IPs permitidas (`--allow-from` o Administración › Ajustes) y **abre el puerto en el cortafuegos solo para ellas y para tus administradores**.

localSIEM envía un **latido** cada 5 minutos. Si el SOC no recibe ni alertas ni latidos durante un tiempo (60 minutos por defecto), avisa a su equipo. Las alertas esperan en una cola persistente: un corte de red o un reinicio no pierde ninguna, y volver a enviar una nunca la duplica en el SOC. Si el SOC responde que el cliente ha agotado sus números de alerta, localSIEM deja de enviar, conserva la cola y lo muestra en Administración › SOC.

Cada alerta lleva un nombre de regla estable, una descripción con la consulta exacta para pegarla en la búsqueda de localSIEM, y detalles: vhost, IP del cliente, método, URI (enmascarada), respuesta, user agent, los datos de ModSecurity (motor, acción, fase, puntuación, umbral, reglas, datos coincidentes), el grupo (recuento, primera y última vez, `UNIQUE_ID` de muestra) y el **contexto** de la IP: peticiones y peticiones bloqueadas en la última hora, reglas bloqueadas y la primera vez que se vio.

<a id="signin"></a>
## 6. Inicio de sesión y cuentas

Abre `https://<server>:10443/`: la página de inicio de sesión es solo el formulario, con el logo, el usuario, la contraseña, **Continuar** y, debajo, el idioma y el tema. Las cuentas las crea un administrador; no hay registro abierto. Las contraseñas tienen al menos 8 caracteres. La **verificación en dos pasos** viene desactivada; cuando un administrador la activa (Administración › Ajustes, sección 14) es obligatoria para todas las cuentas: en el siguiente inicio de sesión, escanea el código QR con una aplicación de autenticación (Google Authenticator, Microsoft Authenticator, Aegis, FreeOTP...; aparece como «PYMEHackers localSIEM») y escribe su código; a partir de ahí, cada inicio de sesión pide el código de la aplicación. Tras varios intentos fallidos, el inicio de sesión se bloquea durante unos minutos.

**Acceso directo con un token.** Un administrador puede dar a un analista una URL de acceso, `https://<server>:10443/auth/login/auto?token=...` (Usuarios › Tokens de acceso, sección 14). Al abrirla desde una dirección permitida, la sesión se inicia en el acto, sin contraseña ni segundo factor, y se abre el Resumen del panel de usuario; añade `&next=/user/dashboard/search/?q=...` para abrir otra página del sitio. Si el token no funciona, la página de inicio de sesión indica por qué: token desconocido, caducado o revocado, o la cuenta está desactivada o ya no es de analista. Guarda la URL como una contraseña: quien la tenga puede iniciar sesión con esa cuenta hasta que caduque o se revoque. Cada inicio de sesión, con contraseña o con un token, y cada intento fallido quedan registrados (Inicios de sesión, sección 14).

Tras iniciar sesión llegas al **Resumen** de tu panel (sección 7). Un enlace a una búsqueda (por ejemplo, desde el SOC) abre la página de inicio de sesión si hace falta y después **la misma búsqueda con sus parámetros**.

Roles: **analista** (trabaja en el panel de usuario: resumen, búsqueda, vista en directo, alertas, el estado de los módulos y la cuenta) y **administrador** (trabaja en el panel de administración: lo mismo más la configuración de los módulos y la administración). El idioma (en-GB, en-US, es-AR, es-ES), el tema (el del sistema, claro u oscuro) y el reloj UTC están en la barra de título de todas las páginas de los paneles; la página de inicio de sesión los tiene debajo de **Continuar** y empieza con el último idioma y el último tema elegidos en este navegador (si no se ha elegido ninguno, los del navegador y del sistema). El idioma que se ve al pulsar **Continuar** pasa a ser el idioma de tu cuenta: los paneles lo mantienen, en cualquier navegador, hasta que lo cambies. Las horas siempre están en UTC con el formato nativo `2026/10/29@13:59:59.723`. Los archivos que escribe localSIEM (las exportaciones, `/root/webapp-credentials.txt`, el log del instalador) y las alertas que envía al SOC usan el formato de almacenamiento `2026-10-29@13-59-59.723`, también en UTC.

<a id="dashboards"></a>
## 7. Los dos paneles

Cada rol tiene su propio panel; su dirección indica en cuál estás. La barra lateral tiene el logo arriba, las pestañas (una línea entre cada grupo) y, abajo, **Cerrar sesión**.

| | Panel de administración | Panel de usuario |
|---|---|---|
| Quién | Administradores | Analistas |
| Dirección | `/admin/dashboard/<tab>/` | `/user/dashboard/<tab>/` |
| Pestañas | Resumen, Búsqueda, Directo, Alertas; Módulos (Instalados e Instalables), Usuarios (Cuentas y Tokens de acceso), SOC, Canales (General y Telegram), Ajustes, Auditoría de búsquedas, Inicios de sesión; Cuenta | Resumen, Búsqueda, Directo, Alertas, Módulos (solo el estado), Cuenta |

Cada pestaña tiene su propia dirección (por ejemplo, `/admin/dashboard/logins/`), y `/admin/dashboard/` o `/user/dashboard/` abren el Resumen. Las secciones de una pestaña también tienen la suya: `/admin/dashboard/users/` abre `/admin/dashboard/users/accounts/` y los tokens de acceso están en `/admin/dashboard/users/tokens/`; `/admin/dashboard/modules/` abre `/admin/dashboard/modules/installed/` y los módulos instalables están en `/admin/dashboard/modules/installable/`. Una dirección del otro panel te lleva a la misma pestaña del tuyo: un administrador que abre un enlace a `/user/dashboard/search/?q=...` (el enlace habitual del SOC) obtiene la misma búsqueda en `/admin/dashboard/search/`; un analista que abre una pestaña de administración obtiene el Resumen del panel de usuario.

**Qué ven los analistas.** Todo lo necesario para investigar: el resumen, las búsquedas con sus fichas de la petición, la vista en directo, las alertas y el estado de cada módulo (activado o desactivado, funcionando o no, y sus contadores). No pueden activar ni desactivar módulos, configurarlos ni ver su doctor o sus reglas, ni gestionar los usuarios, los tokens de acceso, la conexión con el SOC, los ajustes, la auditoría de búsquedas o el registro de los inicios de sesión.

<a id="overview"></a>
## 8. Resumen

La primera pestaña de los dos paneles. Se actualiza cada 15 segundos y muestra:

- **Eventos (24 h)**, con cuántos de ellos generaron una alerta; **Bloqueados (24 h)**, lo que ModSecurity ya resolvió (se guarda, sin alerta); **Alertas (24 h)**, con cuántas esperan al SOC; y **Módulos funcionando**, los módulos activados que están «Activado y funcionando» del total de activados (en verde cuando funcionan todos).
- **Actividad de las últimas 24 horas**: eventos por hora; la parte azul de cada barra es lo que bloqueó ModSecurity. Pulsa una hora para abrir la búsqueda de sus eventos.
- **Estado de los módulos**: cada módulo con su estado (sección 13) y lo que está leyendo; «Ver los módulos» abre la pestaña Módulos.
- **Sistema**: si el colector está en marcha (y su versión), desde cuándo, el estado de la conexión con el SOC, el último latido, las alertas que esperan al SOC, el disco libre y el tamaño de la base de datos frente a su máximo.
- **Últimas alertas**: las seis más recientes (severidad, regla, IP, recuento, estado, última vez); «Ver todas las alertas» abre la pestaña Alertas.

<a id="search"></a>
## 9. Búsqueda

La pestaña **Búsqueda** tiene un campo de búsqueda y un rango de tiempo (últimos 15 minutos, última hora, últimas 24 horas, últimos 7 días, últimos 30 días o un rango personalizado en el formato nativo).

| Sintaxis | Significado |
|---|---|
| `word` | Búsqueda de texto completo en el texto original (enmascarado), también decodificado de URL |
| `"exact phrase"` | Frase |
| `field:value` | Campo igual a un valor (los campos de texto no distinguen entre mayúsculas y minúsculas) |
| `field:*part*` | Comodines |
| `status:>=500`, `status:400..499`, `status:4xx` | Comparaciones y rangos en campos numéricos |
| `a b` / `a AND b`, `a OR b`, `NOT a` / `-a`, `( )` | Operadores y paréntesis |

| Grupo | Campos |
|---|---|
| Red | `ip`, `vhost`, `host` |
| Petición | `method`, `uri`, `path`, `query`, `status`, `bytes`, `duration` (microsegundos), `ua`, `referer` |
| Origen | `uid` (UNIQUE_ID), `module`, `source` (`access`/`error`/`audit`) |
| ModSecurity | `rule` (id de CRS, o `localsiem:<rule>`), `category`, `phase`, `score`, `engine` (`on`/`detection-only`) |
| Alertas | `severity`, `action` (`blocked`/`none`), `alert` (código del SOC), `sent` (`yes`/`no`) |
| Calidad | `parse` (`ok`/`partial`/`unparsed`) |

Ejemplos:

- `ip:203.0.113.7` — todo lo de una IP
- `rule:942100` — peticiones que coincidieron con esa regla de CRS
- `status:200 action:none category:sqli` — inyecciones SQL que no se bloquearon y recibieron un 200
- `uri:*wp-login*`
- `"union select"`
- `uid:ZTx1kH8AAQEAAB2gTkAAAAAB` — una petición
- `alert:c00007a0001F` — las peticiones de una alerta del SOC
- `(category:sqli OR category:xss) sent:no -status:404`

Categorías: `sqli`, `xss`, `lfi`, `rfi`, `rce`, `php`, `java`, `fixation`, `generic`, `protocol`, `multipart`, `scanner`, `method`, `data-leakage`, `webshell`, y las de las reglas de localSIEM: `bruteforce`, `enumeration`, `sensitive-file`, `db-error`, más `health-*`.

Un error de sintaxis se muestra debajo del campo con la posición del fallo. Una búsqueda que tarda más que su límite (5 s) te pide que acotes el rango.

La página de resultados muestra:

- **El histograma** en el tiempo; la parte azul de cada barra es lo que bloqueó ModSecurity. Arrastra sobre las barras (o pulsa una) para acotar el rango.
- **Resúmenes** de la consulta: IPs con más peticiones, rutas más pedidas, códigos HTTP y reglas más frecuentes. Pulsa un valor para añadirlo a la consulta.
- **La tabla de resultados** (HORA, ORIGEN, IP, MÉTODO, URI, CÓDIGO, ACCIÓN, REGLAS, ALERTA), con lo más reciente primero, con «Cargar más».
- **Exportar** a CSV o JSON (datos enmascarados, hasta 10 000 filas, con las horas en el formato de almacenamiento `2026-10-29@13-59-59.723`) y **Copiar enlace** (con horas absolutas). El formato del enlace es `/user/dashboard/search/?q=<query>&from=<native time>&to=<native time>` (`/admin/dashboard/search/...` cuando lo copia un administrador); un enlace de cualquiera de los dos paneles funciona para ambos roles.

Todas las búsquedas y exportaciones se registran (quién, qué, cuándo) y los administradores pueden verlas: los logs contienen datos personales.

<a id="card"></a>
## 10. La ficha de la petición y los pivotes

Pulsa una fila para abrir la ficha de la petición: hora, vhost, IP del cliente, método, URI, código, tamaño, duración, user agent, `UNIQUE_ID`, correlación, acción tomada, motor de ModSecurity, fase, puntuación y umbral, categoría, severidad y alertas; y, para cada registro, su contenido analizado: las reglas que coincidieron con su mensaje y sus datos, las cabeceras de la petición y el cuerpo enmascarado, las cabeceras de la respuesta, las líneas de error y la línea original. El módulo de cada registro añade lo que sabe mostrar (el módulo de Apache reconstruye las cabeceras y el cuerpo a partir del registro de auditoría).

Notas de la ficha: un 403 sin ningún rastro de ModSecurity se marca como **dudoso** (no cuenta como bloqueo); **correlación débil** significa que la línea de acceso se juntó con su petición por IP de cliente, método, URI, estado y hora, porque el log de acceso no tiene `UNIQUE_ID`; apareció un **error de base de datos** para la petición.

Pivotes: **Esta IP** (toda su actividad), **±5 min** (la línea de tiempo alrededor de la petición), **Regla …** (cada regla que coincidió), **Esta categoría**, **Este UNIQUE_ID**.

<a id="live"></a>
## 11. Vista en directo

La pestaña **Directo** muestra los eventos nuevos en cuanto el colector los guarda (tras la ventana de correlación de 5 segundos), con los más recientes arriba. El filtro usa la sintaxis de búsqueda. **Pausar** detiene las actualizaciones; al reanudar, continúa desde el evento más reciente.

<a id="alerts"></a>
## 12. Alertas

La pestaña **Alertas** lista las alertas generadas por localSIEM: código del SOC, severidad, regla, IP, vhost, recuento, primera y última vez, y estado:

| Estado | Significado |
|---|---|
| En búfer | Reuniendo la ráfaga (60 s) antes de salir |
| En cola | Esperando al SOC (la red está caída, el SOC no responde) |
| Enviada | Aceptada por el SOC; se muestra su código |
| Rechazada | El SOC rechazó esa alerta; el resto de la cola sigue adelante. Se puede volver a poner en cola desde Administración › SOC. |
| No enviada | No había ningún SOC configurado, o el envío estaba desactivado: la alerta se queda en localSIEM y no se envía nunca (el SOC es opcional, sección 5) |

Pulsa una fila para ver la descripción, la ventana, el `external_id` y la alerta exacta enviada al SOC. **Buscar** abre la búsqueda del grupo.

<a id="modules"></a>
## 13. Módulos

En el panel de administración, la pestaña **Módulos** tiene dos secciones, cada una con su propia dirección: **Instalados** (`/admin/dashboard/modules/installed/`), que se abre por defecto (`/admin/dashboard/modules/` lleva ahí), e **Instalables** (`/admin/dashboard/modules/installable/`), donde se instalan los módulos (más abajo). Los analistas solo tienen la lista de los módulos instalados, sin secciones (`/user/dashboard/modules/`).

**Instalados** lista los módulos instalados, una fila por módulo, a todo lo ancho, con la misma disposición que la cabecera de la página del módulo: arriba, el nombre, el id y la versión y, debajo, su **estado**, un resumen, los motivos de su estado y, si está activado, sus contadores: fuentes en lectura, líneas de la última hora, último dato, eventos y peticiones bloqueadas de las últimas 24 horas y el resultado de su doctor. Los administradores ven además el interruptor a la derecha del nombre y, al final de la fila, sus botones. La página se actualiza cada 10 segundos. Si no hay ningún módulo instalado, muestra «Instala módulos desde la pestaña Instalables.» (a los analistas: «No hay módulos instalados. Los instala un administrador en Módulos › Instalables.»).

| Estado | Significado |
|---|---|
| Activado y funcionando | Activado, cargado por el colector y leyendo sus fuentes. Los avisos del doctor se muestran como notas y no lo cambian. |
| Activado, con avisos | Activado, pero sin fuentes, con una fuente que todavía no existe o instalado después de que arrancara el colector (reinicia el servicio `localsiem`). |
| Error | No se carga (se muestra el motivo), su doctor informa de un error o una fuente no se puede leer (permisos del usuario `localsiem`, sección 3.7). |
| Aplicando el cambio… | Se acaba de activar o desactivar; el colector lo está aplicando (unos segundos). |
| Desactivado | Desactivado: localSIEM no lee sus logs ni envía sus alertas. Lo que ya está guardado se conserva. Con el motivo «A este servidor le falta lo que necesita: …», se instaló sin sus requisitos y todavía no se puede activar (ver Requisitos y Reconfigurar, más abajo). |
| Desconocido | El colector no está en marcha (servicio `localsiem`): nadie está leyendo nada. |

Los **analistas** solo ven esta lista. Los **administradores** tienen además, en cada fila:

- **El interruptor** de cada módulo, para activarlo o desactivarlo. Desactivarlo pide confirmación. El cambio se aplica en el acto, sin reiniciar nada. Mientras al servidor le falta lo que necesita un módulo, su interruptor está bloqueado («Desactivado: faltan requisitos»).
- **Configurar**, que abre la página del módulo (`/admin/dashboard/modules/installed/<name>/`; la dirección anterior, `/admin/dashboard/modules/<name>/`, lleva ahí):
  - la cabecera con el estado, la carpeta en la que está instalado el módulo, el interruptor, «Volver a los módulos instalados» (vuelve a Instalados) y «Descubrir de nuevo y pasar el doctor»; en un módulo con requisitos, también el botón «Reconfigurar» y, mientras el módulo está desactivado o falta alguno, sus **Requisitos** (más abajo);
  - **Ajustes**: el formulario de los ajustes propios del módulo; «Guardar los ajustes» los aplica en el acto;
  - **Fuentes**: los logs que lee (tipo, ruta, vhost, líneas y líneas sin analizar de la última hora, últimos datos, estado) y, debajo, los logs que encontró pero no lee, con el motivo;
  - **Doctor**: sus comprobaciones de requisitos, con el fragmento que corrige cada uno que falta y un botón «Copiar»; en un módulo con opción de preparación, también el comando para root que la aplica (`manage.py setup-modules --configure-apache` para el módulo de Apache);
  - **Reglas**: cada regla del módulo con su interruptor («Activa»), severidad, umbral y ventana (el umbral y la ventana solo en las reglas de umbral y de secuencia); «Guardar las reglas» las aplica en el acto.
- **Actualizar**, cuando el repositorio `localSIEM-modules` tiene una versión más nueva del módulo. Cada vez que abres Instalados, localSIEM consulta el repositorio: mientras tanto muestra «Consultando el repositorio en busca de versiones más nuevas…» y, si la consulta falla, «No se ha podido consultar el repositorio en busca de versiones más nuevas: <error>», y la lista funciona como siempre. Para no descargar el repositorio en cada visita, el navegador reutiliza su respuesta durante 10 minutos; «Consultar el repositorio», en Instalables, siempre lo vuelve a descargar, e instalar, actualizar o desinstalar un módulo descarta la respuesta guardada. La recarga de la lista cada 10 segundos nunca lo descarga. Un módulo con una versión más nueva muestra en su fila el aviso «El repositorio tiene la versión X (la instalada es la Y).» con el botón **Actualizar**. Si esa versión necesita un localSIEM más nuevo, el aviso no tiene botón y lo indica: «El repositorio tiene la versión X, pero necesita localSIEM Z o posterior: actualiza localSIEM para poder instalarla.» **Actualizar** pide confirmación («Actualizar el módulo»): localSIEM descarga la versión nueva del repositorio, la cambia por la instalada y reinicia el colector; sus ajustes se conservan, y el módulo sigue activado o desactivado como estaba. Mientras tanto, el botón dice «Actualizando…»; al terminar, un mensaje indica «<módulo> actualizado a la versión X.» Solo se abre un cuadro de diálogo, «<módulo> actualizado», cuando hay algo más que hacer: si la versión nueva lee otros logs o tiene otra opción de preparación, muestra el comando para root (`manage.py setup-modules`, sección 2, con «Copiar» y, en un módulo con opción de preparación, la indicación de añadirla al comando); si el colector no ha respondido, pide reiniciar el servicio `localsiem`.
- **Desinstalar**, en la fila de cada módulo instalado (también en la de uno que no se carga) y en su página. Tras confirmarlo, localSIEM borra `/opt/localsiem/modules/<name>/` y reinicia el colector sin él: deja de leer sus logs y de enviar sus alertas. En los eventos y las alertas ya guardados se puede seguir buscando, y sus ajustes (y los cambios de sus reglas) se quedan en `settings.json`, así que vuelven si lo instalas de nuevo. El acceso de lectura que root dio a `localsiem` sobre sus logs no se retira; si ningún otro módulo lee esa carpeta, puedes quitarlo a mano, por ejemplo con `setfacl -R -x g:localsiem /var/log/apache2` y `setfacl -d -x g:localsiem /var/log/apache2`.

**Instalables** (solo para administradores) tiene la tarjeta «Módulos instalables»: los módulos del repositorio `localSIEM-modules` (por defecto, `https://github.com/PYMEHackers/localSIEM-modules`, rama `main`; las opciones del instalador `--modules-repository` y `--modules-ref` lo cambian) que todavía no están instalados en este servidor. «Consultar el repositorio» lo descarga y lista esos módulos, cada uno con su nombre, id, versión y resumen y su botón o nota:

| Botón o nota | Significado |
|---|---|
| Instalar | Instala el módulo |
| Necesita localSIEM X o posterior | No se puede instalar: actualiza primero localSIEM |
| El módulo del repositorio no es válido | No se puede instalar |

Si todos los módulos del repositorio ya están instalados, lo indica («Todos los módulos del repositorio ya están instalados.»). Los módulos ya instalados nunca aparecen en esta lista: se actualizan en Instalados (**Actualizar**, más arriba). La web no reinstala un módulo ni instala una versión anterior: para reinstalarlo, desinstálalo y vuelve a instalarlo aquí (sus ajustes se conservan).

Esta lista es la única forma de instalar módulos. localSIEM descarga el módulo, comprueba su `module.json`, copia su carpeta (`mod-<name>/` en el repositorio) en `/opt/localsiem/modules/<name>/` (sin su carpeta `tests/`; un módulo que se vuelve a instalar recupera los ajustes que tenía) y reinicia el colector, que lo carga en unos segundos. El módulo sale de la lista y un cuadro de diálogo, «<módulo> instalado», indica qué viene después:

- Permitir que `localsiem` lea los logs del módulo requiere root, así que el cuadro de diálogo muestra **el comando que hay que ejecutar como root** en el servidor, con un botón «Copiar»: `manage.py setup-modules` (sección 2), que da el acceso de lectura y reinicia localSIEM. En un módulo con opción de preparación, sugiere además añadir esa opción al comando (`--configure-apache` para el módulo de Apache) para aplicar también sus requisitos. Hasta que se ejecute el comando, el módulo puede mostrar «Error» porque no se pueden leer sus logs.
- Si, en su primera instalación, al servidor le falta lo que necesita el módulo, el módulo se instala desactivado y el cuadro de diálogo lista lo que falta en lugar del comando, con la indicación de abrir el módulo en Instalados (**Configurar**) y pulsar **Reconfigurar** cuando ya esté (más abajo).

El cuadro de diálogo tiene dos botones: «Cerrar» y «Ver los módulos instalados», que abre Instalados. Para esta lista y para la consulta de versiones más nuevas de Instalados, el servidor tiene que poder llegar a GitHub (HTTPS).

**Requisitos y Reconfigurar.** Instalar un módulo nunca instala el software que vigila. Un módulo puede declarar lo que el servidor debe tener antes de poder activarlo: el módulo de Apache necesita Apache (su configuración: `apache2.conf`, `httpd.conf` o el archivo del ajuste **Archivo de configuración de Apache**) y ModSecurity 2 cargado (`mod_security2`; ModSecurity 3 no cuenta). Si faltan en su primera instalación, el módulo se instala **desactivado** («Desactivado», con el motivo «A este servidor le falta lo que necesita: …») y su interruptor queda **bloqueado**. Su página lista sus requisitos como el doctor (título, detalle y el comando que instala lo que falta, con «Copiar»), también mientras está desactivado. Cuando hayas instalado lo que falta (y, si Apache está en un sitio no estándar, hayas indicado el **Archivo de configuración de Apache** y guardado los ajustes), pulsa **Reconfigurar**: localSIEM lo vuelve a buscar con los ajustes guardados.

- Si lo encuentra todo, desbloquea el interruptor pero no activa el módulo: lo activas tú con su interruptor. También muestra el comando para root de la sección 2, con la opción de preparación como sugerencia (`--configure-apache`): ejecútalo, porque los logs creados después de instalar el módulo (`/var/log/apache2`) solo se pueden leer con el acceso de lectura que da root.
- Si todavía falta algo, los requisitos lo vuelven a mostrar.
- Si el módulo ya está activado, Reconfigurar además vuelve a descubrir sus fuentes y ejecuta su doctor.

Un módulo activado que después pierde sus requisitos (alguien desinstala ModSecurity) sigue activado: lo notifican su doctor y el aviso de salud «ModSecurity ya no está cargado» (sección 15), y desactivarlo silenciaría precisamente ese aviso. El colector comprueba los requisitos al arrancar y cuando cambian sus ajustes, nunca de forma periódica; `manage.py modules` y `manage.py doctor` también los muestran (sección 17).

**Desactivar y volver a activar el módulo de Apache.** En **Módulos › Instalados**, usa el interruptor de «Apache + ModSecurity» y confirma. Mientras está desactivado, localSIEM no lee los logs de Apache, no ejecuta su doctor ni sus reglas y no envía ninguna alerta suya; en los eventos ya guardados se puede seguir buscando. Vuelve a activar el interruptor para reanudarlo (solo es posible mientras Apache y ModSecurity estén presentes): el colector sigue desde la posición en la que se detuvo en cada log (siguiendo las rotaciones que haya habido mientras tanto), así que también lee lo que Apache escribió mientras el módulo estaba desactivado y envía las alertas que eso merezca.

**Ajustes del módulo de Apache** (Módulos › Instalados › Apache + ModSecurity › Configurar):

| Ajuste | Uso |
|---|---|
| Sólo las fuentes de abajo | No descubrir los logs a partir de la configuración de Apache: leer solo las fuentes añadidas a mano |
| Fuentes añadidas a mano | Logs que se leen además de los descubiertos (ver más abajo) |
| Archivo de configuración de Apache | Vacío: se encuentra automáticamente (`/etc/apache2/apache2.conf` en Debian, `/etc/apache2/httpd.conf` en Alpine). Reconfigurar también busca Apache ahí |
| Intervalo de descubrimiento (segundos) | Cada cuánto se vuelve a leer la configuración de Apache para encontrar vhosts y logs nuevos (3600 por defecto) |
| Umbral de bloqueo de ModSecurity | 0: se lee de la configuración de CRS (`tx.inbound_anomaly_score_threshold`), o 5 si no está ahí |
| Días de aprendizaje de archivos PHP nuevos | Durante los primeros días, un archivo PHP que no se había visto nunca no se notifica como nuevo (regla `apache-webshell`; 3 por defecto) |

**Añadir un log a mano.** En **Fuentes añadidas a mano**, pulsa «Añadir fuente» y rellena **Tipo** (access.log, error.log o «Registro de auditoría de ModSecurity»), **Ruta** (absoluta) y, si hace falta, **Vhost**, **LogFormat** (para un log de acceso con un formato propio), **Tipo de registro de auditoría** («Serie (un único archivo)» o «Concurrente (un archivo por petición)») y **Carpeta de la auditoría** (para un log de auditoría concurrente). «Quitar» borra una fuente. Pulsa «Guardar los ajustes»: el colector vuelve a descubrir las fuentes en el acto y el log nuevo aparece en **Fuentes**. Si aparece como no legible, da a `localsiem` acceso de lectura a su carpeta (sección 3.7).

**Del módulo `apache` a `apache2`.** Hasta localSIEM 2.1, el módulo de Apache se llamaba `apache`; ahora es `apache2` (carpeta `mod-apache2/` en el repositorio, instalado en `/opt/localsiem/modules/apache2/`, página `/admin/dashboard/modules/installed/apache2/`). En un servidor que tenía `apache`, instalar `apache2` deja los dos cargados: el antiguo se queda con los logs de Apache (los dos encuentran las mismas fuentes), `apache2` no muestra ninguna fuente hasta que se desinstala el antiguo, y los ajustes de `apache` no se trasladan por sí solos. Para migrar:

1. Apunta los ajustes que cambiaste en la página del módulo `apache` (Configurar): fuentes añadidas a mano, archivo de configuración de Apache, intervalo de descubrimiento, umbral de bloqueo, días de aprendizaje.
2. Instala `apache2` en Módulos › Instalables.
3. Desinstala el módulo `apache`: **Desinstalar**, en su fila de Módulos › Instalados o en su página. El colector se reinicia y, desde entonces, `apache2` lee los logs de Apache.
4. Abre la página de `apache2`, vuelve a introducir esos ajustes y guárdalos. (En su lugar, como root, puedes copiar en `/opt/localsiem/config/settings.json`, dentro de `"modules"`, lo que hay bajo `"apache"` en `"apache2"`, y después reiniciar localSIEM.)

Las reglas conservan sus ids (`apache-bruteforce`…) y sus modificaciones, y se conservan las posiciones leídas en cada log y la memoria de los avisos de salud: `apache2` sigue donde se detuvo `apache`, sin leer nada dos veces. Los eventos que guardó el módulo `apache` se pueden seguir buscando (`module:apache`).

<a id="administration"></a>
## 14. Administración

Estas pestañas solo están en el panel de administración:

- **Módulos** (sección 13), en dos secciones: **Instalados** (`/admin/dashboard/modules/installed/`), la lista con el interruptor de cada módulo, **Configurar** (requisitos y Reconfigurar, ajustes, fuentes, doctor y reglas del módulo), **Actualizar** (cuando el repositorio tiene una versión más nueva) y **Desinstalar**; e **Instalables** (`/admin/dashboard/modules/installable/`), los módulos del repositorio que todavía no están instalados, con **Instalar**. Los módulos solo se instalan, actualizan y desinstalan ahí.
- **Usuarios › Cuentas** (`/admin/dashboard/users/accounts/`): crear cuentas (se genera una contraseña que se muestra una sola vez; hay que cambiarla en el primer inicio de sesión), restablecer la contraseña o la verificación en dos pasos, activar o desactivar, cambiar el rol, borrar. Siempre hay al menos un administrador activo.
- **Usuarios › Tokens de acceso** (`/admin/dashboard/users/tokens/`): **Crear token** para una cuenta de analista activa (los administradores siempre inician sesión con su contraseña, y con el segundo factor cuando la verificación en dos pasos está activada), con una etiqueta opcional y una validez de 7, 30, 90 (por defecto), 180 o 365 días. La URL de acceso, `https://<server>:10443/auth/login/auto?token=...`, se muestra **una sola vez**, con un botón «Copiar»: dásela al analista (sección 6). La lista muestra la cuenta y la etiqueta de cada token, sus últimos 4 caracteres, su estado (Activo, Caducado, Revocado, o No utilizable cuando la cuenta está desactivada o ya no es de analista), cuándo y quién lo creó, cuándo caduca y su último uso (hora e IP). **Revocar** hace que deje de funcionar en el acto; las sesiones que ya abrió terminan cuando caducan. Una sesión abierta con un token no pide ni el segundo factor ni el cambio de contraseña. Los intentos fallidos cuentan para el bloqueo temporal del inicio de sesión.
- **SOC**: URL, token (nunca se muestra entero), fichero de CA opcional, **Probar la conexión** (envía un latido), estado del envío, último latido, último error, cola (en espera, enviadas, rechazadas) y **Enviar la cola ahora**. También la Dirección del SIEM que hay que dar al SOC. El SOC es opcional (sección 5).
- **Canales** (`/admin/dashboard/channels/`), en dos secciones, **General** (se abre por defecto) y **Telegram**: los mensajes que localSIEM te envía, además de las alertas que entrega al SOC (más abajo).
- **Ajustes**: retención, disco máximo, IPs permitidas (tu propia dirección debe estar en la lista), verificación en dos pasos (desactivada por defecto; al activarla pasa a ser obligatoria para todas las cuentas y se cierra en el acto la sesión de las cuentas que aún no la tienen configurada, incluida la tuya, que la configuran en su siguiente inicio de sesión; al desactivarla se conservan las aplicaciones de autenticación ya configuradas para cuando se vuelva a activar), tiempo máximo de búsqueda, límite de exportación, ventana y búfer de agrupación, ventana de correlación y severidad por debajo del umbral. Los cambios se aplican en el acto. Las reglas ya no están aquí: se configuran en cada módulo (Módulos › Instalados › Configurar).
- **Auditoría de búsquedas**: quién buscó qué y cuándo.
- **Inicios de sesión** (`/admin/dashboard/logins/`): cada inicio de sesión en localSIEM y cada intento fallido, con los más recientes primero: hora, cuenta, método (Contraseña, Contraseña y segundo factor, o Token de acceso), resultado (Correcto o Fallido), el motivo de un fallo (usuario o contraseña incorrectos, código del segundo factor incorrecto, bloqueado tras varios fallos, el inicio de sesión tardó demasiado, token desconocido, caducado o revocado, cuenta desactivada, la cuenta no es de analista), IP y navegador. Filtra por resultado; **Cargar más** carga los anteriores. Se conservan tanto como las alertas (365 días por defecto).

El estado del colector, del disco y de la base de datos está en el Resumen (sección 8).

### Canales: mensajes para ti (Telegram)

Además de entregar todas las alertas al SOC, localSIEM puede enviarte las más importantes por un **canal**. Por ahora el canal es **Telegram**.

**General** (`/admin/dashboard/channels/general/`):

- **Enviar mensajes por los canales**: activa o desactiva todos los canales a la vez.
- **Severidad mínima**: se envían las alertas de esta severidad o superior (por defecto: Alta).
- **Idioma de los mensajes**: en-GB, en-US, es-AR o es-ES (por defecto en-US). La regla y la descripción de la alerta se mantienen tal como las escribió localSIEM.
- Una tabla con cada canal: su estado (Desactivado, Sin configurar, Funcionando o Error), los mensajes enviados, el último y el último error.

**Telegram** (`/admin/dashboard/channels/telegram/`):

1. En Telegram, abre **@BotFather**, envía `/newbot` y sigue sus pasos. Te da el **token del bot** (`123456789:AA...`; el número que va antes de los dos puntos es el id del bot).
2. Abre el chat con tu bot y pulsa **Iniciar** (o añade el bot al grupo, o como administrador del canal, que vaya a recibir los mensajes): un bot no puede escribir a quien no le ha hablado antes.
3. Averigua el **id del chat**: envía cualquier mensaje al bot y abre `https://api.telegram.org/bot<token>/getUpdates` en un navegador; el id es el número que va después de `"chat":{"id":`. El id de un grupo empieza por `-` y el de un canal por `-100`; un canal o grupo público también se puede indicar como `@usuario`.
4. Escribe el token y el id del chat, marca **Enviar los mensajes por Telegram** y pulsa **Guardar y enviar un mensaje de prueba**. Si Telegram lo rechaza, el aviso dice por qué (por ejemplo `Unauthorized`: token incorrecto; `Bad Request: chat not found`: id del chat incorrecto, o nadie ha pulsado Iniciar).

El token se guarda en el servidor, en `/opt/localsiem/config/telegram-bot-token` (modo 600), y nunca se muestra entero; **Quitar el token** lo borra y desactiva Telegram. El servidor necesita llegar a `https://api.telegram.org` (puerto 443 de salida).

Cada mensaje indica la severidad, la regla, la descripción, el módulo, el número de eventos, la primera y la última vez (UTC) y la búsqueda que los muestra. localSIEM envía como máximo un mensaje por segundo. Si Telegram no responde, lo reintenta unas cuantas veces; si Telegram rechaza un mensaje (token incorrecto, chat desconocido, bot bloqueado), lo descarta y muestra el error. Los mensajes en espera se pierden si localSIEM se reinicia: los canales son un aviso para ti, y el SOC sigue recibiendo todas las alertas.

<a id="health"></a>
## 15. Avisos de salud y qué hacer

También van al SOC (reglas `localSIEM health: …`), agrupados para que no se repitan:

| Aviso | Severidad | Qué hacer |
|---|---|---|
| Log truncado, desaparecido o sustituido fuera de una rotación | alta | Alguien puede estar borrando rastros. Comprueba quién tuvo acceso al servidor en ese momento y sus otros logs. |
| ModSecurity ya no está cargado, o el motor se ha puesto en Off | alta | Si nadie lo hizo a propósito, se ha desactivado la protección: revisa la configuración de Apache y sus cambios recientes. |
| Fuente de log no legible | media | Normalmente son permisos tras una rotación: vuelve a ejecutar como root el comando de la sección 2 (`manage.py setup-modules`) o da a `localsiem` acceso de lectura (sección 3.7). |
| Fuente de log en silencio durante mucho tiempo (24 h) | media | Comprueba que Apache sigue escribiendo ese archivo (cambios en la configuración de los logs, disco lleno). |
| Falta la IP real del cliente | media | Casi todas las peticiones vienen de una única dirección privada: la web está detrás de un proxy; configura `mod_remoteip`. |
| Muchas líneas sin analizar (más del 5 %) | baja | El formato del log ha cambiado: mira el doctor del módulo (Módulos › Instalados › Configurar) y, si hace falta, usa `localsiem_combined`. |
| Poco disco libre, o retención recortada por falta de espacio | media | Libera espacio o sube el tamaño máximo en disco. Mientras tanto, localSIEM guarda menos detalle. |

<a id="retention"></a>
## 16. Retención y disco

Los eventos se conservan 90 días y las alertas, 365 días. La base de datos nunca crece más allá de su máximo (por defecto: lo menor entre el 15 % del disco y 10 GB): los eventos más antiguos se borran primero, en lotes pequeños, y el espacio vuelve al disco. Con poco disco libre, localSIEM deja de guardar el detalle voluminoso (cabeceras y cuerpos de los registros de auditoría); casi sin disco libre, solo guarda los eventos que forman parte de una alerta, y avisa al SOC. Cambia los valores con `--retention-days` y `--max-disk` (por ejemplo, `--max-disk 5G`) o en Administración › Ajustes.

<a id="cli"></a>
## 17. Línea de comandos

Como root, `/opt/localsiem/venv/bin/python /opt/localsiem/webapp/backend/manage.py`:

| Comando | Uso |
|---|---|
| `list-users` | Cuentas y su verificación en dos pasos |
| `create-user NAME --role admin\|analyst --credentials /root/webapp-credentials.txt` | Cuenta nueva con una contraseña generada |
| `reset-password NAME --credentials /root/webapp-credentials.txt` | Contraseña nueva (hay que cambiarla en el siguiente inicio de sesión) |
| `reset-mfa NAME` | La verificación en dos pasos se vuelve a configurar en el siguiente inicio de sesión |
| `doctor` (`--json`) | Requisitos y fuentes de cada módulo activado y, en un módulo desactivado que tiene requisitos, lo que necesita antes de poder activarlo (ejecútalo como `localsiem`, sección 4) |
| `modules` | Módulos instalados: nombre, versión, activado, desactivado o sin cargar, carpeta, y debajo de un módulo los requisitos que le faltan al servidor para él; y los módulos que no se pueden cargar, con el motivo |
| `read-paths` | Carpetas que leen los módulos instalados (`setup-modules` y el instalador dan a `localsiem` acceso de lectura a ellas) |
| `soc-test` | Envía un latido al SOC |
| `configure-apache` | Muestra el archivo que escribiría `--configure-apache` (necesita el módulo `apache2`) |
| `setup-modules [OPTION...]` | Como root, el comando que muestra la web después de instalar un módulo, después de una actualización que cambia los logs que lee el módulo o su opción de preparación, y con Reconfigurar: acceso de lectura para `localsiem` a las carpetas de los módulos instalados (ACL, también para las siguientes rotaciones; el grupo `adm` en Debian), las opciones de preparación indicadas (`setup-modules --configure-apache`), un reinicio de localSIEM y el doctor como `localsiem`. Con `--no-restart` (lo que usa el instalador) solo da el acceso de lectura y aplica las opciones. |
| `apply-setup -- OPTION` | Aplica solo la opción de preparación de un módulo instalado (`apply-setup -- --configure-apache`), como root, sin reiniciar nada |

Los módulos solo se instalan, actualizan y desinstalan desde la web (sección 13): no hay ningún comando para ello.

Servicios: `systemctl restart localsiem localsiem-web` (Debian) o `rc-service localsiem restart; rc-service localsiem-web restart` (Alpine); reinicia los dos después de copiar o borrar un módulo a mano en `/opt/localsiem/modules/` (la web lo hace sola cuando instala, actualiza o desinstala uno). Logs: `journalctl -u localsiem -u localsiem-web` (Debian) o `/opt/localsiem/log/` (Alpine); al arrancar, el colector escribe en el log la línea `Modules: ...` con cada módulo, su versión y si está activado o desactivado, y `Module <name>: requirements missing: ...` para un módulo al que le faltan sus requisitos.
