# localSIEM

Este README también está disponible en:\
[en-GB](README.en-GB.md), [en-US](../README.md), [es-AR](README.es-AR.md), es-ES

localSIEM es un SIEM ligero para el servidor de una pequeña empresa. Se ejecuta en el mismo servidor Debian o Alpine que protege, junto a su web de Apache, y solo vigila los logs de ese servidor: nunca recibe logs de otras máquinas. En ese servidor, localSIEM:

- lee los logs de acceso y de errores de Apache y el log de auditoría de **ModSecurity**, junta los tres registros de cada petición y permite buscar en ellos;
- guarda lo que ya está resuelto (una petición que ModSecurity bloqueó antes de que llegara a la aplicación) y envía al **SOC de PYMEHackers** lo que todavía nadie ha resuelto, agrupado para que un escáner nunca inunde a los analistas;
- también puede enviarte las alertas más importantes por **Telegram** (la pestaña Canales), con la severidad mínima y el idioma que elijas;
- da al analista del SOC una **herramienta de búsqueda** (un campo de búsqueda y un rango de tiempo) para investigar esas alertas;
- nunca deja que las contraseñas, las cookies, los tokens ni los cuerpos de las peticiones salgan del servidor;
- usa poca memoria (unos 100 MB en uso normal y unos 200 MB en los picos) y nunca llena el disco.

**Modular.** localSIEM es un núcleo genérico (almacenamiento, búsqueda, reglas, agrupación, envío al SOC, salud) más **módulos**, uno por cada servicio del servidor. El instalador de localSIEM instala solo el núcleo; los módulos, como el de Apache + ModSecurity (`apache2`), viven en el repositorio [localSIEM-modules](https://github.com/PYMEHackers/localSIEM-modules) y se instalan, actualizan y desinstalan solo desde la web de localSIEM. Instalar un módulo nunca instala el software que vigila: si al servidor le falta (Apache y ModSecurity, en el caso de `apache2`), el módulo se instala desactivado y, cuando el servidor ya lo tiene, la web reconfigura el módulo para que lo encuentre. Los módulos se pueden activar, desactivar y configurar desde la web sin reiniciar nada.

**Dos paneles.** Los administradores trabajan en `/admin/dashboard/` (resumen, búsqueda, vista en directo, alertas, módulos, usuarios y tokens de acceso, SOC, canales (Telegram), ajustes, auditoría de búsquedas, inicios de sesión, cuenta); los analistas trabajan en `/user/dashboard/` (resumen, búsqueda, vista en directo, alertas, el estado de los módulos, cuenta). Un administrador puede dar a un analista una URL de acceso, `https://<server>:10443/auth/login/auto?token=...`, que abre su panel sin contraseña; cada inicio de sesión queda registrado.

[Manual de uso](MANUAL.es-ES.md) · [Referencia técnica](CODE.es-ES.md)

## Requisitos

- Debian 13 (systemd) o Alpine Linux 3.24 o posterior (OpenRC), con Python 3.13 o posterior. La instalación se ejecuta como root (no hace falta `sudo`).
- Para el módulo de Apache (`apache2`): Apache con **ModSecurity 2 (mod_security2) y el OWASP Core Rule Set** ya activos. En Debian: `apt-get install libapache2-mod-security2 modsecurity-crs`. Alpine no tiene paquete de ModSecurity para Apache; hay que compilarlo desde el código fuente. Ni localSIEM ni el módulo los instalan: sin ellos, el módulo se instala desactivado y su página en la web lista lo que falta; cuando estén instalados, **Reconfigurar** los encuentra y podrás activar el módulo.
- El puerto TCP 10443 libre: la web de localSIEM siempre escucha en él, con HTTPS (un certificado autofirmado si no hay otro). localSIEM nunca usa los puertos 80 ni 443 y nunca toca la web del servidor.
- Opcional: un token de ingesta del SOC para este cliente (lo crea un administrador del SOC). Sin SOC, localSIEM funciona por su cuenta y guarda sus alertas.

El instalador instala lo demás que necesita (el `venv` de Python, OpenSSL, las herramientas de ACL, logrotate...) cuando falta. En Alpine, instala primero Bash y curl (`apk add bash curl`): el instalador es un script de Bash.

## Instalar o actualizar

**1. El núcleo.** Directamente desde GitHub, como root, en el servidor:

```bash
# Debian
curl -fsSL -H 'Accept: application/vnd.github.raw+json' https://api.github.com/repos/PYMEHackers/localSIEM/contents/deploy/install-update-reinstall-debian.sh | bash -s -- --install --allow-from 203.0.113.10,198.51.100.0/24 --soc-token TOKEN
# Alpine
curl -fsSL -H 'Accept: application/vnd.github.raw+json' https://api.github.com/repos/PYMEHackers/localSIEM/contents/deploy/install-update-reinstall-alpine.sh | bash -s -- --install --allow-from 203.0.113.10,198.51.100.0/24 --soc-token TOKEN
```

- `--allow-from`: IPs y redes a las que se permite abrir la web de localSIEM: las IPs de salida del SOC y las de tus administradores. Sin esta opción, la web queda abierta a cualquier dirección y el instalador lo advierte.
- `--soc-token`: el token de ingesta, opcional. También se puede configurar más tarde en Administración › SOC; al SOC solo se le envían las alertas posteriores.

El instalador siempre necesita una acción, y sin ella se detiene: `--install` (un servidor sin localSIEM; se detiene si encuentra uno), `--update` (actualiza el localSIEM instalado y conserva sus datos, cuentas, ajustes, módulos y opciones), `--reinstall` (borra el localSIEM instalado con todos sus datos y lo vuelve a instalar desde cero; antes pide confirmación, y hay que volver a dar las opciones) o `--uninstall` (borra localSIEM y todos sus datos del servidor; antes pide confirmación).

El instalador descarga la rama `main` de este repositorio (`--ref TAG` para una etiqueta u otra rama). Si se ejecuta desde una copia del proyecto (`bash deploy/install-update-reinstall-debian.sh --install`), instala esa copia. Otras opciones: `--domain`, `--certificate` y `--private-key`, `--soc-url`, `--retention-days`, `--max-disk`, `--modules-repository` y `--modules-ref` (desde dónde instala y actualiza módulos la web), `--enable-mfa` (verificación en dos pasos obligatoria para todas las cuentas; desactivada por defecto). Ejecuta el instalador con `--help` para ver la lista completa.

**2. Los módulos.** El instalador de localSIEM no instala ningún módulo: deja localSIEM preparado para ellos. Los módulos se instalan **solo desde la web**: como administrador, abre **Módulos › Instalables**, pulsa **Consultar el repositorio** (lista los módulos que todavía no están instalados) y después **Instalar** en el módulo; localSIEM lo descarga de [localSIEM-modules](https://github.com/PYMEHackers/localSIEM-modules). Leer los logs de un módulo requiere root, así que a continuación la web muestra, en un cuadro de diálogo, el comando que hay que ejecutar como root en el servidor:

```bash
/opt/localsiem/venv/bin/python /opt/localsiem/webapp/backend/manage.py setup-modules
```

Da al usuario `localsiem` acceso de lectura a los logs de los módulos instalados, también a los archivos de las siguientes rotaciones, y reinicia localSIEM. Añádele `--configure-apache` para que el módulo de Apache aplique sus requisitos de Apache (un archivo propio, que se deshace si falla `configtest`). Si al servidor le falta lo que necesita un módulo (Apache o ModSecurity, en el caso del módulo de Apache), el módulo se instala desactivado y la web indica qué falta: instálalo, pulsa **Reconfigurar** en la página del módulo (Módulos › Instalados › Configurar) y, cuando lo encuentre, activa el módulo y ejecuta el comando que muestra. Cuando el repositorio tiene una versión más nueva de un módulo instalado, su fila de **Módulos › Instalados** lo indica y ofrece **Actualizar**: localSIEM descarga la versión nueva y la cambia por la instalada, conserva sus ajustes y deja el módulo activado o desactivado como estaba (el comando para root solo vuelve a hacer falta cuando la versión nueva lee otros logs o tiene otra opción de preparación, y entonces la web lo muestra). Para quitar un módulo, pulsa **Desinstalar** en su fila de **Módulos › Instalados** o en su página. En los servidores que tenían el módulo anterior, `apache`, el [manual de uso](MANUAL.es-ES.md#modules) explica cómo pasar a `apache2`.

Para actualizar, ejecuta el mismo comando con `--update` en lugar de `--install` (las opciones se pueden omitir); se puede ejecutar todas las veces que haga falta. Recuerda sus opciones en `/opt/localsiem/config/install.env` y conserva los módulos que ya estaban instalados, y su acceso de lectura. Escribe su log en `/root/webapp-install.log` y las contraseñas generadas en `/root/webapp-credentials.txt`, ambos con modo 600. Al terminar, ejecuta el doctor de cada módulo activado y muestra la **Dirección del SIEM** que hay que dar al SOC (`https://server:10443`).

## Ejecutar

localSIEM se ejecuta como dos servicios del usuario de sistema `localsiem`:

```bash
# Debian
systemctl status localsiem localsiem-web
# Alpine
rc-service localsiem status; rc-service localsiem-web status
```

Abre `https://<server>:10443/` desde una dirección permitida e inicia sesión como `admin` con la contraseña de `/root/webapp-credentials.txt`. Se te pedirá que elijas una contraseña nueva. La verificación en dos pasos viene desactivada: un administrador puede hacerla obligatoria para todas las cuentas en Administración › Ajustes, y entonces cada cuenta la configura con una aplicación de autenticación (aparece como «PYMEHackers localSIEM»). Se abre el **Resumen** de tu panel; **Módulos** muestra si cada módulo está activado y funcionando.

## Archivos en el servidor

| Ruta | Contenido |
|---|---|
| `/opt/localsiem/webapp/` | Código del núcleo |
| `/opt/localsiem/modules/` | Módulos instalados, una carpeta por módulo (`apache2/`), que instala la web desde `localSIEM-modules` |
| `/opt/localsiem/venv/` | Dependencias de Python (separadas de las del sistema) |
| `/opt/localsiem/config/` | Ajustes, token del SOC, secretos (modo 600) |
| `/opt/localsiem/db/` | Bases de datos |
| `/opt/localsiem/certificates/` | Certificado de la web |
| `/opt/localsiem/log/`, `/opt/localsiem/run/` | Logs (Alpine) y archivos de ejecución |

El [manual de uso](MANUAL.es-ES.md) explica los dos paneles, los módulos, los requisitos de Apache, la conexión con el SOC, qué va al SOC y qué se queda, la sintaxis de búsqueda y los avisos de salud.
