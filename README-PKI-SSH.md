# PKI y SSH

Parte 2 · Anna Lizbeth Barajas Sandoval 222835 - Requerimientos 3 y 4 + Pruebas de 9

Este documento detalla la Autoridad Certificadora del proyecto, la cadena de confianza, los certificados de prueba y el acceso administrativo mediante SSH, incluyendo su registro de eventos.

## PKI

La organización tiene su propia Autoridad Certificadora (CA), creada con OpenSSL. Con ella se emite el certificado con el que el servidor TLS demuestra su identidad. El cliente no confía en un certificado por el simple hecho de recibirlo: solo lo acepta si puede rastrearlo, firma por firma, hasta la CA raíz del proyecto.

### Cadena de confianza

```
Proyecto Root CA                          autofirmada · 10 años · RSA 4096
│                                         ← el cliente solo confía en esta (ca.crt)
└── Proyecto Intermediate CA              firmada por la raíz · 5 años · RSA 4096
    │                                     ← firma los certificados de servidor
    └── 222835-cliente-servidor.duckdns.org   firmado por la intermedia · 1 año · RSA 2048
                                          ← certificado que presenta el servidor
```

Se usa una CA intermedia para que la llave de la raíz no se use en el día a día. La raíz se mantiene fuera de línea, y si la intermedia se viera comprometida, se podría reemplazar sin cambiar el `ca.crt` que ya tienen instalado los clientes.

El servidor envía su certificado junto con el de la intermedia (`server-chain.crt`), y el cliente solo tiene `ca.crt`. Para aceptar la conexión, el cliente comprueba que:

1. La cadena servidor → intermedia → raíz se pueda reconstruir y cada firma sea válida.
2. La raíz de la cadena sea la CA en la que confía.
3. Ningún certificado de la cadena esté fuera de su periodo de validez.
4. El nombre del certificado (`subjectAltName`) coincida con el servidor al que se conectó.
5. Cada certificado se use solo para lo que sus extensiones permiten.

| Certificado | `basicConstraints` | `keyUsage` | Otras extensiones |
|---|---|---|---|
| Raíz | `CA:TRUE` | `keyCertSign`, `cRLSign` | — |
| Intermedia | `CA:TRUE`, `pathlen:0` | `keyCertSign`, `cRLSign` | `pathlen:0`: no puede crear otras CA, solo certificados finales |
| Servidor | `CA:FALSE` | `digitalSignature`, `keyEncipherment` | `extendedKeyUsage=serverAuth`, `subjectAltName=DNS:222835-cliente-servidor.duckdns.org` |

El `subjectAltName` lleva solo el dominio y no la IP, para que el certificado no dependa de la dirección del servidor. Por eso los clientes deben conectarse siempre usando el dominio.

### Certificados para las pruebas de rechazo

Cada uno provoca una falla distinta, para demostrar que el cliente rechaza certificados que no son de confianza:

| Certificado | Por qué debe rechazarse | Error esperado |
|---|---|---|
| `malos/autofirmado.crt` | Nadie de confianza lo firmó | `self-signed certificate` |
| `malos/expirado.crt` | Firmado por la intermedia, pero fuera de su periodo de validez | `certificate has expired` |
| `malos/nombre-incorrecto-chain.crt` | La cadena es válida, pero el nombre no coincide con el servidor | `hostname mismatch` |
| `malos/otra-ca.crt` | Tiene el nombre correcto, pero lo firmó una CA desconocida | `unable to get local issuer certificate` |

### Archivos

| Archivo | Contenido | ¿En el repositorio? |
|---|---|---|
| `pki/root/ca.crt` | Certificado de la CA raíz; es lo que instalan los clientes | Sí |
| `pki/intermedia/int.crt` | Certificado de la CA intermedia | Sí |
| `pki/servidor/server.crt`, `server-chain.crt` | Certificado del servidor y su cadena | Sí |
| `pki/malos/` | Certificados y llaves de prueba | Sí (son de prueba) |
| `pki/*/ext.cnf` | Extensiones usadas al firmar | Sí |
| `pki/generar_pki.sh` | Script que genera toda la PKI | Sí |
| `root/ca.key`, `intermedia/int.key` | Llaves privadas de las CA | **No.** Fuera de línea, con respaldo |
| `servidor/server.key` | Llave privada del servidor | **No.** Solo en el servidor |
| `malos/ca-falsa/ca-falsa.key` | Llave de la CA falsa | No |

### Cómo generar la PKI

Requiere `openssl`. Para el certificado expirado se usa `faketime`, o en su lugar `python3` con el paquete `cryptography` y `generar_expirado.py`.

```bash
cd pki
./generar_pki.sh
```

El script genera todos los certificados y al final verifica cada uno contra `ca.crt`, mostrando si se acepta o se rechaza y por qué. Si ya existe una CA, se niega a continuar, porque regenerarla invalidaría los certificados ya entregados. Para empezar de cero a propósito: `./generar_pki.sh --forzar`.

Para verificar la cadena manualmente:

```bash
openssl verify -CAfile root/ca.crt -untrusted intermedia/int.crt \
  -verify_hostname 222835-cliente-servidor.duckdns.org servidor/server.crt
```

La respuesta esperada es `servidor/server.crt: OK`.

Una vez generados, el certificado se instala en el servidor:

```bash
sudo mkdir -p /opt/proyecto/certs
sudo cp servidor/server-chain.crt servidor/server.key /opt/proyecto/certs/
sudo chmod 600 /opt/proyecto/certs/server.key
```

### Evidencias

- `docs/evidencias/local/`: pruebas con `openssl s_server` y `s_client` en una misma máquina, una por cada certificado.
- `docs/evidencias/remoto/`: las mismas pruebas desde otra computadora en una red distinta.

### Limitaciones

- **Sin revocación.** No hay CRL ni OCSP. Si una llave se ve comprometida, la única forma de dejar de confiar en ella es regenerar los certificados afectados y redistribuirlos.
- **Llaves de CA sin protección de hardware.** Las llaves de la raíz y la intermedia están en archivos sin contraseña. En una organización real estarían en un HSM o, al menos, cifradas con una frase de paso.
- **CA privada.** Solo es de confianza para los clientes que tienen `ca.crt` instalado. Un navegador o cualquier otro programa la rechazaría.
- **Renovación manual.** El certificado del servidor vence en un año y no hay un proceso automático para renovarlo.

## SSH

SSH proporciona el acceso administrativo remoto al servidor. A diferencia de TLS, que protege la sesión de una aplicación concreta, SSH permite que una persona entre al equipo para operarlo. Por eso, además de cifrar la conexión, controla quién puede entrar, qué puede hacer una vez dentro y deja registro de cada intento.

### Dónde corre

El servidor es Ubuntu en WSL. Los integrantes se conectan desde sus casas, cada uno en una red distinta, a través de Tailscale. El dominio de DuckDNS apunta a la IP de Tailscale del servidor. Tailscale solo da la conectividad entre redes; la autenticación, la autorización y el registro los hace SSH por sí mismo.

### Autenticación: solo con llave pública

Cada integrante tiene un par de llaves Ed25519. La llave privada nunca sale de su computadora; el servidor solo guarda la pública en `~/.ssh/authorized_keys`. Al conectarse, el cliente demuestra que posee la llave privada sin enviarla.

Las contraseñas están deshabilitadas. Así, los ataques de adivinación de contraseñas no tienen nada que adivinar.

La identidad también se valida en la otra dirección: en la primera conexión el cliente muestra la huella (*fingerprint*) de la llave del servidor y la guarda en `known_hosts`. Si en una conexión posterior la llave del servidor cambia, el cliente avisa de un posible ataque de intermediario.

### Autorización: quién entra y qué puede hacer

Autenticarse (demostrar quién eres) no es lo mismo que estar autorizado (tener permiso). Hay dos niveles de autorización:

1. **Para entrar:** solo los miembros del grupo `sshusers` (`AllowGroups`).
2. **Para administrar:** solo los miembros del grupo `sudo`.

| Cuenta | Grupo `sshusers` | Grupo `sudo` | Resultado |
|---|---|---|---|
| Administradora | Sí | Sí | Entra y puede administrar el servidor |
| Integrantes | Sí | No | Entra, pero no puede ejecutar operaciones administrativas |
| `invitado` | No | No | Rechazada, aunque la cuenta exista |
| Cualquier otro nombre | — | — | Rechazado: el usuario no existe |

### Configuración

La configuración está en `ssh/01-proyecto.conf` y se instala en `/etc/ssh/sshd_config.d/`. El archivo empieza con `01` porque sshd usa el primer valor que lee para cada opción, y Ubuntu puede traer otros archivos en esa carpeta que de otra forma lo anularían.

| Directiva | Valor | Para qué sirve |
|---|---|---|
| `PermitRootLogin` | `no` | Nadie entra directamente como root |
| `PasswordAuthentication` | `no` | Sin contraseñas |
| `KbdInteractiveAuthentication` | `no` | Cierra la otra vía para pedir contraseña |
| `PubkeyAuthentication` | `yes` | Única forma de autenticarse |
| `AllowGroups` | `sshusers` | Solo los miembros del grupo pueden entrar |
| `MaxAuthTries` | `3` | Máximo de intentos de autenticación por conexión |
| `LoginGraceTime` | `30` | Segundos para autenticarse antes de que se cierre la conexión |
| `LogLevel` | `VERBOSE` | Registra también la huella de la llave usada en cada acceso |

### Registro de intentos

Los eventos se guardan en `/var/log/auth.log` (con `rsyslog`) y también pueden consultarse con `journalctl -u ssh`.

| Línea en el registro | Significado |
|---|---|
| `Accepted publickey for <usuario> from <IP> ... SHA256:...` | Acceso permitido, con la huella de la llave usada |
| `User invitado from <IP> not allowed because none of user's groups are listed in AllowGroups` | La cuenta existe, pero no está autorizada |
| `Invalid user <nombre> from <IP>` | Intento con un usuario que no existe |
| `Connection closed by authenticating user ... [preauth]` | Se intentó entrar, pero la autenticación no se completó |
| `sudo: ... COMMAND=...` | Operación administrativa ejecutada |
| `sudo: <usuario> : user NOT in sudoers` o `incorrect password attempts` | Operación administrativa rechazada |

Para consultar los últimos eventos de SSH directamente:

```bash
sudo grep sshd /var/log/auth.log | tail -30
```

#### Integración con el registro común

`ssh/parsear_auth_log.py` lee `auth.log` y registra cada evento con `registrar()` de `comun/registro.py`, con `componente="ssh"`. Así los eventos de SSH quedan en `logs/eventos.jsonl` junto con los del resto del sistema y con el mismo formato. Cada registro conserva la hora real del evento en `auth.log`.

| Evento | Nivel | Cuándo | Datos principales |
|---|---|---|---|
| `autenticacion_exitosa` | INFO | Acceso con llave aceptado | `usuario`, `ip_origen`, `metodo`, `huella` |
| `autenticacion_fallida` | WARNING | Acceso rechazado | `usuario`, `ip_origen`, `motivo` |
| `sesion_cerrada` | INFO | El usuario cerró la sesión | `usuario`, `ip_origen` |
| `operacion_administrativa` | INFO | Comando ejecutado con `sudo` | `usuario`, `ejecutado_como`, `comando` |
| `acceso_denegado` | WARNING | Intento de usar `sudo` sin privilegios | `usuario`, `motivo`, `comando` |

Valores de `motivo` en `autenticacion_fallida`: `usuario_no_permitido` (existe, pero no está en `sshusers`), `usuario_inexistente`, `credencial_rechazada` (llave no autorizada), `demasiados_intentos` y `autenticacion_no_completada` (por ejemplo, un intento con contraseña). Si un mismo intento genera varias líneas en `auth.log`, se registra una sola vez.

```bash
python3 ssh/parsear_auth_log.py            # procesa los eventos nuevos
python3 ssh/parsear_auth_log.py --seguir   # registra los eventos en tiempo real
```

El script recuerda el último evento procesado (`logs/.auth_log_ultimo`), así que puede correrse varias veces sin duplicar registros; `--desde-inicio` vuelve a procesar todo. Para leer `auth.log` sin `sudo`, el usuario debe pertenecer al grupo `adm`.

### Instalación

```bash
# 1. Servidor SSH y registro
sudo apt install openssh-server rsyslog -y
sudo systemctl enable --now ssh rsyslog

# 2. Configuración endurecida
sudo cp ssh/01-proyecto.conf /etc/ssh/sshd_config.d/01-proyecto.conf
sudo sshd -t                    # no debe mostrar nada
sudo systemctl restart ssh

# 3. Cuentas
sudo ./ssh/crear_usuarios.sh <usuario> <llave.pub> admin   # administradora
sudo ./ssh/crear_usuarios.sh <usuario> <llave.pub>         # integrante
sudo ./ssh/crear_usuarios.sh invitado --sin-acceso         # cuenta para la prueba de rechazo
```

`crear_usuarios.sh` valida que el archivo sea una llave pública (y no la privada) antes de crear la cuenta, limpia los saltos de línea de Windows y deja los permisos que exige SSH. Al final muestra la huella de la llave para compararla con la del integrante.

Antes de aplicar `AllowGroups`, la cuenta de administración debe estar ya en `sshusers`; de lo contrario, la administradora no podría entrar por SSH.

### Pruebas

| Prueba | Comando (desde el cliente) | Resultado esperado |
|---|---|---|
| Acceso autorizado | `ssh <usuario>@222835-cliente-servidor.duckdns.org` | Entra |
| Cuenta existente sin autorización | `ssh invitado@222835-cliente-servidor.duckdns.org` | `Permission denied (publickey)` |
| Usuario inexistente | `ssh admin@222835-cliente-servidor.duckdns.org` | `Permission denied (publickey)` |
| Intento con contraseña | `ssh -o PubkeyAuthentication=no <usuario>@222835-cliente-servidor.duckdns.org` | Rechazado sin pedir contraseña |
| Operación administrativa sin permiso | Ya dentro como integrante: `sudo ls` | Rechazado; queda registrado como `acceso_denegado` |

Las capturas y el extracto del registro están en `docs/evidencias/remoto/`, con el cliente conectado desde una red distinta a la del servidor.

### Limitaciones

- **Disponibilidad.** El servidor es una computadora personal: solo está disponible mientras esté encendida, con WSL activo y conectada a Tailscale.
- **Un solo factor.** La llave es el único factor. Si la llave privada de un integrante no tiene frase de paso, cualquiera que obtenga ese archivo puede entrar como él.
- **Sin bloqueo automático de IP.** `MaxAuthTries` limita los intentos por conexión, pero no impide abrir conexiones nuevas. Una herramienta como fail2ban bloquearía las IPs con intentos fallidos repetidos.
- **Revocación manual.** Para quitarle el acceso a alguien hay que borrar su llave de `authorized_keys` o sacarlo del grupo `sshusers`.