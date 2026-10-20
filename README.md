# Comunicaciones Seguras en Cliente-Servidor

> **Integrantes**
>
>Adan Oswaldo Fraire Lopez | 202765
>
>Berenice Flores Hernandez | 215861
>
>Anna Lizbeth Barajas Sandoval | 222835
>
>Santiago Medivil Alvarez | 226129


En esta actividad se representa la infraestructura de comunicaciones seguras de una pequeña organización. Incluye una aplicación cliente y una aplicación servidor, y demuestra cómo distintos mecanismos de seguridad protegen las comunicaciones por Internet.

Algunos mecanismos se implementan de forma real, como TLS, los certificados digitales emitidos por una Autoridad Certificadora propia y el acceso administrativo mediante SSH. Otros, como IPSec y las VPN, se simulan a nivel de software, ya que el objetivo es demostrar su funcionamiento y sus diferencias, no construir protocolos de producción.

---

## Arquitectura


## Instrucciones de ejecución

### Preparación (una sola vez)

```bash
git clone https://github.com/222835/ejercicio-cliente-servidor
cd ejercicio-cliente-servidor
python -m venv .venv
source .venv/bin/activate        # en fish: source .venv/bin/activate.fish · en Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Cliente-servidor y TLS (Parte 1)

```bash
python -m pytest -v tests/test_tls.py
python -m tls.servidor --modo tls            # o --modo plano; en el equipo del servidor
python -m tls.cliente --modo tls --host <IP_DEL_SERVIDOR> --hostname 222835-cliente-servidor.duckdns.org
```

El servidor necesita `pki/servidor/server.key`, que no está en el repositorio. Pasos para las dos computadoras y para Wireshark en [`README-TLS.md`](README-TLS.md).
### PKI y SSH (Parte 2)

El servidor es Ubuntu en WSL, accesible desde otras redes a través de Tailscale con el dominio `222835-cliente-servidor.duckdns.org`. Para conectarse hay que estar en la red de Tailscale del equipo.

```bash
ssh <usuario>@222835-cliente-servidor.duckdns.org        # acceso administrativo (solo con llave)

# En el servidor, desde la raíz del repo:
python3 ssh/parsear_auth_log.py --seguir                  # pasa los eventos de SSH y sudo a logs/eventos.jsonl
sudo bash ssh/crear_usuarios.sh <usuario> <llave.pub>     # da de alta a un integrante
```

La PKI ya está generada; `pki/generar_pki.sh` documenta cómo se creó y permite reproducirla (no debe correrse sobre la PKI actual).

### IPSec (Parte 3)

```bash
python -m pytest -v tests/test_ipsec.py
python demo_ipsec.py             # paquete original, modo transporte y modo túnel lado a lado
```

### VPN, autenticación y registro (Parte 4)

```bash
python -m pytest -v              # todas las pruebas, siempre desde la raíz del repo
python demo_vpn.py               # demo completa (o --remota / --sitio)
```

Los eventos se guardan en `logs/eventos.jsonl`.


## TLS

> Parte 1 · Santiago Medivil Alvarez · Código en `tls/` · Detalle completo en [`README-TLS.md`](README-TLS.md)

Un servidor y un cliente TCP de eco que funcionan en dos modos, para comparar qué protege TLS:

- **Modo `plano`**: TCP sin protección. El mensaje viaja legible y cualquiera puede hacerse pasar por el servidor.
- **Modo `tls`**: el servidor presenta su certificado y la cadena de la PKI (servidor → intermedia → raíz) y el canal queda cifrado y autenticado (TLS 1.2 o superior).

El cliente **no confía en nada por defecto**: carga únicamente `pki/root/ca.crt` (no las CA del sistema), valida la cadena, la vigencia y el **hostname**, y si algo falla no envía ningún dato (`ErrorCertificado`, código de salida 2). El hostname a validar (`--hostname`) es independiente de la dirección a la que se conecta (`--host`), así que en la red local se puede conectar por IP y seguir validando contra `222835-cliente-servidor.duckdns.org`.

| Certificado que presenta el servidor | Resultado en el cliente |
|---|---|
| Emitido por la PKI, con el nombre correcto | ✔ conexión TLS |
| Autofirmado | ✘ rechazado (`self-signed certificate`) |
| Expirado | ✘ rechazado (`certificate has expired`) |
| De otro nombre (`otro-servidor.com`) | ✘ rechazado (`Hostname mismatch`) |
| Firmado por otra CA ("CA Falsa") | ✘ rechazado (`unable to get local issuer certificate`) |

Los rechazos se registran como `WARNING` (`certificado_rechazado`, `handshake_fallido`) en el mismo log que las demás partes. Las pruebas usan los certificados inválidos de la Parte 2 (`pki/malos/`) y están en `tests/test_tls.py`.

## PKI

> Parte 2 · Anna Lizbeth Barajas Sandoval · Archivos en `pki/` · Detalle completo en [`README-PKI-SSH.md`](README-PKI-SSH.md)

La organización tiene su propia Autoridad Certificadora, creada con OpenSSL. El cliente solo confía en `pki/root/ca.crt` y acepta el certificado del servidor únicamente si puede rastrearlo, firma por firma, hasta esa raíz.

```
Proyecto Root CA                     autofirmada · 10 años   ← el cliente confía solo en esta
└── Proyecto Intermediate CA         5 años                  ← firma los certificados de servidor
    └── 222835-cliente-servidor.duckdns.org   1 año          ← certificado que presenta el servidor
```

- La **intermedia** permite que la llave raíz no se use en el día a día: se mantiene fuera de línea, y la intermedia podría reemplazarse sin cambiar el `ca.crt` de los clientes. Tiene `pathlen:0`, así que no puede crear otras CA.
- El servidor envía su certificado junto con la intermedia (`server-chain.crt`). El cliente verifica las firmas de la cadena, las fechas de validez y que el `subjectAltName` coincida con el dominio al que se conectó.
- Las llaves privadas de las CA **no están en el repositorio**; la del servidor solo existe en el servidor (`/opt/proyecto/certs/`).

Para demostrar los rechazos hay un certificado inválido por cada falla posible:

| Certificado | Por qué se rechaza | Error |
|---|---|---|
| `malos/autofirmado.crt` | Nadie de confianza lo firmó | `self-signed certificate` |
| `malos/expirado.crt` | Fuera de su periodo de validez | `certificate has expired` |
| `malos/nombre-incorrecto-chain.crt` | Cadena válida, pero nombre distinto | `hostname mismatch` |
| `malos/otra-ca.crt` | Firmado por una CA desconocida | `unable to get local issuer certificate` |

Las pruebas con cada certificado, hechas desde otra computadora en una red distinta, están en `docs/evidencias/remoto`.

## SSH

> Parte 2 · Anna Lizbeth Barajas Sandoval · Archivos en `ssh/` · Detalle completo en [`README-PKI-SSH.md`](README-PKI-SSH.md)

SSH da el acceso administrativo remoto al servidor. A diferencia de TLS, que protege la sesión de una aplicación, SSH permite que una persona entre al equipo para operarlo; por eso además controla quién entra, qué puede hacer y registra cada intento.

- **Autenticación solo con llave pública** (Ed25519). Las contraseñas y el acceso directo como root están deshabilitados (`ssh/01-proyecto.conf`).
- **Autorización en dos niveles:** solo los miembros del grupo `sshusers` pueden entrar (`AllowGroups`), y solo los del grupo `sudo` pueden administrar.

| Cuenta | Puede entrar | Puede administrar |
|---|:-:|:-:|
| Administradora | ✔ | ✔ |
| Integrantes | ✔ | ✘ |
| `invitado` (existe, pero no está en `sshusers`) | ✘ | ✘ |
| Usuario inexistente | ✘ | ✘ |

- **Registro:** sshd y sudo escriben en `/var/log/auth.log`. `ssh/parsear_auth_log.py` convierte esos eventos al registro común con `componente="ssh"`: `autenticacion_exitosa`, `autenticacion_fallida` (con su `motivo`), `sesion_cerrada`, `operacion_administrativa` y `acceso_denegado`.

Las pruebas de acceso autorizado, rechazos y operación administrativa sin permiso están en `docs/evidencias/remoto/`.


## IPSec

> Parte 3 · Adan Oswaldo Fraire Lopez · Código en `ipsec/ipsec.py` · Detalle completo en [`README-IPSec.md`](README-IPSec.md)

IPSec se **simula** en Python con la librería `cryptography`. No modifica paquetes reales del sistema operativo, pero reproduce los elementos de ESP:

- **Asociación de seguridad (SA)**: `IPSecSA` guarda el SPI, la clave y el algoritmo (AES-GCM, que cifra y autentica a la vez).
- **Modo transporte** (`modo_transporte`): cifra solo el contenido y deja visible el encabezado IP original. Se usa entre dos equipos que se comunican directamente.
- **Modo túnel** (`modo_tunel`): cifra el paquete IP completo, incluidas las direcciones internas, y le pone un encabezado IP nuevo con las direcciones de los gateways. Es el que usa la VPN sitio a sitio.
- **Anti-replay**: cada paquete lleva un número de secuencia y el receptor mantiene una ventana deslizante de 64. Rechaza los números repetidos y los demasiado viejos.
- **Integridad**: el SPI y el número de secuencia van como datos autenticados de GCM; cualquier cambio en el paquete hace que se rechace.

`IPSecSA.recibir()` procesa los paquetes en el orden de RFC 4303: revisa la ventana, verifica la integridad y solo entonces marca el número de secuencia. Así un paquete falso no puede "gastar" el número de uno legítimo.

| | Modo transporte | Modo túnel |
|---|---|---|
| Qué se cifra | Solo el contenido | El paquete IP completo |
| Encabezado IP visible | El original (IP de los equipos) | Uno nuevo (IP de los gateways) |
| Uso típico | Equipo ↔ equipo | Gateway ↔ gateway (VPN sitio a sitio) |

## VPN

> Parte 4 · Berenice Flores Hernández · Detalle completo en [`README-VPN.md`](README-VPN.md)

Ambas VPN son **simuladas** en Python: no crean interfaces de red, pero aplican la autenticación, el control de acceso y la protección del tráfico que haría una VPN real.

**VPN de acceso remoto** (`vpn/acceso_remoto.py`). Un usuario desde Internet se autentica con usuario y contraseña, recibe una IP virtual del pool `10.8.0.0/24` y obtiene una sesión con vencimiento. Conectarse **no da acceso ilimitado**: en cada petición se revisa el rol.

| Recurso interno | admin | empleado | invitado |
|---|:-:|:-:|:-:|
| archivos (10.0.0.10) | ✔ | ✔ | ✘ |
| wiki (10.0.0.20) | ✔ | ✔ | ✔ |
| base_datos (10.0.0.30) | ✔ | ✘ | ✘ |
| panel_admin (10.0.0.40) | ✔ | ✘ | ✘ |

**VPN sitio a sitio** (`vpn/sitio_a_sitio.py`). Une la red de la matriz (`10.1.0.0/24`) con la de la sucursal (`10.2.0.0/24`). No hay usuario final: los **gateways** se autentican entre sí con una clave precompartida (desafío-respuesta HMAC, sin enviar la clave) y derivan sus claves con HKDF. El tráfico viaja en **modo túnel usando el módulo IPSec de la Parte 3**, por lo que en Internet solo se ven las IP públicas de los gateways.

## Autenticación, autorización y registro

La separación está explícita en `vpn/auth.py`:

- `autenticar()` responde **¿quién eres?** Compara la contraseña con un hash PBKDF2-HMAC-SHA256 (600 000 iteraciones, sal única por usuario) y bloquea la cuenta tras 3 intentos fallidos.
- `autorizar()` responde **¿qué puedes hacer?** Revisa el rol contra el recurso. Un usuario puede estar autenticado y aun así no autorizado.

Todas las partes registran sus eventos con `comun/registro.py`, que escribe un JSON por línea en `logs/eventos.jsonl`:

```json
{"timestamp": "2026-10-19T22:32:00+00:00", "nivel": "WARNING", "componente": "authz", "evento": "acceso_denegado", "usuario": "beto", "rol": "empleado", "recurso": "base_datos"}
```

Se registran conexiones, autenticaciones exitosas y fallidas, accesos permitidos y denegados, operaciones administrativas, túneles establecidos o rechazados y paquetes rechazados por replay o alteración.


## Diferencias entre los mecanismos

### VPN de acceso remoto vs. VPN sitio a sitio

| Aspecto | Acceso remoto | Sitio a sitio |
|---|---|---|
| Qué conecta | Un usuario con la red interna | Dos redes completas |
| Quién se autentica | La persona (usuario y contraseña) | Los gateways (clave precompartida) |
| Dirección | IP virtual por sesión | Rutas fijas entre redes |
| Duración | Sesión con vencimiento | Túnel permanente |
| Control de acceso | Por rol de usuario | Por red o ruta |
| Equipos finales | Necesitan cliente VPN | No saben que existe la VPN |


## Limitaciones de seguridad

### Cliente-servidor y TLS (Parte 1)

- Solo se autentica al servidor (no hay TLS mutuo) y no se consulta revocación (CRL/OCSP).
- La llave privada del servidor es un archivo sin contraseña; no se versiona y debe copiarse al equipo servidor por un medio seguro.
- El modo `plano` existe solo para comparar; el cliente no cae a texto plano por su cuenta, pero se le puede pedir.
- El *handshake* deja visibles metadatos (SNI, IP, puertos, tamaños y tiempos) aunque el contenido esté cifrado.
- El servidor usa una hebra por conexión sin límite; los tiempos de espera acotan cada una pero no evitan el agotamiento por muchas conexiones.

Más detalle en [`README-TLS.md`](README-TLS.md).
### PKI y SSH (Parte 2)

- No hay revocación de certificados (CRL u OCSP): si una llave se compromete, hay que regenerar y redistribuir los certificados.
- Las llaves de las CA están en archivos sin contraseña ni HSM, y el certificado del servidor se renueva manualmente.
- La CA es privada: solo la reconocen los clientes que tienen `ca.crt`.
- El servidor es una computadora personal: solo está disponible mientras esté encendida y conectada a Tailscale.
- SSH usa un solo factor (la llave) y no bloquea automáticamente las IP con intentos fallidos repetidos.

Más detalle en [`README-PKI-SSH.md`](README-PKI-SSH.md).

### VPN, autenticación y registro (Parte 4)

- Las VPN son simulaciones dentro de un proceso de Python; no crean interfaces ni mueven paquetes reales.
- La negociación entre gateways sustituye a IKEv2 sin Diffie-Hellman, así que no hay *perfect forward secrecy*, y usa clave precompartida en lugar de certificados de la PKI.
- Usuarios y sesiones viven en memoria y se pierden al reiniciar; no hay autenticación multifactor.
- El bloqueo por intentos fallidos puede usarse para bloquear cuentas a propósito.
- El archivo de log no está protegido contra modificaciones.

Más detalle en [`README-VPN.md`](README-VPN.md).

