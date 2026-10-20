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


## PKI


## SSH


## IPSec

> Parte 3 · Adan Oswaldo Fraire Lopez · Código en `ipsec/ipsec.py`

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

> Parte 4 · Berenice Flores Hernández · Detalle completo en [`README_parte4.md`](README_parte4.md)

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

### VPN, autenticación y registro (Parte 4)

- Las VPN son simulaciones dentro de un proceso de Python; no crean interfaces ni mueven paquetes reales.
- La negociación entre gateways sustituye a IKEv2 sin Diffie-Hellman, así que no hay *perfect forward secrecy*, y usa clave precompartida en lugar de certificados de la PKI.
- Usuarios y sesiones viven en memoria y se pierden al reiniciar; no hay autenticación multifactor.
- El bloqueo por intentos fallidos puede usarse para bloquear cuentas a propósito.
- El archivo de log no está protegido contra modificaciones.

Más detalle en [`README_parte4.md`](README_parte4.md).

