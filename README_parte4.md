# Parte 4 — VPN, autenticación, autorización y registro

Requerimientos 6, 7 y 8 (y sus pruebas del requerimiento 9). Responsable: Berenice.

## Estructura

```
comun/
  registro.py          # Logger JSON por línea, compartido por todo el proyecto
vpn/
  auth.py              # autenticar() y autorizar(), PBKDF2, roles y permisos
  acceso_remoto.py     # VPN de acceso remoto (usuario → red interna)
  sitio_a_sitio.py     # VPN sitio a sitio (red ↔ red, gateways con PSK)
  tunel_ipsec.py       # Puente hacia el IPSec de la Parte 3 (desencapsulado del lado receptor)
ipsec/                 # Parte 3 (Adán): IPSecSA, modo transporte y modo túnel
tests/                 # 49 pruebas con pytest (incluye las 7 de IPSec)
demo_vpn.py            # Demo visual de la Parte 4 con rich
demo_ipsec.py          # Demo visual de la Parte 3 (transporte vs. túnel)
```

## Ejecución

```bash
pip install -r requirements.txt
python -m pytest -v          # todas las pruebas, desde la raíz del repo
python demo_vpn.py           # demo de VPN (o --remota / --sitio)
python demo_ipsec.py         # demo de IPSec (Parte 3)
```

Los eventos quedan en `logs/eventos.jsonl` (se puede cambiar con la variable `RUTA_LOG`).

## Autenticación vs. autorización

La separación está explícita en `vpn/auth.py`:

| Función | Pregunta que responde | Qué revisa | Si falla |
|---|---|---|---|
| `autenticar()` | ¿Quién eres? | Contraseña contra el hash PBKDF2-SHA256 (600 000 iteraciones, sal aleatoria de 16 bytes) | `ErrorAutenticacion` |
| `autorizar()` | ¿Qué puedes hacer? | Rol del usuario contra el recurso pedido | Devuelve `False` (o `ErrorAutorizacion` con `exigir_autorizacion()`) |

Un usuario puede estar autenticado y aun así no autorizado: la invitada entra a la VPN pero no puede abrir la base de datos.

Medidas adicionales: las contraseñas nunca se guardan ni se registran en texto plano; la comparación de hashes es en tiempo constante (`hmac.compare_digest`); el mensaje de error es el mismo para usuario inexistente y contraseña incorrecta; la cuenta se bloquea tras 3 intentos fallidos.

### Permisos por rol

| Recurso (IP interna) | admin | empleado | invitado |
|---|:-:|:-:|:-:|
| archivos (10.0.0.10) | ✔ | ✔ | ✘ |
| wiki (10.0.0.20) | ✔ | ✔ | ✔ |
| base_datos (10.0.0.30) | ✔ | ✘ | ✘ |
| panel_admin (10.0.0.40) | ✔ | ✘ | ✘ |

Solo quien tiene `panel_admin` puede ejecutar operaciones administrativas (`crear_usuario`, `listar_sesiones`, `desbloquear_usuario`, `expulsar_usuario`).

## VPN de acceso remoto

1. El usuario se conecta desde Internet con usuario y contraseña.
2. El servidor VPN lo autentica y le asigna una IP virtual del pool `10.8.0.0/24` (el servidor es `10.8.0.1`).
3. Se crea una sesión con identificador aleatorio y vencimiento (1 hora por defecto).
4. En **cada** petición a un recurso interno se valida la sesión y se aplica `autorizar()`. Conectarse no da acceso ilimitado.
5. Al desconectar, la IP virtual vuelve al pool.

## VPN sitio a sitio

```
[10.1.0.0/24] ── GW-Matriz 198.51.100.1 ══[ túnel IPSec ]══ 203.0.113.1 GW-Sucursal ── [10.2.0.0/24]
```

1. No hay usuario final. Los gateways se autentican entre sí con una clave precompartida (PSK) mediante desafío-respuesta HMAC-SHA256: cada uno genera un nonce y demuestra que conoce la PSK sin enviarla.
2. Con HKDF se derivan dos claves AES-256 (una por sentido) y se crean dos SA con SPI aleatorios.
3. Cualquier equipo de una red puede hablar con uno de la otra; el gateway encapsula con `IPSecSimulator.modo_tunel()` de la Parte 3 (**modo túnel**): el paquete IP original (con las IP internas) viaja cifrado, y en Internet solo se ven las IP públicas de los gateways.
4. El receptor rechaza paquetes repetidos (ventana anti-replay de 64), alterados (etiqueta GCM inválida), con SPI desconocido o con destino fuera de su red.

## Comparación de escenarios

| Aspecto | VPN de acceso remoto | VPN sitio a sitio |
|---|---|---|
| Qué conecta | Un usuario con una red interna | Dos redes completas |
| Quién se autentica | La persona (usuario + contraseña) | Los gateways (PSK) |
| Dirección | IP virtual 10.8.0.x por sesión | Rutas fijas 10.1.0.0/24 ↔ 10.2.0.0/24 |
| Duración | Sesión con vencimiento | Túnel permanente |
| Control de acceso | Por rol de usuario | Por red/ruta |
| Equipos finales | Necesitan cliente VPN | No saben que existe la VPN |
| Modo IPSec típico | Túnel (cliente ↔ concentrador) | Túnel (gateway ↔ gateway) |
| Ejemplo real | OpenVPN, WireGuard, AnyConnect | IPSec entre routers de dos oficinas |

## Registro de eventos

`comun/registro.py` escribe una línea JSON por evento:

```json
{"timestamp": "2026-10-19T22:32:00+00:00", "nivel": "WARNING", "componente": "authz", "evento": "acceso_denegado", "usuario": "beto", "rol": "empleado", "recurso": "base_datos", "ip_virtual": "10.8.0.4"}
```

Eventos registrados: `intento_conexion_vpn`, `conexion_vpn_establecida`, `conexion_vpn_rechazada`, `desconexion_vpn`, `autenticacion_exitosa`, `autenticacion_fallida`, `cuenta_bloqueada`, `acceso_permitido`, `acceso_denegado`, `sesion_invalida`, `operacion_administrativa`, `operacion_admin_rechazada`, `negociacion_tunel`, `tunel_establecido`, `tunel_rechazado`, `paquete_enviado_tunel`, `paquete_entregado`, `paquete_rechazado`, `replay_detectado`, `ruta_rechazada`.

Los eventos de seguridad negativos se marcan como `WARNING`.

**Para las otras partes:** pueden usar el mismo logger para que todo quede en un solo archivo:

```python
from comun.registro import registrar
registrar("conexion_tls", componente="tls", cliente="192.168.1.20", resultado="ok")
```

## Integración con la Parte 3 (IPSec de Adán)

La VPN sitio a sitio **no tiene criptografía propia**: cada sentido del túnel es una `IPSecSA` de `ipsec/ipsec.py`, los paquetes se arman con `IPSecSimulator.modo_tunel()` y se reciben con `IPSecSA.recibir()`. `vpn/tunel_ipsec.py` solo traduce entre los dos módulos.

`IPSecSA.recibir()` procesa cada paquete en este orden (como en RFC 4303):

1. Revisa la ventana anti-replay **sin marcar** el número de secuencia.
2. Verifica la integridad y descifra con AES-GCM. El SPI y el número de secuencia van como datos autenticados, así que alterarlos también se detecta.
3. **Solo si el paquete es auténtico**, marca el número como recibido.

El orden importa: si la ventana se actualizara antes de validar la integridad, un atacante podría mandar un paquete falso con el número de secuencia del siguiente paquete legítimo y hacer que el legítimo se rechazara como duplicado. Hay pruebas para ese caso en `test_ipsec.py` y `test_sitio_a_sitio.py`.

Ajustes hechos al módulo de la Parte 3 para integrarlo:
- `ipsec/__init__.py`: sin él, `from ipsec import IPSecSA` fallaba al correr las pruebas desde la raíz del repo.
- Los eventos de IPSec usan el registro común (`comun/registro.py`) en lugar de `logging.basicConfig`.
- Nuevo método `IPSecSA.recibir()` con el orden de verificación descrito arriba. `check_replay()` acepta `marcar=False` para solo consultar la ventana, y rechaza el número de secuencia 0. Las funciones y pruebas originales siguen igual.
- La demo se movió a la raíz (`demo_ipsec.py`) para ejecutarla con `python demo_ipsec.py`.

## Pruebas (requerimiento 9)

| Archivo | Qué demuestra |
|---|---|
| `test_auth.py` | Login válido e inválido, hash con sal, mismo error para usuario inexistente, bloqueo tras 3 intentos, permisos por rol, autenticado ≠ autorizado, log JSON sin contraseñas |
| `test_acceso_remoto.py` | Conexión VPN con IP virtual (se reutiliza la más baja libre), conexión rechazada, acceso permitido y denegado después de conectar, operaciones admin permitidas y rechazadas, sesión falsa, cerrada y vencida |
| `test_sitio_a_sitio.py` | Tráfico entre sitios en ambos sentidos, IP internas ocultas en Internet, gateway con PSK incorrecta rechazado, uso del modo túnel de la Parte 3, replay detectado (duplicado y fuera de la ventana), alteración del contenido o del número de secuencia detectada por GCM, paquete falso que no bloquea al legítimo, paquetes fuera de orden dentro de la ventana, rutas inválidas, SPI desconocido |
| `test_ipsec.py` (Parte 3) | Modo transporte y túnel, alteración detectada por GCM, anti-replay, recepción en el orden correcto (un paquete falso no consume el número de secuencia del legítimo) |

## Limitaciones de seguridad

- **Es una simulación.** Ni la VPN ni el túnel crean interfaces de red reales ni mueven paquetes por la red; todo ocurre dentro del proceso de Python. La fila "lo que vería un sniffer" de la demo es una representación generada por el programa, no una captura de Wireshark.
- **Negociación simplificada.** El desafío-respuesta con PSK sustituye a IKEv2: no hay Diffie-Hellman, así que no hay *perfect forward secrecy* (si la PSK se filtra, se pueden derivar las claves de sesiones grabadas).
- **PSK en lugar de certificados.** En producción los gateways deberían autenticarse con certificados de la PKI (Parte 2).
- **Sin renovación de claves.** Las SA no se renegocian por tiempo ni por volumen, y el número de secuencia no se controla contra desbordamiento (en ESP real es de 32 bits y obliga a renegociar).
- **El encabezado IP externo no está autenticado.** Igual que en ESP real, el ICV cubre el encabezado ESP y la carga, no el encabezado IP nuevo; el gateway receptor compensa revisando que el origen sea la IP pública del gateway par.
- **Usuarios y sesiones en memoria.** Se pierden al reiniciar; en producción irían en una base de datos o en LDAP/RADIUS.
- **Sin MFA.** La VPN de acceso remoto solo usa contraseña.
- **Bloqueo de cuenta simple.** Un atacante podría bloquear cuentas a propósito (denegación de servicio); no hay desbloqueo automático por tiempo.
- **El log no está protegido contra manipulación.** Quien tenga acceso al archivo puede alterarlo; en producción se enviaría a un servidor de logs aparte (syslog/SIEM).
