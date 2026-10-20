# Parte 1: Cliente-servidor y TLS

**Desarrollador:** Santiago Medivil Alvarez  
**Módulo:** `tls/servidor.py` y `tls/cliente.py` · Requerimientos 1 y 2 (y sus pruebas del requerimiento 9)

---

## 1. Función del mecanismo y arquitectura

Una aplicación cliente y una aplicación servidor se comunican por TCP en dos modos que se eligen al arrancar (`--modo plano` o `--modo tls`). El servicio es un **eco**: el cliente envía una línea y el servidor la devuelve con el prefijo `ECO: `. Es deliberadamente simple para que lo importante sea el canal, no la aplicación.

| | Modo `plano` | Modo `tls` |
|---|---|---|
| Transporte | TCP sin protección | TCP + TLS (mínimo 1.2; en la práctica 1.3) |
| Confidencialidad | ✘ cualquiera en la red lee el mensaje | ✔ cifrado (AES-GCM) |
| Integridad | ✘ se puede alterar en tránsito | ✔ autenticado por el propio cifrado |
| Autenticación del servidor | ✘ cualquiera puede hacerse pasar por él | ✔ certificado validado contra la CA del proyecto |

El modo `plano` existe **solo para comparar** (por ejemplo, en Wireshark) qué se ve con y sin protección.

### Estructura

```
tls/
  servidor.py    # Servidor de eco: Servidor(modo="plano" | "tls"), una hebra por conexión
  cliente.py     # Cliente: enviar(), validación del certificado, ErrorCertificado
pki/             # Parte 2: ca.crt, certificados del servidor y certificados inválidos para las pruebas
tests/test_tls.py                       # 13 pruebas con pytest
docs/evidencias/generar_evidencias_tls.sh   # Regenera las evidencias que no requieren dos equipos
docs/evidencias/tls/                    # Salidas de pruebas, demo por línea de comandos y eventos
```

### Servidor (`tls/servidor.py`)

- En modo TLS carga `pki/servidor/server-chain.crt` (certificado del servidor **más** la CA intermedia) y `pki/servidor/server.key`. La cadena completa es necesaria: el cliente solo conoce la raíz, así que el servidor debe presentar la intermedia.
- Acepta TLS 1.2 o superior. El *handshake* ocurre en la hebra de cada conexión, de modo que un cliente lento o malicioso no bloquea a los demás; cada conexión tiene un tiempo de espera de 10 s y las líneas están limitadas a 4096 bytes.
- Registra los eventos con el logger común (`comun/registro.py`): `servidor_iniciado`, `conexion_tcp`, `conexion_tls` (con protocolo y cifrado), `mensaje_recibido` (solo el tamaño, nunca el contenido), `handshake_fallido`, `mensaje_rechazado`.

### Cliente (`tls/cliente.py`)

El cliente **no confía en nada por defecto**. `crear_contexto()` usa `ssl.create_default_context(cafile=ca.crt)`, lo que implica:

1. **Solo confía en la CA del proyecto** (`pki/root/ca.crt`), no en las CA del sistema operativo.
2. **Valida la cadena completa** (servidor → intermedia → raíz), las fechas de vigencia y los usos permitidos del certificado.
3. **Valida el hostname**: el nombre esperado debe estar en el `subjectAltName` del certificado.
4. Exige TLS 1.2 como mínimo.

Si cualquiera de las validaciones falla, **no se envía ningún dato**: se lanza `ErrorCertificado` (con el motivo y el código de verificación de OpenSSL), se registra `certificado_rechazado` como `WARNING` y la línea de comandos termina con código 2.

`--host` y `--hostname` son independientes a propósito. El certificado se emitió para `222835-cliente-servidor.duckdns.org`, pero en una red local conviene conectarse por la IP del servidor. Así se conecta a `--host 192.168.1.50` y se **valida** contra `--hostname 222835-cliente-servidor.duckdns.org`. Si no se indica `--hostname`, se usa el valor de `--host`.

---

## 2. Ejecución en dos computadoras de la misma red

### Preparación (en ambas)

```bash
git clone https://github.com/222835/ejercicio-cliente-servidor
cd ejercicio-cliente-servidor
python -m venv .venv
.venv\Scripts\activate            # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

### Equipo A: servidor

1. Colocar la llave privada en `pki/servidor/server.key`. **No está en el repositorio** (está en `.gitignore`); se obtiene de quien generó la PKI (Parte 2) y se pasa por un medio seguro.
2. Abrir el puerto en el firewall (Windows, en una consola de administrador):
   ```
   netsh advfirewall firewall add rule name="Demo TLS" dir=in action=allow protocol=TCP localport=5443
   ```
3. Obtener su IP en la red (`ipconfig` en Windows, `ip a` en Linux) y arrancar el servidor:
   ```bash
   python -m tls.servidor --modo plano    # sin protección
   python -m tls.servidor --modo tls      # con TLS
   ```
   Se detiene con Ctrl+C. Solo corre un modo a la vez en el mismo puerto; se puede usar `--puerto` para tener ambos.

### Equipo B: cliente

Solo necesita `pki/root/ca.crt`, que ya viene en el repositorio.

```bash
# Sin protección
python -m tls.cliente --modo plano --host <IP_DEL_SERVIDOR>

# Con TLS: se conecta por IP y valida contra el nombre del certificado
python -m tls.cliente --modo tls --host <IP_DEL_SERVIDOR> --hostname 222835-cliente-servidor.duckdns.org
```

Salida esperada en TLS:

```
Modo: TLS · TLSv1.3 · TLS_AES_256_GCM_SHA384
Respuesta: ECO: Mensaje de prueba: usuario=ana clave=Secreta#2026
```

Parámetros útiles: `--puerto` (por defecto 5443), `--ca` (ruta de otro `ca.crt`), `--mensaje`.

| Código de salida del cliente | Significado |
|:-:|---|
| 0 | Respuesta recibida |
| 1 | Error de red o TLS que no es del certificado (servidor apagado, firewall, servidor sin TLS) |
| 2 | **Certificado rechazado** |

---

## 3. Pruebas (requerimiento 9)

```bash
python -m pytest -v tests/test_tls.py
```

Las pruebas arrancan el servidor y el cliente reales en `127.0.0.1` con un puerto libre. Los casos de rechazo usan **los certificados inválidos de la Parte 2** (`pki/malos/`) contra el `ca.crt` real. Para el caso exitoso se genera al vuelo una PKI desechable (raíz → intermedia → servidor) porque la llave del servidor real no se versiona; si `pki/servidor/server.key` existe en el equipo, una prueba adicional usa además el certificado real.

| Prueba | Qué demuestra | Código OpenSSL |
|---|---|:-:|
| `test_modo_sin_proteccion_devuelve_el_eco` | El modo sin protección funciona y no negocia TLS | |
| `test_tls_exitoso_valida_cadena_y_hostname_aunque_se_conecte_por_ip` | **Conexión TLS exitosa**: valida la cadena de tres niveles y el hostname aunque se conecte por IP | |
| `test_tls_exitoso_con_el_certificado_real_de_la_pki` | Lo mismo con el certificado real (se omite si no está `server.key`) | |
| `…_invalidos_de_la_parte_2[autofirmado]` | Certificado autofirmado rechazado | 18 |
| `…_invalidos_de_la_parte_2[expirado]` | Certificado expirado rechazado | 10 |
| `…_invalidos_de_la_parte_2[nombre-incorrecto]` | Certificado válido pero de `otro-servidor.com` rechazado | 62 |
| `…_invalidos_de_la_parte_2[firmado-por-otra-CA]` | Certificado firmado por una "CA Falsa" rechazado | 20 |
| `test_cliente_rechaza_un_servidor_valido_si_su_ca_no_es_de_confianza` | Un servidor legítimo se rechaza si el cliente tiene otra CA | 20 |
| `test_cliente_rechaza_un_servidor_que_no_envia_la_intermedia` | Si el servidor no envía la intermedia, la cadena no se puede validar | 20 |
| `test_cliente_rechaza_si_el_hostname_esperado_no_coincide` | El hostname se valida aunque la cadena sea buena | 62 |
| `test_el_rechazo_de_un_certificado_queda_en_el_registro` | El rechazo queda como `WARNING` en el log | |
| `test_cliente_tls_contra_servidor_sin_proteccion_falla` | Un cliente TLS no "cae" a texto plano | |
| `test_cliente_sin_proteccion_contra_servidor_tls_no_recibe_eco` | Un cliente sin TLS no obtiene servicio de un servidor TLS | |

Se comprobó que las pruebas detectan una validación débil: al desactivar `check_hostname` en el cliente fallan las 2 pruebas de nombre, y al desactivar toda la verificación fallan 8.

---

## 4. Captura con Wireshark (recomendada)

Sirve para **ver** la diferencia entre los dos modos. Se captura en cualquiera de los dos equipos, en la interfaz de la red local (no en loopback), con el filtro de captura `tcp port 5443`.

**Pasos**

1. Iniciar la captura en Wireshark.
2. Ejecutar el cliente en modo `plano` y detener la captura. Guardar como `plano.pcapng`.
3. Repetir con el modo `tls`. Guardar como `tls.pcapng`.
4. Guardar ambos archivos en `docs/evidencias/tls/capturas/`.

**Qué debe verse**

| | Modo `plano` | Modo `tls` |
|---|---|---|
| Filtro de visualización | `tcp.port == 5443` | `tls` |
| Protocolo que muestra Wireshark | TCP | TLSv1.3 (Client Hello, Server Hello, Application Data) |
| *Follow → TCP Stream* | Se lee en claro `Mensaje de prueba: usuario=ana clave=Secreta#2026` y la respuesta `ECO: …` | Solo bytes ilegibles |
| Certificado | No hay | En TLS 1.2 se ve el certificado en el *handshake*; en TLS 1.3 viaja cifrado |
| Lo que sigue visible en TLS | | IP y puertos, tamaños y tiempos de los paquetes, y el nombre del servidor (SNI) en el Client Hello |

Para ver el rechazo de un certificado, repetir la captura con un servidor que use uno de `pki/malos/`: el cliente corta el *handshake* con una alerta TLS (`Alert`, por ejemplo `Unknown CA` o `Certificate Expired`) y nunca aparece un `Application Data` con el mensaje.

> Las capturas son una evidencia manual: dependen de los dos equipos y de Wireshark, por eso no las genera el script automático. Los archivos `.pcapng` se agregan a `docs/evidencias/tls/capturas/` cuando se hagan.

---

## 5. Evidencias

Las salidas automáticas están en `docs/evidencias/tls/` (cada archivo indica el comando, la fecha y el commit con que se generó):

| Archivo | Qué demuestra | Req. |
|---|---|:-:|
| `pruebas-tls.txt` | Las 13 pruebas de la parte | 2, 9 |
| `demo-cliente-servidor.txt` | Servidor y cliente reales por línea de comandos: modo sin protección y rechazo de los cuatro certificados inválidos | 1, 2 |
| `eventos.jsonl` | Registro real generado por esa demo (JSON por línea), incluidos los `WARNING` de rechazo | 8 |
| `capturas/` | Capturas de Wireshark de ambos modos *(pendiente de agregar)* | 1, 2 |

Para regenerar las automáticas (desde la raíz, con el entorno virtual activo):

```bash
bash docs/evidencias/generar_evidencias_tls.sh
```

---

## 6. Limitaciones de seguridad

- **Solo autentica al servidor.** No hay TLS mutuo: el servidor no sabe quién es el cliente y no hay usuarios ni contraseñas en este servicio (eso lo cubre la VPN, Parte 4).
- **Sin revocación.** No se consultan CRL ni OCSP; un certificado robado seguiría siendo válido hasta que expire (el del servidor vence el 19/10/2027).
- **La llave privada está en un archivo sin contraseña.** Quien lo lea puede suplantar al servidor. Por eso no se sube al repositorio y debe tener permisos restringidos.
- **El modo `plano` existe a propósito.** Nada impide que un usuario elija usarlo; el cliente no puede "bajar" por sí solo de TLS a texto plano, pero sí se le puede pedir. En un servicio real solo existiría TLS.
- **El *handshake* revela metadatos.** El nombre del servidor (SNI), las IP, los puertos y el tamaño y el momento de los mensajes se ven aunque el contenido esté cifrado.
- **Una hebra por conexión, sin límite.** Los tiempos de espera acotan cada conexión, pero un atacante que abra muchas podría agotar recursos del servidor.
- **El caso exitoso con el certificado real no corre en las pruebas automáticas** si falta `server.key`; allí se prueba con una PKI generada de la misma forma. La conexión con el certificado real se verifica a mano entre los dos equipos.
- **Protocolo de aplicación mínimo.** Un eco de líneas de texto, sin formato, versión ni manejo de errores propio.
