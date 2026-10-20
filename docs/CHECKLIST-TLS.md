# Checklist de pruebas: Parte 1 (cliente-servidor y TLS)

Todos los comandos se corren desde la raíz del repo, con el entorno virtual activo. Detalle de cada parte en [`README-TLS.md`](../README-TLS.md).

## 0. Preparación (en ambos equipos)
- [ ] `git pull` de la rama con los cambios.
- [ ] `pip install -r requirements.txt` termina sin errores.
- [ ] Los dos equipos están en la misma red y se hacen `ping` entre sí.
- [ ] Anotaste la IP del servidor (`ipconfig` en Windows, `ip a` en Linux).

## 1. Pruebas automáticas (un solo equipo)
- [ ] `python -m pytest -v tests/test_tls.py` da **12 passed, 1 skipped**.
- [ ] `python -m pytest -v` (suite completa) no tiene fallos. Debe dar 61 passed y 1 skipped, o 62 passed si ya tienes `server.key`.
- [ ] `bash docs/evidencias/generar_evidencias_tls.sh` regenera `docs/evidencias/tls/` sin errores.
- [ ] `demo-cliente-servidor.txt` muestra los 4 rechazos con códigos 18, 10, 62 y 20.

## 2. Modo sin protección (dos equipos)
- [ ] **Servidor:** `python -m tls.servidor --modo plano`. Debe imprimir que escucha en `0.0.0.0:5443`.
- [ ] **Servidor:** abriste el puerto con `netsh advfirewall firewall add rule name="Demo TLS" dir=in action=allow protocol=TCP localport=5443`.
- [ ] **Cliente:** `python -m tls.cliente --modo plano --host <IP_SERVIDOR>` devuelve `ECO: …` y muestra `(sin cifrado)`.
- [ ] Si falla, el cliente sale con código 1 y se revisó el firewall, la IP y que el servidor esté corriendo.

## 3. Modo TLS con el certificado real (dos equipos)
- [ ] Copiaste `pki/servidor/server.key` al servidor por un medio seguro (no está en el repo).
- [ ] **Servidor:** `python -m tls.servidor --modo tls` arranca sin error. Si falta la llave, sale con "No se pudo cargar el certificado o la llave".
- [ ] **Cliente:** `python -m tls.cliente --modo tls --host <IP_SERVIDOR> --hostname 222835-cliente-servidor.duckdns.org` muestra `TLSv1.3`, el cifrado y `ECO: …`.
- [ ] Con `--ca` apuntando a otro certificado, el cliente rechaza al servidor (código 2).
- [ ] Sin `--hostname` (se valida contra la IP), el cliente rechaza con `Hostname mismatch` (código 2). Eso confirma que el hostname sí se valida.
- [ ] `--hostname otro-servidor.com` también se rechaza.
- [ ] Al correr `python -m pytest -v tests/test_tls.py` con `server.key` presente, la prueba del certificado real pasa y ya no se omite.

## 4. Rechazo de certificados inválidos (dos equipos)
En el servidor, uno por uno (Ctrl+C entre cada uno). El cliente usa siempre `--modo tls --host <IP> --hostname 222835-cliente-servidor.duckdns.org` y debe terminar con **código 2** y no mostrar `ECO`.

- [ ] **Autofirmado** → código 18: `python -m tls.servidor --cert pki/malos/autofirmado.crt --llave pki/malos/autofirmado.key`
- [ ] **Otra CA** → código 20: `python -m tls.servidor --cert pki/malos/otra-ca.crt --llave pki/malos/otra-ca.key`
- [ ] **Nombre incorrecto** → código 62: `python -m tls.servidor --cert pki/malos/nombre-incorrecto-chain.crt --llave pki/malos/nombre-incorrecto.key`
- [ ] **Expirado** → código 10. Primero crea la cadena con `cat pki/malos/expirado.crt pki/intermedia/int.crt > expirado-chain.crt` (en PowerShell, `Get-Content … | Set-Content`). Luego `python -m tls.servidor --cert expirado-chain.crt --llave pki/malos/expirado.key`
- [ ] Tras cada rechazo, el servidor sigue vivo y atiende al siguiente cliente.

## 5. Mezclar modos (comportamiento esperado)
- [ ] Cliente `--modo tls` contra servidor `--modo plano` falla con error de TLS (código 1) y no envía el mensaje.
- [ ] Cliente `--modo plano` contra servidor `--modo tls` no recibe un `ECO` con el texto enviado.

## 6. Wireshark (en cualquiera de los dos equipos)
Captura en la interfaz de la red local (no en loopback), con el filtro de captura `tcp port 5443`.

- [ ] **Modo plano:** al hacer *Follow → TCP Stream* se lee en claro `usuario=ana clave=Secreta#2026` y la respuesta `ECO: …`. Guardar como `plano.pcapng`.
- [ ] **Modo TLS:** con el filtro `tls` aparecen Client Hello, Server Hello y Application Data. *Follow → TCP Stream* solo muestra bytes ilegibles. Guardar como `tls.pcapng`.
- [ ] En el Client Hello se ve el SNI (el nombre del servidor en claro).
- [ ] **Rechazo:** con un servidor de `pki/malos/`, aparece una alerta TLS (`Unknown CA`, `Certificate Expired`, etc.) y nunca un Application Data con el mensaje. Guardar como `tls-rechazo.pcapng`.
- [ ] Los `.pcapng` están en `docs/evidencias/tls/capturas/`.

## 7. Registro de eventos
- [ ] Existe `logs/eventos.jsonl` en cada equipo.
- [ ] Hay `servidor_iniciado`, `conexion_tcp` o `conexion_tls` (con protocolo y cifrado) y `mensaje_recibido`.
- [ ] Los rechazos aparecen como `WARNING`: `certificado_rechazado` en el cliente y `handshake_fallido` en el servidor.
- [ ] En el log no aparece el contenido de los mensajes, solo su tamaño.

## 8. Antes de entregar
- [ ] `server.key` **no** aparece en `git status` (debe seguir ignorado).
- [ ] `README-TLS.md` y la tabla de evidencias reflejan lo que realmente hiciste, incluidas las capturas que ya agregaste.
- [ ] Hiciste commit y push de `tls/`, `tests/test_tls.py`, los README y `docs/evidencias/tls/`.
