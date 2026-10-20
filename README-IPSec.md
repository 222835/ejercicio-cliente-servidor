# Parte 3: Simulación de IPSec (Capa de Red)

**Desarrollador:** Adán  
**Módulo:** `ipsec.py`

---

## 1. Función del Mecanismo y Arquitectura

Este módulo actúa como el motor criptográfico de la capa de red del proyecto, simulando el protocolo IPSec para asegurar la comunicación entre nodos. La arquitectura está diseñada para garantizar tres pilares fundamentales de la seguridad de la información: **Confidencialidad, Integridad y Autenticación del origen**.

### Motor Criptográfico (AES-GCM)
El núcleo de la seguridad utiliza **AES-GCM (Advanced Encryption Standard - Galois/Counter Mode)** provisto por la librería `cryptography`. AES-GCM es un algoritmo de Cifrado Autenticado (AEAD). 
* **Confidencialidad:** Cifra el texto plano utilizando una clave simétrica compartida y un *Nonce* (Number Used Once) de 12 bytes generado aleatoriamente para cada paquete, asegurando que dos mensajes idénticos produzcan textos cifrados completamente distintos.
* **Integridad:** Genera una etiqueta de autenticación (Tag) de 16 bytes mediante multiplicaciones en el campo de Galois. Si un atacante altera un solo bit del paquete en tránsito, la validación matemática fallará al momento de descifrar, lanzando una excepción (`InvalidTag`) y descartando el paquete.

### Prevención de Ataques (Ventana Anti-Replay)
Para mitigar los ataques de *Replay* (donde un atacante intercepta un paquete válido y lo retransmite más tarde para engañar al sistema), se implementó una **Ventana Deslizante de 64 posiciones**. 
* Cada paquete saliente recibe un número de secuencia único y correlativo.
* El receptor rastrea el número de secuencia más alto validado (`highest_seq`) y mantiene un registro en memoria de los últimos 64 paquetes recibidos.
* Si llega un paquete con un número de secuencia duplicado o un número que quedó rezagado fuera del límite de la ventana, es clasificado como tráfico malicioso y es rechazado instantáneamente.

---

## 2. Diferencia entre Mecanismos (Modos de Operación)

El simulador implementa y diferencia claramente los dos modos de encapsulamiento estándar de IPSec:

### Modo Transporte (Comunicación Host a Host)
* **Comportamiento:** Cifra y autentica de forma exclusiva el contenido del mensaje (*payload*), dejando el encabezado IP original intacto.
* **Caso de uso:** Ideal para conexiones de extremo a extremo dentro de una misma red. Las direcciones IP originales (origen y destino) siguen siendo visibles en la red, pero el contenido es ilegible para los intermediarios.

### Modo Túnel (VPN de Sitio a Sitio)
* **Comportamiento:** Toma el paquete IP original completo (incluyendo sus direcciones IP privadas locales) y lo cifra en su totalidad. Luego, envuelve este paquete cifrado agregando un encabezado IP completamente nuevo con las direcciones públicas de los enrutadores (Gateways).
* **Caso de uso:** Diseñado para interconectar redes corporativas a través de Internet (Parte 4 del proyecto). Al utilizar este modo, se oculta por completo la topología interna de la red local.

---

## 3. Limitaciones de Seguridad de la Solución

Al ser una simulación educativa en Python enfocada en demostrar la teoría de redes, este modelo presenta las siguientes limitaciones arquitectónicas respecto a un entorno de producción real:

1. **Gestión de Claves Estática:** No se ha implementado el protocolo IKE (*Internet Key Exchange*). Las claves simétricas se configuran manualmente en el código (Pre-Shared Keys). No hay soporte para Perfect Forward Secrecy (PFS), negociación asimétrica ni rotación automática de llaves por tiempo o volumen de datos.
2. **Abstracción de Capa de Aplicación:** El motor manipula diccionarios de Python (`json`) en la capa de aplicación, en lugar de interceptar flujos de bytes crudos (`Raw Sockets`) directamente en el kernel del sistema operativo o en la tarjeta de red (Capa 3 del modelo OSI).
3. **Estado Volátil:** El historial de la ventana anti-replay y los contadores de secuencia residen en la memoria RAM (estado volátil de la clase). Si el proceso de Python se reinicia, el contexto de la Asociación de Seguridad (SA) se pierde.

---

## 4. Instrucciones de Ejecución

Para ejecutar las pruebas aisladas de este módulo sin necesidad de iniciar la VPN completa, asegúrese de tener instalado Python 3.8+ y ejecute:

**Instalación de dependencias:**
```bash
pip install cryptography pytest rich
```

### 4.1. Laboratorio de Pruebas Automatizadas (Pytest)
Ejecute el marco de pruebas para validar la lógica matemática y de seguridad:
```bash
python -m pytest test_ipsec.py -v
```
*Las pruebas verifican el correcto encapsulamiento en ambos modos, la efectividad del rechazo anti-replay y la correcta detección de paquetes con el payload alterado maliciosamente.*

### 4.2. Demostración Visual (Lado a Lado)
Ejecute el script de demostración interactiva:
```bash
python demo_ipsec.py
```
*Este script utiliza la librería `rich` para generar una tabla comparativa en la terminal, mostrando lado a lado un paquete de red en texto plano, cómo se visualiza al aplicar el Modo Transporte (conservando IPs) y cómo se visualiza al aplicar el Modo Túnel (encapsulamiento total).*