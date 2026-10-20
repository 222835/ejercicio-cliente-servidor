from __future__ import annotations

import argparse
import os
import socket
import ssl
import sys
from dataclasses import dataclass

from comun.registro import registrar

RAIZ_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CA_DEFECTO = os.path.join(RAIZ_REPO, "pki", "root", "ca.crt")
PUERTO_DEFECTO = 5443
TIEMPO_ESPERA = 10


class ErrorCertificado(Exception):
    """El certificado del servidor no es de confianza; no se envió nada."""

    def __init__(self, motivo: str, codigo: int | None):
        super().__init__(motivo)
        self.motivo, self.codigo = motivo, codigo


@dataclass
class Resultado:
    respuesta: str
    protocolo: str | None
    cifrado: str | None


def crear_contexto(ca: str) -> ssl.SSLContext:
    # Con cafile solo se confía en esa CA (no en las del sistema). create_default_context
    # deja CERT_REQUIRED y check_hostname activos.
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _abrir(host: str, puerto: int, contexto: ssl.SSLContext | None,
           hostname: str) -> socket.socket:
    sock = socket.create_connection((host, puerto), timeout=TIEMPO_ESPERA)
    if contexto is None:
        return sock
    try:
        return contexto.wrap_socket(sock, server_hostname=hostname)
    except BaseException:
        sock.close()
        raise


def enviar(host: str, puerto: int, mensaje: str, modo: str = "tls",
           hostname: str | None = None, ca: str = CA_DEFECTO) -> Resultado:
    """Envía una línea y devuelve la respuesta.

    `host` es la dirección a la que se conecta (IP o nombre); `hostname` es el nombre que
    debe aparecer en el certificado (por defecto, `host`).
    """
    if modo not in ("plano", "tls"):
        raise ValueError(f"Modo desconocido: {modo}")
    hostname = hostname or host
    contexto = crear_contexto(ca) if modo == "tls" else None

    try:
        conexion = _abrir(host, puerto, contexto, hostname)
    except ssl.SSLCertVerificationError as e:
        registrar("certificado_rechazado", "tls", servidor=hostname, host=host,
                  motivo=e.verify_message, codigo=e.verify_code)
        raise ErrorCertificado(e.verify_message, e.verify_code) from e

    with conexion:
        with conexion.makefile("rwb") as f:
            f.write(mensaje.encode("utf-8") + b"\n")
            f.flush()
            linea = f.readline()
        if not linea:
            raise ConnectionError("El servidor cerró la conexión sin responder")

        protocolo = conexion.version() if contexto else None
        cifrado = conexion.cipher()[0] if contexto else None
    registrar("conexion_tls" if contexto else "conexion_tcp", "tls",
              servidor=hostname, host=host, protocolo=protocolo, cifrado=cifrado,
              resultado="ok")
    return Resultado(linea.decode("utf-8", errors="replace").rstrip("\r\n"),
                     protocolo, cifrado)


def main() -> None:
    p = argparse.ArgumentParser(description="Cliente de eco TCP, sin protección o con TLS")
    p.add_argument("--modo", choices=("plano", "tls"), default="tls")
    p.add_argument("--host", required=True, help="IP o nombre del servidor")
    p.add_argument("--puerto", type=int, default=PUERTO_DEFECTO)
    p.add_argument("--hostname", help="nombre que debe tener el certificado (por defecto, --host)")
    p.add_argument("--ca", default=CA_DEFECTO, help="certificado de la CA raíz (ca.crt)")
    p.add_argument("--mensaje", default="Mensaje de prueba: usuario=ana clave=Secreta#2026")
    a = p.parse_args()

    try:
        r = enviar(a.host, a.puerto, a.mensaje, a.modo, a.hostname, a.ca)
    except ErrorCertificado as e:
        print(f"CONEXIÓN RECHAZADA: certificado no confiable ({e.motivo}, código {e.codigo})")
        sys.exit(2)
    except (OSError, ssl.SSLError) as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    print(f"Modo: {a.modo.upper()}" + (f" · {r.protocolo} · {r.cifrado}" if r.protocolo else
                                       " (sin cifrado)"))
    print(f"Respuesta: {r.respuesta}")


if __name__ == "__main__":
    main()
