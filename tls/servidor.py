from __future__ import annotations

import argparse
import os
import socket
import ssl
import threading

from comun.registro import registrar

RAIZ_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CERT_DEFECTO = os.path.join(RAIZ_REPO, "pki", "servidor", "server-chain.crt")
LLAVE_DEFECTO = os.path.join(RAIZ_REPO, "pki", "servidor", "server.key")
PUERTO_DEFECTO = 5443
MAX_LINEA = 4096
TIEMPO_ESPERA = 10


class Servidor:
    """Servidor TCP de eco, con o sin TLS. Una línea recibida es una línea devuelta."""

    def __init__(self, host: str = "0.0.0.0", puerto: int = PUERTO_DEFECTO,
                 modo: str = "tls", cert: str | None = None, llave: str | None = None):
        if modo not in ("plano", "tls"):
            raise ValueError(f"Modo desconocido: {modo}")
        self.host, self.puerto, self.modo = host, puerto, modo
        self._contexto = self._crear_contexto(cert or CERT_DEFECTO,
                                              llave or LLAVE_DEFECTO) if modo == "tls" else None
        self._socket: socket.socket | None = None
        self._hilo: threading.Thread | None = None

    @staticmethod
    def _crear_contexto(cert: str, llave: str) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=cert, keyfile=llave)
        return ctx

    def iniciar(self) -> None:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self.host, self.puerto))
        self._socket.listen()
        self.puerto = self._socket.getsockname()[1]
        registrar("servidor_iniciado", "tls", modo=self.modo, host=self.host,
                  puerto=self.puerto)
        self._hilo = threading.Thread(target=self._aceptar, daemon=True)
        self._hilo.start()

    def detener(self) -> None:
        if self._socket:
            self._socket.close()
        if self._hilo:
            self._hilo.join(timeout=2)

    def esperar(self) -> None:
        self._hilo.join()

    def _aceptar(self) -> None:
        while True:
            try:
                conexion, direccion = self._socket.accept()
            except OSError:
                return  # el socket de escucha se cerró
            threading.Thread(target=self._atender, args=(conexion, direccion[0]),
                             daemon=True).start()

    def _atender(self, conexion: socket.socket, cliente: str) -> None:
        try:
            conexion.settimeout(TIEMPO_ESPERA)
            if self._contexto:
                # El handshake va en el hilo de la conexión para que un cliente lento
                # o malicioso no bloquee a los demás.
                conexion = self._contexto.wrap_socket(conexion, server_side=True)
                registrar("conexion_tls", "tls", cliente=cliente,
                          protocolo=conexion.version(), cifrado=conexion.cipher()[0])
            else:
                registrar("conexion_tcp", "tls", cliente=cliente)
            self._eco(conexion, cliente)
        except (ssl.SSLError, OSError) as e:
            registrar("handshake_fallido" if self._contexto else "conexion_error", "tls",
                      cliente=cliente, motivo=getattr(e, "reason", None) or str(e))
        finally:
            conexion.close()

    def _eco(self, conexion: socket.socket, cliente: str) -> None:
        with conexion.makefile("rwb") as f:
            while True:
                linea = f.readline(MAX_LINEA + 1)
                if not linea:
                    return
                if len(linea) > MAX_LINEA:
                    registrar("mensaje_rechazado", "tls", cliente=cliente,
                              motivo="linea_demasiado_larga")
                    return
                registrar("mensaje_recibido", "tls", cliente=cliente, bytes=len(linea))
                f.write(b"ECO: " + linea)
                f.flush()


def main() -> None:
    p = argparse.ArgumentParser(description="Servidor de eco TCP, sin protección o con TLS")
    p.add_argument("--modo", choices=("plano", "tls"), default="tls")
    p.add_argument("--host", default="0.0.0.0", help="interfaz donde escucha")
    p.add_argument("--puerto", type=int, default=PUERTO_DEFECTO)
    p.add_argument("--cert", default=CERT_DEFECTO, help="certificado del servidor + intermedia")
    p.add_argument("--llave", default=LLAVE_DEFECTO, help="llave privada del servidor")
    a = p.parse_args()

    try:
        s = Servidor(a.host, a.puerto, a.modo, a.cert, a.llave)
    except (OSError, ssl.SSLError) as e:
        raise SystemExit(f"No se pudo cargar el certificado o la llave: {e}")
    s.iniciar()
    print(f"Servidor en modo {a.modo.upper()} escuchando en {a.host}:{s.puerto} (Ctrl+C para salir)")
    try:
        s.esperar()
    except KeyboardInterrupt:
        s.detener()


if __name__ == "__main__":
    main()
