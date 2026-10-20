from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from comun.registro import registrar
from vpn.auth import ErrorAutenticacion
from vpn.tunel_ipsec import ErrorIPSec, crear_tunel_entrada, crear_tunel_salida


class ErrorRuta(Exception):
    pass


class Gateway:
    def __init__(self, nombre: str, red_local: str, ip_publica: str, psk: bytes):
        self.nombre = nombre
        self.red_local = ipaddress.ip_network(red_local)
        self.ip_publica = ip_publica
        self._psk = psk
        self._salida: dict = {}
        self._entrada: dict = {}

    def __repr__(self) -> str:
        return f"Gateway({self.nombre}, {self.red_local}, {self.ip_publica})"

    def _prueba(self, nonce_propio: bytes, nonce_par: bytes, identidad: str) -> bytes:
        return hmac.new(self._psk, identidad.encode() + nonce_propio + nonce_par,
                        hashlib.sha256).digest()

    def _verificar_par(self, par: "Gateway", nonce_par: bytes, nonce_propio: bytes,
                       prueba_recibida: bytes) -> bool:
        esperada = hmac.new(self._psk, par.nombre.encode() + nonce_par + nonce_propio,
                            hashlib.sha256).digest()
        return hmac.compare_digest(esperada, prueba_recibida)

    def establecer_tunel(self, par: "Gateway") -> None:
        registrar("negociacion_tunel", "vpn_s2s", gateway=self.nombre, par=par.nombre,
                  ip_local=self.ip_publica, ip_par=par.ip_publica)
        n_a, n_b = os.urandom(16), os.urandom(16)
        prueba_a = self._prueba(n_a, n_b, self.nombre)
        prueba_b = par._prueba(n_b, n_a, par.nombre)

        if not (self._verificar_par(par, n_b, n_a, prueba_b)
                and par._verificar_par(self, n_a, n_b, prueba_a)):
            registrar("tunel_rechazado", "vpn_s2s", gateway=self.nombre, par=par.nombre,
                      motivo="psk_no_coincide")
            raise ErrorAutenticacion(f"{par.nombre} no pudo autenticarse (PSK distinta)")

        material = HKDF(algorithm=hashes.SHA256(), length=64, salt=n_a + n_b,
                        info=b"vpn-sitio-a-sitio").derive(self._psk)
        clave_ida, clave_vuelta = material[:32], material[32:]
        spi_ida, spi_vuelta = (int.from_bytes(os.urandom(4), "big") for _ in range(2))

        self._salida[par.red_local] = (crear_tunel_salida(spi_ida, clave_ida), par)
        par._entrada[spi_ida] = (crear_tunel_entrada(spi_ida, clave_ida), self)
        par._salida[self.red_local] = (crear_tunel_salida(spi_vuelta, clave_vuelta), self)
        self._entrada[spi_vuelta] = (crear_tunel_entrada(spi_vuelta, clave_vuelta), par)

        registrar("tunel_establecido", "vpn_s2s", gateway=self.nombre, par=par.nombre,
                  red_local=str(self.red_local), red_remota=str(par.red_local),
                  spi_salida=hex(spi_ida), spi_entrada=hex(spi_vuelta))

    def enviar(self, ip_origen: str, ip_destino: str, datos: str) -> dict:
        if ipaddress.ip_address(ip_origen) not in self.red_local:
            registrar("ruta_rechazada", "vpn_s2s", gateway=self.nombre,
                      ip_origen=ip_origen, motivo="origen_fuera_de_red_local")
            raise ErrorRuta(f"{ip_origen} no pertenece a {self.red_local}")

        destino = ipaddress.ip_address(ip_destino)
        for red_remota, (tunel, par) in self._salida.items():
            if destino in red_remota:
                interno = {"src": ip_origen, "dst": ip_destino, "proto": "TCP", "datos": datos}
                paquete = tunel.encapsular(interno, self.ip_publica, par.ip_publica)
                registrar("paquete_enviado_tunel", "vpn_s2s", gateway=self.nombre,
                          ip_origen=ip_origen, ip_destino=ip_destino,
                          spi=hex(paquete["ipsec_header"]["spi"]), seq=paquete["ipsec_header"]["seq"])
                return paquete

        registrar("ruta_rechazada", "vpn_s2s", gateway=self.nombre,
                  ip_destino=ip_destino, motivo="sin_tunel_hacia_destino")
        raise ErrorRuta(f"No hay túnel hacia {ip_destino}")

    def recibir(self, paquete_esp: dict) -> dict:
        spi = paquete_esp["ipsec_header"]["spi"]
        entrada = self._entrada.get(spi)
        if entrada is None:
            registrar("paquete_rechazado", "vpn_s2s", gateway=self.nombre,
                      spi=hex(spi), motivo="spi_desconocido")
            raise ErrorIPSec("SPI desconocido: no hay SA para este paquete")
        tunel, par = entrada

        if paquete_esp["new_ip_header"]["src"] != par.ip_publica:
            registrar("paquete_rechazado", "vpn_s2s", gateway=self.nombre,
                      motivo="gateway_origen_inesperado")
            raise ErrorIPSec("El paquete no viene del gateway par")

        try:
            interno = tunel.desencapsular(paquete_esp)
        except ErrorIPSec as e:
            evento = "replay_detectado" if "Replay" in str(e) else "paquete_rechazado"
            registrar(evento, "vpn_s2s", gateway=self.nombre, spi=hex(spi),
                      seq=paquete_esp["ipsec_header"]["seq"], motivo=str(e))
            raise

        if ipaddress.ip_address(interno["dst"]) not in self.red_local:
            registrar("paquete_rechazado", "vpn_s2s", gateway=self.nombre,
                      motivo="destino_fuera_de_red_local", ip_destino=interno["dst"])
            raise ErrorRuta(f"{interno['dst']} no está en {self.red_local}")

        registrar("paquete_entregado", "vpn_s2s", gateway=self.nombre,
                  ip_origen=interno["src"], ip_destino=interno["dst"],
                  seq=paquete_esp["ipsec_header"]["seq"])
        return interno


def vista_desde_internet(paquete_esp: dict) -> dict:
    return {
        "src": paquete_esp["new_ip_header"]["src"],
        "dst": paquete_esp["new_ip_header"]["dst"],
        "proto": paquete_esp["new_ip_header"]["proto"],
        "spi": hex(paquete_esp["ipsec_header"]["spi"]),
        "seq": paquete_esp["ipsec_header"]["seq"],
        "carga": paquete_esp["encrypted_packet"][:48] + "...",
    }
