from __future__ import annotations

import json

from ipsec import IPSecSA, IPSecSimulator


class ErrorIPSec(Exception):
    pass


class TunelIPSec:
    def __init__(self, spi: int, clave: bytes):
        self.sa = IPSecSA(spi=spi, key=clave)
        self.simulador = IPSecSimulator(self.sa)

    @property
    def spi(self) -> int:
        return self.sa.spi

    def encapsular(self, paquete_interno: dict, ip_gw_origen: str, ip_gw_destino: str) -> dict:
        encabezado_externo = {"src": ip_gw_origen, "dst": ip_gw_destino, "proto": "ESP(50)"}
        return self.simulador.modo_tunel(paquete_interno, encabezado_externo)

    def desencapsular(self, paquete_esp: dict) -> dict:
        spi = paquete_esp["ipsec_header"]["spi"]
        seq = paquete_esp["ipsec_header"]["seq"]
        if spi != self.sa.spi:
            raise ErrorIPSec("SPI desconocido")
        try:
            datos = self.sa.recibir(seq, bytes.fromhex(paquete_esp["encrypted_packet"]))
        except ValueError as e:
            if "Replay" in str(e):
                raise ErrorIPSec(f"Replay detectado: seq={seq} ya recibido o fuera de la ventana") from None
            raise ErrorIPSec("Integridad fallida: el paquete fue alterado") from None
        return json.loads(datos)


def crear_tunel_salida(spi: int, clave: bytes) -> TunelIPSec:
    return TunelIPSec(spi, clave)


def crear_tunel_entrada(spi: int, clave: bytes) -> TunelIPSec:
    return TunelIPSec(spi, clave)
