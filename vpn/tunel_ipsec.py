"""Puente entre la VPN sitio a sitio (Parte 4) y el IPSec de la Parte 3.

La VPN sitio a sitio no implementa criptografía propia: reutiliza
IPSecSA (SPI, clave AES-GCM, ventana anti-replay de 64) e IPSecSimulator
(modo túnel) del módulo ipsec/ de Adán.

Este archivo solo agrega lo que la VPN necesita del lado receptor:
desencapsular un paquete en modo túnel en el orden correcto.
"""
from __future__ import annotations

import json

from ipsec import IPSecSA, IPSecSimulator


class ErrorIPSec(Exception):
    """Paquete rechazado (replay, alteración o SPI desconocido)."""


class TunelIPSec:
    """Una SA unidireccional en modo túnel, construida con la Parte 3."""

    def __init__(self, spi: int, clave: bytes):
        self.sa = IPSecSA(spi=spi, key=clave)
        self.simulador = IPSecSimulator(self.sa)

    @property
    def spi(self) -> int:
        return self.sa.spi

    def encapsular(self, paquete_interno: dict, ip_gw_origen: str, ip_gw_destino: str) -> dict:
        """Usa modo_tunel() de la Parte 3: cifra el paquete IP completo y
        agrega un encabezado IP nuevo entre gateways."""
        encabezado_externo = {"src": ip_gw_origen, "dst": ip_gw_destino, "proto": "ESP(50)"}
        return self.simulador.modo_tunel(paquete_interno, encabezado_externo)

    def desencapsular(self, paquete_esp: dict) -> dict:
        """Verifica y descifra un paquete en modo túnel.

        Orden importante: primero se comprueba la integridad con AES-GCM y
        SOLO si el paquete es auténtico se registra su número de secuencia en
        la ventana anti-replay. Si se hiciera al revés, un atacante podría
        mandar un paquete falso con el número de secuencia del siguiente
        paquete legítimo y hacer que este se rechazara como "duplicado".
        """
        spi = paquete_esp["ipsec_header"]["spi"]
        seq = paquete_esp["ipsec_header"]["seq"]
        if spi != self.sa.spi:
            raise ErrorIPSec("SPI desconocido")
        try:
            # IPSecSA.recibir() revisa replay, verifica GCM y solo entonces marca el seq.
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
