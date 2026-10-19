"""Adaptador del modo túnel de IPSec para la VPN sitio a sitio.

La implementación real de IPSec es la Parte 3 (Adán). Para que la Parte 4 se
pueda probar desde ya, aquí hay una versión mínima compatible:
  - SA con SPI, clave y algoritmo (AES-256-GCM)
  - Modo túnel: cifra el paquete IP completo y agrega un encabezado externo
  - Anti-replay con número de secuencia y ventana deslizante de 64

PARA INTEGRAR LA PARTE 3: solo hay que cambiar crear_tunel_salida() y
crear_tunel_entrada() para que devuelvan objetos de Adán que tengan los métodos
encapsular(paquete, ip_gw_origen, ip_gw_destino) -> dict y
desencapsular(paquete_esp) -> dict. El resto del código no cambia.
"""
from __future__ import annotations

import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class ErrorIPSec(Exception):
    """Paquete rechazado (replay, alteración o SPI desconocido)."""


class VentanaAntiReplay:
    """Ventana deslizante estilo RFC 4303 con un mapa de bits."""

    def __init__(self, tamano: int = 64):
        self.tamano = tamano
        self.mayor = 0
        self.mapa = 0

    def es_valido(self, seq: int) -> tuple[bool, str]:
        if seq <= 0:
            return False, "secuencia inválida"
        if seq > self.mayor:
            return True, "nuevo"
        diferencia = self.mayor - seq
        if diferencia >= self.tamano:
            return False, "demasiado viejo (fuera de la ventana)"
        if (self.mapa >> diferencia) & 1:
            return False, "duplicado (replay)"
        return True, "dentro de la ventana"

    def marcar(self, seq: int) -> None:
        mascara = (1 << self.tamano) - 1
        if seq > self.mayor:
            self.mapa = ((self.mapa << (seq - self.mayor)) | 1) & mascara
            self.mayor = seq
        else:
            self.mapa |= 1 << (self.mayor - seq)


class TunelSimulado:
    """Una SA unidireccional en modo túnel."""

    ALGORITMO = "AES-256-GCM"

    def __init__(self, spi: int, clave: bytes):
        self.spi = spi
        self.clave = clave
        self._aes = AESGCM(clave)
        self.seq_salida = 0
        self.ventana = VentanaAntiReplay(64)

    @staticmethod
    def _aad(encabezado_externo: dict, spi: int, seq: int) -> bytes:
        # El encabezado ESP y el externo se autentican (no se cifran) para detectar alteraciones.
        return json.dumps({"ext": encabezado_externo, "spi": spi, "seq": seq},
                          sort_keys=True).encode()

    def encapsular(self, paquete_interno: dict, ip_gw_origen: str, ip_gw_destino: str) -> dict:
        self.seq_salida += 1
        externo = {"src": ip_gw_origen, "dst": ip_gw_destino, "proto": "ESP(50)"}
        nonce = os.urandom(12)
        texto = json.dumps(paquete_interno, sort_keys=True).encode()
        cifrado = self._aes.encrypt(nonce, texto, self._aad(externo, self.spi, self.seq_salida))
        return {
            "encabezado_ip_externo": externo,
            "esp": {"spi": self.spi, "seq": self.seq_salida},
            "nonce": nonce.hex(),
            "carga_cifrada": cifrado.hex(),   # incluye la etiqueta GCM de 16 bytes
        }

    def desencapsular(self, paquete_esp: dict) -> dict:
        spi, seq = paquete_esp["esp"]["spi"], paquete_esp["esp"]["seq"]
        if spi != self.spi:
            raise ErrorIPSec("SPI desconocido")
        valido, motivo = self.ventana.es_valido(seq)
        if not valido:
            raise ErrorIPSec(f"Replay detectado: seq={seq} {motivo}")
        try:
            texto = self._aes.decrypt(bytes.fromhex(paquete_esp["nonce"]),
                                      bytes.fromhex(paquete_esp["carga_cifrada"]),
                                      self._aad(paquete_esp["encabezado_ip_externo"], spi, seq))
        except InvalidTag:
            raise ErrorIPSec("Integridad fallida: el paquete fue alterado") from None
        # Solo se marca la secuencia cuando el paquete es auténtico.
        self.ventana.marcar(seq)
        return json.loads(texto)


def crear_tunel_salida(spi: int, clave: bytes) -> TunelSimulado:
    return TunelSimulado(spi, clave)


def crear_tunel_entrada(spi: int, clave: bytes) -> TunelSimulado:
    return TunelSimulado(spi, clave)
