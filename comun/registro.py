"""Registro de eventos de seguridad (requerimiento 8).

Escribe un evento por línea en formato JSON (JSON Lines) en logs/eventos.jsonl.
Lo pueden usar todas las partes del proyecto:

    from comun.registro import registrar
    registrar("acceso_denegado", componente="vpn", usuario="ana", recurso="base_datos")

Cada línea queda así:
    {"timestamp": "2026-10-19T22:30:00+00:00", "nivel": "WARNING", "componente": "vpn",
     "evento": "acceso_denegado", "usuario": "ana", "recurso": "base_datos"}
"""
from __future__ import annotations

import json
import logging
import os
from collections import deque
from datetime import datetime, timezone

_NOMBRE_LOGGER = "seguridad"
RUTA_DEFECTO = os.environ.get("RUTA_LOG", os.path.join("logs", "eventos.jsonl"))

# Copia en memoria de los últimos eventos (útil para la demo y las pruebas).
historial: deque[dict] = deque(maxlen=2000)

# Eventos que se registran como advertencia por ser relevantes para seguridad.
EVENTOS_ADVERTENCIA = {
    "autenticacion_fallida",
    "cuenta_bloqueada",
    "acceso_denegado",
    "sesion_invalida",
    "paquete_rechazado",
    "replay_detectado",
    "tunel_rechazado",
    "integridad_fallida",
    "ruta_rechazada",
}


class FormatoJSON(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(record.evento_dict, ensure_ascii=False)


def configurar(ruta: str | None = None) -> logging.Logger:
    """(Re)configura el archivo de log. Se llama sola la primera vez."""
    logger = logging.getLogger(_NOMBRE_LOGGER)
    for h in list(logger.handlers):
        logger.removeHandler(h)
        h.close()
    ruta = ruta or RUTA_DEFECTO
    carpeta = os.path.dirname(ruta)
    if carpeta:
        os.makedirs(carpeta, exist_ok=True)
    manejador = logging.FileHandler(ruta, encoding="utf-8")
    manejador.setFormatter(FormatoJSON())
    logger.addHandler(manejador)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


def _logger() -> logging.Logger:
    logger = logging.getLogger(_NOMBRE_LOGGER)
    if not logger.handlers:
        configurar()
    return logger


def registrar(evento: str, componente: str = "general", **datos) -> dict:
    """Registra un evento y lo devuelve como diccionario."""
    nivel = logging.WARNING if evento in EVENTOS_ADVERTENCIA else logging.INFO
    registro = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "nivel": logging.getLevelName(nivel),
        "componente": componente,
        "evento": evento,
        **datos,
    }
    historial.append(registro)
    _logger().log(nivel, evento, extra={"evento_dict": registro})
    return registro


def eventos(tipo: str | None = None, componente: str | None = None) -> list[dict]:
    """Filtra el historial en memoria."""
    return [
        e for e in historial
        if (tipo is None or e["evento"] == tipo)
        and (componente is None or e["componente"] == componente)
    ]
