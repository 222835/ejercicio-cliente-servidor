import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from comun import registro  # noqa: E402
from vpn.auth import AlmacenUsuarios  # noqa: E402

ITERACIONES_PRUEBA = 1_000  # bajo solo para que las pruebas sean rápidas


@pytest.fixture(autouse=True)
def log_temporal(tmp_path):
    ruta = tmp_path / "eventos.jsonl"
    registro.configurar(str(ruta))
    registro.historial.clear()
    yield ruta


@pytest.fixture
def almacen():
    a = AlmacenUsuarios(iteraciones=ITERACIONES_PRUEBA)
    a.agregar("ana", "Admin#2026", "admin")
    a.agregar("beto", "Empleado#2026", "empleado")
    a.agregar("carla", "Invitada#2026", "invitado")
    return a
