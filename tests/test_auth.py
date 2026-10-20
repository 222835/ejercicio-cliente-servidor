import json

import pytest

from comun import registro
from vpn.auth import (MAX_INTENTOS, ErrorAutenticacion, autenticar, autorizar,
                      hashear_contrasena)


def test_contrasena_no_se_guarda_en_texto_plano(almacen):
    u = almacen.obtener("ana")
    assert b"Admin#2026" not in u.hash_contrasena
    assert len(u.sal) == 16 and len(u.hash_contrasena) == 32
    assert "Admin" not in repr(u)


def test_misma_contrasena_distinta_sal_distinto_hash():
    s1, h1 = hashear_contrasena("igual", iteraciones=1000)
    s2, h2 = hashear_contrasena("igual", iteraciones=1000)
    assert s1 != s2 and h1 != h2


def test_login_valido(almacen):
    u = autenticar(almacen, "ana", "Admin#2026")
    assert u.nombre == "ana" and u.rol == "admin"
    assert registro.eventos("autenticacion_exitosa")


def test_login_contrasena_incorrecta(almacen):
    with pytest.raises(ErrorAutenticacion):
        autenticar(almacen, "ana", "mala")
    assert registro.eventos("autenticacion_fallida")[-1]["motivo"] == "contrasena_incorrecta"


def test_login_usuario_inexistente_mismo_mensaje(almacen):
    with pytest.raises(ErrorAutenticacion) as e1:
        autenticar(almacen, "nadie", "x")
    with pytest.raises(ErrorAutenticacion) as e2:
        autenticar(almacen, "ana", "x")
    assert str(e1.value) == str(e2.value)


def test_bloqueo_tras_intentos_fallidos(almacen):
    for _ in range(MAX_INTENTOS):
        with pytest.raises(ErrorAutenticacion):
            autenticar(almacen, "beto", "mala")
    with pytest.raises(ErrorAutenticacion, match="bloqueada"):
        autenticar(almacen, "beto", "Empleado#2026")
    assert registro.eventos("cuenta_bloqueada")


@pytest.mark.parametrize("rol_usuario,recurso,esperado", [
    ("ana", "base_datos", True), ("ana", "panel_admin", True),
    ("beto", "archivos", True), ("beto", "wiki", True),
    ("beto", "base_datos", False), ("beto", "panel_admin", False),
    ("carla", "wiki", True), ("carla", "archivos", False),
])
def test_autorizacion_por_rol(almacen, rol_usuario, recurso, esperado):
    assert autorizar(almacen.obtener(rol_usuario), recurso) is esperado


def test_autenticado_no_implica_autorizado(almacen):
    u = autenticar(almacen, "carla", "Invitada#2026")
    assert autorizar(u, "base_datos") is False


def test_log_es_json_por_linea(almacen, log_temporal):
    autenticar(almacen, "ana", "Admin#2026")
    with pytest.raises(ErrorAutenticacion):
        autenticar(almacen, "ana", "mala")
    lineas = log_temporal.read_text(encoding="utf-8").strip().splitlines()
    eventos = [json.loads(l) for l in lineas]
    assert {"timestamp", "nivel", "componente", "evento"} <= eventos[0].keys()
    assert eventos[-1]["nivel"] == "WARNING"
    assert "Admin#2026" not in log_temporal.read_text(encoding="utf-8")
