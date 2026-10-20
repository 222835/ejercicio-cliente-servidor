"""Pruebas de la VPN de acceso remoto (req. 6 y 9)."""
import ipaddress

import pytest

from comun import registro
from vpn.acceso_remoto import ErrorSesion, ServidorVPNAccesoRemoto
from vpn.auth import ErrorAutenticacion, ErrorAutorizacion


@pytest.fixture
def servidor(almacen):
    return ServidorVPNAccesoRemoto(almacen)


def test_conexion_valida_asigna_ip_virtual(servidor):
    s = servidor.conectar("beto", "Empleado#2026")
    assert ipaddress.ip_address(s.ip_virtual) in ipaddress.ip_network("10.8.0.0/24")
    assert s.ip_virtual != servidor.ip_servidor
    assert registro.eventos("conexion_vpn_establecida")


def test_ips_virtuales_distintas(servidor):
    a = servidor.conectar("ana", "Admin#2026")
    b = servidor.conectar("beto", "Empleado#2026")
    assert a.ip_virtual != b.ip_virtual


def test_conexion_invalida_no_crea_sesion(servidor):
    with pytest.raises(ErrorAutenticacion):
        servidor.conectar("beto", "incorrecta")
    assert servidor.sesiones == {}
    assert registro.eventos("conexion_vpn_rechazada")


def test_empleado_acceso_permitido_y_denegado(servidor):
    s = servidor.conectar("beto", "Empleado#2026")
    assert "Servidor de archivos" in servidor.acceder(s.id, "archivos")
    assert "Wiki" in servidor.acceder(s.id, "wiki")
    with pytest.raises(ErrorAutorizacion):
        servidor.acceder(s.id, "base_datos")
    with pytest.raises(ErrorAutorizacion):
        servidor.acceder(s.id, "panel_admin")
    denegado = registro.eventos("acceso_denegado")[-1]
    assert denegado["usuario"] == "beto" and denegado["ip_virtual"] == s.ip_virtual


def test_invitado_solo_wiki(servidor):
    s = servidor.conectar("carla", "Invitada#2026")
    assert servidor.recursos_disponibles(s.id) == ["wiki"]
    servidor.acceder(s.id, "wiki")
    with pytest.raises(ErrorAutorizacion):
        servidor.acceder(s.id, "archivos")


def test_admin_accede_a_todo(servidor):
    s = servidor.conectar("ana", "Admin#2026")
    for r in ("archivos", "wiki", "base_datos", "panel_admin"):
        servidor.acceder(s.id, r)


def test_operacion_admin_permitida_y_registrada(servidor):
    s = servidor.conectar("ana", "Admin#2026")
    servidor.operacion_admin(s.id, "crear_usuario", nombre="dani", contrasena="Nuevo#1", rol="empleado")
    assert servidor.almacen.obtener("dani").rol == "empleado"
    ev = registro.eventos("operacion_administrativa")[-1]
    assert ev["operacion"] == "crear_usuario" and "contrasena" not in ev


def test_operacion_admin_denegada_a_empleado(servidor):
    s = servidor.conectar("beto", "Empleado#2026")
    with pytest.raises(ErrorAutorizacion):
        servidor.operacion_admin(s.id, "listar_sesiones")
    assert registro.eventos("operacion_admin_rechazada")


def test_sesion_falsa_o_cerrada(servidor):
    with pytest.raises(ErrorSesion):
        servidor.acceder("token-inventado", "wiki")
    s = servidor.conectar("carla", "Invitada#2026")
    servidor.desconectar(s.id)
    with pytest.raises(ErrorSesion):
        servidor.acceder(s.id, "wiki")


def test_sesion_vencida(almacen):
    ahora = [1000.0]
    srv = ServidorVPNAccesoRemoto(almacen, duracion_sesion=60, reloj=lambda: ahora[0])
    s = srv.conectar("beto", "Empleado#2026")
    ahora[0] += 61
    with pytest.raises(ErrorSesion, match="venció"):
        srv.acceder(s.id, "wiki")


def test_ip_se_libera_al_desconectar(servidor):
    s = servidor.conectar("beto", "Empleado#2026")
    ip = s.ip_virtual
    servidor.desconectar(s.id)
    assert ip in servidor._ips_libres


def test_reconexion_reutiliza_la_ip_mas_baja(servidor):
    a = servidor.conectar("beto", "Empleado#2026")
    b = servidor.conectar("ana", "Admin#2026")
    servidor.desconectar(a.id)
    c = servidor.conectar("beto", "Empleado#2026")
    assert c.ip_virtual == a.ip_virtual and c.ip_virtual != b.ip_virtual
