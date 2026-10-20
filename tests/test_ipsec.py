import pytest
import json
from ipsec import IPSecSA, IPSecSimulator 


# Un fixture en pytest es una configuracion inicial que se recicla para cada prueba.
# Aqui creamos nuestra SA y el Simulador para no tener que escribirlos en cada test.
@pytest.fixture
def ipsec_setup():
    llave = b"llave_secreta_16" 
    sa = IPSecSA(spi=100, key=llave)
    simulador = IPSecSimulator(sa)
    return sa, simulador

# --- 1 PRUEBA DE AMBOS MODOS (TRANSPORTE Y TUNEL) ---
def test_modo_transporte_cifrado_y_descifrado(ipsec_setup):
    sa, simulador = ipsec_setup
    header_original = {"src": "192.168.1.10", "dst": "192.168.1.20"}
    mensaje = "Transferencia bancaria"
    
    # Probamos el cifrado
    paquete_cifrado = simulador.modo_transporte(header_original, mensaje)
    
    # Verificamos que el IP original siga visible (caracteristica del modo transporte)
    assert paquete_cifrado["ip_header"] == header_original
    assert "encrypted_payload" in paquete_cifrado
    
    # Probamos el descifrado para confirmar que la logica funciona
    datos_cifrados_bytes = bytes.fromhex(paquete_cifrado["encrypted_payload"])
    secuencia = paquete_cifrado["ipsec_header"]["seq"]
    
    datos_descifrados = sa.decrypt_payload(datos_cifrados_bytes, secuencia)
    assert datos_descifrados.decode() == mensaje

def test_modo_tunel_cifrado_y_descifrado(ipsec_setup):
    sa, simulador = ipsec_setup
    paquete_interno = {"src": "10.0.0.5", "dst": "10.0.0.8", "data": "Secreto"}
    header_gateway = {"src": "200.1.1.1", "dst": "200.2.2.2"}
    
    # Probamos el cifrado
    paquete_cifrado = simulador.modo_tunel(paquete_interno, header_gateway)
    
    # Verificamos que el IP visible sea el del Gateway (caracteristica del modo tnel)
    assert paquete_cifrado["new_ip_header"] == header_gateway
    
    # Extraemos y desciframos para confirmar
    datos_cifrados_bytes = bytes.fromhex(paquete_cifrado["encrypted_packet"])
    secuencia = paquete_cifrado["ipsec_header"]["seq"]
    
    datos_descifrados = sa.decrypt_payload(datos_cifrados_bytes, secuencia)
    paquete_recuperado = json.loads(datos_descifrados.decode())
    
    assert paquete_recuperado == paquete_interno

# --- 2 PRUEBA DE ALTERACION DETECTADA POR GCM ---
def test_alteracion_paquete_falla(ipsec_setup):
    sa, _ = ipsec_setup
    mensaje = b"Datos confidenciales"
    secuencia = 1
    
    # Ciframos el mensaje legitimamente
    datos_cifrados = sa.encrypt_payload(mensaje, secuencia)
    
    # Simulamos a un hacker alterando un solo byte en el medio del paquete cifrado
    # Convertimos a un arreglo que se puede modificar (bytearray)
    datos_alterados = bytearray(datos_cifrados)
    datos_alterados[15] = datos_alterados[15] ^ 0xFF # Cambiamos los bits
    
    # Verificamos que al intentar descifrar el paquete alterado, lance la excepcion ValueError
    with pytest.raises(ValueError, match="El paquete fue alterado"):
        sa.decrypt_payload(bytes(datos_alterados), secuencia)

# --- 3 PRUEBA DE ANTI-REPLAY ---
def test_anti_replay_rechaza_duplicados_y_viejos(ipsec_setup):
    sa, _ = ipsec_setup
    
    # Paquete legitimo #1 es aceptado
    assert sa.check_replay(1) == True
    
    # El atacante intenta reenviar el paquete #1 inmediatamente (Duplicado)
    assert sa.check_replay(1) == False
    
    # Recibimos muchos paquetes legitimos (simulamos que llegamos a la secuencia 100)
    sa.check_replay(100)
    
    # El atacante intenta enviar un paquete muy viejo (secuencia 10), fuera de la ventana de 64
    assert sa.check_replay(10) == False

# --- 4 PRUEBA DE RECEPCION ---
def test_recibir_paquete_legitimo_y_rechazar_replay(ipsec_setup):
    sa, simulador = ipsec_setup
    paquete = simulador.modo_transporte({"src": "192.168.1.10", "dst": "192.168.1.20"}, "hola")
    seq = paquete["ipsec_header"]["seq"]
    datos = bytes.fromhex(paquete["encrypted_payload"])

    assert sa.recibir(seq, datos) == b"hola"
    with pytest.raises(ValueError, match="Replay"):
        sa.recibir(seq, datos)


def test_paquete_falso_no_consume_el_numero_de_secuencia(ipsec_setup):
    sa, simulador = ipsec_setup
    paquete = simulador.modo_transporte({"src": "192.168.1.10", "dst": "192.168.1.20"}, "pago")
    seq = paquete["ipsec_header"]["seq"]

    with pytest.raises(ValueError, match="alterado"):
        sa.recibir(seq, b"\x00" * 40)

    assert sa.recibir(seq, bytes.fromhex(paquete["encrypted_payload"])) == b"pago"


def test_secuencia_cero_invalida(ipsec_setup):
    sa, _ = ipsec_setup
    assert sa.check_replay(0) is False
