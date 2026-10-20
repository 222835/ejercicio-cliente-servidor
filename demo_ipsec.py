import json
from rich.console import Console
from rich.table import Table
from ipsec import IPSecSA, IPSecSimulator

def ejecutar_demo():
    # 1 Configuracion inicial (como si ya estuviera conectado)
    llave = b"1234567890123456" # Exactamente 16 bytes (Correcto)
    sa = IPSecSA(spi=555, key=llave)
    simulador = IPSecSimulator(sa)

    # 2 Definimos los datos de prueba
    ip_original = {"src": "192.168.1.10", "dst": "192.168.1.20"}
    mensaje = "Datos confidenciales: NIP 4321"
    
    # Paquete original como se veria sin proteccion
    paquete_original = {
        "ip_header": ip_original,
        "payload": mensaje
    }

    # 3 Aplicamos el Modo Transporte
    paquete_transporte = simulador.modo_transporte(ip_original, mensaje)

    # 4 Aplicamos el Modo Tunel
    ip_gateways = {"src": "200.10.10.1", "dst": "200.20.20.2"}
    paquete_tunel = simulador.modo_tunel(paquete_original, ip_gateways)

    # 5 --- VISUALIZACION LADO A LADO CON 'RICH' ---
    console = Console()
    
    # Creamos una tabla con 3 columnas
    tabla = Table(title="Demostración IPSec: Lado a Lado", show_lines=True)
    tabla.add_column("1. Paquete Original\n(Sin protección)", style="red", justify="left")
    tabla.add_column("2. Modo Transporte\n(Cifra payload, IP visible)", style="yellow", justify="left")
    tabla.add_column("3. Modo Túnel\n(Cifra todo, nueva IP)", style="green", justify="left")

    # Formateamos los diccionarios a texto JSON con sangria para que se vean como bloques de codigo
    str_original = json.dumps(paquete_original, indent=2)
    str_transporte = json.dumps(paquete_transporte, indent=2)
    str_tunel = json.dumps(paquete_tunel, indent=2)

    # Añadimos la fila con los 3 textos
    tabla.add_row(str_original, str_transporte, str_tunel)

    # Imprimimos la tabla en consola
    console.print(tabla)

if __name__ == "__main__":
    ejecutar_demo()