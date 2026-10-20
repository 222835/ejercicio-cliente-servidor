import argparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from comun import registro
from vpn.acceso_remoto import ServidorVPNAccesoRemoto, RECURSOS_INTERNOS
from vpn.auth import AlmacenUsuarios, ErrorAutenticacion, ErrorAutorizacion, PERMISOS_POR_ROL
from vpn.sitio_a_sitio import ErrorRuta, Gateway, vista_desde_internet
from vpn.tunel_ipsec import ErrorIPSec

consola = Console()
OK, NO = "[bold green]✔[/]", "[bold red]✘[/]"


def demo_acceso_remoto():
    consola.rule("[bold cyan]1. VPN de acceso remoto")
    almacen = AlmacenUsuarios()
    with consola.status("Creando usuarios con PBKDF2-SHA256 (600 000 iteraciones)..."):
        almacen.agregar("ana", "Admin#2026", "admin")
        almacen.agregar("beto", "Empleado#2026", "empleado")
        almacen.agregar("carla", "Invitada#2026", "invitado")
    vpn = ServidorVPNAccesoRemoto(almacen)

    u = almacen.obtener("beto")
    consola.print(Panel(f"usuario: beto\nsal:  {u.sal.hex()}\nhash: {u.hash_contrasena.hex()}",
                        title="Así se guarda una contraseña (nunca en texto plano)"))

    consola.print("\n[bold]Autenticación (¿quién eres?)[/]")
    sesiones = {}
    for nombre, clave in [("beto", "Empleado#2026"), ("beto", "123456"), ("mallory", "admin")]:
        try:
            s = vpn.conectar(nombre, clave, ip_origen="189.203.40.12")
            sesiones[nombre] = s
            consola.print(f"  {OK} {nombre}: conectado, IP virtual [cyan]{s.ip_virtual}[/]")
        except ErrorAutenticacion as e:
            consola.print(f"  {NO} {nombre}: {e}")

    consola.print("\n[bold]Autorización (¿qué puedes hacer?) después de conectar[/]")
    sesiones["ana"] = vpn.conectar("ana", "Admin#2026")
    sesiones["carla"] = vpn.conectar("carla", "Invitada#2026")
    sesiones = {n: sesiones[n] for n in ("ana", "beto", "carla")}
    t = Table(title="Acceso real a recursos internos por la VPN")
    t.add_column("Usuario (rol)")
    t.add_column("IP virtual")
    for r, info in RECURSOS_INTERNOS.items():
        t.add_column(f"{r}\n{info['ip']}", justify="center")
    for nombre, s in sesiones.items():
        fila = [f"{nombre} ({s.usuario.rol})", s.ip_virtual]
        for r in RECURSOS_INTERNOS:
            try:
                vpn.acceder(s.id, r)
                fila.append(OK)
            except ErrorAutorizacion:
                fila.append(NO)
        t.add_row(*fila)
    consola.print(t)

    consola.print("\n[bold]Operaciones administrativas[/]")
    for nombre in ("ana", "beto"):
        try:
            r = vpn.operacion_admin(sesiones[nombre].id, "listar_sesiones")
            consola.print(f"  {OK} {nombre} lista sesiones: {r}")
        except ErrorAutorizacion as e:
            consola.print(f"  {NO} {e}")


def demo_sitio_a_sitio():
    consola.rule("[bold magenta]2. VPN sitio a sitio")
    psk = b"PSK-matriz-sucursal-2026"
    matriz = Gateway("GW-Matriz", "10.1.0.0/24", "198.51.100.1", psk)
    sucursal = Gateway("GW-Sucursal", "10.2.0.0/24", "203.0.113.1", psk)
    consola.print(
        "  [10.1.0.0/24] ── GW-Matriz 198.51.100.1 ══[ túnel IPSec ]══ "
        "203.0.113.1 GW-Sucursal ── [10.2.0.0/24]\n")

    falso = Gateway("GW-Falso", "10.2.0.0/24", "192.0.2.66", b"adivinanza")
    try:
        matriz.establecer_tunel(falso)
    except ErrorAutenticacion as e:
        consola.print(f"  {NO} Gateway impostor: {e}")
    matriz.establecer_tunel(sucursal)
    consola.print(f"  {OK} Gateways autenticados con PSK (desafío-respuesta HMAC); claves derivadas con HKDF")
    consola.print("  [dim]Cifrado y anti-replay: módulo IPSec de la Parte 3 (IPSecSA + modo_tunel)[/]")

    p = matriz.enviar("10.1.0.5", "10.2.0.7", "Reporte de ventas Q3")
    v = vista_desde_internet(p)
    t = Table(title="El mismo paquete visto en cada punto")
    t.add_column("Punto"); t.add_column("Origen"); t.add_column("Destino"); t.add_column("Contenido")
    t.add_row("Red matriz (antes del GW)", "10.1.0.5", "10.2.0.7", "Reporte de ventas Q3")
    t.add_row("[red]Internet (lo que vería\nun sniffer)[/]", v["src"], v["dst"],
              f"ESP spi={v['spi']} seq={v['seq']}\n{v['carga']}")
    interno = sucursal.recibir(p)
    t.add_row("Red sucursal (después del GW)", interno["src"], interno["dst"], interno["datos"])
    consola.print(t)

    consola.print("\n[bold]Ataques[/]")
    try:
        sucursal.recibir(p)
    except ErrorIPSec as e:
        consola.print(f"  {NO} Reenvío del mismo paquete: {e}")
    p2 = matriz.enviar("10.1.0.5", "10.2.0.7", "Transferir $100")
    p2["encrypted_packet"] = "ff" + p2["encrypted_packet"][2:]
    try:
        sucursal.recibir(p2)
    except ErrorIPSec as e:
        consola.print(f"  {NO} Paquete modificado en tránsito: {e}")
    try:
        matriz.enviar("10.1.0.5", "8.8.8.8", "x")
    except ErrorRuta as e:
        consola.print(f"  {NO} Destino fuera de la VPN: {e}")


def comparativa():
    consola.rule("[bold]3. Acceso remoto vs. sitio a sitio")
    t = Table(show_lines=True)
    t.add_column("Aspecto", style="bold"); t.add_column("Acceso remoto"); t.add_column("Sitio a sitio")
    for fila in [
        ("Conecta", "Un usuario → red interna", "Red completa ↔ red completa"),
        ("Quién se autentica", "La persona (usuario + contraseña)", "Los gateways (PSK)"),
        ("Dirección", "IP virtual 10.8.0.x por sesión", "Rutas fijas 10.1.0.0/24 ↔ 10.2.0.0/24"),
        ("Duración", "Sesión con vencimiento", "Túnel permanente"),
        ("Control de acceso", "Por rol de usuario", "Por red/ruta"),
        ("Equipos finales", "Necesitan cliente VPN", "No saben que existe la VPN"),
    ]:
        t.add_row(*fila)
    consola.print(t)


def ultimos_eventos(n=12):
    consola.rule("[bold]4. Registro de eventos (logs/eventos.jsonl)")
    t = Table()
    for c in ("hora", "componente", "evento", "detalle"):
        t.add_column(c)
    for e in list(registro.historial)[-n:]:
        detalle = {k: v for k, v in e.items() if k not in ("timestamp", "nivel", "componente", "evento")}
        estilo = "red" if e["nivel"] == "WARNING" else ""
        t.add_row(e["timestamp"][11:19], e["componente"], f"[{estilo}]{e['evento']}[/]" if estilo else e["evento"],
                  ", ".join(f"{k}={v}" for k, v in list(detalle.items())[:4]))
    consola.print(t)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--remota", action="store_true")
    ap.add_argument("--sitio", action="store_true")
    args = ap.parse_args()
    todo = not (args.remota or args.sitio)
    if todo or args.remota:
        demo_acceso_remoto()
    if todo or args.sitio:
        demo_sitio_a_sitio()
    if todo:
        comparativa()
    ultimos_eventos()
