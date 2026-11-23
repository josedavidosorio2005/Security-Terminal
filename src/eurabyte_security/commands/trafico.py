"""Comandos y presentación del análisis pasivo de tráfico."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Group
from rich.table import Table
from rich.text import Text

from eurabyte_security.core.errores import ErrorEST
from eurabyte_security.modules.network.trafico import (
    MedicionLocal,
    ResumenRed,
    medir_equipo,
    resumir_red,
)
from eurabyte_security.ui.consola import consola, mostrar_error

trafico_app = typer.Typer(help="Mide el equipo o resume registros de tráfico de tu red.")


def _unidad(cantidad: int) -> str:
    for unidad, divisor in (("GB", 10**9), ("MB", 10**6), ("kB", 10**3)):
        if cantidad >= divisor:
            return f"{cantidad / divisor:.2f} {unidad}"
    return f"{cantidad} B"


def _nombre_local(nombre: str) -> Text:
    return Text("".join(c for c in nombre if c.isprintable()))


def mostrar_medicion(medicion: MedicionLocal) -> Group:
    interfaces = Table("Interfaz", "Carga", "Descarga", "↑ Mb/s", "↓ Mb/s")
    for nombre, volumen in sorted(medicion.interfaces.items()):
        interfaces.add_row(
            _nombre_local(nombre),
            _unidad(volumen.carga),
            _unidad(volumen.descarga),
            f"{volumen.carga * 8 / medicion.segundos / 10**6:.2f}",
            f"{volumen.descarga * 8 / medicion.segundos / 10**6:.2f}",
        )
    aplicaciones = Table("Aplicación local", "Conexiones con destino remoto")
    for nombre, cantidad in medicion.aplicaciones:
        aplicaciones.add_row(_nombre_local(nombre), str(cantidad))
    if medicion.conexiones_sin_nombre:
        aplicaciones.add_row("Sin nombre disponible", str(medicion.conexiones_sin_nombre))
    detalle_apps = (
        "Conexiones observadas al final de la muestra. La visibilidad depende de los permisos."
        if medicion.aplicaciones_disponibles
        else "El sistema no permitió consultar las aplicaciones."
    )
    return Group(
        Text(f"Este equipo · {medicion.segundos:.2f} s de medición", style="bold cyan"),
        interfaces if interfaces.row_count else Text("No hay interfaces comparables."),
        Text(detalle_apps),
        aplicaciones if aplicaciones.row_count else Text("Sin aplicaciones identificadas."),
    )


def mostrar_red(resumen: ResumenRed) -> Group:
    dispositivos = Table("Equipo (IP)", "Carga", "Descarga")
    for equipo, volumen in resumen.dispositivos:
        dispositivos.add_row(equipo, _unidad(volumen.carga), _unidad(volumen.descarga))
    servicios = Table("Servicio detectado", "Carga", "Descarga")
    for servicio, volumen in resumen.servicios:
        servicios.add_row(servicio, _unidad(volumen.carga), _unidad(volumen.descarga))
    dominios = Table("Dominio DNS", "Consultas")
    for dominio, cantidad in resumen.dominios or []:
        dominios.add_row(dominio, str(cantidad))
    dominios_web = Table("Dominio observado", "Fuente", "Eventos")
    for (dominio, origen), cantidad in resumen.dominios_web or []:
        dominios_web.add_row(dominio, origen, str(cantidad))
    return Group(
        Text(
            f"Carga {_unidad(resumen.total.carga)}  ·  Descarga {_unidad(resumen.total.descarga)}",
            style="bold cyan",
        ),
        Text(
            f"{resumen.flujos} flujos entre la LAN y otras redes · "
            f"{resumen.flujos_incompletos} sin contadores completos · "
            f"{resumen.registros_invalidos} registros inválidos"
        ),
        dispositivos if dispositivos.row_count else Text("Sin flujos entre la LAN y otras redes."),
        servicios if servicios.row_count else Text("Sin servicios detectados en el registro."),
        dominios if dominios.row_count else Text(
            "Importa dns.log para ver dominios." if resumen.dominios is None
            else "Sin consultas DNS de clientes LAN en el registro."
        ),
        dominios_web if dominios_web.row_count else Text(
            "Importa http.log o ssl.log para ver dominios HTTP o TLS."
            if resumen.dominios_web is None
            else "Sin dominios HTTP o TLS visibles para clientes LAN en el registro."
        ),
        Text(
            "El ranking cuenta consultas DNS. La caché, el cifrado y las consultas de fondo "
            "afectan la cobertura."
        ),
    )


@trafico_app.command("equipo")
def equipo(segundos: Annotated[float, typer.Option("--segundos", min=0.2, max=10)] = 1) -> None:
    """Mide carga, descarga y conexiones por aplicación en este equipo."""
    try:
        consola.print(mostrar_medicion(medir_equipo(segundos)))
    except ErrorEST as exc:
        mostrar_error(str(exc))
        raise typer.Exit(1) from exc


@trafico_app.command("red")
def red(
    conexiones: Annotated[Path, typer.Argument(help="Ruta al conn.log JSON de Zeek.")],
    lan: Annotated[str, typer.Option("--lan", help="Subredes LAN en CIDR separadas por comas.")],
    dns: Annotated[Path | None, typer.Option("--dns", help="Ruta al dns.log JSON de Zeek.")] = None,
    web: Annotated[Path | None, typer.Option("--web", help="Ruta a http.log o ssl.log.")] = None,
) -> None:
    """Resume carga, descarga, servicios y dominios de registros de la red."""
    try:
        consola.print(mostrar_red(resumir_red(
            conexiones.expanduser(),
            lan,
            dns.expanduser() if dns else None,
            web.expanduser() if web else None,
        )))
    except ErrorEST as exc:
        mostrar_error(str(exc))
        raise typer.Exit(1) from exc
