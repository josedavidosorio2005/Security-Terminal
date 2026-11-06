"""Gestion del alcance autorizado de un proyecto."""

from __future__ import annotations

import typer
from rich.table import Table

from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto
from eurabyte_security.core.validation import validar_red
from eurabyte_security.storage.database import Alcance, BaseDatos, Proyecto
from eurabyte_security.ui.consola import consola, mostrar_exito

alcance_app = typer.Typer(
    help="Gestiona el alcance autorizado (IP/CIDR) de un proyecto.", no_args_is_help=True
)


def agregar_alcance(base_datos: BaseDatos, proyecto: Proyecto, objetivo: str) -> Alcance:
    red = validar_red(objetivo)
    return base_datos.agregar_alcance(proyecto.id, str(red))


def listar_alcance(base_datos: BaseDatos, proyecto: Proyecto) -> list[Alcance]:
    return base_datos.listar_alcance(proyecto.id)


@alcance_app.command("agregar")
def agregar_cmd(
    objetivo: str = typer.Argument(..., help="IP o red CIDR autorizada (ej: 127.0.0.1/32)."),
    proyecto: str | None = typer.Option(
        None, "--proyecto", help="Proyecto al que se agrega el alcance (por defecto, el activo)."
    ),
) -> None:
    """Agrega una IP o red al alcance autorizado de un proyecto."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)
    alcance = agregar_alcance(base_datos, proyecto_obj, objetivo)
    mostrar_exito(f"Alcance '{alcance.red}' autorizado para el proyecto '{proyecto_obj.nombre}'.")


@alcance_app.command("listar")
def listar_cmd(
    proyecto: str | None = typer.Option(
        None, "--proyecto", help="Proyecto a consultar (por defecto, el activo)."
    ),
) -> None:
    """Lista el alcance autorizado de un proyecto."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)
    alcances = listar_alcance(base_datos, proyecto_obj)

    if not alcances:
        consola.print(f"El proyecto '{proyecto_obj.nombre}' no tiene alcance registrado.")
        return

    tabla = Table(title=f"Alcance autorizado - {proyecto_obj.nombre}")
    tabla.add_column("Red")
    tabla.add_column("Registrado")
    for alcance in alcances:
        tabla.add_row(alcance.red, alcance.creado_en)
    consola.print(tabla)
