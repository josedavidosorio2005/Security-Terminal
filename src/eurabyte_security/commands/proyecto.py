"""Gestion de proyectos de auditoria."""

from __future__ import annotations

import typer
from rich.table import Table

from eurabyte_security.commands._comun import obtener_base_datos
from eurabyte_security.core import config
from eurabyte_security.core.validation import validar_nombre_proyecto
from eurabyte_security.storage.database import BaseDatos, Proyecto
from eurabyte_security.ui.consola import consola, mostrar_exito

proyecto_app = typer.Typer(help="Gestiona proyectos de auditoria.", no_args_is_help=True)


def crear_proyecto(base_datos: BaseDatos, nombre: str) -> Proyecto:
    """Crea un proyecto y lo deja como proyecto activo."""
    nombre_valido = validar_nombre_proyecto(nombre)
    proyecto = base_datos.crear_proyecto(nombre_valido)
    config.establecer_proyecto_activo(proyecto.nombre)
    return proyecto


def listar_proyectos(base_datos: BaseDatos) -> tuple[list[Proyecto], str | None]:
    return base_datos.listar_proyectos(), config.obtener_proyecto_activo()


def usar_proyecto(base_datos: BaseDatos, nombre: str) -> Proyecto:
    """Marca un proyecto existente como proyecto activo."""
    proyecto = base_datos.obtener_proyecto_por_nombre(validar_nombre_proyecto(nombre))
    config.establecer_proyecto_activo(proyecto.nombre)
    return proyecto


@proyecto_app.command("crear")
def crear_cmd(nombre: str = typer.Argument(..., help="Nombre del nuevo proyecto.")) -> None:
    """Crea un nuevo proyecto de auditoria y lo activa."""
    proyecto = crear_proyecto(obtener_base_datos(), nombre)
    mostrar_exito(f"Proyecto '{proyecto.nombre}' creado y marcado como activo.")


@proyecto_app.command("listar")
def listar_cmd() -> None:
    """Lista todos los proyectos registrados."""
    proyectos, activo = listar_proyectos(obtener_base_datos())
    if not proyectos:
        consola.print("No hay proyectos registrados todavia.")
        return

    tabla = Table(title="Proyectos de EST")
    tabla.add_column("Activo")
    tabla.add_column("Nombre")
    tabla.add_column("Creado")
    for proyecto in proyectos:
        marca = "*" if proyecto.nombre == activo else ""
        tabla.add_row(marca, proyecto.nombre, proyecto.creado_en)
    consola.print(tabla)


@proyecto_app.command("usar")
def usar_cmd(nombre: str = typer.Argument(..., help="Nombre del proyecto a activar.")) -> None:
    """Marca un proyecto existente como proyecto activo."""
    proyecto = usar_proyecto(obtener_base_datos(), nombre)
    mostrar_exito(f"Proyecto activo: '{proyecto.nombre}'.")
