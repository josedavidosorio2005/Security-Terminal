"""Consulta de resultados de escaneos guardados."""

from __future__ import annotations

import typer
from rich.table import Table

from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto
from eurabyte_security.storage.database import BaseDatos, Proyecto, Resultado
from eurabyte_security.ui.consola import consola

_ESTILOS_ESTADO = {
    "abierto": "bold green",
    "cerrado": "grey70",
    "error": "bold red",
}


def obtener_resultados(
    base_datos: BaseDatos, proyecto: Proyecto, limite: int = 200
) -> list[Resultado]:
    return base_datos.listar_resultados(proyecto.id, limite=limite)


def resultados_cmd(
    proyecto: str | None = typer.Option(
        None, "--proyecto", help="Proyecto a consultar (por defecto, el activo)."
    ),
    limite: int = typer.Option(50, "--limite", help="Numero maximo de resultados a mostrar."),
) -> None:
    """Muestra los resultados de escaneos guardados para un proyecto."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)
    resultados = obtener_resultados(base_datos, proyecto_obj, limite=limite)

    if not resultados:
        consola.print(f"El proyecto '{proyecto_obj.nombre}' no tiene resultados guardados.")
        return

    tabla = Table(title=f"Resultados - {proyecto_obj.nombre}")
    tabla.add_column("Objetivo")
    tabla.add_column("Puerto")
    tabla.add_column("Estado")
    tabla.add_column("Fecha")
    for resultado in resultados:
        estilo = _ESTILOS_ESTADO.get(resultado.estado, "")
        tabla.add_row(
            resultado.objetivo,
            str(resultado.puerto),
            f"[{estilo}]{resultado.estado}[/{estilo}]",
            resultado.creado_en,
        )
    consola.print(tabla)
