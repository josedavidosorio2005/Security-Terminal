"""Generacion de informes de auditoria (HTML/JSON)."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import typer

from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto
from eurabyte_security.core.config import ruta_reportes
from eurabyte_security.core.errores import ErrorValidacion
from eurabyte_security.modules.reporting.generador import (
    construir_datos_informe_global,
    generar_html_global,
    generar_json_global,
)
from eurabyte_security.storage.database import BaseDatos, Proyecto
from eurabyte_security.ui.consola import mostrar_exito

reporte_app = typer.Typer(help="Genera informes a partir de los resultados guardados.")

FORMATOS_VALIDOS = {"html", "json"}


def generar_reporte(
    base_datos: BaseDatos, proyecto: Proyecto, formato: str, salida: Path | None = None
) -> Path:
    """Genera el informe GLOBAL de la auditoria: combina las cinco herramientas.

    Reutiliza ``BaseDatos.listar_resultados_unificados`` (nunca borra ni migra datos:
    cada herramienta sigue teniendo su propia tabla y su propio informe, ver
    ``est nuclei reporte``/``est zap reporte``/``est web reporte``). El informe global
    aplica, ademas, una segunda pasada de redaccion propia (ver
    ``modules/reporting/generador.py:_redactar_resultado_unificado``) antes de exportar
    cualquier dato.
    """
    formato = formato.lower()
    if formato not in FORMATOS_VALIDOS:
        raise ErrorValidacion(
            f"Formato '{formato}' no soportado. Usa uno de: {', '.join(sorted(FORMATOS_VALIDOS))}."
        )

    resultados = base_datos.listar_resultados_unificados(proyecto.id, limite=10_000)
    alcance = tuple(a.red for a in base_datos.listar_alcance(proyecto.id))
    datos = construir_datos_informe_global(proyecto.nombre, resultados, alcance=alcance)
    contenido = (
        generar_html_global(datos) if formato == "html" else generar_json_global(datos)
    )

    if salida is None:
        marca_tiempo = datetime.now().strftime("%Y%m%d-%H%M%S")
        ruta_salida = (
            ruta_reportes() / f"informe-global-{proyecto.nombre}-{marca_tiempo}.{formato}"
        )
    else:
        ruta_salida = salida
    ruta_salida.parent.mkdir(parents=True, exist_ok=True)
    ruta_salida.write_text(contenido, encoding="utf-8")
    return ruta_salida


@reporte_app.command("generar")
def generar_cmd(
    formato: str = typer.Option("html", "--formato", help="Formato del informe: html o json."),
    proyecto: str | None = typer.Option(
        None, "--proyecto", help="Proyecto a reportar (por defecto, el activo)."
    ),
    salida: Path | None = typer.Option(  # noqa: B008
        None, "--salida", help="Ruta del archivo de salida (por defecto, se genera una)."
    ),
) -> None:
    """Genera el informe global (todas las herramientas) en HTML o JSON de un proyecto."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)
    ruta = generar_reporte(base_datos, proyecto_obj, formato, salida)
    mostrar_exito(f"Informe generado en: {ruta}")
