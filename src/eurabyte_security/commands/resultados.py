"""Consulta de resultados y hallazgos guardados, unificada entre las cinco herramientas."""

from __future__ import annotations

import typer
from rich.table import Table

from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto
from eurabyte_security.core.errores import ErrorValidacion
from eurabyte_security.storage.database import (
    FUENTES_RESULTADOS,
    BaseDatos,
    Proyecto,
    Resultado,
    ResultadoUnificado,
    agrupar_severidad,
)
from eurabyte_security.ui.consola import consola, texto_seguro

FUENTES_VALIDAS = frozenset(FUENTES_RESULTADOS)

_ETIQUETAS_FUENTE = {
    "tcp": "TCP",
    "nmap": "Nmap",
    "web": "Web",
    "nuclei": "Nuclei",
    "zap": "OWASP ZAP",
}

_ESTILOS_ESTADO = {
    "abierto": "bold green",
    "cerrado": "grey70",
    "error": "bold red",
}

# Claves de 'agrupar_severidad' (ver storage/database.py): nunca severidades propias de
# una herramienta en concreto, para no tener que repetir este mapeo por cada una.
_ESTILOS_SEVERIDAD = {
    "info": "grey70",
    "baja": "cyan",
    "media": "yellow",
    "alta": "bold red",
}


def obtener_resultados(
    base_datos: BaseDatos, proyecto: Proyecto, limite: int = 200
) -> list[Resultado]:
    """Resultados de ``escanear tcp`` unicamente. Se mantiene para uso interno/API.

    Para una vista que combine las cinco herramientas, usa
    :func:`obtener_resultados_unificados`.
    """
    return base_datos.listar_resultados(proyecto.id, limite=limite)


def obtener_resultados_unificados(
    base_datos: BaseDatos,
    proyecto: Proyecto,
    *,
    fuentes: frozenset[str] | None = None,
    severidad: str | None = None,
    estado: str | None = None,
    desde: str | None = None,
    hasta: str | None = None,
    limite: int = 200,
) -> list[ResultadoUnificado]:
    """Combina los resultados/hallazgos de las cinco herramientas para un proyecto.

    Reutiliza ``BaseDatos.listar_resultados_unificados``: no toca ninguna tabla
    directamente. ``fuentes`` es ``None`` para "todas"; si se indica, debe ser un
    subconjunto de :data:`FUENTES_VALIDAS`.
    """
    if fuentes is not None:
        invalidas = fuentes - FUENTES_VALIDAS
        if invalidas:
            raise ErrorValidacion(
                f"Herramienta(s) no reconocida(s): {', '.join(sorted(invalidas))}. "
                f"Usa una o varias de: {', '.join(sorted(FUENTES_VALIDAS))}."
            )
    return base_datos.listar_resultados_unificados(
        proyecto.id,
        fuentes=fuentes,
        severidad=severidad,
        estado=estado,
        desde=desde,
        hasta=hasta,
        limite=limite,
    )


def _tabla_resultados_unificados(resultados: list[ResultadoUnificado], titulo: str) -> Table:
    tabla = Table(title=titulo)
    tabla.add_column("Fuente")
    tabla.add_column("Objetivo")
    tabla.add_column("Tipo")
    tabla.add_column("Hallazgo")
    tabla.add_column("Severidad")
    tabla.add_column("Estado")
    tabla.add_column("Revision")
    tabla.add_column("Fecha")
    for r in resultados:
        grupo = agrupar_severidad(r.severidad) or ""
        estilo_severidad = _ESTILOS_SEVERIDAD.get(grupo, "")
        severidad_texto = (
            f"[{estilo_severidad}]{texto_seguro(r.severidad)}[/{estilo_severidad}]"
            if r.severidad and estilo_severidad
            else (texto_seguro(r.severidad) if r.severidad else "-")
        )
        estilo_estado = _ESTILOS_ESTADO.get(r.estado or "", "")
        estado_texto = (
            f"[{estilo_estado}]{texto_seguro(r.estado)}[/{estilo_estado}]"
            if r.estado and estilo_estado
            else (texto_seguro(r.estado) if r.estado else "-")
        )
        tabla.add_row(
            _ETIQUETAS_FUENTE.get(r.fuente, r.fuente),
            texto_seguro(r.objetivo),
            texto_seguro(r.tipo),
            texto_seguro(r.nombre),
            severidad_texto,
            estado_texto,
            texto_seguro(r.estado_revision) if r.estado_revision else "-",
            r.creado_en,
        )
    return tabla


def resultados_cmd(
    proyecto: str | None = typer.Option(
        None, "--proyecto", help="Proyecto a consultar (por defecto, el activo)."
    ),
    fuente: str | None = typer.Option(
        None,
        "--fuente",
        help="Filtra por herramienta(s), separadas por comas: tcp, nmap, web, nuclei, zap.",
    ),
    severidad: str | None = typer.Option(
        None,
        "--severidad",
        help="Filtra por severidad (alta, media, baja, info); agrupa equivalentes entre "
        "herramientas (ej. 'alta' incluye 'high' y 'critical').",
    ),
    estado: str | None = typer.Option(
        None,
        "--estado",
        help="Filtra por estado (abierto/cerrado/error) o estado de revision "
        "(nuevo/confirmado/falso_positivo), segun aplique a cada herramienta.",
    ),
    desde: str | None = typer.Option(
        None, "--desde", help="Fecha/hora ISO minima incluida, ej: 2026-01-01."
    ),
    hasta: str | None = typer.Option(
        None, "--hasta", help="Fecha/hora ISO maxima incluida."
    ),
    limite: int = typer.Option(50, "--limite", help="Numero maximo de filas a mostrar."),
) -> None:
    """Muestra los resultados y hallazgos guardados de un proyecto (todas las herramientas)."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)

    fuentes = None
    if fuente:
        fuentes = frozenset(f.strip().lower() for f in fuente.split(",") if f.strip())

    resultados = obtener_resultados_unificados(
        base_datos,
        proyecto_obj,
        fuentes=fuentes,
        severidad=severidad,
        estado=estado,
        desde=desde,
        hasta=hasta,
        limite=limite,
    )

    if not resultados:
        consola.print(
            f"El proyecto '{proyecto_obj.nombre}' no tiene resultados guardados "
            "con esos filtros."
        )
        return

    consola.print(_tabla_resultados_unificados(resultados, f"Resultados - {proyecto_obj.nombre}"))
    consola.print(
        "[grey70]Nota: 'tcp' y 'nmap' son resultados de conectividad/puertos, no "
        "vulnerabilidades (por eso nunca llevan severidad). 'web', 'nuclei' y 'zap' son "
        "hallazgos de auditoria/vulnerabilidad. Usa 'est nuclei resultados' o "
        "'est zap resultados' para ver el detalle completo especifico de cada "
        "herramienta.[/grey70]"
    )
