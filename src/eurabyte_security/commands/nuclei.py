"""Comando Nuclei: plantillas HTTP aprobadas de bajo impacto, dentro del alcance autorizado."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import typer
from rich.table import Table

from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto
from eurabyte_security.core.config import ruta_reportes
from eurabyte_security.core.errores import (
    ErrorEscaneoCancelado,
    ErrorFueraDeAlcance,
    ErrorValidacion,
)
from eurabyte_security.core.validation import validar_objetivo_nuclei
from eurabyte_security.integrations.nuclei import (
    PLANTILLAS_APROBADAS,
    AdaptadorNuclei,
    HallazgoNuclei,
)
from eurabyte_security.integrations.nuclei import ResultadoNuclei as ResultadoNucleiEjecucion
from eurabyte_security.modules.reporting.generador import (
    construir_datos_informe_nuclei,
    generar_html_nuclei,
    generar_json_nuclei,
)
from eurabyte_security.storage.database import BaseDatos, Proyecto
from eurabyte_security.storage.database import ResultadoNuclei as ResultadoNucleiGuardado
from eurabyte_security.ui.consola import consola, texto_seguro

nuclei_app = typer.Typer(
    help="Integra Nuclei para plantillas HTTP aprobadas de bajo impacto.", no_args_is_help=True
)

FORMATOS_VALIDOS_REPORTE = {"html", "json"}
ESTADOS_REVISION_VALIDOS = {"nuevo", "confirmado", "falso_positivo"}

_ESTILOS_SEVERIDAD = {
    "info": "grey70",
    "low": "cyan",
    "medium": "yellow",
    "high": "bold red",
    "critical": "bold red",
    "unknown": "grey70",
}


def _verificar_alcance(
    base_datos: BaseDatos, proyecto: Proyecto, ip: ipaddress.IPv4Address
) -> None:
    redes = [ipaddress.IPv4Network(a.red) for a in base_datos.listar_alcance(proyecto.id)]
    if not any(ip in red for red in redes):
        raise ErrorFueraDeAlcance(
            f"El objetivo '{ip}' no esta dentro del alcance autorizado del proyecto "
            f"'{proyecto.nombre}'. Registralo primero con 'est alcance agregar'."
        )


def ejecutar_nuclei(
    base_datos: BaseDatos,
    proyecto: Proyecto,
    objetivo: str,
    plantillas_ids: list[str],
    *,
    tiempo_limite: float = 60.0,
    guardar_evidencia: bool = True,
    debe_cancelar: Callable[[], bool] | None = None,
) -> tuple[ResultadoNucleiEjecucion, list[ResultadoNucleiGuardado]]:
    """Valida el alcance, ejecuta Nuclei y persiste los hallazgos atomicamente.

    La verificacion de alcance ocurre ANTES de ejecutar nada, igual que en
    ``commands/nmap.py``: ningun objetivo fuera del alcance autorizado llega a recibir
    una sola peticion. Si ``debe_cancelar`` indica cancelacion mientras Nuclei esta en
    curso, no se persiste ningun hallazgo (``AdaptadorNuclei.ejecutar`` lanza
    ``ErrorEscaneoCancelado``). Se vuelve a comprobar ``debe_cancelar`` una segunda vez,
    justo antes de la transaccion que persiste los hallazgos: una cancelacion detectada
    entre el momento en que Nuclei termino y el momento en que se iba a guardar el
    resultado tampoco debe dejar nada escrito (misma semantica todo-o-nada que
    ``escanear_tcp``/``auditar_web``).
    """
    componentes = validar_objetivo_nuclei(objetivo)
    _verificar_alcance(base_datos, proyecto, componentes.host)

    adaptador = AdaptadorNuclei()
    resultado = adaptador.ejecutar(
        objetivo=objetivo,
        plantillas_ids=plantillas_ids,
        tiempo_limite=tiempo_limite,
        debe_cancelar=debe_cancelar,
    )

    if not guardar_evidencia:
        return resultado, []

    if debe_cancelar is not None and debe_cancelar():
        raise ErrorEscaneoCancelado(
            f"El analisis de Nuclei contra '{objetivo}' se cancelo antes de guardar los "
            "resultados. No se guardo ningun hallazgo."
        )

    filas = [
        (
            h.plantilla_id,
            _version_plantilla(h.plantilla_id),
            h.plantilla_nombre,
            h.severidad,
            h.descripcion,
            h.evidencia,
        )
        for h in resultado.hallazgos
    ]
    guardados = base_datos.agregar_resultados_nuclei(proyecto.id, resultado.objetivo, filas)
    return resultado, guardados


def _version_plantilla(plantilla_id: str) -> str:
    """Version (propia de AST) de la plantilla que genero este hallazgo.

    El ``template-id`` que Nuclei reporta es exactamente el ``id:`` de nuestro propio
    archivo .yaml, que a su vez coincide con la clave del catalogo (ver
    ``integrations/nuclei.py:PLANTILLAS_APROBADAS``): no deberia haber un hallazgo cuyo
    identificador no sea uno de los nuestros, ya que AST nunca ejecuta otra plantilla.
    """
    info = PLANTILLAS_APROBADAS.get(plantilla_id)
    return info.version if info is not None else "desconocida"


def _tabla_hallazgos_nuclei(hallazgos: list[HallazgoNuclei], titulo: str) -> Table:
    tabla = Table(title=titulo)
    tabla.add_column("Plantilla")
    tabla.add_column("Hallazgo")
    tabla.add_column("Severidad")
    tabla.add_column("Evidencia")
    for h in hallazgos:
        estilo = _ESTILOS_SEVERIDAD.get(h.severidad.lower(), "")
        severidad_texto = f"[{estilo}]{h.severidad}[/{estilo}]" if estilo else h.severidad
        evidencia = texto_seguro(h.evidencia)
        if len(evidencia) > 80:
            evidencia = evidencia[:77] + "..."
        tabla.add_row(
            texto_seguro(h.plantilla_id), texto_seguro(h.plantilla_nombre),
            severidad_texto, evidencia,
        )
    return tabla


@nuclei_app.command("version")
def version_cmd() -> None:
    """Muestra si Nuclei esta instalado en el sistema y su version."""
    info = AdaptadorNuclei().info()
    if not info.instalada:
        consola.print(
            f"[bold yellow]Nuclei no esta instalado[/bold yellow] (no se encontro el "
            f"comando '{info.comando}' en el PATH del sistema)."
        )
        return
    consola.print(f"Nuclei instalado en: {info.ruta}\nVersion: {info.version or 'desconocida'}")


@nuclei_app.command("plantillas")
def plantillas_cmd() -> None:
    """Lista el catalogo de plantillas de Nuclei aprobadas por AST, con su explicacion."""
    tabla = Table(title="Plantillas de Nuclei aprobadas por AST")
    tabla.add_column("Id")
    tabla.add_column("Nombre")
    tabla.add_column("Severidad esperada")
    tabla.add_column("Descripcion")
    for info in PLANTILLAS_APROBADAS.values():
        tabla.add_row(info.id_, info.nombre, info.severidad_esperada, info.descripcion)
    consola.print(tabla)
    consola.print(
        "\n[bold]Por que solo estas:[/bold] cada una es una unica peticion GET de solo "
        "lectura contra el objetivo (nunca sigue redirecciones, nunca usa Interactsh/OAST, "
        "nunca ejecuta codigo). AST no acepta rutas de plantilla arbitrarias: solo estos "
        "identificadores. Usa 'est nuclei analizar OBJETIVO --plantillas id1,id2'."
    )


@nuclei_app.command("analizar")
def analizar_cmd(
    objetivo: str = typer.Argument(
        ..., help="Objetivo autorizado: IP, o esquema://IP[:puerto] (sin ruta)."
    ),
    plantillas: str = typer.Option(
        ...,
        "--plantillas",
        help="Identificadores separados por comas (ver 'est nuclei plantillas').",
    ),
    proyecto: str | None = typer.Option(
        None, "--proyecto", help="Proyecto a usar (por defecto, el activo)."
    ),
    tiempo_limite: float = typer.Option(
        60.0, "--tiempo-limite", help="Segundos maximos de espera para Nuclei (5-120)."
    ),
) -> None:
    """Ejecuta Nuclei contra un objetivo autorizado, solo con plantillas aprobadas."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)
    ids = [p.strip() for p in plantillas.split(",") if p.strip()]

    with consola.status(f"Ejecutando Nuclei contra {texto_seguro(objetivo)}..."):
        resultado, guardados = ejecutar_nuclei(
            base_datos, proyecto_obj, objetivo, ids, tiempo_limite=tiempo_limite
        )

    consola.print(_tabla_hallazgos_nuclei(resultado.hallazgos, f"Nuclei - {objetivo}"))
    consola.print(
        f"Plantillas ejecutadas: {', '.join(resultado.plantillas_ejecutadas)}. "
        f"Hallazgos guardados: {len(guardados)}."
    )
    if resultado.lineas_jsonl_descartadas:
        consola.print(
            f"[bold yellow]Aviso:[/bold yellow] se descartaron "
            f"{resultado.lineas_jsonl_descartadas} lineas de salida mal formadas."
        )


@nuclei_app.command("resultados")
def resultados_cmd(
    proyecto: str | None = typer.Option(
        None, "--proyecto", help="Proyecto a consultar (por defecto, el activo)."
    ),
    limite: int = typer.Option(50, "--limite", help="Numero maximo de hallazgos a mostrar."),
) -> None:
    """Muestra los hallazgos de Nuclei guardados para un proyecto."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)
    guardados = base_datos.listar_resultados_nuclei(proyecto_obj.id, limite=limite)

    if not guardados:
        consola.print(
            f"El proyecto '{proyecto_obj.nombre}' no tiene hallazgos de Nuclei guardados."
        )
        return

    tabla = Table(title=f"Hallazgos de Nuclei - {proyecto_obj.nombre}")
    tabla.add_column("Id")
    tabla.add_column("Objetivo")
    tabla.add_column("Plantilla")
    tabla.add_column("Hallazgo")
    tabla.add_column("Severidad")
    tabla.add_column("Revision")
    tabla.add_column("Fecha")
    for g in guardados:
        estilo = _ESTILOS_SEVERIDAD.get(g.severidad.lower(), "")
        severidad_texto = f"[{estilo}]{g.severidad}[/{estilo}]" if estilo else g.severidad
        tabla.add_row(
            str(g.id), texto_seguro(g.objetivo), texto_seguro(g.plantilla_id),
            texto_seguro(g.nombre_hallazgo), severidad_texto, texto_seguro(g.estado_revision),
            g.creado_en,
        )
    consola.print(tabla)


@nuclei_app.command("revisar")
def revisar_cmd(
    id_hallazgo: int = typer.Argument(..., help="Id del hallazgo (ver 'est nuclei resultados')."),
    estado: str = typer.Option(
        ..., "--estado", help="Nuevo estado: nuevo, confirmado o falso_positivo."
    ),
) -> None:
    """Marca un hallazgo de Nuclei ya guardado como confirmado o falso positivo."""
    if estado not in ESTADOS_REVISION_VALIDOS:
        raise ErrorValidacion(
            f"Estado '{estado}' no valido. Usa uno de: "
            f"{', '.join(sorted(ESTADOS_REVISION_VALIDOS))}."
        )
    base_datos = obtener_base_datos()
    base_datos.actualizar_estado_revision_nuclei(id_hallazgo, estado)
    consola.print(f"[bold green]OK[/bold green] Hallazgo {id_hallazgo} marcado como '{estado}'.")


def generar_reporte_nuclei(
    base_datos: BaseDatos, proyecto: Proyecto, formato: str, salida: Path | None = None
) -> Path:
    """Genera un informe HTML/JSON con los hallazgos de Nuclei guardados.

    Reutiliza el mismo esqueleto (CSS, cabecera) que ``commands/reporte.py`` usa para
    los resultados de ``escanear tcp``, en vez de duplicar la generacion del informe.
    """
    formato = formato.lower()
    if formato not in FORMATOS_VALIDOS_REPORTE:
        raise ErrorValidacion(
            f"Formato '{formato}' no soportado. Usa uno de: "
            f"{', '.join(sorted(FORMATOS_VALIDOS_REPORTE))}."
        )

    resultados = base_datos.listar_resultados_nuclei(proyecto.id, limite=10_000)
    datos = construir_datos_informe_nuclei(proyecto.nombre, resultados)
    contenido = generar_html_nuclei(datos) if formato == "html" else generar_json_nuclei(datos)

    if salida is None:
        marca_tiempo = datetime.now().strftime("%Y%m%d-%H%M%S")
        ruta_salida = (
            ruta_reportes() / f"informe-nuclei-{proyecto.nombre}-{marca_tiempo}.{formato}"
        )
    else:
        ruta_salida = salida
    ruta_salida.parent.mkdir(parents=True, exist_ok=True)
    ruta_salida.write_text(contenido, encoding="utf-8")
    return ruta_salida


@nuclei_app.command("reporte")
def reporte_cmd(
    formato: str = typer.Option("html", "--formato", help="Formato del informe: html o json."),
    proyecto: str | None = typer.Option(
        None, "--proyecto", help="Proyecto a reportar (por defecto, el activo)."
    ),
    salida: str | None = typer.Option(None, "--salida", help="Ruta del archivo de salida."),
) -> None:
    """Genera un informe HTML o JSON con los hallazgos de Nuclei guardados."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)
    ruta = generar_reporte_nuclei(
        base_datos, proyecto_obj, formato, Path(salida) if salida else None
    )
    consola.print(f"[bold green]OK[/bold green] Informe generado en: {texto_seguro(ruta)}")
