"""Comando OWASP ZAP: analisis pasivo, dentro del alcance autorizado y sin API key visible."""

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
from eurabyte_security.integrations.zap import AdaptadorZAP, HallazgoZAP
from eurabyte_security.integrations.zap import ResultadoZAP as ResultadoZAPEjecucion
from eurabyte_security.modules.reporting.generador import (
    construir_datos_informe_zap,
    generar_html_zap,
    generar_json_zap,
)
from eurabyte_security.modules.vulnerability.zap import validar_objetivo_zap
from eurabyte_security.storage.database import BaseDatos, Proyecto
from eurabyte_security.storage.database import ResultadoZAP as ResultadoZAPGuardado
from eurabyte_security.ui.consola import consola, texto_seguro

zap_app = typer.Typer(
    help="Integra OWASP ZAP (API local) para analisis pasivo de un objetivo autorizado.",
    no_args_is_help=True,
)

FORMATOS_VALIDOS_REPORTE = {"html", "json"}
ESTADOS_REVISION_VALIDOS = {"nuevo", "confirmado", "falso_positivo"}

_ESTILOS_RIESGO = {
    "informational": "grey70",
    "low": "cyan",
    "medium": "yellow",
    "high": "bold red",
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


def ejecutar_zap_pasivo(
    base_datos: BaseDatos,
    proyecto: Proyecto,
    objetivo: str,
    *,
    tiempo_limite: float = 60.0,
    guardar_evidencia: bool = True,
    debe_cancelar: Callable[[], bool] | None = None,
) -> tuple[ResultadoZAPEjecucion, list[ResultadoZAPGuardado]]:
    """Valida el alcance, ejecuta el analisis pasivo de ZAP y persiste los hallazgos.

    La verificacion de alcance ocurre ANTES de llamar a la API de ZAP, igual que en
    ``commands/nuclei.py``: ningun objetivo fuera del alcance autorizado llega a recibir
    ni una sola peticion (ni siquiera la unica peticion GET controlada que alimenta el
    analizador pasivo). Si ``debe_cancelar`` indica cancelacion mientras el analisis esta
    en curso, no se persiste ningun hallazgo (``AdaptadorZAP.ejecutar`` propaga
    ``ErrorEscaneoCancelado``). Se vuelve a comprobar ``debe_cancelar`` una segunda vez,
    justo antes de la transaccion que persiste los hallazgos: misma semantica todo-o-nada
    que el resto de integraciones de AST.
    """
    componentes = validar_objetivo_zap(objetivo)
    _verificar_alcance(base_datos, proyecto, componentes.host)

    adaptador = AdaptadorZAP()
    resultado = adaptador.ejecutar(
        objetivo=objetivo, tiempo_limite=tiempo_limite, debe_cancelar=debe_cancelar
    )

    if not guardar_evidencia:
        return resultado, []

    if debe_cancelar is not None and debe_cancelar():
        raise ErrorEscaneoCancelado(
            f"El analisis de ZAP contra '{objetivo}' se cancelo antes de guardar los "
            "resultados. No se guardo ningun hallazgo."
        )

    filas = [
        (
            h.plugin_id,
            h.nombre,
            h.riesgo,
            h.confianza,
            h.descripcion,
            h.evidencia,
            h.solucion,
            h.referencia,
        )
        for h in resultado.hallazgos
    ]
    guardados = base_datos.agregar_resultados_zap(proyecto.id, resultado.objetivo, filas)
    return resultado, guardados


def _tabla_hallazgos_zap(hallazgos: list[HallazgoZAP], titulo: str) -> Table:
    tabla = Table(title=titulo)
    tabla.add_column("Regla")
    tabla.add_column("Hallazgo")
    tabla.add_column("Riesgo")
    tabla.add_column("Confianza")
    tabla.add_column("Evidencia")
    for h in hallazgos:
        estilo = _ESTILOS_RIESGO.get(h.riesgo.lower(), "")
        riesgo_texto = f"[{estilo}]{h.riesgo}[/{estilo}]" if estilo else h.riesgo
        evidencia = texto_seguro(h.evidencia)
        if len(evidencia) > 80:
            evidencia = evidencia[:77] + "..."
        tabla.add_row(
            texto_seguro(h.plugin_id), texto_seguro(h.nombre), riesgo_texto,
            texto_seguro(h.confianza), evidencia,
        )
    return tabla


@zap_app.command("estado")
def estado_cmd() -> None:
    """Muestra si la API de OWASP ZAP responde en el endpoint configurado."""
    info = AdaptadorZAP().info()
    if not info.disponible:
        consola.print(
            f"[bold yellow]OWASP ZAP no esta disponible:[/bold yellow] {texto_seguro(info.mensaje)}"
        )
        return
    consola.print(f"OWASP ZAP disponible. Version: {texto_seguro(info.version or 'desconocida')}")


@zap_app.command("pasivo")
def pasivo_cmd(
    objetivo: str = typer.Argument(
        ..., help="URL autorizada a auditar pasivamente (IPv4 literal, http o https)."
    ),
    proyecto: str | None = typer.Option(
        None, "--proyecto", help="Proyecto a usar (por defecto, el activo)."
    ),
    tiempo_limite: float = typer.Option(
        60.0, "--tiempo-limite", help="Segundos maximos de espera para el analisis (5-300)."
    ),
) -> None:
    """Ejecuta un analisis pasivo de ZAP contra un objetivo autorizado (nunca active scan)."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)

    with consola.status(f"Ejecutando analisis pasivo de ZAP contra {texto_seguro(objetivo)}..."):
        resultado, guardados = ejecutar_zap_pasivo(
            base_datos, proyecto_obj, objetivo, tiempo_limite=tiempo_limite
        )

    consola.print(_tabla_hallazgos_zap(resultado.hallazgos, f"OWASP ZAP - {objetivo}"))
    consola.print(f"Hallazgos guardados: {len(guardados)}.")
    if resultado.alertas_descartadas:
        consola.print(
            f"[bold yellow]Aviso:[/bold yellow] se descartaron "
            f"{resultado.alertas_descartadas} alertas con forma inesperada."
        )


@zap_app.command("resultados")
def resultados_cmd(
    proyecto: str | None = typer.Option(
        None, "--proyecto", help="Proyecto a consultar (por defecto, el activo)."
    ),
    limite: int = typer.Option(50, "--limite", help="Numero maximo de hallazgos a mostrar."),
) -> None:
    """Muestra los hallazgos de OWASP ZAP guardados para un proyecto."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)
    guardados = base_datos.listar_resultados_zap(proyecto_obj.id, limite=limite)

    if not guardados:
        consola.print(f"El proyecto '{proyecto_obj.nombre}' no tiene hallazgos de ZAP guardados.")
        return

    tabla = Table(title=f"Hallazgos de OWASP ZAP - {proyecto_obj.nombre}")
    tabla.add_column("Id")
    tabla.add_column("Objetivo")
    tabla.add_column("Regla")
    tabla.add_column("Hallazgo")
    tabla.add_column("Riesgo")
    tabla.add_column("Revision")
    tabla.add_column("Fecha")
    for g in guardados:
        estilo = _ESTILOS_RIESGO.get(g.riesgo.lower(), "")
        riesgo_texto = f"[{estilo}]{g.riesgo}[/{estilo}]" if estilo else g.riesgo
        tabla.add_row(
            str(g.id), texto_seguro(g.objetivo), texto_seguro(g.plugin_id),
            texto_seguro(g.nombre_hallazgo), riesgo_texto, texto_seguro(g.estado_revision),
            g.creado_en,
        )
    consola.print(tabla)


@zap_app.command("revisar")
def revisar_cmd(
    id_hallazgo: int = typer.Argument(..., help="Id del hallazgo (ver 'est zap resultados')."),
    estado: str = typer.Option(
        ..., "--estado", help="Nuevo estado: nuevo, confirmado o falso_positivo."
    ),
) -> None:
    """Marca un hallazgo de ZAP ya guardado como confirmado o falso positivo."""
    if estado not in ESTADOS_REVISION_VALIDOS:
        raise ErrorValidacion(
            f"Estado '{estado}' no valido. Usa uno de: "
            f"{', '.join(sorted(ESTADOS_REVISION_VALIDOS))}."
        )
    base_datos = obtener_base_datos()
    base_datos.actualizar_estado_revision_zap(id_hallazgo, estado)
    consola.print(f"[bold green]OK[/bold green] Hallazgo {id_hallazgo} marcado como '{estado}'.")


def generar_reporte_zap(
    base_datos: BaseDatos, proyecto: Proyecto, formato: str, salida: Path | None = None
) -> Path:
    """Genera un informe HTML/JSON con los hallazgos de OWASP ZAP guardados."""
    formato = formato.lower()
    if formato not in FORMATOS_VALIDOS_REPORTE:
        raise ErrorValidacion(
            f"Formato '{formato}' no soportado. Usa uno de: "
            f"{', '.join(sorted(FORMATOS_VALIDOS_REPORTE))}."
        )

    resultados = base_datos.listar_resultados_zap(proyecto.id, limite=10_000)
    datos = construir_datos_informe_zap(proyecto.nombre, resultados)
    contenido = generar_html_zap(datos) if formato == "html" else generar_json_zap(datos)

    if salida is None:
        marca_tiempo = datetime.now().strftime("%Y%m%d-%H%M%S")
        ruta_salida = ruta_reportes() / f"informe-zap-{proyecto.nombre}-{marca_tiempo}.{formato}"
    else:
        ruta_salida = salida
    ruta_salida.parent.mkdir(parents=True, exist_ok=True)
    ruta_salida.write_text(contenido, encoding="utf-8")
    return ruta_salida


@zap_app.command("reporte")
def reporte_cmd(
    formato: str = typer.Option("html", "--formato", help="Formato del informe: html o json."),
    proyecto: str | None = typer.Option(
        None, "--proyecto", help="Proyecto a reportar (por defecto, el activo)."
    ),
    salida: str | None = typer.Option(None, "--salida", help="Ruta del archivo de salida."),
) -> None:
    """Genera un informe HTML o JSON con los hallazgos de OWASP ZAP guardados."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)
    ruta = generar_reporte_zap(base_datos, proyecto_obj, formato, Path(salida) if salida else None)
    consola.print(f"[bold green]OK[/bold green] Informe generado en: {texto_seguro(ruta)}")
