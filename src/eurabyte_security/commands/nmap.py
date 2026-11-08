"""Comando Nmap: descubrimiento de puertos y servicios dentro del alcance autorizado."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import typer
from rich.table import Table

from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto
from eurabyte_security.core.config import ruta_evidencias
from eurabyte_security.core.errores import ErrorFueraDeAlcance
from eurabyte_security.core.validation import validar_objetivo
from eurabyte_security.integrations.nmap import AdaptadorNmap, ResultadoNmap
from eurabyte_security.storage.database import BaseDatos, Proyecto
from eurabyte_security.storage.database import ResultadoNmap as ResultadoNmapGuardado
from eurabyte_security.ui.consola import consola, texto_seguro

nmap_app = typer.Typer(
    help="Integra Nmap para descubrimiento de puertos y servicios.", no_args_is_help=True
)

_ESTILOS_ESTADO = {"open": "bold green", "closed": "grey70", "filtered": "yellow"}


def _verificar_alcance(base_datos: BaseDatos, proyecto: Proyecto, ip: str) -> None:
    redes = [ipaddress.IPv4Network(a.red) for a in base_datos.listar_alcance(proyecto.id)]
    objetivo_ip = ipaddress.IPv4Address(ip)
    if not any(objetivo_ip in red for red in redes):
        raise ErrorFueraDeAlcance(
            f"El objetivo '{ip}' no esta dentro del alcance autorizado del proyecto "
            f"'{proyecto.nombre}'. Registralo primero con 'est alcance agregar'."
        )


def ejecutar_nmap(
    base_datos: BaseDatos,
    proyecto: Proyecto,
    objetivo: str,
    puertos_especificacion: str,
    *,
    deteccion_version: bool = False,
    tiempo_limite: float = 120.0,
    guardar_evidencia: bool = True,
    debe_cancelar: Callable[[], bool] | None = None,
) -> tuple[ResultadoNmap, list[ResultadoNmapGuardado], Path | None]:
    """Valida el alcance, ejecuta Nmap, persiste resultados y guarda la evidencia XML.

    Devuelve ``(resultado_de_nmap, filas_guardadas_en_bd, ruta_de_la_evidencia)``.
    La verificacion de alcance ocurre ANTES de ejecutar nada, igual que en
    ``commands/escanear.py``: ningun objetivo fuera del alcance autorizado
    llega a abrir una sola conexion. Si ``debe_cancelar`` indica cancelacion
    mientras Nmap esta en curso, no se persiste ni se guarda evidencia de
    ningun resultado (``AdaptadorNmap.ejecutar`` lanza ``ErrorEscaneoCancelado``).
    """
    ip_validada = validar_objetivo(objetivo)
    _verificar_alcance(base_datos, proyecto, str(ip_validada))

    adaptador = AdaptadorNmap()
    resultado = adaptador.ejecutar(
        objetivo=str(ip_validada),
        puertos_especificacion=puertos_especificacion,
        deteccion_version=deteccion_version,
        tiempo_limite=tiempo_limite,
        debe_cancelar=debe_cancelar,
    )

    filas = [(p.puerto, p.protocolo, p.estado, p.servicio, p.version) for p in resultado.puertos]
    guardados = base_datos.agregar_resultados_nmap(proyecto.id, resultado.objetivo, filas)

    if not guardar_evidencia:
        return resultado, guardados, None

    marca_tiempo = datetime.now().strftime("%Y%m%d-%H%M%S")
    ruta_xml = (
        ruta_evidencias("nmap") / f"{proyecto.nombre}-{resultado.objetivo}-{marca_tiempo}.xml"
    )
    ruta_xml.write_text(resultado.xml_crudo, encoding="utf-8")
    return resultado, guardados, ruta_xml


def _tabla_resultado_nmap(resultado: ResultadoNmap) -> Table:
    # Protocolo/estado/servicio/version vienen de la respuesta del objetivo escaneado
    # (Nmap los vuelca tal cual): se escapan siempre antes de mostrarlos con marcado
    # Rich, igual que cualquier otro texto no controlado por AST (ver ui/consola.py).
    tabla = Table(title=f"Nmap - {texto_seguro(resultado.objetivo)}")
    tabla.add_column("Puerto")
    tabla.add_column("Protocolo")
    tabla.add_column("Estado")
    tabla.add_column("Servicio")
    tabla.add_column("Version")
    for puerto in resultado.puertos:
        estilo = _ESTILOS_ESTADO.get(puerto.estado, "")
        estado_seguro = texto_seguro(puerto.estado)
        estado_texto = f"[{estilo}]{estado_seguro}[/{estilo}]" if estilo else estado_seguro
        tabla.add_row(
            str(puerto.puerto),
            texto_seguro(puerto.protocolo),
            estado_texto,
            texto_seguro(puerto.servicio) if puerto.servicio else "-",
            texto_seguro(puerto.version) if puerto.version else "-",
        )
    return tabla


@nmap_app.command("descubrir")
def descubrir_cmd(
    objetivo: str = typer.Argument(..., help="Direccion IPv4 a comprobar."),
    puertos: str = typer.Option(..., "--puertos", help="Lista de puertos, ej: 22,80,443."),
    proyecto: str | None = typer.Option(
        None, "--proyecto", help="Proyecto a usar (por defecto, el activo)."
    ),
    deteccion_version: bool = typer.Option(
        False,
        "--deteccion-version",
        help="Activa -sV (identificacion de servicios y version). Usalo solo si esta "
        "explicitamente autorizado para el objetivo.",
    ),
    tiempo_limite: float = typer.Option(
        120.0, "--tiempo-limite", help="Segundos maximos de espera para Nmap (5-600)."
    ),
) -> None:
    """Descubre puertos (y, si se autoriza, servicios) con Nmap dentro del alcance."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)

    with consola.status(f"Ejecutando Nmap contra {texto_seguro(objetivo)}..."):
        resultado, _guardados, ruta_xml = ejecutar_nmap(
            base_datos,
            proyecto_obj,
            objetivo,
            puertos,
            deteccion_version=deteccion_version,
            tiempo_limite=tiempo_limite,
        )

    consola.print(_tabla_resultado_nmap(resultado))
    if ruta_xml is not None:
        consola.print(f"Evidencia XML guardada en: {texto_seguro(ruta_xml)}")


@nmap_app.command("version")
def version_cmd() -> None:
    """Muestra si Nmap esta instalado en el sistema y su version."""
    info = AdaptadorNmap().info()
    if not info.instalada:
        consola.print(
            f"[bold yellow]Nmap no esta instalado[/bold yellow] (no se encontro el "
            f"comando '{info.comando}' en el PATH del sistema)."
        )
        return
    consola.print(
        f"Nmap instalado en: {texto_seguro(info.ruta)}\n"
        f"Version: {texto_seguro(info.version) if info.version else 'desconocida'}"
    )
