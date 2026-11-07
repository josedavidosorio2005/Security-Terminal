"""Comprobacion de puertos TCP dentro del alcance autorizado."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable

import typer
from rich.table import Table

from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto
from eurabyte_security.core.errores import ErrorEscaneoCancelado, ErrorFueraDeAlcance
from eurabyte_security.core.validation import (
    validar_concurrencia,
    validar_objetivo,
    validar_puertos,
    validar_timeout,
)
from eurabyte_security.modules.network.tcp_scanner import escanear_puertos_tcp
from eurabyte_security.storage.database import BaseDatos, Proyecto, Resultado
from eurabyte_security.ui.consola import consola

escanear_app = typer.Typer(help="Ejecuta comprobaciones de red.", no_args_is_help=True)

_ESTILOS_ESTADO = {
    "abierto": "bold green",
    "cerrado": "grey70",
    "error": "bold red",
}


def escanear_tcp(
    base_datos: BaseDatos,
    proyecto: Proyecto,
    objetivo: str,
    puertos_especificacion: str,
    *,
    tiempo_espera: float = 1.0,
    concurrencia: int = 50,
    debe_cancelar: Callable[[], bool] | None = None,
) -> list[Resultado]:
    """Valida objetivo/alcance/puertos y ejecuta el escaneo TCP persistiendo resultados.

    ``debe_cancelar``, si se indica, se consulta durante el escaneo (para dejar
    de abrir conexiones nuevas en cuanto sea posible) y otra vez justo antes de
    guardar nada en la base de datos. Semantica de cancelacion: todo o nada. Si
    ``debe_cancelar()`` es verdadero en ese segundo chequeo, no se persiste
    ningun resultado (ni siquiera los de puertos que ya se habian comprobado) y
    se lanza :class:`ErrorEscaneoCancelado`. Las conexiones que ya se hubieran
    iniciado en segundo plano pueden completarse igualmente, pero sus
    resultados se descartan.
    """
    ip_objetivo = validar_objetivo(objetivo)
    puertos = validar_puertos(puertos_especificacion)
    tiempo_espera = validar_timeout(tiempo_espera)
    concurrencia = validar_concurrencia(concurrencia)

    redes_autorizadas = [
        ipaddress.IPv4Network(a.red) for a in base_datos.listar_alcance(proyecto.id)
    ]
    if not any(ip_objetivo in red for red in redes_autorizadas):
        raise ErrorFueraDeAlcance(
            f"El objetivo '{objetivo}' no esta dentro del alcance autorizado del "
            f"proyecto '{proyecto.nombre}'. Registralo primero con "
            "'est alcance agregar'."
        )

    resultados_escaneo = escanear_puertos_tcp(
        str(ip_objetivo),
        puertos,
        tiempo_espera=tiempo_espera,
        concurrencia=concurrencia,
        debe_cancelar=debe_cancelar,
    )

    if debe_cancelar is not None and debe_cancelar():
        raise ErrorEscaneoCancelado(
            f"El escaneo de '{objetivo}' se cancelo antes de completarse. "
            "Las conexiones que ya se habian iniciado pueden haber terminado "
            "en segundo plano, pero no se guardo ningun resultado."
        )

    resultados_guardados = [
        base_datos.agregar_resultado(proyecto.id, str(ip_objetivo), r.puerto, r.estado)
        for r in resultados_escaneo
    ]
    return resultados_guardados


@escanear_app.command("tcp")
def tcp_cmd(
    objetivo: str = typer.Argument(..., help="Direccion IPv4 a comprobar."),
    puertos: str = typer.Option(..., "--puertos", help="Lista de puertos, ej: 22,80,443."),
    proyecto: str | None = typer.Option(
        None, "--proyecto", help="Proyecto a usar (por defecto, el activo)."
    ),
    timeout: float = typer.Option(
        1.0, "--timeout", help="Tiempo de espera por puerto en segundos (0.1-10)."
    ),
    concurrencia: int = typer.Option(
        50, "--concurrencia", help="Conexiones simultaneas maximas (1-200)."
    ),
) -> None:
    """Comprueba el estado de una lista de puertos TCP en un objetivo autorizado."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)

    with consola.status(f"Escaneando {objetivo}..."):
        resultados = escanear_tcp(
            base_datos,
            proyecto_obj,
            objetivo,
            puertos,
            tiempo_espera=timeout,
            concurrencia=concurrencia,
        )

    tabla = Table(title=f"Resultado del escaneo TCP - {objetivo}")
    tabla.add_column("Puerto")
    tabla.add_column("Estado")
    for resultado in resultados:
        estilo = _ESTILOS_ESTADO.get(resultado.estado, "")
        tabla.add_row(str(resultado.puerto), f"[{estilo}]{resultado.estado}[/{estilo}]")
    consola.print(tabla)
