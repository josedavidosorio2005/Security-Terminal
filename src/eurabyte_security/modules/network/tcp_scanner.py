"""Comprobacion basica de puertos TCP.

El escaner realiza una conexion TCP ("connect scan") controlada: concurrencia
limitada mediante un ``ThreadPoolExecutor`` acotado y un tiempo de espera por
puerto configurable. Esta pensado unicamente para objetivos ya validados y
dentro del alcance autorizado por el proyecto (esa comprobacion la hace la
capa de comandos antes de llamar aqui).
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass

ABIERTO = "abierto"
CERRADO = "cerrado"
ERROR = "error"

# Intervalo de sondeo de `debe_cancelar` mientras se espera a que terminen
# puertos ya en curso. No depende de que un puerto termine para comprobar la
# cancelacion: si todos los puertos en curso estuvieran bloqueados (p. ej. un
# objetivo que no responde), igual se detecta la cancelacion en este plazo.
_INTERVALO_SONDEO_CANCELACION = 0.05


@dataclass(frozen=True, slots=True)
class ResultadoPuerto:
    puerto: int
    estado: str


def _comprobar_puerto(objetivo: str, puerto: int, tiempo_espera: float) -> ResultadoPuerto:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conexion:
            conexion.settimeout(tiempo_espera)
            resultado = conexion.connect_ex((objetivo, puerto))
            estado = ABIERTO if resultado == 0 else CERRADO
            return ResultadoPuerto(puerto=puerto, estado=estado)
    except OSError:
        return ResultadoPuerto(puerto=puerto, estado=ERROR)


def escanear_puertos_tcp(
    objetivo: str,
    puertos: list[int],
    *,
    tiempo_espera: float = 1.0,
    concurrencia: int = 50,
    debe_cancelar: Callable[[], bool] | None = None,
) -> list[ResultadoPuerto]:
    """Comprueba el estado de una lista de puertos TCP sobre ``objetivo``.

    Los resultados se devuelven ordenados por numero de puerto,
    independientemente del orden en que terminen las tareas concurrentes.

    Si se proporciona ``debe_cancelar`` y empieza a devolver ``True`` mientras
    el escaneo esta en curso, se cancelan las tareas que todavia no hayan
    empezado a ejecutarse (no se abren conexiones nuevas) y se deja de
    esperar por mas resultados. Las conexiones que ya se habian iniciado
    siguen su curso en segundo plano (acotadas por ``tiempo_espera``), pero
    sus resultados no se incluyen en el valor devuelto: quien llama a esta
    funcion debe considerar el escaneo como cancelado, no como parcial.
    """
    trabajadores = max(1, min(concurrencia, len(puertos)))
    resultados: list[ResultadoPuerto] = []
    with ThreadPoolExecutor(max_workers=trabajadores) as pool:
        futuros = {
            pool.submit(_comprobar_puerto, objetivo, puerto, tiempo_espera): puerto
            for puerto in puertos
        }
        pendientes = set(futuros)
        while pendientes:
            if debe_cancelar is not None and debe_cancelar():
                for pendiente in pendientes:
                    pendiente.cancel()
                return []
            terminados, pendientes = wait(
                pendientes, timeout=_INTERVALO_SONDEO_CANCELACION, return_when=FIRST_COMPLETED
            )
            for futuro in terminados:
                resultados.append(futuro.result())
    return sorted(resultados, key=lambda r: r.puerto)
