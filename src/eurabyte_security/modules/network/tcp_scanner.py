"""Comprobacion basica de puertos TCP.

El escaner realiza una conexion TCP ("connect scan") controlada: concurrencia
limitada mediante un ``ThreadPoolExecutor`` acotado y un tiempo de espera por
puerto configurable. Esta pensado unicamente para objetivos ya validados y
dentro del alcance autorizado por el proyecto (esa comprobacion la hace la
capa de comandos antes de llamar aqui).
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

ABIERTO = "abierto"
CERRADO = "cerrado"
ERROR = "error"


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
) -> list[ResultadoPuerto]:
    """Comprueba el estado de una lista de puertos TCP sobre ``objetivo``.

    Los resultados se devuelven ordenados por numero de puerto,
    independientemente del orden en que terminen las tareas concurrentes.
    """
    trabajadores = max(1, min(concurrencia, len(puertos)))
    resultados: list[ResultadoPuerto] = []
    with ThreadPoolExecutor(max_workers=trabajadores) as pool:
        futuros = {
            pool.submit(_comprobar_puerto, objetivo, puerto, tiempo_espera): puerto
            for puerto in puertos
        }
        for futuro in as_completed(futuros):
            resultados.append(futuro.result())
    return sorted(resultados, key=lambda r: r.puerto)
