"""Ejecucion controlada de procesos externos (Fase 3).

Punto unico de ejecucion de binarios de terceros (Nmap, Nuclei, tshark...).
Reglas que no se negocian aqui:

- Nunca ``shell=True``: ``comando`` siempre es una lista de argumentos ya
  validados, nunca una cadena construida por interpolacion. Un argumento como
  ``"127.0.0.1; rm -rf /"`` se pasa literal al binario como un unico
  argumento; no hay ninguna capa de shell que lo interprete.
- Siempre con limite de tiempo (``tiempo_limite``): ningun proceso externo
  puede colgarse indefinidamente.
- Cancelable: se sondea ``debe_cancelar`` periodicamente (no solo al final,
  como con ``subprocess.run``), para poder matar el proceso mientras sigue en
  curso en vez de esperar a que termine o se agote el tiempo.
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass

TIEMPO_LIMITE_MINIMO = 1.0
TIEMPO_LIMITE_MAXIMO = 600.0
_INTERVALO_SONDEO = 0.1


@dataclass(frozen=True, slots=True)
class ResultadoProceso:
    codigo_salida: int
    stdout: str
    stderr: str
    agotado_por_tiempo: bool
    cancelado: bool = False


def ejecutar_proceso(
    comando: list[str],
    *,
    tiempo_limite: float = 30.0,
    entrada: str | None = None,
    debe_cancelar: Callable[[], bool] | None = None,
    variables_entorno: dict[str, str] | None = None,
) -> ResultadoProceso:
    """Ejecuta ``comando`` sin shell, con limite de tiempo, E/S capturada y cancelacion.

    ``variables_entorno`` es opcional: si no se indica (``None``), el proceso hereda
    el entorno de AST sin cambios (igual que antes de este parametro). Si se indica,
    sustituye por completo el entorno del proceso -- lo usa ``AdaptadorNuclei`` para
    aislar la ejecucion de una configuracion de Nuclei preexistente del usuario (ver
    ``integrations/nuclei.py``).
    """
    proceso = subprocess.Popen(  # noqa: S603 - sin shell, argumentos en lista
        comando,
        stdin=subprocess.PIPE if entrada is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        env=variables_entorno,
    )

    inicio = time.monotonic()
    try:
        if entrada is not None and proceso.stdin is not None:
            proceso.stdin.write(entrada)
            proceso.stdin.close()

        while True:
            try:
                stdout, stderr = proceso.communicate(timeout=_INTERVALO_SONDEO)
                return ResultadoProceso(
                    codigo_salida=proceso.returncode, stdout=stdout or "", stderr=stderr or "",
                    agotado_por_tiempo=False, cancelado=False,
                )
            except subprocess.TimeoutExpired:
                if debe_cancelar is not None and debe_cancelar():
                    return _detener_y_recoger(proceso, cancelado=True, agotado_por_tiempo=False)
                if time.monotonic() - inicio > tiempo_limite:
                    return _detener_y_recoger(proceso, cancelado=False, agotado_por_tiempo=True)
    except BaseException:
        proceso.kill()
        proceso.wait()
        raise


def _detener_y_recoger(
    proceso: subprocess.Popen, *, cancelado: bool, agotado_por_tiempo: bool
) -> ResultadoProceso:
    proceso.kill()
    try:
        stdout, stderr = proceso.communicate(timeout=5.0)
    except subprocess.TimeoutExpired:
        stdout, stderr = "", ""
    return ResultadoProceso(
        codigo_salida=proceso.returncode if proceso.returncode is not None else -1,
        stdout=stdout or "",
        stderr=stderr or "",
        agotado_por_tiempo=agotado_por_tiempo,
        cancelado=cancelado,
    )
