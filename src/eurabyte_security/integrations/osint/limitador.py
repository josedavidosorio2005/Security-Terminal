"""Limitador de tasa simple, por fuente, para las consultas OSINT.

Deliberadamente solo de proceso (en memoria, no persistido): cada invocacion de la CLI
es un proceso nuevo, y el objetivo aqui es evitar rafagas de peticiones DENTRO de una
misma investigacion (varias fuentes o varios objetivos en la misma ejecucion), no
sustituir al limite de tasa que ya aplica cada proveedor por su cuenta (ver
``Retry-After`` en ``integrations/osint/cliente_http.py``, que si se respeta entre
ejecuciones porque lo informa el propio servidor).
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

_INTERVALO_SONDEO_CANCELACION = 0.1


class LimitadorTasa:
    """Garantiza al menos ``intervalo_minimo_segundos`` entre dos llamadas consecutivas."""

    def __init__(self, intervalo_minimo_segundos: float) -> None:
        self._intervalo = max(0.0, intervalo_minimo_segundos)
        self._ultima_llamada: float | None = None
        self._bloqueo = threading.Lock()

    def esperar_si_necesario(self, debe_cancelar: Callable[[], bool] | None = None) -> None:
        with self._bloqueo:
            ahora = time.monotonic()
            if self._ultima_llamada is not None:
                restante = self._intervalo - (ahora - self._ultima_llamada)
                while restante > 0:
                    if debe_cancelar is not None and debe_cancelar():
                        return
                    paso = min(_INTERVALO_SONDEO_CANCELACION, restante)
                    time.sleep(paso)
                    restante -= paso
            self._ultima_llamada = time.monotonic()


# Un limitador por id de fuente, compartido por todas las investigaciones del proceso
# (ver ``integrations/osint/registro.py``): evita que dos investigaciones concurrentes
# en la misma interfaz (poco probable, pero posible desde Textual) saturen la misma
# fuente externa.
_LIMITADORES: dict[str, LimitadorTasa] = {}


def limitador_para_fuente(id_fuente: str, intervalo_minimo_segundos: float) -> LimitadorTasa:
    if id_fuente not in _LIMITADORES:
        _LIMITADORES[id_fuente] = LimitadorTasa(intervalo_minimo_segundos)
    return _LIMITADORES[id_fuente]
