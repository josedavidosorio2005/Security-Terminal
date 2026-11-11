"""Resumen de indicadores de exposicion de una investigacion OSINT.

Agrega, sin fabricar nada nuevo, los ``indicador_exposicion`` que ya trae cada hallazgo
guardado (ver ``modules/osint/modelos.py:HallazgoOSINT``): un simple conteo y listado,
nunca una puntuacion de riesgo inventada. AST no promete cobertura total de Internet ni
de las filtraciones existentes (seccion 3 de la especificacion del modulo): este resumen
solo refleja lo que las fuentes consultadas devolvieron.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from eurabyte_security.storage.database import HallazgoOSINTGuardado


@dataclass(frozen=True, slots=True)
class ResumenExposicion:
    total_hallazgos: int
    total_indicadores: int
    fuentes_con_indicador: tuple[str, ...]
    indicadores: tuple[str, ...]


def construir_resumen_exposicion(
    hallazgos: Sequence[HallazgoOSINTGuardado],
) -> ResumenExposicion:
    con_indicador = [h for h in hallazgos if h.indicador_exposicion]
    return ResumenExposicion(
        total_hallazgos=len(hallazgos),
        total_indicadores=len(con_indicador),
        fuentes_con_indicador=tuple(sorted({h.fuente for h in con_indicador})),
        indicadores=tuple(h.indicador_exposicion for h in con_indicador if h.indicador_exposicion),
    )
