"""Deteccion (sin ejecucion) de herramientas externas de la Fase 3.

Para las herramientas que ya tienen un adaptador real (ver
``integrations/nmap.py``), este modulo reutiliza ``AdaptadorExterno.info()``
(que tambien lee la version instalada). Para las que todavia no tienen
adaptador, solo comprueba si el binario esta en el PATH del sistema
(``shutil.which``). En ningun caso se ejecuta un analisis real, solo
comprobaciones de version/presencia, de solo lectura.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass

from eurabyte_security.integrations.base import AdaptadorExterno
from eurabyte_security.integrations.nmap import AdaptadorNmap
from eurabyte_security.integrations.nuclei import AdaptadorNuclei

HERRAMIENTAS_SOLO_DETECCION: tuple[tuple[str, str], ...] = (
    ("OWASP ZAP", "zap.sh"),
    ("tshark", "tshark"),
)

_ADAPTADORES: tuple[AdaptadorExterno, ...] = (AdaptadorNmap(), AdaptadorNuclei())


@dataclass(frozen=True, slots=True)
class HerramientaExterna:
    nombre: str
    comando: str
    instalada: bool
    ruta: str | None
    version: str | None = None


def detectar_herramientas() -> list[HerramientaExterna]:
    """Comprueba que herramientas de la Fase 3 estan instaladas en el PATH."""
    resultado = [
        HerramientaExterna(
            nombre=info.nombre, comando=info.comando, instalada=info.instalada,
            ruta=info.ruta, version=info.version,
        )
        for info in (adaptador.info() for adaptador in _ADAPTADORES)
    ]
    for nombre, comando in HERRAMIENTAS_SOLO_DETECCION:
        ruta = shutil.which(comando)
        resultado.append(
            HerramientaExterna(
                nombre=nombre, comando=comando, instalada=ruta is not None, ruta=ruta
            )
        )
    return resultado
