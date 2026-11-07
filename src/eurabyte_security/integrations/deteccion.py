"""Deteccion (sin ejecucion) de herramientas externas de la Fase 3.

Este modulo solo comprueba si un binario esta disponible en el PATH del
sistema (``shutil.which``). Nunca invoca la herramienta: la Fase 1/2 de EST
no integra todavia Nmap, Nuclei, OWASP ZAP ni tshark (ver
``integrations/base.py`` y docs/ROADMAP.md).
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass

HERRAMIENTAS_PREVISTAS: tuple[tuple[str, str], ...] = (
    ("Nmap", "nmap"),
    ("Nuclei", "nuclei"),
    ("OWASP ZAP", "zap.sh"),
    ("tshark", "tshark"),
)


@dataclass(frozen=True, slots=True)
class HerramientaExterna:
    nombre: str
    comando: str
    instalada: bool
    ruta: str | None


def detectar_herramientas() -> list[HerramientaExterna]:
    """Comprueba que herramientas de la Fase 3 estan instaladas en el PATH."""
    resultado = []
    for nombre, comando in HERRAMIENTAS_PREVISTAS:
        ruta = shutil.which(comando)
        resultado.append(
            HerramientaExterna(
                nombre=nombre, comando=comando, instalada=ruta is not None, ruta=ruta
            )
        )
    return resultado
