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
from eurabyte_security.integrations.zap import TIEMPO_LIMITE_DIAGNOSTICO_AUTOMATICO, AdaptadorZAP

HERRAMIENTAS_SOLO_DETECCION: tuple[tuple[str, str], ...] = (
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
    """Comprueba que herramientas de la Fase 3 estan instaladas/disponibles.

    Para Nmap/Nuclei, "disponible" significa que el binario esta en el PATH del sistema
    (``shutil.which``). Para OWASP ZAP, que no se invoca como binario sino como un
    servicio HTTP ya en marcha, significa que su API responde en el endpoint configurado
    (``EST_ZAP_URL``) -- ver ``integrations/zap.py``. Ninguna de estas comprobaciones
    ejecuta un analisis real, solo lectura.
    """
    resultado = [
        HerramientaExterna(
            nombre=info.nombre, comando=info.comando, instalada=info.instalada,
            ruta=info.ruta, version=info.version,
        )
        for info in (adaptador.info() for adaptador in _ADAPTADORES)
    ]

    info_zap = AdaptadorZAP().info(tiempo_limite=TIEMPO_LIMITE_DIAGNOSTICO_AUTOMATICO)
    resultado.append(
        HerramientaExterna(
            nombre="OWASP ZAP",
            comando=AdaptadorZAP().configuracion().url_base,
            instalada=info_zap.disponible,
            ruta=None,
            version=info_zap.version,
        )
    )

    for nombre, comando in HERRAMIENTAS_SOLO_DETECCION:
        ruta = shutil.which(comando)
        resultado.append(
            HerramientaExterna(
                nombre=nombre, comando=comando, instalada=ruta is not None, ruta=ruta
            )
        )
    return resultado
