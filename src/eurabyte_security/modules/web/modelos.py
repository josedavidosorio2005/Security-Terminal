"""Modelos compartidos por los submodulos de auditoria web (Fase 3, Paso 3)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Severidad = Literal["info", "baja", "media", "alta"]

# Orden de severidad, de menor a mayor, para ordenar hallazgos en tablas/informes.
ORDEN_SEVERIDAD: dict[Severidad, int] = {"info": 0, "baja": 1, "media": 2, "alta": 3}


@dataclass(frozen=True, slots=True)
class Hallazgo:
    """Un hallazgo de auditoria web, con toda la informacion que se le muestra al usuario.

    ``categoria`` agrupa el hallazgo (``cabecera``, ``tls``, ``cookie``, ``redireccion``);
    ``id_`` identifica el hallazgo dentro de esa categoria (p. ej. el nombre de la
    cabecera). El resto de campos son exactamente los que pide la auditoria: que
    significa, para que sirve, el valor detectado, la severidad justificada, el
    riesgo potencial, la recomendacion y una referencia tecnica.
    """

    categoria: str
    id_: str
    nombre: str
    significado: str
    proposito: str
    valor_detectado: str | None
    severidad: Severidad
    estado: str
    riesgo: str
    recomendacion: str
    referencia: str
