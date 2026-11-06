"""Contrato base del futuro asistente de IA (Fase 4).

Define la forma que tendra cualquier sugerencia del asistente: una propuesta
de texto o de comando que SIEMPRE debe mostrarse al usuario para su
aprobacion antes de ejecutarse. Todavia no hay ninguna implementacion
conectada a un proveedor de IA.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SugerenciaAsistente:
    """Una sugerencia que el asistente propone pero no ejecuta por si mismo."""

    explicacion: str
    comando_propuesto: str | None = None
    requiere_autorizacion: bool = True
