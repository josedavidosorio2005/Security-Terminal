"""Interfaz base para adaptadores de herramientas externas (Fase 3).

Cada adaptador concreto (Nmap, Nuclei, OWASP ZAP, tshark...) debera heredar de
``AdaptadorExterno`` e implementar ``esta_instalado`` y ``ejecutar``. Este
modulo solo define el contrato; todavia no hay adaptadores implementados.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class HerramientaNoDisponible(Exception):
    """La herramienta externa no esta instalada o no es accesible."""


class AdaptadorExterno(ABC):
    """Contrato minimo que debe cumplir cualquier integracion externa."""

    nombre: str

    @abstractmethod
    def esta_instalado(self) -> bool:
        """Indica si el binario/servicio requerido esta disponible."""

    @abstractmethod
    def ejecutar(self, *args: Any, **kwargs: Any) -> Any:
        """Ejecuta la herramienta. Debe validar primero ``esta_instalado``."""

    def mensaje_no_disponible(self) -> str:
        return (
            f"La integracion con '{self.nombre}' no esta disponible todavia. "
            "Esta prevista para una fase posterior del roadmap de EST."
        )
