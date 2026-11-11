"""Contrato comun para una fuente OSINT (ver ``integrations/base.py`` para su equivalente
sobre binarios externos).

Una fuente OSINT nunca ejecuta un binario ni abre una conexion directa contra el
objetivo investigado: siempre consulta un servicio de terceros ya documentado (DNS
publico, RDAP, Certificate Transparency, la API publica de una plataforma...) via
``integrations/osint/cliente_http.py``. Cada adaptador concreto declara que tipos de
objetivo admite (``tipos_objetivo``) y si necesita una clave de configuracion opcional
(``requiere_clave``): el motor (``modules/osint/motor.py``) nunca llama a
``investigar()`` si la fuente no admite ese tipo de objetivo o no esta configurada.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from collections.abc import Callable

from eurabyte_security.modules.osint.modelos import HallazgoOSINT


class AdaptadorFuenteOSINT(ABC):
    """Contrato comun para integrar una fuente OSINT (gratuita u opcional)."""

    id_fuente: str
    nombre: str
    tipos_objetivo: frozenset[str]
    requiere_clave: bool = False
    variable_entorno_clave: str | None = None
    url_documentacion: str = ""

    # Por defecto, para un objetivo de tipo 'correo' el motor deriva y pasa solo el
    # DOMINIO a ``investigar()`` (DNS/RDAP/Certificate Transparency/VirusTotal operan
    # sobre un dominio, no sobre una direccion de correo completa). Una fuente que
    # necesite el objetivo tal cual se valido -- p. ej. Have I Been Pwned, que consulta
    # por CUENTA DE CORREO completa, no por dominio -- debe fijar esto en ``True`` para
    # recibir ``objetivo_saneado`` sin derivar nada (ver modules/osint/motor.py).
    requiere_objetivo_original: bool = False

    def configurada(self) -> bool:
        """``True`` si la fuente puede usarse ya mismo (gratuita, o con su clave presente)."""
        if not self.requiere_clave:
            return True
        return bool(self.variable_entorno_clave and os.environ.get(self.variable_entorno_clave))

    def mensaje_no_configurada(self) -> str:
        doc = f" Documentacion: {self.url_documentacion}" if self.url_documentacion else ""
        return (
            f"'{self.nombre}' requiere configurar la variable de entorno "
            f"'{self.variable_entorno_clave}' con una clave/suscripcion valida.{doc}"
        )

    @abstractmethod
    def investigar(
        self,
        objetivo: str,
        *,
        tipo_objetivo: str,
        tiempo_limite: float,
        debe_cancelar: Callable[[], bool] | None,
    ) -> list[HallazgoOSINT]:
        """Consulta la fuente y devuelve sus hallazgos (lista vacia si no hay nada util).

        Lanza ``ErrorFuenteOSINTNoDisponible`` si el objetivo no es apto para esta fuente
        (p. ej. un dominio sin ningun registro que consultar) y ``ErrorFuenteOSINTError``
        ante cualquier fallo de la consulta (tiempo agotado, respuesta invalida...). Nunca
        lanza una excepcion de ``urllib``/``dns`` sin traducir: eso es responsabilidad de
        cada adaptador concreto (ver ``integrations/osint/cliente_http.py``).
        """
