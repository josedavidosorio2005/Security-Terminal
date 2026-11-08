"""Adaptador de OWASP ZAP (Fase 3, Paso 5): solo analisis pasivo, API local en loopback.

A diferencia de Nmap/Nuclei, ZAP no es un binario que AST invoque como subproceso: es un
servicio que el usuario ya tiene corriendo por su cuenta (con su propia interfaz grafica o
como daemon), con su API REST expuesta en un endpoint local. Por eso este adaptador no
hereda de ``integrations/base.py:AdaptadorExterno`` (pensado para binarios resueltos con
``shutil.which`` y ejecutados sin shell): en vez de "esta instalado en el PATH", la pregunta
aqui es "responde su API en el endpoint configurado". La logica real de conexion HTTP,
validacion del endpoint y analisis pasivo vive en ``modules/vulnerability/zap.py`` (igual
que la logica de Nuclei vive en este mismo paquete); esta clase es la fachada que usan
``commands/zap.py`` y la interfaz visual, con una forma similar a la de los demas
adaptadores para que el resto de AST no necesite tratarla como un caso especial.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from eurabyte_security.core.errores import ErrorParametrosIntegracion
from eurabyte_security.modules.vulnerability.zap import (
    TIEMPO_LIMITE_DIAGNOSTICO_AUTOMATICO,
    TIEMPO_LIMITE_MAXIMO,
    TIEMPO_LIMITE_MINIMO,
    TIEMPO_LIMITE_POR_DEFECTO,
    ConfiguracionZAP,
    HallazgoZAP,
    InfoZAP,
    ResultadoZAP,
    diagnosticar_zap,
    ejecutar_analisis_pasivo,
    obtener_configuracion_zap,
    validar_objetivo_zap,
)

__all__ = [
    "TIEMPO_LIMITE_DIAGNOSTICO_AUTOMATICO",
    "TIEMPO_LIMITE_MAXIMO",
    "TIEMPO_LIMITE_MINIMO",
    "TIEMPO_LIMITE_POR_DEFECTO",
    "AdaptadorZAP",
    "ConfiguracionZAP",
    "HallazgoZAP",
    "InfoZAP",
    "ResultadoZAP",
]


@dataclass(frozen=True, slots=True)
class AdaptadorZAP:
    """Fachada de la integracion con OWASP ZAP: diagnostico y analisis pasivo."""

    nombre: str = "OWASP ZAP"

    def configuracion(self) -> ConfiguracionZAP:
        return obtener_configuracion_zap()

    def info(self, *, tiempo_limite: float | None = None) -> InfoZAP:
        """Diagnostico de solo lectura: nunca ejecuta un analisis.

        ``tiempo_limite`` es opcional: por defecto usa el limite normal (pensado para una
        comprobacion explicita del usuario, p. ej. 'est zap estado'). La comprobacion
        AUTOMATICA del panel "Herramientas"/arranque de la interfaz pasa un limite mucho
        mas corto (ver ``TIEMPO_LIMITE_DIAGNOSTICO_AUTOMATICO``) para no bloquear el
        arranque cuando ZAP no esta corriendo.
        """
        if tiempo_limite is None:
            return diagnosticar_zap(self.configuracion())
        return diagnosticar_zap(self.configuracion(), tiempo_limite=tiempo_limite)

    def validar_parametros(
        self, *, objetivo: str, tiempo_limite: float = TIEMPO_LIMITE_POR_DEFECTO
    ):
        if not (TIEMPO_LIMITE_MINIMO <= tiempo_limite <= TIEMPO_LIMITE_MAXIMO):
            raise ErrorParametrosIntegracion(
                f"El tiempo limite de ZAP debe estar entre {TIEMPO_LIMITE_MINIMO:g} y "
                f"{TIEMPO_LIMITE_MAXIMO:g} segundos."
            )
        return validar_objetivo_zap(objetivo)

    def ejecutar(
        self,
        *,
        objetivo: str,
        tiempo_limite: float = TIEMPO_LIMITE_POR_DEFECTO,
        debe_cancelar: Callable[[], bool] | None = None,
    ) -> ResultadoZAP:
        self.validar_parametros(objetivo=objetivo, tiempo_limite=tiempo_limite)
        return ejecutar_analisis_pasivo(
            self.configuracion(),
            objetivo,
            tiempo_limite=tiempo_limite,
            debe_cancelar=debe_cancelar,
        )
