"""Interfaz base para adaptadores de herramientas externas (Fase 3).

Cada adaptador concreto (Nmap, Nuclei, OWASP ZAP, tshark...) hereda de
``AdaptadorExterno``. La clase base ya resuelve lo comun a cualquier
integracion -- deteccion del binario, lectura de version, limites de tiempo,
captura de E/S -- para que cada adaptador concreto solo tenga que ocuparse de
construir su propio comando y de interpretar su propia salida.
"""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from eurabyte_security.core.errores import ErrorHerramientaNoDisponible
from eurabyte_security.integrations.proceso import ResultadoProceso, ejecutar_proceso

TIEMPO_LIMITE_VERSION = 5.0


@dataclass(frozen=True, slots=True)
class InfoHerramienta:
    nombre: str
    comando: str
    instalada: bool
    ruta: str | None
    version: str | None


class AdaptadorExterno(ABC):
    """Contrato comun para integrar una herramienta externa de pentesting."""

    nombre: str
    comando: str
    # Argumento(s) para pedirle la version a la herramienta. La mayoria usa
    # "--version"; un adaptador concreto puede sobrescribirlo si necesita otra cosa.
    argumentos_version: tuple[str, ...] = ("--version",)

    def ruta_binario(self) -> str | None:
        return shutil.which(self.comando)

    def esta_instalado(self) -> bool:
        return self.ruta_binario() is not None

    def obtener_version(self) -> str | None:
        """Ejecuta ``<comando> <argumentos_version>`` y devuelve la primera linea util."""
        if not self.esta_instalado():
            return None
        resultado = ejecutar_proceso(
            [self.comando, *self.argumentos_version], tiempo_limite=TIEMPO_LIMITE_VERSION
        )
        salida = (resultado.stdout or resultado.stderr or "").strip()
        return salida.splitlines()[0].strip() if salida else None

    def info(self) -> InfoHerramienta:
        instalada = self.esta_instalado()
        return InfoHerramienta(
            nombre=self.nombre,
            comando=self.comando,
            instalada=instalada,
            ruta=self.ruta_binario(),
            version=self.obtener_version() if instalada else None,
        )

    def requerir_instalada(self) -> None:
        if not self.esta_instalado():
            raise ErrorHerramientaNoDisponible(self.mensaje_no_disponible())

    def mensaje_no_disponible(self) -> str:
        return (
            f"'{self.nombre}' no esta instalado o no se encuentra en el PATH del "
            f"sistema (se esperaba el comando '{self.comando}'). Instalalo y vuelve "
            "a intentarlo."
        )

    def _ejecutar_binario(
        self,
        argumentos: list[str],
        *,
        tiempo_limite: float,
        debe_cancelar: Callable[[], bool] | None = None,
    ) -> ResultadoProceso:
        """Punto unico de ejecucion real del binario: sin shell, con limite de tiempo."""
        self.requerir_instalada()
        return ejecutar_proceso(
            [self.comando, *argumentos], tiempo_limite=tiempo_limite, debe_cancelar=debe_cancelar
        )

    @abstractmethod
    def validar_parametros(self, **kwargs: Any) -> Any:
        """Valida los parametros de ``ejecutar``.

        Lanza ``ErrorParametrosIntegracion`` si no son validos.
        """

    @abstractmethod
    def ejecutar(self, **kwargs: Any) -> Any:
        """Ejecuta la herramienta. Debe validar parametros y comprobar que esta instalada."""
