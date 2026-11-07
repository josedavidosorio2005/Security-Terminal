"""Interfaz base para adaptadores de herramientas externas (Fase 3).

Cada adaptador concreto (Nmap, Nuclei, OWASP ZAP, tshark...) hereda de
``AdaptadorExterno``. La clase base ya resuelve lo comun a cualquier
integracion -- deteccion del binario, lectura de version, limites de tiempo,
captura de E/S -- para que cada adaptador concreto solo tenga que ocuparse de
construir su propio comando y de interpretar su propia salida.
"""

from __future__ import annotations

import os
import shutil
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from eurabyte_security.core.errores import ErrorHerramientaNoDisponible
from eurabyte_security.integrations.proceso import ResultadoProceso, ejecutar_proceso

TIEMPO_LIMITE_VERSION = 5.0

# En Windows, shutil.which() antepone el directorio de trabajo actual a la
# busqueda en PATH salvo que esta variable este definida (asi lo documenta
# CPython: internamente llama a la API de Windows NeedCurrentDirectoryForExePath,
# que respeta esta variable). Sin esto, alguien podria colocar un ejecutable
# malicioso con el mismo nombre ("nmap.exe", etc.) en el directorio desde el
# que se ejecuta AST y que se use ese en vez del binario real instalado en el
# sistema ("binary planting"). No tiene efecto en Linux/macOS.
os.environ.setdefault("NoDefaultCurrentDirectoryInExePath", "1")


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
        """Resuelve la ruta absoluta del binario (o ``None`` si no esta instalado).

        Se resuelve una sola vez por llamada y esa misma ruta absoluta es la
        que se pasa a ``Popen`` en ``_ejecutar_binario``/``obtener_version``:
        nunca se le pide al propio proceso que vuelva a buscar el nombre
        "pelado" del comando (eso dejaria la resolucion en manos del
        mecanismo de busqueda del sistema operativo en el momento de
        lanzar el proceso, en vez de en la que ya validamos aqui).
        """
        return shutil.which(self.comando)

    def esta_instalado(self) -> bool:
        return self.ruta_binario() is not None

    def _resolver_ruta_o_fallar(self) -> str:
        ruta = self.ruta_binario()
        if ruta is None:
            raise ErrorHerramientaNoDisponible(self.mensaje_no_disponible())
        return ruta

    def obtener_version(self) -> str | None:
        """Ejecuta ``<comando> <argumentos_version>`` y devuelve la primera linea util."""
        ruta = self.ruta_binario()
        if ruta is None:
            return None
        resultado = ejecutar_proceso(
            [ruta, *self.argumentos_version], tiempo_limite=TIEMPO_LIMITE_VERSION
        )
        salida = (resultado.stdout or resultado.stderr or "").strip()
        return salida.splitlines()[0].strip() if salida else None

    def info(self) -> InfoHerramienta:
        ruta = self.ruta_binario()
        return InfoHerramienta(
            nombre=self.nombre,
            comando=self.comando,
            instalada=ruta is not None,
            ruta=ruta,
            version=self.obtener_version() if ruta is not None else None,
        )

    def requerir_instalada(self) -> None:
        self._resolver_ruta_o_fallar()

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
        """Punto unico de ejecucion real del binario: sin shell, con limite de tiempo.

        Usa la ruta absoluta ya resuelta por ``ruta_binario()`` (no el nombre
        "pelado" del comando), para que no haya una segunda resolucion de
        PATH independiente al lanzar el proceso.
        """
        ruta = self._resolver_ruta_o_fallar()
        return ejecutar_proceso(
            [ruta, *argumentos], tiempo_limite=tiempo_limite, debe_cancelar=debe_cancelar
        )

    @abstractmethod
    def validar_parametros(self, **kwargs: Any) -> Any:
        """Valida los parametros de ``ejecutar``.

        Lanza ``ErrorParametrosIntegracion`` si no son validos.
        """

    @abstractmethod
    def ejecutar(self, **kwargs: Any) -> Any:
        """Ejecuta la herramienta. Debe validar parametros y comprobar que esta instalada."""
