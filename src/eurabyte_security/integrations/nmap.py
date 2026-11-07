"""Adaptador de Nmap (Fase 3): descubrimiento de puertos y servicios.

Ejecuta Nmap como un proceso externo (sin shell) contra un unico objetivo ya
validado, lee su salida en XML (``-oX``) y la convierte en datos estructurados
en espanol. La verificacion de alcance autorizado vive en
``commands/nmap.py``, no aqui: este modulo no sabe nada de proyectos ni de
alcance, solo sabe ejecutar Nmap e interpretar su resultado.
"""

from __future__ import annotations

import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from xml.etree.ElementTree import ParseError  # noqa: S405 - solo el tipo de excepcion

import defusedxml.ElementTree as ET

from eurabyte_security.core.errores import (
    ErrorEscaneoCancelado,
    ErrorIntegracion,
    ErrorParametrosIntegracion,
)
from eurabyte_security.core.validation import validar_objetivo, validar_puertos
from eurabyte_security.integrations.base import AdaptadorExterno

TIEMPO_LIMITE_MINIMO = 5.0
TIEMPO_LIMITE_MAXIMO = 600.0
TIEMPO_LIMITE_POR_DEFECTO = 120.0


@dataclass(frozen=True, slots=True)
class PuertoNmap:
    puerto: int
    protocolo: str
    estado: str
    servicio: str | None
    version: str | None


@dataclass(frozen=True, slots=True)
class ResultadoNmap:
    objetivo: str
    puertos: list[PuertoNmap]
    xml_crudo: str
    comando_ejecutado: tuple[str, ...]


def _analizar_xml_nmap(xml_texto: str) -> list[PuertoNmap]:
    try:
        raiz = ET.fromstring(xml_texto)
    except ParseError as exc:
        raise ErrorIntegracion(
            f"No se pudo interpretar la salida XML de Nmap: {exc}"
        ) from exc

    puertos: list[PuertoNmap] = []
    for puerto_el in raiz.findall("./host/ports/port"):
        portid = puerto_el.get("portid")
        if portid is None:
            continue
        protocolo = puerto_el.get("protocol", "tcp")
        estado_el = puerto_el.find("state")
        estado = estado_el.get("state", "desconocido") if estado_el is not None else "desconocido"
        servicio_el = puerto_el.find("service")
        servicio = servicio_el.get("name") if servicio_el is not None else None
        version = None
        if servicio_el is not None:
            partes = [servicio_el.get("product"), servicio_el.get("version")]
            partes_validas = [p for p in partes if p]
            version = " ".join(partes_validas) if partes_validas else None
        puertos.append(
            PuertoNmap(
                puerto=int(portid),
                protocolo=protocolo,
                estado=estado or "desconocido",
                servicio=servicio,
                version=version,
            )
        )
    return sorted(puertos, key=lambda p: p.puerto)


class AdaptadorNmap(AdaptadorExterno):
    """Descubrimiento de puertos TCP y, opcionalmente, deteccion de servicios."""

    nombre = "Nmap"
    comando = "nmap"
    argumentos_version = ("--version",)

    def validar_parametros(
        self,
        *,
        objetivo: str,
        puertos_especificacion: str,
        tiempo_limite: float = TIEMPO_LIMITE_POR_DEFECTO,
        **_kwargs: object,
    ) -> tuple[str, list[int]]:
        ip = validar_objetivo(objetivo)
        puertos = validar_puertos(puertos_especificacion)
        if not (TIEMPO_LIMITE_MINIMO <= tiempo_limite <= TIEMPO_LIMITE_MAXIMO):
            raise ErrorParametrosIntegracion(
                f"El tiempo limite de Nmap debe estar entre {TIEMPO_LIMITE_MINIMO} y "
                f"{TIEMPO_LIMITE_MAXIMO} segundos."
            )
        return str(ip), puertos

    def ejecutar(
        self,
        *,
        objetivo: str,
        puertos_especificacion: str,
        deteccion_version: bool = False,
        tiempo_limite: float = TIEMPO_LIMITE_POR_DEFECTO,
        debe_cancelar: Callable[[], bool] | None = None,
    ) -> ResultadoNmap:
        """Ejecuta Nmap contra ``objetivo`` y devuelve los puertos encontrados.

        ``deteccion_version`` activa ``-sV`` (identificacion de servicios y
        version): debe dejarse en ``False`` salvo que esa comprobacion este
        explicitamente autorizada para el objetivo, igual que el resto de
        parametros activos de EST. ``debe_cancelar``, si se indica, permite
        detener el proceso de Nmap mientras sigue en curso (ver
        ``integrations/proceso.py``); al cancelarse se lanza
        ``ErrorEscaneoCancelado`` y no se devuelve ningun resultado.
        """
        self.requerir_instalada()
        ip, puertos = self.validar_parametros(
            objetivo=objetivo, puertos_especificacion=puertos_especificacion,
            tiempo_limite=tiempo_limite,
        )
        lista_puertos = ",".join(str(p) for p in puertos)

        with tempfile.TemporaryDirectory(prefix="ast-nmap-") as directorio_temporal:
            ruta_xml = Path(directorio_temporal) / "resultado.xml"
            # -sT: connect scan, no requiere privilegios elevados (a diferencia de -sS).
            # -Pn: no descartar el objetivo aunque no responda a ping.
            argumentos = ["-sT", "-Pn", "-p", lista_puertos]
            if deteccion_version:
                argumentos.append("-sV")
            argumentos += ["-oX", str(ruta_xml), ip]

            resultado_proceso = self._ejecutar_binario(
                argumentos, tiempo_limite=tiempo_limite, debe_cancelar=debe_cancelar
            )

            if resultado_proceso.cancelado:
                raise ErrorEscaneoCancelado(
                    f"El analisis de Nmap contra '{objetivo}' se cancelo antes de "
                    "completarse. No se guardo ningun resultado."
                )
            if resultado_proceso.agotado_por_tiempo:
                raise ErrorIntegracion(
                    f"Nmap no termino en {tiempo_limite:g} segundos contra '{objetivo}'. "
                    "Reduce la cantidad de puertos o aumenta el limite de tiempo."
                )
            if not ruta_xml.exists():
                detalle = resultado_proceso.stderr.strip() or resultado_proceso.stdout.strip()
                raise ErrorIntegracion(
                    f"Nmap no genero resultados para '{objetivo}'"
                    + (f": {detalle}" if detalle else ".")
                )
            xml_crudo = ruta_xml.read_text(encoding="utf-8")

        puertos_resultado = _analizar_xml_nmap(xml_crudo)
        return ResultadoNmap(
            objetivo=ip,
            puertos=puertos_resultado,
            xml_crudo=xml_crudo,
            comando_ejecutado=(self.comando, *argumentos),
        )
