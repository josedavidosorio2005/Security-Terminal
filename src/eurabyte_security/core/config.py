"""Rutas y configuracion local de EST.

Toda la informacion persistente (base de datos SQLite, configuracion e
historial de la terminal interactiva) vive bajo un unico directorio de datos,
para que la aplicacion funcione igual en Windows y en Linux. El directorio se
puede redirigir con la variable de entorno ``EST_HOME`` (usada sobre todo por
las pruebas automatizadas para aislar el estado entre ejecuciones).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

_NOMBRE_DIRECTORIO = ".eurabyte_security"


def directorio_datos() -> Path:
    """Devuelve el directorio de datos de EST, creandolo si no existe."""
    override = os.environ.get("EST_HOME")
    base = Path(override).expanduser() if override else Path.home() / _NOMBRE_DIRECTORIO
    base.mkdir(parents=True, exist_ok=True)
    return base


def ruta_base_datos() -> Path:
    return directorio_datos() / "est.db"


def ruta_configuracion() -> Path:
    return directorio_datos() / "config.json"


def ruta_historial() -> Path:
    return directorio_datos() / "historial.txt"


def ruta_reportes() -> Path:
    directorio = directorio_datos() / "reportes"
    directorio.mkdir(parents=True, exist_ok=True)
    return directorio


def ruta_evidencias(herramienta: str) -> Path:
    """Directorio donde cada integracion (Nmap, Nuclei...) guarda su salida cruda."""
    directorio = directorio_datos() / "evidencias" / herramienta
    directorio.mkdir(parents=True, exist_ok=True)
    return directorio


def _leer_configuracion() -> dict[str, Any]:
    ruta = ruta_configuracion()
    if not ruta.exists():
        return {}
    try:
        return json.loads(ruta.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _escribir_configuracion(datos: dict[str, Any]) -> None:
    ruta_configuracion().write_text(
        json.dumps(datos, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def obtener_proyecto_activo() -> str | None:
    return _leer_configuracion().get("proyecto_activo")


def establecer_proyecto_activo(nombre: str) -> None:
    datos = _leer_configuracion()
    datos["proyecto_activo"] = nombre
    _escribir_configuracion(datos)
