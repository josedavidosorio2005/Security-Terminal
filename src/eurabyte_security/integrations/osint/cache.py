"""Cache con caducidad para respuestas de fuentes OSINT.

Reduce consultas repetidas a la misma fuente/objetivo dentro de su ventana de
caducidad (``ttl_segundos``), respetando los limites de tasa de cada proveedor. Se
guarda en disco, bajo ``EST_HOME`` (``core/config.py:ruta_cache_osint``), como un
archivo JSON por clave: sobrevive entre ejecuciones de la CLI (cada invocacion de
``est`` es un proceso nuevo), a diferencia de ``integrations/osint/limitador.py``, que
es deliberadamente solo de proceso.

Nunca se usa para cachear hallazgos ya persistidos (esos viven en
``hallazgos_osint``/``investigaciones_osint``, ver ``storage/database.py``): esta cache
es exclusivamente de la respuesta cruda de la fuente, para no repetir la peticion HTTP.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from eurabyte_security.core.config import ruta_cache_osint


def _ruta_entrada(clave: str) -> Any:
    nombre = hashlib.sha256(clave.encode("utf-8")).hexdigest()
    return ruta_cache_osint() / f"{nombre}.json"


def obtener(clave: str) -> Any | None:
    """Devuelve el valor cacheado para ``clave``, o ``None`` si no existe o caducó.

    Cualquier archivo ilegible o corrupto se trata como "sin cache" (nunca lanza una
    excepcion): la cache es una optimizacion, no una fuente de verdad.
    """
    ruta = _ruta_entrada(clave)
    if not ruta.exists():
        return None
    try:
        datos = json.loads(ruta.read_text(encoding="utf-8"))
        expira_en = datetime.fromisoformat(datos["expira_en"])
    except (json.JSONDecodeError, KeyError, ValueError, OSError):
        return None
    if datetime.now(UTC) >= expira_en:
        return None
    return datos["valor"]


def guardar(clave: str, valor: Any, ttl_segundos: float) -> None:
    ruta = _ruta_entrada(clave)
    expira_en = datetime.now(UTC) + timedelta(seconds=ttl_segundos)
    ruta.write_text(
        json.dumps({"expira_en": expira_en.isoformat(), "valor": valor}, ensure_ascii=False),
        encoding="utf-8",
    )
