"""Cliente HTTP(S) compartido por las fuentes OSINT.

Punto unico de acceso a una fuente externa vía HTTP(S) para todo ``integrations/osint/``
(equivalente, para fuentes OSINT, a lo que ``integrations/proceso.py`` es para binarios
externos): siempre con limite de tiempo, con reintentos acotados que respetan
``Retry-After``, cancelable entre reintentos, y que nunca deja escapar una excepcion
cruda de ``urllib`` hacia un adaptador -- todo se traduce a ``ErrorFuenteOSINTError``
con un mensaje saneado (sin la URL completa sin redactar, por si llevara una clave de
consulta sensible).

``urlopen`` se referencia como atributo de modulo (no se importa el nombre suelto)
precisamente para que las pruebas puedan sustituirlo
(``monkeypatch.setattr(cliente_http, "urlopen", doble)``) sin tener que parchear
``urllib.request`` global ni hacer una peticion de red real -- ninguna prueba de OSINT
toca una red de terceros (ver CLAUDE.md, regla 5).
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from email.message import Message

from eurabyte_security import __version__
from eurabyte_security.core.errores import ErrorFuenteOSINTError
from eurabyte_security.core.redaccion import redactar_url

urlopen = urllib.request.urlopen

AGENTE_USUARIO = f"AURABYTE-Security-Terminal/{__version__} (+OSINT; uso autorizado)"

TIEMPO_LIMITE_MINIMO = 1.0
TIEMPO_LIMITE_MAXIMO = 60.0
REINTENTOS_POR_DEFECTO = 2
ESPERA_REINTENTO_MAXIMA = 15.0
_INTERVALO_SONDEO_CANCELACION = 0.1


@dataclass(frozen=True, slots=True)
class RespuestaHTTP:
    codigo: int
    cuerpo: str
    cabeceras: Message


def _esperar_cancelable(segundos: float, debe_cancelar: Callable[[], bool] | None) -> bool:
    """Espera ``segundos``, sondeando cancelacion. Devuelve ``True`` si se cancelo."""
    restante = segundos
    while restante > 0:
        if debe_cancelar is not None and debe_cancelar():
            return True
        paso = min(_INTERVALO_SONDEO_CANCELACION, restante)
        time.sleep(paso)
        restante -= paso
    return debe_cancelar is not None and debe_cancelar()


def _segundos_retry_after(cabeceras: Message) -> float | None:
    valor = cabeceras.get("Retry-After")
    if valor is None:
        return None
    try:
        return max(0.0, float(valor))
    except ValueError:
        return None


def peticion_http(
    url: str,
    *,
    cabeceras: dict[str, str] | None = None,
    tiempo_limite: float = 10.0,
    reintentos: int = REINTENTOS_POR_DEFECTO,
    debe_cancelar: Callable[[], bool] | None = None,
) -> RespuestaHTTP:
    """Hace una peticion GET y devuelve ``(codigo, cuerpo, cabeceras)`` ya leidos.

    Reintenta sobre 429/503 respetando ``Retry-After`` (acotado a
    ``ESPERA_REINTENTO_MAXIMA`` para no bloquear la investigacion indefinidamente por una
    fuente que pida una espera larga); cualquier otro error HTTP o de conexion se traduce
    de inmediato a ``ErrorFuenteOSINTError`` sin reintentar. Nunca sigue reintentando
    despues de que ``debe_cancelar`` indique cancelacion.
    """
    tiempo_limite = max(TIEMPO_LIMITE_MINIMO, min(tiempo_limite, TIEMPO_LIMITE_MAXIMO))
    cabeceras_finales = {"User-Agent": AGENTE_USUARIO, "Accept": "application/json"}
    cabeceras_finales.update(cabeceras or {})

    intento = 0
    while True:
        if debe_cancelar is not None and debe_cancelar():
            raise ErrorFuenteOSINTError(
                "La investigacion se cancelo antes de completar la consulta."
            )

        peticion = urllib.request.Request(url, headers=cabeceras_finales, method="GET")
        try:
            with urlopen(peticion, timeout=tiempo_limite) as respuesta:
                cuerpo = respuesta.read().decode("utf-8", errors="replace")
                return RespuestaHTTP(
                    codigo=getattr(respuesta, "status", None) or respuesta.getcode(),
                    cuerpo=cuerpo,
                    cabeceras=respuesta.headers,
                )
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 503) and intento < reintentos:
                espera = _segundos_retry_after(exc.headers) if exc.headers else None
                espera = (
                    min(espera, ESPERA_REINTENTO_MAXIMA)
                    if espera is not None
                    else 1.0 * (intento + 1)
                )
                if _esperar_cancelable(espera, debe_cancelar):
                    raise ErrorFuenteOSINTError(
                        "La investigacion se cancelo mientras se esperaba el limite de tasa."
                    ) from exc
                intento += 1
                continue
            raise ErrorFuenteOSINTError(
                f"'{redactar_url(url)}' respondio con el codigo HTTP {exc.code}."
            ) from exc
        except TimeoutError as exc:
            raise ErrorFuenteOSINTError(
                f"'{redactar_url(url)}' no respondio en {tiempo_limite:g} segundos."
            ) from exc
        except urllib.error.URLError as exc:
            raise ErrorFuenteOSINTError(
                f"No se pudo contactar con '{redactar_url(url)}': {exc.reason}"
            ) from exc


def peticion_json(
    url: str,
    *,
    cabeceras: dict[str, str] | None = None,
    tiempo_limite: float = 10.0,
    reintentos: int = REINTENTOS_POR_DEFECTO,
    debe_cancelar: Callable[[], bool] | None = None,
) -> object:
    """Igual que :func:`peticion_http`, pero interpreta el cuerpo como JSON."""
    respuesta = peticion_http(
        url, cabeceras=cabeceras, tiempo_limite=tiempo_limite, reintentos=reintentos,
        debe_cancelar=debe_cancelar,
    )
    try:
        return json.loads(respuesta.cuerpo)
    except json.JSONDecodeError as exc:
        raise ErrorFuenteOSINTError(
            f"'{redactar_url(url)}' devolvio una respuesta que no es JSON valido."
        ) from exc
