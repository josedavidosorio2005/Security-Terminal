"""Cliente HTTP(S) de auditoria web: una unica peticion, sin shell ni intermediarios.

Usa ``http.client`` directamente (no ``urllib.request`` ni una libreria de terceros)
precisamente porque no sigue redirecciones automaticamente y no lee las variables de
entorno ``HTTP_PROXY``/``HTTPS_PROXY``/``NO_PROXY``: la unica conexion que se abre es la
que ``core.validation.validar_url_web`` ya valido como IPv4 literal. Quien decide si se
sigue una redireccion (y a donde) es ``modules/web/redirecciones.py``, nunca este modulo.

Certificados no confiables (autofirmados, vencidos, con el nombre equivocado): la
conexion HTTPS real (``HTTPSConnection``) sigue usando siempre validacion TLS completa
-- nunca se desactiva en silencio para poder leer el cuerpo de la respuesta. Si esa
conexion falla por confianza, ``realizar_peticion`` no se limita a lanzar un error: la
informacion que ``modules/web/tls.py:obtener_info_tls`` ya diagnostico (version,
cifrado, metadatos del certificado) se conserva y se devuelve igualmente, marcando
explicitamente que la parte HTTP de la peticion no se pudo completar.
"""

from __future__ import annotations

import http.client
import ssl
from collections.abc import Callable
from dataclasses import dataclass

from eurabyte_security.core.errores import ErrorAuditoriaWeb
from eurabyte_security.core.redaccion import redactar_url
from eurabyte_security.core.validation import ComponentesURL
from eurabyte_security.modules.web.tls import InfoTLS, obtener_info_tls

TIEMPO_LIMITE_POR_DEFECTO = 10.0

# Limite de bytes de cuerpo leidos de la respuesta: una auditoria de cabeceras/cookies no
# necesita paginas completas, y evita que una respuesta enorme (o infinita) agote memoria.
TAMANO_MAXIMO_CUERPO = 2 * 1024 * 1024  # 2 MiB


@dataclass(frozen=True, slots=True)
class RespuestaWeb:
    componentes: ComponentesURL
    codigo_estado: int | None
    cabeceras: tuple[tuple[str, str], ...]
    cuerpo: bytes
    cuerpo_truncado: bool
    ubicacion_redireccion: str | None
    tls: InfoTLS | None
    # Si no es None, la peticion HTTP no se completo (p. ej. porque la conexion TLS no
    # era confiable y AST no la fuerza igualmente): codigo_estado, cabeceras, cuerpo y
    # ubicacion_redireccion quedan vacios/None, pero tls conserva lo que se diagnostico.
    error_http: str | None = None


def _es_redireccion(codigo_estado: int) -> bool:
    return codigo_estado in (301, 302, 303, 307, 308)


def realizar_peticion(
    componentes: ComponentesURL,
    *,
    metodo: str = "GET",
    tiempo_limite: float = TIEMPO_LIMITE_POR_DEFECTO,
    debe_cancelar: Callable[[], bool] | None = None,
) -> RespuestaWeb:
    """Realiza una unica peticion HTTP(S) contra ``componentes``, sin seguir redirecciones.

    La verificacion de alcance autorizado debe haberse hecho YA antes de llamar a esta
    funcion (ver ``commands/web.py``): este modulo solo sabe hablar HTTP, no sabe nada de
    proyectos ni de alcance. ``debe_cancelar``, si se indica, se consulta antes de abrir
    la conexion y mientras se lee el cuerpo de la respuesta; si se cancela, se lanza
    ``ErrorAuditoriaWeb`` y no se devuelve ningun resultado parcial.
    """
    if debe_cancelar is not None and debe_cancelar():
        raise ErrorAuditoriaWeb("La auditoria se cancelo antes de iniciar la peticion.")

    host_texto = str(componentes.host)
    if componentes.esquema == "https":
        # obtener_info_tls() nunca deja escapar un TimeoutError/OSError crudo: los
        # convierte siempre a ErrorAuditoriaWeb (ver modules/web/tls.py), asi que no
        # hace falta envolver esta llamada en un try/except adicional aqui.
        tls_info = obtener_info_tls(
            componentes.host, componentes.puerto, tiempo_limite=tiempo_limite
        )
        conexion: http.client.HTTPConnection = http.client.HTTPSConnection(
            host_texto, componentes.puerto, timeout=tiempo_limite
        )
    else:
        tls_info = None
        conexion = http.client.HTTPConnection(host_texto, componentes.puerto, timeout=tiempo_limite)

    try:
        conexion.connect()
    except ssl.SSLError as exc:
        # La conexion TLS no es confiable (certificado autofirmado, vencido, nombre de
        # host equivocado...). Nunca se continua con la peticion HTTP ignorando esa
        # validacion: se devuelve lo que obtener_info_tls ya diagnostico (version,
        # cifrado, metadatos del certificado) marcando explicitamente que la parte
        # HTTP de la peticion no se pudo completar, en vez de perder esa informacion.
        conexion.close()
        return RespuestaWeb(
            componentes=componentes,
            codigo_estado=None,
            cabeceras=(),
            cuerpo=b"",
            cuerpo_truncado=False,
            ubicacion_redireccion=None,
            tls=tls_info,
            error_http=(
                "No se pudo completar la peticion HTTP: la conexion TLS no es "
                f"confiable ({exc})."
            ),
        )
    except TimeoutError as exc:
        conexion.close()
        raise ErrorAuditoriaWeb(
            f"Tiempo agotado al conectar con {host_texto}:{componentes.puerto}."
        ) from exc
    except OSError as exc:
        conexion.close()
        raise ErrorAuditoriaWeb(
            f"No se pudo conectar con {host_texto}:{componentes.puerto}: {exc}"
        ) from exc

    try:
        if debe_cancelar is not None and debe_cancelar():
            raise ErrorAuditoriaWeb("La auditoria se cancelo antes de completarse.")

        conexion.putrequest(
            metodo, componentes.ruta, skip_host=True, skip_accept_encoding=True
        )
        conexion.putheader("Host", host_texto)
        conexion.putheader("User-Agent", "AURABYTE-Security-Terminal/auditoria-web")
        conexion.putheader("Accept", "*/*")
        conexion.putheader("Connection", "close")
        conexion.endheaders()

        respuesta = conexion.getresponse()
        cabeceras = tuple(respuesta.getheaders())
        ubicacion = respuesta.getheader("Location") if _es_redireccion(respuesta.status) else None

        cuerpo = bytearray()
        truncado = False
        while True:
            if debe_cancelar is not None and debe_cancelar():
                raise ErrorAuditoriaWeb("La auditoria se cancelo antes de completarse.")
            fragmento = respuesta.read(8192)
            if not fragmento:
                break
            cuerpo.extend(fragmento)
            if len(cuerpo) >= TAMANO_MAXIMO_CUERPO:
                truncado = True
                break

        return RespuestaWeb(
            componentes=componentes,
            codigo_estado=respuesta.status,
            cabeceras=cabeceras,
            cuerpo=bytes(cuerpo),
            cuerpo_truncado=truncado,
            ubicacion_redireccion=ubicacion,
            tls=tls_info,
        )
    except TimeoutError as exc:
        raise ErrorAuditoriaWeb(
            f"Tiempo agotado al auditar {redactar_url(componentes.url_original)}."
        ) from exc
    except ConnectionError as exc:
        raise ErrorAuditoriaWeb(
            f"No se pudo conectar con {host_texto}:{componentes.puerto}: {exc}"
        ) from exc
    except OSError as exc:
        raise ErrorAuditoriaWeb(
            f"Fallo de red auditando {redactar_url(componentes.url_original)}: {exc}"
        ) from exc
    finally:
        conexion.close()
