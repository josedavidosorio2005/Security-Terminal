"""Evaluacion segura de redirecciones HTTP.

``modules/web/cliente.py`` nunca sigue una redireccion por si mismo. Este modulo decide
si una redireccion detectada puede seguirse de forma segura (destino IPv4 literal,
dentro del alcance autorizado del proyecto) y, si no, explica por que AST se detuvo en
vez de seguirla -- esa es la defensa principal contra SSRF y contra que una
redireccion saque una peticion fuera del alcance acordado.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urljoin

from eurabyte_security.core.errores import ErrorAuditoriaWeb, ErrorFueraDeAlcance
from eurabyte_security.core.errores import ErrorValidacion as _ErrorValidacion
from eurabyte_security.core.validation import ComponentesURL, validar_url_web
from eurabyte_security.modules.web.cliente import RespuestaWeb
from eurabyte_security.modules.web.modelos import Hallazgo
from eurabyte_security.modules.web.redaccion import redactar_url

_REFERENCIA = "https://developer.mozilla.org/docs/Web/HTTP/Redirections"


def resolver_siguiente_salto(
    respuesta: RespuestaWeb, *, redes_autorizadas: list[ipaddress.IPv4Network]
) -> ComponentesURL:
    """Valida el destino de una redireccion y lo devuelve ya como ``ComponentesURL``.

    Lanza ``ErrorAuditoriaWeb`` si el destino no se puede evaluar con seguridad (nombre
    de dominio en vez de IPv4 literal, URL malformada) y ``ErrorFueraDeAlcance`` si el
    destino es una IP valida pero no esta autorizada en el proyecto. Nunca se abre una
    conexion desde aqui: solo se interpreta y valida la URL de destino.
    """
    if not respuesta.ubicacion_redireccion:
        raise ErrorAuditoriaWeb("La respuesta no incluye una cabecera 'Location' a seguir.")

    destino_absoluto = urljoin(respuesta.componentes.url_original, respuesta.ubicacion_redireccion)
    try:
        componentes_destino = validar_url_web(destino_absoluto)
    except _ErrorValidacion as exc:
        raise ErrorAuditoriaWeb(
            f"La redireccion apunta a '{redactar_url(destino_absoluto)}', que no se "
            f"puede seguir de forma segura: {exc}"
        ) from exc

    objetivo_ip = componentes_destino.host
    if not any(objetivo_ip in red for red in redes_autorizadas):
        raise ErrorFueraDeAlcance(
            f"La redireccion de '{redactar_url(respuesta.componentes.url_original)}' "
            f"apunta a '{redactar_url(destino_absoluto)}', que no esta dentro del "
            "alcance autorizado del proyecto. AST no la sigue."
        )

    return componentes_destino


def evaluar_redireccion(
    respuesta: RespuestaWeb,
    *,
    redes_autorizadas: list[ipaddress.IPv4Network],
    se_siguio: bool,
) -> list[Hallazgo]:
    """Describe la redireccion detectada (si hay alguna) y si AST la siguio o no."""
    if not respuesta.ubicacion_redireccion:
        return []

    destino_absoluto = urljoin(
        respuesta.componentes.url_original, respuesta.ubicacion_redireccion
    )

    try:
        componentes_destino = validar_url_web(destino_absoluto)
        dentro_de_alcance = any(
            componentes_destino.host in red for red in redes_autorizadas
        )
    except _ErrorValidacion:
        componentes_destino = None
        dentro_de_alcance = False

    if componentes_destino is None:
        severidad = "media"
        estado = "No se puede evaluar con seguridad"
        riesgo = (
            "El destino no es una direccion IPv4 literal (p. ej. es un nombre de dominio). "
            "Seguirlo implicaria una resolucion DNS fuera del control explicito del "
            "usuario, lo que abre la puerta a SSRF mediante respuestas DNS manipuladas."
        )
        recomendacion = "Verifica manualmente el destino antes de auditarlo por su IP."
    elif not dentro_de_alcance:
        severidad = "alta"
        estado = "Fuera de alcance -- no seguida"
        riesgo = (
            "Si AST (u otro cliente automatizado) siguiera esta redireccion sin "
            "comprobar el alcance, podria terminar haciendo peticiones contra un "
            "objetivo no autorizado (SSRF)."
        )
        recomendacion = (
            "Si el destino es intencional y esta autorizado, agregalo al alcance del "
            "proyecto antes de auditarlo explicitamente."
        )
    elif se_siguio:
        severidad = "info"
        estado = "Dentro de alcance -- seguida"
        riesgo = "Ninguno: el destino esta autorizado y AST la siguio de forma explicita."
        recomendacion = "Ninguna accion necesaria."
    else:
        severidad = "info"
        estado = "Dentro de alcance -- no seguida (usa --seguir-redirecciones)"
        riesgo = "Ninguno detectado en el destino en si."
        recomendacion = (
            "Si quieres que AST audite tambien el destino, repite el analisis con "
            "'--seguir-redirecciones'."
        )

    return [
        Hallazgo(
            categoria="redireccion",
            id_="redireccion",
            nombre=f"Redireccion HTTP {respuesta.codigo_estado}",
            significado="El servidor respondio con una redireccion hacia otra URL.",
            proposito=(
                "Verificar que ninguna redireccion saque la auditoria fuera del "
                "alcance autorizado."
            ),
            valor_detectado=redactar_url(destino_absoluto),
            severidad=severidad,  # type: ignore[arg-type]
            estado=estado,
            riesgo=riesgo,
            recomendacion=recomendacion,
            referencia=_REFERENCIA,
        )
    ]
