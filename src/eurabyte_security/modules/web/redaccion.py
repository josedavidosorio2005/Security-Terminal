"""Redaccion de parametros sensibles en URLs mostradas al usuario o persistidas.

``redactar_url`` nunca se usa para construir la URL real contra la que AST se conecta
(esa sigue viviendo, intacta, en ``ComponentesURL``/``core/validation.py``): sirve
unicamente para la version que se MUESTRA en pantalla, se guarda en ``resultados_web``
o se exporta en un informe, de modo que un token, contrasena o API key que viaje en la
cadena de consulta de la URL (o en una cabecera ``Location`` de una redireccion) no
quede en claro en ningun registro.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

VALOR_REDACTADO = "<redactado>"

# Nombres de parametro (insensible a mayusculas) que habitualmente llevan un secreto.
PARAMETROS_SENSIBLES = frozenset(
    {
        "token",
        "access_token",
        "accesstoken",
        "refresh_token",
        "id_token",
        "api_key",
        "apikey",
        "api-key",
        "key",
        "secret",
        "client_secret",
        "clientsecret",
        "password",
        "passwd",
        "pwd",
        "pass",
        "auth",
        "authorization",
        "session",
        "sessionid",
        "session_id",
        "sid",
        "jwt",
        "credential",
        "credentials",
        "code",
        "otp",
        "pin",
    }
)


def redactar_url(url: str) -> str:
    """Devuelve ``url`` con los valores de sus parametros de consulta sensibles ocultos.

    Conserva el esquema, host, puerto, ruta y fragmento tal cual; solo reemplaza el
    *valor* de cada parametro de consulta cuyo nombre esta en ``PARAMETROS_SENSIBLES``
    (insensible a mayusculas) por ``"<redactado>"``. Si ``url`` no se puede interpretar,
    se devuelve sin cambios en vez de fallar: esta funcion es solo para presentacion, no
    para validacion (eso vive en ``core/validation.py``).
    """
    try:
        partes = urlsplit(url)
    except ValueError:
        return url

    if not partes.query:
        return url

    pares = parse_qsl(partes.query, keep_blank_values=True)
    pares_redactados = [
        (nombre, VALOR_REDACTADO if nombre.lower() in PARAMETROS_SENSIBLES else valor)
        for nombre, valor in pares
    ]
    query_redactada = urlencode(pares_redactados)
    return urlunsplit(
        (partes.scheme, partes.netloc, partes.path, query_redactada, partes.fragment)
    )
