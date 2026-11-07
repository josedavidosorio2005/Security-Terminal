"""Redaccion de datos sensibles en URLs mostradas al usuario o persistidas.

``redactar_url`` nunca se usa para construir la URL real contra la que AST se conecta
(esa sigue viviendo, intacta, en ``ComponentesURL``/``core/validation.py``): sirve
unicamente para la version que se MUESTRA en pantalla, se guarda en ``resultados_web``
o se exporta en un informe, de modo que un token, contrasena o API key que viaje en la
cadena de consulta, en el fragmento (``#...``, usado p. ej. por flujos OAuth implicitos)
o como credenciales en el propio host (``usuario:clave@host``) de una URL -- la del
objetivo, o la de destino de una cabecera ``Location`` de una redireccion -- no quede en
claro en ningun registro.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

VALOR_REDACTADO = "<redactado>"

# Palabras (insensibles a mayusculas) que, como SUBSTRING del nombre de un parametro,
# sugieren que su valor es un secreto. Se usa substring (no una lista exacta) a proposito:
# captura variantes como "auth_token", "my_api_key" o "x_session_id" que un nombre exacto
# no cubriria. El coste de un falso positivo (ocultar un parametro inocente) es minimo;
# el de un falso negativo (mostrar un secreto) no lo es.
PALABRAS_SENSIBLES = (
    "token",
    "key",
    "secret",
    "password",
    "passwd",
    "pwd",
    "pass",
    "auth",
    "session",
    "sid",
    "jwt",
    "credential",
    "code",
    "otp",
    "pin",
)


def _es_nombre_sensible(nombre: str) -> bool:
    nombre_bajo = nombre.lower()
    return any(palabra in nombre_bajo for palabra in PALABRAS_SENSIBLES)


def _redactar_pares(valor_bruto: str) -> str:
    """Redacta una cadena con forma de query string (``a=1&b=2``), sea query o fragmento."""
    pares = parse_qsl(valor_bruto, keep_blank_values=True)
    pares_redactados = [
        (nombre, VALOR_REDACTADO if _es_nombre_sensible(nombre) else valor)
        for nombre, valor in pares
    ]
    return urlencode(pares_redactados)


def redactar_url(url: str) -> str:
    """Devuelve ``url`` sin datos sensibles, lista para mostrarse o persistirse.

    Oculta tres cosas, cada una solo si esta presente:

    1. Credenciales en el host (``usuario:clave@host``): se eliminan por completo.
    2. El *valor* de cada parametro de la cadena de consulta cuyo nombre sugiere un
       secreto (ver ``PALABRAS_SENSIBLES``).
    3. Lo mismo, pero sobre el fragmento (``#...``) cuando tiene forma de parametros
       (``a=1&b=2``, el formato que usan los flujos OAuth implicitos); un fragmento sin
       esa forma (p. ej. un ancla simple ``#seccion2``) se deja intacto.

    Conserva el esquema, host, puerto y ruta tal cual. Si ``url`` no se puede interpretar,
    se devuelve sin cambios en vez de fallar: esta funcion es solo para presentacion, no
    para validacion (eso vive en ``core/validation.py``).
    """
    try:
        partes = urlsplit(url)
        puerto = partes.port
    except ValueError:
        return url

    netloc = partes.hostname or ""
    if puerto is not None:
        netloc = f"{netloc}:{puerto}"

    query_redactada = _redactar_pares(partes.query) if partes.query else partes.query
    fragmento_redactado = (
        _redactar_pares(partes.fragment) if "=" in partes.fragment else partes.fragment
    )

    return urlunsplit((partes.scheme, netloc, partes.path, query_redactada, fragmento_redactado))
