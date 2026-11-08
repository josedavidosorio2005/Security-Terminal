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

import re
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

    Conserva el esquema, host, puerto y ruta tal cual. Si ``url`` no se puede interpretar en
    absoluto, se devuelve ``VALOR_REDACTADO`` (nunca la cadena original sin tocar): esta
    funcion falla CERRADA, no abierta -- un dato que no se pudo analizar con seguridad no se
    muestra "por si acaso" tal cual, aunque eso signifique perder algo de informacion de
    presentacion en un caso raro. Un puerto invalido (no numerico) se trata por separado: no
    impide redactar el resto de la URL (credenciales, consulta, fragmento), simplemente se omite.
    """
    try:
        partes = urlsplit(url)
    except ValueError:
        return VALOR_REDACTADO

    try:
        puerto = partes.port
    except ValueError:
        puerto = None

    netloc = partes.hostname or ""
    if puerto is not None:
        netloc = f"{netloc}:{puerto}"

    query_redactada = _redactar_pares(partes.query) if partes.query else partes.query
    fragmento_redactado = (
        _redactar_pares(partes.fragment) if "=" in partes.fragment else partes.fragment
    )

    return urlunsplit((partes.scheme, netloc, partes.path, query_redactada, fragmento_redactado))


# Busca 'palabra_sensible: valor' o 'palabra_sensible=valor' (insensible a mayusculas) en
# texto libre (no necesariamente una URL): "Authorization: Bearer abc123" redacta
# "Bearer abc123" completo, no solo el primer token, deteniendose en el siguiente separador
# de campo (coma, punto y coma o salto de linea) si lo hay. Compartido por cualquier
# integracion externa que trate su propia salida como no confiable (Nuclei, OWASP ZAP...),
# para no duplicar la misma logica de redaccion en cada adaptador.
_PATRON_SECRETO_EN_TEXTO = re.compile(
    r"(?i)((?:" + "|".join(re.escape(p) for p in PALABRAS_SENSIBLES) + r")\w*\s*[:=]\s*)([^,;\n]+)"
)


def redactar_texto_libre(texto: str) -> str:
    """Redacta posibles secretos en texto libre (no necesariamente una URL).

    A diferencia de ``redactar_url`` (pensada para query strings/fragmentos de una URL),
    esta funcion busca el patron ``palabra_sensible: valor`` o ``palabra_sensible=valor``
    en cualquier texto -- por ejemplo, una cabecera ``Authorization: Bearer ...`` que una
    herramienta externa hubiera volcado en un mensaje de error o en un campo de texto libre
    de su salida (descripcion, evidencia...). Se aplica aunque, en el camino normal, ese
    campo sea texto estatico de confianza: AST trata TODA la salida de un binario o servicio
    externo como no confiable, no solo cuando se sabe de antemano que puede traer algo
    sensible.
    """
    return _PATRON_SECRETO_EN_TEXTO.sub(lambda m: m.group(1) + VALOR_REDACTADO, texto)
