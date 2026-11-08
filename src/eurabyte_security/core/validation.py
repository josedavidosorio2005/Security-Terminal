"""Validaciones de entrada compartidas por comandos y modulos.

Estas funciones son el punto de control de seguridad del MVP: evitan que un
objetivo, puerto o rango mal formado (o fuera del alcance autorizado) llegue a
ejecutar trafico de red real.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from eurabyte_security.core.errores import ErrorValidacion
from eurabyte_security.core.redaccion import redactar_url

NOMBRE_PROYECTO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

ESQUEMAS_WEB_VALIDOS = ("http", "https")
PUERTOS_POR_DEFECTO_WEB = {"http": 80, "https": 443}

PUERTO_MINIMO = 1
PUERTO_MAXIMO = 65535
MAX_PUERTOS_POR_ESCANEO = 1024

ESQUEMAS_NUCLEI_VALIDOS = ("http", "https")
PUERTOS_POR_DEFECTO_NUCLEI = {"http": 80, "https": 443}

TIMEOUT_MINIMO = 0.1
TIMEOUT_MAXIMO = 10.0

CONCURRENCIA_MINIMA = 1
CONCURRENCIA_MAXIMA = 200

# Tiempo limite por peticion de auditoria web (una sola peticion HTTP(S)); distinto del
# tiempo limite total de toda la auditoria (ver modules/web/auditor.py:TIEMPO_LIMITE_TOTAL_MAXIMO),
# que acota la suma de todas las peticiones cuando se siguen redirecciones.
TIEMPO_LIMITE_WEB_MINIMO = 1.0
TIEMPO_LIMITE_WEB_MAXIMO = 30.0


def validar_nombre_proyecto(nombre: str) -> str:
    nombre = nombre.strip()
    if not nombre:
        raise ErrorValidacion("El nombre del proyecto no puede estar vacio.")
    if not NOMBRE_PROYECTO_RE.match(nombre):
        raise ErrorValidacion(
            "El nombre del proyecto solo puede contener letras, numeros, "
            "puntos, guiones y guiones bajos (maximo 64 caracteres)."
        )
    return nombre


def validar_red(objetivo: str) -> ipaddress.IPv4Network:
    """Valida una entrada de alcance (IP unica o red en notacion CIDR)."""
    objetivo = objetivo.strip()
    if not objetivo:
        raise ErrorValidacion("El alcance no puede estar vacio.")
    try:
        if "/" not in objetivo:
            objetivo = f"{objetivo}/32"
        return ipaddress.IPv4Network(objetivo, strict=False)
    except ValueError as exc:
        raise ErrorValidacion(
            f"'{objetivo}' no es una direccion IPv4 ni una red CIDR valida."
        ) from exc


def validar_objetivo(objetivo: str) -> ipaddress.IPv4Address:
    """Valida el objetivo de un escaneo.

    En la Fase 1 solo se aceptan direcciones IPv4 literales: resolver nombres
    de dominio implicaria trafico de red adicional fuera del control del
    usuario, por lo que queda fuera del MVP.
    """
    objetivo = objetivo.strip()
    try:
        return ipaddress.IPv4Address(objetivo)
    except ValueError as exc:
        raise ErrorValidacion(
            f"'{objetivo}' no es una direccion IPv4 valida. "
            "La Fase 1 no admite nombres de dominio, solo direcciones IP."
        ) from exc


def validar_puertos(especificacion: str) -> list[int]:
    """Convierte '22,80,443' en una lista de puertos validados y sin duplicados."""
    especificacion = especificacion.strip()
    if not especificacion:
        raise ErrorValidacion("Debes indicar al menos un puerto con --puertos.")

    puertos: list[int] = []
    for parte in especificacion.split(","):
        parte = parte.strip()
        if not parte:
            continue
        if not parte.isdigit():
            raise ErrorValidacion(f"'{parte}' no es un numero de puerto valido.")
        puerto = int(parte)
        if not (PUERTO_MINIMO <= puerto <= PUERTO_MAXIMO):
            raise ErrorValidacion(
                f"El puerto {puerto} esta fuera del rango valido "
                f"({PUERTO_MINIMO}-{PUERTO_MAXIMO})."
            )
        if puerto not in puertos:
            puertos.append(puerto)

    if not puertos:
        raise ErrorValidacion("Debes indicar al menos un puerto con --puertos.")
    if len(puertos) > MAX_PUERTOS_POR_ESCANEO:
        raise ErrorValidacion(
            f"No se pueden escanear mas de {MAX_PUERTOS_POR_ESCANEO} puertos en una "
            "sola ejecucion. Divide el escaneo en lotes mas pequenos."
        )
    return puertos


# Cantidad maxima de puertos/rangos separados por comas en una especificacion para
# Nmap (p. ej. '22,80,1000-2000'): limita el TAMAÑO DEL TEXTO de entrada (una
# proteccion razonable contra una cadena absurdamente larga), nunca la cantidad de
# puertos que un rango puede cubrir -- un solo token '1-65535' sigue siendo valido.
MAX_TOKENS_ESPECIFICACION_PUERTOS_NMAP = 64

# Perfiles de puertos predefinidos para Nmap (ver docs/COMANDOS.md): 'rapido' es un
# listado corto de servicios comunes; 'completo' es el rango IANA completo. Nmap los
# expande de forma NATIVA al ejecutar '-p' -- AST nunca construye una lista de 65535
# enteros en Python para pasarsela (eso es exactamente lo que se evita aqui).
PERFILES_PUERTOS_NMAP: dict[str, str] = {
    "rapido": "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080",
    "completo": f"{PUERTO_MINIMO}-{PUERTO_MAXIMO}",
}


def validar_especificacion_puertos_nmap(especificacion: str) -> str:
    """Valida una especificacion de puertos para Nmap: admite rangos ('1-1024'),
    ademas de una lista separada por comas, porque Nmap los expande de forma nativa
    al recibir '-p' -- a diferencia de ``validar_puertos`` (usado por el motor TCP
    propio de AST, que abre una conexion por puerto desde el propio proceso de
    Python y por eso sigue acotado a ``MAX_PUERTOS_POR_ESCANEO``), aqui no hace falta
    expandir nada: se devuelve la especificacion normalizada tal cual, lista para
    pasarse como UN SOLO argumento de '-p' (``integrations/proceso.py`` nunca la
    interpola en un shell).

    Tambien acepta los nombres de los perfiles predefinidos (ver
    ``PERFILES_PUERTOS_NMAP``): ``'rapido'`` o ``'completo'``.
    """
    especificacion = especificacion.strip()
    if not especificacion:
        raise ErrorValidacion("Debes indicar al menos un puerto o rango con --puertos.")

    perfil = PERFILES_PUERTOS_NMAP.get(especificacion.lower())
    if perfil is not None:
        especificacion = perfil

    tokens = [t.strip() for t in especificacion.split(",") if t.strip()]
    if not tokens:
        raise ErrorValidacion("Debes indicar al menos un puerto o rango con --puertos.")
    if len(tokens) > MAX_TOKENS_ESPECIFICACION_PUERTOS_NMAP:
        raise ErrorValidacion(
            f"No se pueden indicar mas de {MAX_TOKENS_ESPECIFICACION_PUERTOS_NMAP} "
            "puertos/rangos separados por comas en una sola especificacion."
        )

    normalizados: list[str] = []
    for token in tokens:
        if "-" in token:
            extremos = token.split("-")
            if len(extremos) != 2 or not all(e.isdigit() for e in extremos):
                raise ErrorValidacion(
                    f"'{token}' no es un rango de puertos valido (ej. '1-1024')."
                )
            inicio, fin = int(extremos[0]), int(extremos[1])
            for valor in (inicio, fin):
                if not (PUERTO_MINIMO <= valor <= PUERTO_MAXIMO):
                    raise ErrorValidacion(
                        f"El rango '{token}' esta fuera de {PUERTO_MINIMO}-{PUERTO_MAXIMO}."
                    )
            if inicio > fin:
                raise ErrorValidacion(
                    f"El rango '{token}' tiene el extremo inicial mayor que el final."
                )
            normalizados.append(f"{inicio}-{fin}")
        else:
            if not token.isdigit():
                raise ErrorValidacion(f"'{token}' no es un numero de puerto valido.")
            puerto = int(token)
            if not (PUERTO_MINIMO <= puerto <= PUERTO_MAXIMO):
                raise ErrorValidacion(
                    f"El puerto {puerto} esta fuera del rango valido "
                    f"({PUERTO_MINIMO}-{PUERTO_MAXIMO})."
                )
            normalizados.append(str(puerto))

    return ",".join(normalizados)


def validar_timeout(valor: float) -> float:
    if not (TIMEOUT_MINIMO <= valor <= TIMEOUT_MAXIMO):
        raise ErrorValidacion(
            f"El tiempo de espera debe estar entre {TIMEOUT_MINIMO} y "
            f"{TIMEOUT_MAXIMO} segundos."
        )
    return valor


def validar_tiempo_limite_web(valor: float) -> float:
    """Valida el tiempo limite de UNA peticion de auditoria web (no el total de la auditoria)."""
    if not (TIEMPO_LIMITE_WEB_MINIMO <= valor <= TIEMPO_LIMITE_WEB_MAXIMO):
        raise ErrorValidacion(
            f"El tiempo limite de la peticion debe estar entre {TIEMPO_LIMITE_WEB_MINIMO:g} y "
            f"{TIEMPO_LIMITE_WEB_MAXIMO:g} segundos."
        )
    return valor


def validar_concurrencia(valor: int) -> int:
    if not (CONCURRENCIA_MINIMA <= valor <= CONCURRENCIA_MAXIMA):
        raise ErrorValidacion(
            f"La concurrencia debe estar entre {CONCURRENCIA_MINIMA} y "
            f"{CONCURRENCIA_MAXIMA} conexiones simultaneas."
        )
    return valor


def objetivo_en_alcance(
    objetivo: ipaddress.IPv4Address, redes: list[ipaddress.IPv4Network]
) -> bool:
    return any(objetivo in red for red in redes)


@dataclass(frozen=True, slots=True)
class ComponentesURL:
    """URL de auditoria web ya validada: esquema, host IPv4 literal, puerto y ruta."""

    url_original: str
    esquema: str
    host: ipaddress.IPv4Address
    puerto: int
    ruta: str


def validar_url_web(url: str) -> ComponentesURL:
    """Valida una URL objetivo de auditoria web.

    Igual que ``validar_objetivo``, por ahora solo se aceptan direcciones IPv4
    literales como host: resolver nombres de dominio implicaria trafico de red
    (una consulta DNS) fuera del control explicito del usuario y abre la puerta
    a SSRF mediante respuestas DNS manipuladas. Solo se aceptan los esquemas
    ``http`` y ``https``.
    """
    url = url.strip()
    if not url:
        raise ErrorValidacion("La URL no puede estar vacia.")

    # Todos los mensajes de error de aqui en adelante interpolan la URL (o partes de
    # ella) tal como la escribio el usuario; siempre a traves de redactar_url(), nunca
    # el valor crudo, para que un token/contrasena/API key en la cadena de consulta (o
    # las propias credenciales que la segunda comprobacion rechaza) no queden en claro
    # en una excepcion visible, en la CLI/Textual o en un registro.
    try:
        partes = urlsplit(url)
    except ValueError as exc:
        raise ErrorValidacion(f"'{redactar_url(url)}' no es una URL valida: {exc}") from exc

    esquema = partes.scheme.lower()
    if esquema not in ESQUEMAS_WEB_VALIDOS:
        raise ErrorValidacion(
            f"'{redactar_url(url)}' usa el esquema '{esquema or '(ninguno)'}', pero solo "
            f"se admiten {' y '.join(ESQUEMAS_WEB_VALIDOS)}."
        )

    if partes.username or partes.password:
        raise ErrorValidacion(
            f"'{redactar_url(url)}' incluye credenciales en la URL (usuario/contrasena); "
            "no estan permitidas en un objetivo de auditoria."
        )

    nombre_host = partes.hostname
    if not nombre_host:
        raise ErrorValidacion(f"'{redactar_url(url)}' no indica un host valido.")

    try:
        host = ipaddress.IPv4Address(nombre_host)
    except ValueError as exc:
        raise ErrorValidacion(
            f"'{nombre_host}' no es una direccion IPv4 valida. Esta version de AST no "
            "admite nombres de dominio como objetivo de auditoria web, solo direcciones IP."
        ) from exc

    try:
        puerto = partes.port if partes.port is not None else PUERTOS_POR_DEFECTO_WEB[esquema]
    except ValueError as exc:
        raise ErrorValidacion(f"'{redactar_url(url)}' tiene un puerto invalido.") from exc
    if not (PUERTO_MINIMO <= puerto <= PUERTO_MAXIMO):
        raise ErrorValidacion(
            f"El puerto {puerto} esta fuera del rango valido ({PUERTO_MINIMO}-{PUERTO_MAXIMO})."
        )

    ruta = partes.path or "/"
    if partes.query:
        ruta = f"{ruta}?{partes.query}"

    return ComponentesURL(url_original=url, esquema=esquema, host=host, puerto=puerto, ruta=ruta)


@dataclass(frozen=True, slots=True)
class ObjetivoNuclei:
    """Objetivo de un analisis de Nuclei ya validado: esquema, host IPv4 y puerto."""

    url_original: str
    esquema: str
    host: ipaddress.IPv4Address
    puerto: int


def validar_objetivo_nuclei(objetivo: str) -> ObjetivoNuclei:
    """Valida el objetivo de un analisis de Nuclei: esquema + host IPv4 + puerto, sin ruta.

    A diferencia de una auditoria web completa, Nuclei nunca recibe una ruta ni una
    cadena de consulta del usuario: los unicos caminos que puede pedir son los que ya
    definen las plantillas aprobadas de AST (ver ``integrations/nuclei.py``). Aceptar
    una ruta aqui no tendria ningun efecto util y solo anadiria una entrada que validar
    sin necesidad. Igual que ``validar_objetivo``, solo se aceptan direcciones IPv4
    literales como host (no nombres de dominio).
    """
    objetivo = objetivo.strip()
    if not objetivo:
        raise ErrorValidacion("El objetivo no puede estar vacio.")
    if "://" not in objetivo:
        objetivo = f"http://{objetivo}"

    try:
        partes = urlsplit(objetivo)
    except ValueError as exc:
        raise ErrorValidacion(f"'{objetivo}' no es un objetivo valido: {exc}") from exc

    esquema = partes.scheme.lower()
    if esquema not in ESQUEMAS_NUCLEI_VALIDOS:
        raise ErrorValidacion(
            f"El objetivo usa el esquema '{esquema or '(ninguno)'}', pero solo se "
            f"admiten {' y '.join(ESQUEMAS_NUCLEI_VALIDOS)}."
        )

    if partes.username or partes.password:
        raise ErrorValidacion("El objetivo no puede incluir credenciales (usuario/contrasena).")

    if (partes.path and partes.path != "/") or partes.query or partes.fragment:
        raise ErrorValidacion(
            "El objetivo de Nuclei no admite ruta ni parametros de consulta: solo "
            "esquema, host y puerto opcional (las rutas las define cada plantilla "
            "aprobada, no el usuario)."
        )

    nombre_host = partes.hostname
    if not nombre_host:
        raise ErrorValidacion(f"'{objetivo}' no indica un host valido.")

    try:
        host = ipaddress.IPv4Address(nombre_host)
    except ValueError as exc:
        raise ErrorValidacion(
            f"'{nombre_host}' no es una direccion IPv4 valida. Esta version de AST no "
            "admite nombres de dominio como objetivo, solo direcciones IP."
        ) from exc

    try:
        puerto = partes.port if partes.port is not None else PUERTOS_POR_DEFECTO_NUCLEI[esquema]
    except ValueError as exc:
        raise ErrorValidacion(f"'{objetivo}' tiene un puerto invalido.") from exc
    if not (PUERTO_MINIMO <= puerto <= PUERTO_MAXIMO):
        raise ErrorValidacion(
            f"El puerto {puerto} esta fuera del rango valido ({PUERTO_MINIMO}-{PUERTO_MAXIMO})."
        )

    return ObjetivoNuclei(url_original=objetivo, esquema=esquema, host=host, puerto=puerto)
