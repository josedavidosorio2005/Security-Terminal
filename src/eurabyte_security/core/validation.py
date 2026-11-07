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

NOMBRE_PROYECTO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

ESQUEMAS_WEB_VALIDOS = ("http", "https")
PUERTOS_POR_DEFECTO_WEB = {"http": 80, "https": 443}

PUERTO_MINIMO = 1
PUERTO_MAXIMO = 65535
MAX_PUERTOS_POR_ESCANEO = 1024

TIMEOUT_MINIMO = 0.1
TIMEOUT_MAXIMO = 10.0

CONCURRENCIA_MINIMA = 1
CONCURRENCIA_MAXIMA = 200


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


def validar_timeout(valor: float) -> float:
    if not (TIMEOUT_MINIMO <= valor <= TIMEOUT_MAXIMO):
        raise ErrorValidacion(
            f"El tiempo de espera debe estar entre {TIMEOUT_MINIMO} y "
            f"{TIMEOUT_MAXIMO} segundos."
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

    try:
        partes = urlsplit(url)
    except ValueError as exc:
        raise ErrorValidacion(f"'{url}' no es una URL valida: {exc}") from exc

    esquema = partes.scheme.lower()
    if esquema not in ESQUEMAS_WEB_VALIDOS:
        raise ErrorValidacion(
            f"'{url}' usa el esquema '{esquema or '(ninguno)'}', pero solo se admiten "
            f"{' y '.join(ESQUEMAS_WEB_VALIDOS)}."
        )

    if partes.username or partes.password:
        raise ErrorValidacion(
            f"'{url}' incluye credenciales en la URL (usuario/contrasena); no estan "
            "permitidas en un objetivo de auditoria."
        )

    nombre_host = partes.hostname
    if not nombre_host:
        raise ErrorValidacion(f"'{url}' no indica un host valido.")

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
        raise ErrorValidacion(f"'{url}' tiene un puerto invalido.") from exc
    if not (PUERTO_MINIMO <= puerto <= PUERTO_MAXIMO):
        raise ErrorValidacion(
            f"El puerto {puerto} esta fuera del rango valido ({PUERTO_MINIMO}-{PUERTO_MAXIMO})."
        )

    ruta = partes.path or "/"
    if partes.query:
        ruta = f"{ruta}?{partes.query}"

    return ComponentesURL(url_original=url, esquema=esquema, host=host, puerto=puerto, ruta=ruta)
