"""Interpretacion y resolucion de un objetivo introducido una sola vez.

Punto de entrada comun para el futuro orquestador de reconocimiento automatico (ver
``docs/ROADMAP.md``): acepta una IPv4 literal, un nombre de dominio o una URL
completa, y los normaliza a un :class:`ObjetivoResuelto` unico que el resto de AST
puede reutilizar en todas las etapas posteriores sin que el usuario tenga que volver
a escribir el objetivo.

Este modulo es deliberadamente ADITIVO: no sustituye ni relaja ``core/validation.py``
(``validar_objetivo``, ``validar_url_web``, ``validar_objetivo_nuclei`` siguen
aceptando solo IPv4 literal, exactamente igual que antes, para cada comando que ya
existia). Aqui se anade la capacidad de aceptar tambien un DOMINIO, con dos
salvaguardas que nunca se saltan:

1. **Resolucion explicita, nunca implicita**: un dominio se resuelve una sola vez
   (:func:`resolver_dns`), en un paso que el llamador controla, nunca "por detras"
   dentro de una integracion que ya confia en recibir una IP.
2. **Autorizacion sobre la IP, no sobre el nombre**: el alcance autorizado de un
   proyecto sigue siendo, exactamente igual que hoy, una lista de redes IPv4/CIDR (ver
   ``storage/database.py:Alcance``). Un dominio nunca se "registra" el mismo: se
   considera autorizado solo si, al resolverlo, AL MENOS UNA de sus direcciones cae
   dentro de esas redes ya registradas (:func:`resolver_y_autorizar`). Esa direccion
   -- y solo esa -- se FIJA en ``ObjetivoResuelto.ip`` para el resto del analisis: no
   se vuelve a resolver el dominio mas adelante, lo que evita DNS rebinding (que el
   nombre apunte a una IP distinta entre la comprobacion y el uso real). El nombre de
   host original se conserva aparte (``nombre_host``) unicamente para que las
   integraciones HTTP/TLS puedan enviar el ``Host``/SNI correctos -- nunca para volver
   a resolverlo.

Ninguna funcion de este modulo ejecuta trafico de red contra el objetivo en si (ni
siquiera un ping): la unica operacion de red es la resolucion DNS del propio nombre,
que es inherente a aceptar un dominio como entrada.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from eurabyte_security.core.errores import ErrorFueraDeAlcance, ErrorResolucionDNS, ErrorValidacion

ESQUEMAS_VALIDOS = ("http", "https")
PUERTOS_POR_DEFECTO_ESQUEMA = {"http": 80, "https": 443}
PUERTO_MINIMO = 1
PUERTO_MAXIMO = 65535

# 'host' o 'host:puerto' sin esquema (ej. '127.0.0.1', 'ejemplo.com', '127.0.0.1:8765').
# No admite ruta ni query sin esquema explicito: 'ejemplo.com/ruta' es ambiguo (podria
# confundirse con un nombre de archivo local) y AST prefiere pedir 'http://' explicito
# en ese caso antes que adivinar.
_RE_HOST_SIN_ESQUEMA = re.compile(r"^(?P<host>[^/:?#]+)(?::(?P<puerto>\d+))?$")

# Nombre de dominio: etiquetas alfanumericas (con guiones internos, nunca al borde),
# 1-63 caracteres cada una, separadas por puntos, dominio completo hasta 253
# caracteres -- la misma forma que exige la RFC 1035/1123, sin casos especiales.
_RE_DOMINIO = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)


@dataclass(frozen=True, slots=True)
class EntradaObjetivo:
    """El objetivo tal como lo escribio el usuario, ya separado en sus partes -- sin
    resolver DNS ni comprobar autorizacion todavia (ver :func:`interpretar_entrada`).
    """

    entrada_original: str
    es_ip_literal: bool
    ip_literal: ipaddress.IPv4Address | None
    nombre_host: str | None  # solo si es un dominio (es_ip_literal es False)
    tiene_esquema: bool
    esquema: str | None
    puerto: int | None
    ruta: str | None


@dataclass(frozen=True, slots=True)
class ObjetivoResuelto:
    """Objetivo ya resuelto (si era un dominio) y verificado contra el alcance.

    ``ip`` es la UNICA direccion que cualquier integracion posterior debe usar para
    conectarse: ya fue comprobada contra el alcance autorizado y queda fijada aqui
    para toda la operacion, en vez de volver a resolver el nombre en cada paso (lo que
    abriria la puerta a DNS rebinding). ``ips_resueltas`` conserva TODAS las
    direcciones que devolvio el DNS (para mostrarlas al usuario, p. ej. al "Verificar
    objetivo"), incluso las que no estaban autorizadas.
    """

    entrada: EntradaObjetivo
    ip: ipaddress.IPv4Address
    ips_resueltas: tuple[ipaddress.IPv4Address, ...]
    nombre_host: str | None
    esquema: str | None
    puerto: int | None
    ruta: str | None


def interpretar_entrada(texto: str) -> EntradaObjetivo:
    """Separa la entrada del usuario en sus partes, sin resolver DNS ni red todavia.

    Acepta las cuatro formas documentadas: IPv4 literal, dominio, 'host:puerto' sin
    esquema, o una URL completa (``http://``/``https://``). Rechaza IPv6 (como el
    resto de AST, que sigue siendo IPv4-only) y cualquier credencial embebida en una
    URL (``usuario:clave@host``), igual que ``core/validation.py:validar_url_web``.
    """
    texto = texto.strip()
    if not texto:
        raise ErrorValidacion("El objetivo no puede estar vacio.")

    if "://" in texto:
        return _interpretar_url(texto)
    return _interpretar_host_sin_esquema(texto)


def _interpretar_url(texto: str) -> EntradaObjetivo:
    try:
        partes = urlsplit(texto)
    except ValueError as exc:
        raise ErrorValidacion(f"'{texto}' no es una URL valida: {exc}") from exc

    esquema = partes.scheme.lower()
    if esquema not in ESQUEMAS_VALIDOS:
        raise ErrorValidacion(
            f"'{texto}' usa el esquema '{esquema or '(ninguno)'}', pero solo se "
            f"admiten {' y '.join(ESQUEMAS_VALIDOS)}."
        )
    if partes.username or partes.password:
        raise ErrorValidacion(
            f"'{texto}' incluye credenciales en la URL (usuario/contrasena); no estan "
            "permitidas en un objetivo."
        )

    nombre_host = partes.hostname
    if not nombre_host:
        raise ErrorValidacion(f"'{texto}' no indica un host valido.")

    try:
        puerto = partes.port if partes.port is not None else PUERTOS_POR_DEFECTO_ESQUEMA[esquema]
    except ValueError as exc:
        raise ErrorValidacion(f"'{texto}' tiene un puerto invalido.") from exc
    _validar_puerto(puerto)

    ruta = partes.path or "/"
    if partes.query:
        ruta = f"{ruta}?{partes.query}"

    ip_literal = _ip_v4_o_none(nombre_host)
    return EntradaObjetivo(
        entrada_original=texto,
        es_ip_literal=ip_literal is not None,
        ip_literal=ip_literal,
        nombre_host=None if ip_literal is not None else _validar_dominio(nombre_host),
        tiene_esquema=True,
        esquema=esquema,
        puerto=puerto,
        ruta=ruta,
    )


def _interpretar_host_sin_esquema(texto: str) -> EntradaObjetivo:
    coincidencia = _RE_HOST_SIN_ESQUEMA.match(texto)
    if coincidencia is None:
        raise ErrorValidacion(
            f"'{texto}' no es un objetivo valido. Usa una IPv4 (ej. 127.0.0.1), un "
            "dominio (ej. ejemplo.com) o una URL completa (ej. https://ejemplo.com)."
        )
    host = coincidencia.group("host")
    puerto_txt = coincidencia.group("puerto")
    puerto = None
    if puerto_txt is not None:
        puerto = int(puerto_txt)
        _validar_puerto(puerto)

    ip_literal = _ip_v4_o_none(host)
    return EntradaObjetivo(
        entrada_original=texto,
        es_ip_literal=ip_literal is not None,
        ip_literal=ip_literal,
        nombre_host=None if ip_literal is not None else _validar_dominio(host),
        tiene_esquema=False,
        esquema=None,
        puerto=puerto,
        ruta=None,
    )


def _ip_v4_o_none(host: str) -> ipaddress.IPv4Address | None:
    try:
        return ipaddress.IPv4Address(host)
    except ValueError:
        return None


def _validar_dominio(host: str) -> str:
    try:
        ipaddress.IPv6Address(host)
    except ValueError:
        pass
    else:
        raise ErrorValidacion(
            f"'{host}' es una direccion IPv6; esta version de AST solo admite IPv4."
        )
    if not _RE_DOMINIO.match(host):
        raise ErrorValidacion(f"'{host}' no es una direccion IPv4 ni un nombre de dominio valido.")
    return host.lower()


def _validar_puerto(puerto: int) -> None:
    if not (PUERTO_MINIMO <= puerto <= PUERTO_MAXIMO):
        raise ErrorValidacion(
            f"El puerto {puerto} esta fuera del rango valido ({PUERTO_MINIMO}-{PUERTO_MAXIMO})."
        )


def resolver_dns(nombre_host: str) -> tuple[ipaddress.IPv4Address, ...]:
    """Resuelve los registros A (IPv4) de ``nombre_host``.

    Delega en la resolucion del sistema operativo (``socket.getaddrinfo``), igual que
    cualquier cliente de red: AST no implementa su propio resolver DNS ni sigue CNAME
    manualmente. Nunca se cachea entre llamadas: cada analisis que necesite la IP de
    un dominio debe llamar a esto una vez y fijar el resultado (ver
    :func:`resolver_y_autorizar`), no volver a resolver mas adelante.
    """
    try:
        resultados = socket.getaddrinfo(nombre_host, None, family=socket.AF_INET)
    except OSError as exc:
        raise ErrorResolucionDNS(f"No se pudo resolver el dominio '{nombre_host}': {exc}") from exc

    ips: list[ipaddress.IPv4Address] = []
    for _familia, _tipo, _proto, _canon, direccion in resultados:
        ip = ipaddress.IPv4Address(direccion[0])
        if ip not in ips:
            ips.append(ip)

    if not ips:
        raise ErrorResolucionDNS(
            f"El dominio '{nombre_host}' no tiene ninguna direccion IPv4 (registro A)."
        )
    return tuple(ips)


def resolver_y_autorizar(
    entrada: EntradaObjetivo, redes_autorizadas: list[ipaddress.IPv4Network]
) -> ObjetivoResuelto:
    """Resuelve (si es un dominio) y verifica el objetivo contra el alcance autorizado.

    Si ``entrada`` ya era una IPv4 literal, no se hace ninguna resolucion DNS: se
    comprueba esa unica direccion contra ``redes_autorizadas`` tal cual. Si era un
    dominio, se resuelve una vez (:func:`resolver_dns`) y se exige que AL MENOS UNA de
    las direcciones devueltas este en el alcance; la primera que lo este (en el orden
    que devolvio el DNS) es la que se fija en ``ObjetivoResuelto.ip`` para todo el
    analisis. Nunca se ampliar el alcance ni se autoriza un dominio completo: cada
    direccion se evalua por separado contra las redes YA registradas por el proyecto.
    """
    if entrada.es_ip_literal:
        ip = entrada.ip_literal
        assert ip is not None  # noqa: S101 - invariante garantizada por EntradaObjetivo
        if not any(ip in red for red in redes_autorizadas):
            raise ErrorFueraDeAlcance(
                f"El objetivo '{ip}' no esta dentro del alcance autorizado del proyecto. "
                "Registralo primero con 'est alcance agregar'."
            )
        ips_resueltas: tuple[ipaddress.IPv4Address, ...] = (ip,)
        ip_fijada = ip
    else:
        assert entrada.nombre_host is not None  # noqa: S101
        ips_resueltas = resolver_dns(entrada.nombre_host)
        autorizadas = [ip for ip in ips_resueltas if any(ip in red for red in redes_autorizadas)]
        if not autorizadas:
            direcciones_txt = ", ".join(str(ip) for ip in ips_resueltas)
            raise ErrorFueraDeAlcance(
                f"El dominio '{entrada.nombre_host}' resuelve a {direcciones_txt}, pero "
                "ninguna de esas direcciones esta dentro del alcance autorizado del "
                "proyecto. Registra la IP correspondiente primero con 'est alcance "
                "agregar' (AST nunca amplía el analisis a una IP no autorizada "
                "aunque el dominio resuelva a ella)."
            )
        ip_fijada = autorizadas[0]

    return ObjetivoResuelto(
        entrada=entrada,
        ip=ip_fijada,
        ips_resueltas=ips_resueltas,
        nombre_host=entrada.nombre_host,
        esquema=entrada.esquema,
        puerto=entrada.puerto,
        ruta=entrada.ruta,
    )
