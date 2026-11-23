"""Telemetría pasiva del equipo y análisis local de registros JSON de Zeek."""

from __future__ import annotations

import ipaddress
import json
import re
import time
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import psutil

from eurabyte_security.core.errores import ErrorValidacion

_MAX_ARCHIVO = 128 * 1024 * 1024
_MAX_LINEA = 256 * 1024
_MAX_FILAS = 10
_ETIQUETA_DNS = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", re.ASCII)
_SERVICIO = re.compile(r"[a-z0-9_,+-]{1,48}", re.ASCII)


@dataclass(frozen=True, slots=True)
class Volumen:
    carga: int = 0
    descarga: int = 0

    def __add__(self, otro: Volumen) -> Volumen:
        return Volumen(self.carga + otro.carga, self.descarga + otro.descarga)


@dataclass(frozen=True, slots=True)
class MedicionLocal:
    segundos: float
    interfaces: dict[str, Volumen]
    aplicaciones: list[tuple[str, int]]
    conexiones_sin_nombre: int
    aplicaciones_disponibles: bool


@dataclass(frozen=True, slots=True)
class ResumenRed:
    total: Volumen
    dispositivos: list[tuple[str, Volumen]]
    servicios: list[tuple[str, Volumen]]
    dominios: list[tuple[str, int]] | None
    dominios_web: list[tuple[tuple[str, str], int]] | None
    flujos: int
    flujos_incompletos: int
    registros_invalidos: int


def medir_equipo(segundos: float = 1) -> MedicionLocal:
    """Mide el cambio de contadores de cada interfaz y observa los sockets abiertos."""
    if not 0.2 <= segundos <= 10:
        raise ErrorValidacion("El intervalo debe estar entre 0,2 y 10 segundos.")
    try:
        inicial = psutil.net_io_counters(pernic=True, nowrap=False)
        comienzo = time.monotonic()
        time.sleep(segundos)
        final = psutil.net_io_counters(pernic=True, nowrap=False)
    except (OSError, psutil.Error) as exc:
        raise ErrorValidacion("No se pudieron leer los contadores del equipo.") from exc
    transcurrido = time.monotonic() - comienzo
    interfaces = {}
    for nombre in inicial.keys() & final.keys():
        carga = final[nombre].bytes_sent - inicial[nombre].bytes_sent
        descarga = final[nombre].bytes_recv - inicial[nombre].bytes_recv
        if carga >= 0 and descarga >= 0:
            interfaces[nombre] = Volumen(carga, descarga)

    try:
        conexiones = psutil.net_connections(kind="inet")
    except (OSError, psutil.Error):
        return MedicionLocal(transcurrido, interfaces, [], 0, False)
    por_pid = Counter(conexion.pid for conexion in conexiones if conexion.raddr)
    sin_nombre = por_pid.pop(None, 0)
    nombres: Counter[str] = Counter()
    for pid, cantidad in por_pid.items():
        try:
            nombres[psutil.Process(pid).name()] += cantidad
        except (OSError, psutil.Error):
            sin_nombre += cantidad

    return MedicionLocal(
        transcurrido, interfaces, nombres.most_common(_MAX_FILAS), sin_nombre, True,
    )


def _registros(ruta: Path) -> Iterator[dict | None]:
    """Lee línea por línea con límites de memoria. None indica un registro inválido."""
    nombre = "".join(c for c in ruta.name if c.isprintable())[:120]
    try:
        if not ruta.is_file():
            raise ErrorValidacion(f"Selecciona un archivo de registro regular ({nombre}).")
        if ruta.stat().st_size > _MAX_ARCHIVO:
            raise ErrorValidacion(f"El registro supera 128 MiB ({nombre}).")
        with ruta.open("rb") as archivo:
            leidos = 0
            while linea := archivo.readline(_MAX_LINEA + 1):
                leidos += len(linea)
                if leidos > _MAX_ARCHIVO or len(linea) > _MAX_LINEA:
                    raise ErrorValidacion(
                        f"El registro excede los límites de lectura ({nombre})."
                    )
                if not linea.strip():
                    continue
                try:
                    fila = json.loads(linea)
                except (ValueError, RecursionError):
                    fila = None
                yield fila if isinstance(fila, dict) else None
    except OSError as exc:
        raise ErrorValidacion(f"No se pudo leer el registro ({nombre}).") from exc


def _ip(valor: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not isinstance(valor, str) or "%" in valor:
        return None
    try:
        return ipaddress.ip_address(valor)
    except ValueError:
        return None


def _bytes_ip(valor: object) -> int | None:
    return valor if type(valor) is int and 0 <= valor < 2**64 else None


def _dominio(valor: object) -> str | None:
    if not isinstance(valor, str):
        return None
    nombre = valor.lower().removesuffix(".")
    if not 0 < len(nombre) <= 253 or nombre.endswith((".in-addr.arpa", ".ip6.arpa")):
        return None
    etiquetas = nombre.split(".")
    if (
        len(etiquetas) < 2
        or not all(_ETIQUETA_DNS.fullmatch(e) for e in etiquetas)
        or _ip(nombre) is not None
    ):
        return None
    return nombre


def _mayor_volumen(datos: dict[str, Volumen]) -> list[tuple[str, Volumen]]:
    return sorted(datos.items(), key=lambda item: (
        -(item[1].carga + item[1].descarga), item[0],
    ))[:_MAX_FILAS]


def resumir_red(
    conexiones: Path, redes_lan: str, dns: Path | None = None, web: Path | None = None,
) -> ResumenRed:
    """Atribuye bytes IP a cada lado de la LAN y cuenta consultas de clientes locales."""
    try:
        redes = tuple(ipaddress.ip_network(red.strip()) for red in redes_lan.split(","))
    except ValueError as exc:
        raise ErrorValidacion(
            "Introduce las redes LAN en formato CIDR, separadas por comas."
        ) from exc
    if any(red.prefixlen == 0 for red in redes):
        raise ErrorValidacion("Especifica las subredes LAN del registro.")

    def en_lan(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return any(ip in red for red in redes)

    total = Volumen()
    dispositivos: dict[str, Volumen] = {}
    servicios: dict[str, Volumen] = {}
    validos = invalidos = flujos = incompletos = 0
    for fila in _registros(conexiones):
        origen = _ip(fila.get("id.orig_h")) if fila else None
        destino = _ip(fila.get("id.resp_h")) if fila else None
        if fila is None or origen is None or destino is None:
            invalidos += 1
            continue
        validos += 1
        origen_local = en_lan(origen)
        if origen_local == en_lan(destino):
            continue
        flujos += 1
        orig_bytes = _bytes_ip(fila.get("orig_ip_bytes"))
        resp_bytes = _bytes_ip(fila.get("resp_ip_bytes"))
        incompletos += orig_bytes is None or resp_bytes is None
        ida, vuelta = orig_bytes or 0, resp_bytes or 0
        volumen = Volumen(ida, vuelta) if origen_local else Volumen(vuelta, ida)
        equipo = str(origen if origen_local else destino)
        nombre = fila.get("service")
        servicio = (
            nombre if isinstance(nombre, str) and _SERVICIO.fullmatch(nombre) and nombre != "-"
            else "Sin clasificar"
        )
        dispositivos[equipo] = dispositivos.get(equipo, Volumen()) + volumen
        servicios[servicio] = servicios.get(servicio, Volumen()) + volumen
        total += volumen
    if not validos:
        raise ErrorValidacion("El archivo no contiene flujos válidos de Zeek conn.log en JSON.")

    dominios: Counter[str] | None = None
    if dns is not None:
        dominios = Counter()
        for fila in _registros(dns):
            cliente = _ip(fila.get("id.orig_h")) if fila else None
            if fila is None or cliente is None:
                invalidos += 1
                continue
            dominio = _dominio(fila.get("query"))
            if dominio and en_lan(cliente):
                dominios[dominio] += 1

    dominios_web: Counter[tuple[str, str]] | None = None
    if web is not None:
        dominios_web = Counter()
        for fila in _registros(web):
            cliente = _ip(fila.get("id.orig_h")) if fila else None
            if fila is None or cliente is None:
                invalidos += 1
                continue
            if not en_lan(cliente):
                continue
            host = fila.get("host")
            if isinstance(host, str):
                dominio = _dominio(host.partition(":")[0])
                origen_dominio = "HTTP"
            else:
                dominio = _dominio(fila.get("server_name"))
                origen_dominio = "TLS"
            if dominio:
                dominios_web[dominio, origen_dominio] += 1

    return ResumenRed(
        total,
        _mayor_volumen(dispositivos),
        _mayor_volumen(servicios),
        dominios.most_common(_MAX_FILAS) if dominios is not None else None,
        dominios_web.most_common(_MAX_FILAS) if dominios_web is not None else None,
        flujos,
        incompletos,
        invalidos,
    )
