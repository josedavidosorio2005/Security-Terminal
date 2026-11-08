"""Pruebas de core/objetivo.py: entrada unica (IP, dominio o URL) con resolucion DNS.

Todas las resoluciones DNS se simulan con un doble (nunca se hace una consulta DNS
real): ver ``_resolver_dns_falso``. Ninguna prueba toca una red de terceros.
"""

from __future__ import annotations

import ipaddress
import socket

import pytest

from eurabyte_security.core.errores import ErrorFueraDeAlcance, ErrorResolucionDNS, ErrorValidacion
from eurabyte_security.core.objetivo import (
    EntradaObjetivo,
    interpretar_entrada,
    resolver_dns,
    resolver_y_autorizar,
)


def _red(cidr: str) -> ipaddress.IPv4Network:
    return ipaddress.IPv4Network(cidr)


# -- interpretar_entrada: las cuatro formas documentadas -------------------------


def test_interpreta_ip_literal():
    e = interpretar_entrada("127.0.0.1")
    assert e.es_ip_literal
    assert e.ip_literal == ipaddress.IPv4Address("127.0.0.1")
    assert e.nombre_host is None
    assert not e.tiene_esquema
    assert e.puerto is None


def test_interpreta_ip_literal_con_puerto_sin_esquema():
    e = interpretar_entrada("192.168.1.10:9000")
    assert e.es_ip_literal
    assert e.ip_literal == ipaddress.IPv4Address("192.168.1.10")
    assert e.puerto == 9000


def test_interpreta_dominio_sin_esquema():
    e = interpretar_entrada("ejemplo.com")
    assert not e.es_ip_literal
    assert e.ip_literal is None
    assert e.nombre_host == "ejemplo.com"
    assert not e.tiene_esquema


def test_interpreta_url_https_sin_puerto_explicito():
    e = interpretar_entrada("https://ejemplo.com")
    assert e.tiene_esquema
    assert e.esquema == "https"
    assert e.nombre_host == "ejemplo.com"
    assert e.puerto == 443
    assert e.ruta == "/"


def test_interpreta_url_http_con_puerto_e_ip():
    e = interpretar_entrada("http://127.0.0.1:8765")
    assert e.tiene_esquema
    assert e.esquema == "http"
    assert e.ip_literal == ipaddress.IPv4Address("127.0.0.1")
    assert e.puerto == 8765


def test_dominio_se_normaliza_a_minusculas():
    e = interpretar_entrada("EJEMPLO.com")
    assert e.nombre_host == "ejemplo.com"


# -- interpretar_entrada: rechazos -----------------------------------------------


def test_entrada_vacia_falla():
    with pytest.raises(ErrorValidacion):
        interpretar_entrada("   ")


def test_rechaza_ipv6():
    with pytest.raises(ErrorValidacion):
        interpretar_entrada("::1")


def test_rechaza_esquema_no_admitido():
    with pytest.raises(ErrorValidacion):
        interpretar_entrada("ftp://ejemplo.com")


def test_rechaza_credenciales_en_url():
    with pytest.raises(ErrorValidacion):
        interpretar_entrada("http://usuario:clave@ejemplo.com")


def test_rechaza_ruta_sin_esquema_explicito():
    with pytest.raises(ErrorValidacion):
        interpretar_entrada("ejemplo.com/ruta")


def test_rechaza_dominio_mal_formado():
    with pytest.raises(ErrorValidacion):
        interpretar_entrada("no es un dominio valido")


def test_rechaza_puerto_fuera_de_rango():
    with pytest.raises(ErrorValidacion):
        interpretar_entrada("127.0.0.1:99999")


# -- resolver_dns -----------------------------------------------------------------


def _resolver_dns_falso(direcciones: list[str], monkeypatch):
    llamadas = {"veces": 0}

    def getaddrinfo_falso(host, puerto, family=None):
        llamadas["veces"] += 1
        return [(socket.AF_INET, None, None, "", (d, 0)) for d in direcciones]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo_falso)
    return llamadas


def test_resolver_dns_devuelve_direcciones_unicas_en_orden(monkeypatch):
    _resolver_dns_falso(["10.0.0.5", "10.0.0.5", "10.0.0.6"], monkeypatch)
    ips = resolver_dns("ejemplo.com")
    assert ips == (ipaddress.IPv4Address("10.0.0.5"), ipaddress.IPv4Address("10.0.0.6"))


def test_resolver_dns_sin_resultados_falla(monkeypatch):
    _resolver_dns_falso([], monkeypatch)
    with pytest.raises(ErrorResolucionDNS):
        resolver_dns("ejemplo.com")


def test_resolver_dns_fallo_del_sistema_falla(monkeypatch):
    def getaddrinfo_roto(host, puerto, family=None):
        raise socket.gaierror("simulado: no se pudo resolver")

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo_roto)
    with pytest.raises(ErrorResolucionDNS):
        resolver_dns("no-existe.invalido")


# -- resolver_y_autorizar: IP literal ---------------------------------------------


def test_ip_literal_dentro_de_alcance_se_autoriza():
    entrada = interpretar_entrada("127.0.0.1")
    resuelto = resolver_y_autorizar(entrada, [_red("127.0.0.1/32")])
    assert resuelto.ip == ipaddress.IPv4Address("127.0.0.1")
    assert resuelto.ips_resueltas == (ipaddress.IPv4Address("127.0.0.1"),)
    assert resuelto.nombre_host is None


def test_ip_literal_fuera_de_alcance_se_rechaza():
    entrada = interpretar_entrada("10.0.0.9")
    with pytest.raises(ErrorFueraDeAlcance):
        resolver_y_autorizar(entrada, [_red("127.0.0.1/32")])


# -- resolver_y_autorizar: dominio -------------------------------------------------


def test_dominio_resuelve_a_ip_autorizada_y_se_fija(monkeypatch):
    _resolver_dns_falso(["127.0.0.1"], monkeypatch)
    entrada = interpretar_entrada("ejemplo.com")
    resuelto = resolver_y_autorizar(entrada, [_red("127.0.0.1/32")])
    assert resuelto.ip == ipaddress.IPv4Address("127.0.0.1")
    assert resuelto.nombre_host == "ejemplo.com"


def test_dominio_con_una_sola_ip_fuera_de_alcance_se_rechaza(monkeypatch):
    _resolver_dns_falso(["10.0.0.9"], monkeypatch)
    entrada = interpretar_entrada("ejemplo.com")
    with pytest.raises(ErrorFueraDeAlcance):
        resolver_y_autorizar(entrada, [_red("127.0.0.1/32")])


def test_dominio_con_varias_ip_usa_solo_la_autorizada(monkeypatch):
    """AST no amplia el analisis a una IP no autorizada aunque el dominio resuelva a
    ella: de varias direcciones devueltas por el DNS, solo la que esta en el alcance
    se fija como 'ip', y todas se reportan en 'ips_resueltas' para transparencia."""
    _resolver_dns_falso(["203.0.113.5", "127.0.0.1", "198.51.100.9"], monkeypatch)
    entrada = interpretar_entrada("ejemplo.com")
    resuelto = resolver_y_autorizar(entrada, [_red("127.0.0.1/32")])
    assert resuelto.ip == ipaddress.IPv4Address("127.0.0.1")
    assert len(resuelto.ips_resueltas) == 3
    assert ipaddress.IPv4Address("203.0.113.5") in resuelto.ips_resueltas


def test_dominio_con_ninguna_ip_autorizada_reporta_todas_las_resueltas(monkeypatch):
    _resolver_dns_falso(["203.0.113.5", "198.51.100.9"], monkeypatch)
    entrada = interpretar_entrada("ejemplo.com")
    with pytest.raises(ErrorFueraDeAlcance) as excinfo:
        resolver_y_autorizar(entrada, [_red("127.0.0.1/32")])
    assert "203.0.113.5" in str(excinfo.value)
    assert "198.51.100.9" in str(excinfo.value)


def test_resolver_y_autorizar_resuelve_el_dominio_una_sola_vez(monkeypatch):
    """Nunca se vuelve a resolver el mismo dominio dentro de una misma llamada: evita
    DNS rebinding (que la IP cambie entre la comprobacion y el uso real)."""
    llamadas = _resolver_dns_falso(["127.0.0.1"], monkeypatch)
    entrada = interpretar_entrada("ejemplo.com")
    resolver_y_autorizar(entrada, [_red("127.0.0.1/32")])
    assert llamadas["veces"] == 1


def test_ip_literal_nunca_dispara_resolucion_dns(monkeypatch):
    llamadas = _resolver_dns_falso(["127.0.0.1"], monkeypatch)
    entrada = interpretar_entrada("127.0.0.1")
    resolver_y_autorizar(entrada, [_red("127.0.0.1/32")])
    assert llamadas["veces"] == 0


def test_objetivo_resuelto_conserva_esquema_puerto_y_ruta(monkeypatch):
    _resolver_dns_falso(["127.0.0.1"], monkeypatch)
    entrada = interpretar_entrada("https://ejemplo.com/admin?x=1")
    resuelto = resolver_y_autorizar(entrada, [_red("127.0.0.1/32")])
    assert resuelto.esquema == "https"
    assert resuelto.puerto == 443
    assert resuelto.ruta == "/admin?x=1"
    assert resuelto.nombre_host == "ejemplo.com"


def test_entrada_objetivo_es_inmutable():
    entrada = interpretar_entrada("127.0.0.1")
    with pytest.raises(Exception):  # noqa: B017, PT011 - dataclass(frozen=True)
        entrada.puerto = 80  # type: ignore[misc]
    assert isinstance(entrada, EntradaObjetivo)
