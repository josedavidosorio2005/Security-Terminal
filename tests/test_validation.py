from __future__ import annotations

import ipaddress

import pytest

from eurabyte_security.core.errores import ErrorValidacion
from eurabyte_security.core.validation import (
    MAX_TOKENS_ESPECIFICACION_PUERTOS_NMAP,
    objetivo_en_alcance,
    validar_concurrencia,
    validar_especificacion_puertos_nmap,
    validar_nombre_proyecto,
    validar_objetivo,
    validar_puertos,
    validar_red,
    validar_timeout,
)


def test_validar_nombre_proyecto_acepta_nombres_validos():
    assert validar_nombre_proyecto("laboratorio-1") == "laboratorio-1"


@pytest.mark.parametrize("nombre", ["", "   ", "nombre con espacios", "a" * 100])
def test_validar_nombre_proyecto_rechaza_invalidos(nombre):
    with pytest.raises(ErrorValidacion):
        validar_nombre_proyecto(nombre)


def test_validar_red_acepta_ip_unica():
    red = validar_red("127.0.0.1")
    assert red == ipaddress.IPv4Network("127.0.0.1/32")


def test_validar_red_acepta_cidr():
    red = validar_red("192.168.1.0/24")
    assert red.num_addresses == 256


def test_validar_red_rechaza_invalida():
    with pytest.raises(ErrorValidacion):
        validar_red("no-es-una-red")


def test_validar_objetivo_rechaza_dominio():
    with pytest.raises(ErrorValidacion):
        validar_objetivo("example.com")


def test_validar_objetivo_acepta_ip():
    assert str(validar_objetivo("10.0.0.5")) == "10.0.0.5"


def test_validar_puertos_parsea_lista():
    assert validar_puertos("22,80,443") == [22, 80, 443]


def test_validar_puertos_elimina_duplicados():
    assert validar_puertos("80,80,22") == [80, 22]


@pytest.mark.parametrize("especificacion", ["", "abc", "0", "70000", "22,abc"])
def test_validar_puertos_rechaza_invalidos(especificacion):
    with pytest.raises(ErrorValidacion):
        validar_puertos(especificacion)


def test_validar_puertos_rechaza_demasiados():
    especificacion = ",".join(str(p) for p in range(1, 1200))
    with pytest.raises(ErrorValidacion):
        validar_puertos(especificacion)


# -- validar_especificacion_puertos_nmap (admite rangos, a diferencia de validar_puertos) --


def test_nmap_especificacion_acepta_lista_simple():
    assert validar_especificacion_puertos_nmap("22,80,443") == "22,80,443"


def test_nmap_especificacion_acepta_un_rango():
    assert validar_especificacion_puertos_nmap("1-1024") == "1-1024"


def test_nmap_especificacion_acepta_rango_completo_sin_expandirlo():
    """El rango IANA completo (perfil 'completo') debe pasar tal cual, sin que AST
    construya una lista de 65535 enteros en Python para validarlo."""
    assert validar_especificacion_puertos_nmap("1-65535") == "1-65535"


def test_nmap_especificacion_acepta_mezcla_de_puertos_y_rangos():
    assert validar_especificacion_puertos_nmap("22,80,1000-2000") == "22,80,1000-2000"


def test_nmap_especificacion_acepta_perfil_rapido():
    resultado = validar_especificacion_puertos_nmap("rapido")
    assert "22" in resultado.split(",")
    assert "80" in resultado.split(",")


def test_nmap_especificacion_acepta_perfil_completo():
    assert validar_especificacion_puertos_nmap("completo") == "1-65535"


def test_nmap_especificacion_perfil_es_insensible_a_mayusculas():
    assert validar_especificacion_puertos_nmap("COMPLETO") == "1-65535"


@pytest.mark.parametrize(
    "especificacion",
    ["", "   ", "abc", "0", "70000", "22,abc", "2000-1000", "1-70000", "1-2-3", "a-b"],
)
def test_nmap_especificacion_rechaza_invalidas(especificacion):
    with pytest.raises(ErrorValidacion):
        validar_especificacion_puertos_nmap(especificacion)


def test_nmap_especificacion_rechaza_demasiados_tokens():
    especificacion = ",".join(str(p) for p in range(1, MAX_TOKENS_ESPECIFICACION_PUERTOS_NMAP + 5))
    with pytest.raises(ErrorValidacion):
        validar_especificacion_puertos_nmap(especificacion)


@pytest.mark.parametrize("valor", [0.0, 0.05, 10.1, 100])
def test_validar_timeout_rechaza_fuera_de_rango(valor):
    with pytest.raises(ErrorValidacion):
        validar_timeout(valor)


def test_validar_timeout_acepta_rango_valido():
    assert validar_timeout(1.0) == 1.0


@pytest.mark.parametrize("valor", [0, 201, -5])
def test_validar_concurrencia_rechaza_fuera_de_rango(valor):
    with pytest.raises(ErrorValidacion):
        validar_concurrencia(valor)


def test_objetivo_en_alcance():
    redes = [ipaddress.IPv4Network("192.168.1.0/24")]
    assert objetivo_en_alcance(ipaddress.IPv4Address("192.168.1.10"), redes)
    assert not objetivo_en_alcance(ipaddress.IPv4Address("10.0.0.1"), redes)
