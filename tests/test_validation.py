from __future__ import annotations

import ipaddress

import pytest

from eurabyte_security.core.errores import ErrorValidacion
from eurabyte_security.core.validation import (
    objetivo_en_alcance,
    validar_concurrencia,
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
