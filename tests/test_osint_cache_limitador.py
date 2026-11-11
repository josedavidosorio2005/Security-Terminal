"""Pruebas de la cache con caducidad y el limitador de tasa de OSINT."""

from __future__ import annotations

import time

from eurabyte_security.integrations.osint import cache
from eurabyte_security.integrations.osint.limitador import LimitadorTasa


def test_cache_guarda_y_recupera(monkeypatch, tmp_path):
    monkeypatch.setenv("EST_HOME", str(tmp_path / "datos"))
    cache.guardar("clave-1", {"valor": 42}, ttl_segundos=60)
    assert cache.obtener("clave-1") == {"valor": 42}


def test_cache_caducada_devuelve_none(monkeypatch, tmp_path):
    monkeypatch.setenv("EST_HOME", str(tmp_path / "datos"))
    cache.guardar("clave-2", {"valor": 1}, ttl_segundos=-1)
    assert cache.obtener("clave-2") is None


def test_cache_clave_inexistente_devuelve_none(monkeypatch, tmp_path):
    monkeypatch.setenv("EST_HOME", str(tmp_path / "datos"))
    assert cache.obtener("no-existe") is None


def test_limitador_espera_el_intervalo_minimo():
    limitador = LimitadorTasa(0.2)
    inicio = time.monotonic()
    limitador.esperar_si_necesario()
    limitador.esperar_si_necesario()
    transcurrido = time.monotonic() - inicio
    assert transcurrido >= 0.15  # tolerancia frente a la granularidad de time.sleep()


def test_limitador_se_puede_cancelar_mientras_espera():
    limitador = LimitadorTasa(5.0)
    limitador.esperar_si_necesario()
    inicio = time.monotonic()
    limitador.esperar_si_necesario(debe_cancelar=lambda: True)
    assert time.monotonic() - inicio < 1.0
