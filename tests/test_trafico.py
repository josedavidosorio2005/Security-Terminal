"""Comprueba la atribución de tráfico a partir de registros y contadores sintéticos."""

import json
from types import SimpleNamespace

import pytest
from textual.widgets import Button, ContentSwitcher, Input, TabbedContent

from eurabyte_security.cli.app import app
from eurabyte_security.core.errores import ErrorValidacion
from eurabyte_security.modules.network import trafico
from eurabyte_security.modules.network.trafico import Volumen
from eurabyte_security.ui.tui.app import AuraByteApp
from eurabyte_security.ui.tui.motor_comandos import MotorComandos


def _flujo(origen, destino, carga, descarga, servicio="ssl"):
    return {
        "id.orig_h": origen,
        "id.resp_h": destino,
        "orig_ip_bytes": carga,
        "resp_ip_bytes": descarga,
        "service": servicio,
    }


def _registro(ruta, filas):
    ruta.write_text("".join(json.dumps(fila) + "\n" for fila in filas), encoding="utf-8")
    return ruta


@pytest.fixture
def registros(tmp_path):
    conn = _registro(tmp_path / "conn.log", [
        _flujo("192.168.1.3", "203.0.113.7", 1_000_000, 3_000_000),
        _flujo("203.0.113.7", "192.168.1.3", 10, 20),
        _flujo("192.168.1.3", "192.168.1.4", 800, 800),
        _flujo("2001:db8::1", "2001:db8:1::2", 0, None, "[red]"),
        _flujo("fe80::1%[red]", "192.168.1.3", 1, 1),
        [],
    ])
    dns = _registro(tmp_path / "dns.log", [
        {"id.orig_h": "192.168.1.3", "query": "Ejemplo.com."},
        {"id.orig_h": "192.168.1.4", "query": "ejemplo.com"},
        {"id.orig_h": "192.168.1.4", "query": "3.1.168.192.in-addr.arpa"},
        {"id.orig_h": "203.0.113.7", "query": "fuera.example"},
    ])
    return conn, dns


def test_red_orienta_ambos_sentidos_y_excluye_trafico_interno(registros):
    conn, dns = registros
    resultado = trafico.resumir_red(conn, "192.168.1.0/24,2001:db8::/64", dns)
    assert resultado.total == Volumen(1_000_020, 3_000_010)
    assert resultado.dispositivos == [("192.168.1.3", resultado.total), ("2001:db8::1", Volumen())]
    assert resultado.servicios == [("ssl", resultado.total), ("Sin clasificar", Volumen())]
    assert resultado.dominios == [("ejemplo.com", 2)]
    assert resultado.flujos == 3
    assert resultado.flujos_incompletos == 1
    assert resultado.registros_invalidos == 2


def test_informa_formato_y_subred_invalidos(registros, tmp_path):
    conn, _ = registros
    with pytest.raises(ErrorValidacion, match="CIDR"):
        trafico.resumir_red(conn, "mi-red")
    invalido = tmp_path / "texto.log"
    invalido.write_text("texto sin JSON", encoding="utf-8")
    with pytest.raises(ErrorValidacion, match="flujos válidos"):
        trafico.resumir_red(invalido, "192.168.1.0/24")


def test_equipo_mide_deltas_y_distingue_aplicaciones(monkeypatch):
    muestras = iter([
        {"wifi": SimpleNamespace(bytes_sent=50, bytes_recv=10),
         "vpn": SimpleNamespace(bytes_sent=50, bytes_recv=10)},
        {"wifi": SimpleNamespace(bytes_sent=100, bytes_recv=500),
         "vpn": SimpleNamespace(bytes_sent=2, bytes_recv=5)},
    ])
    monkeypatch.setattr(trafico.psutil, "net_io_counters", lambda **_: next(muestras))
    monkeypatch.setattr(trafico.time, "sleep", lambda _: None)
    monkeypatch.setattr(trafico.psutil, "net_connections", lambda **_: [
        SimpleNamespace(pid=4, raddr=("192.0.2.1", 443)),
        SimpleNamespace(pid=4, raddr=("192.0.2.2", 443)),
        SimpleNamespace(pid=None, raddr=("192.0.2.2", 443)),
        SimpleNamespace(pid=5, raddr=()),
    ])
    monkeypatch.setattr(trafico.psutil, "Process", lambda _: SimpleNamespace(name=lambda: "web"))
    medicion = trafico.medir_equipo()
    assert medicion.interfaces == {"wifi": Volumen(50, 490)}
    assert medicion.aplicaciones == [("web", 2)]
    assert medicion.conexiones_sin_nombre == 1


def test_cli_y_terminal_integrada_analizan_el_archivo(runner, registros):
    conn, dns = registros
    resultado = runner.invoke(app, ["trafico", "red", str(conn), "--lan",
                                     "192.168.1.0/24", "--dns", str(dns)])
    assert resultado.exit_code == 0, resultado.output
    assert "3.00 MB" in resultado.output
    assert "ejemplo.com" in resultado.output
    argumentos = f'trafico red "{conn.as_posix()}" --lan 192.168.1.0/24'
    resultado_terminal = MotorComandos().ejecutar(argumentos)
    assert resultado_terminal.exito


def test_dominios_web_contabilizan_fuentes_sin_incluir_rutas(registros, tmp_path, runner):
    conn, _ = registros
    web = _registro(tmp_path / "web.log", [
        {"id.orig_h": "192.168.1.3", "host": "Web.Example:8080", "uri": "/privado"},
        {"id.orig_h": "192.168.1.3", "server_name": "seguro.example"},
        {"id.orig_h": "203.0.113.7", "server_name": "externo.example"},
    ])
    resumen = trafico.resumir_red(conn, "192.168.1.0/24", web=web)
    assert dict(resumen.dominios_web) == {("web.example", "HTTP"): 1, ("seguro.example", "TLS"): 1}
    cli = runner.invoke(app, ["trafico", "red", str(conn), "--lan",
                              "192.168.1.0/24", "--web", str(web)])
    assert cli.exit_code == 0
    assert "seguro.example" in cli.output
    assert "privado" not in cli.output


async def test_panel_importa_registros_en_terminal_compacta(registros):
    conn, dns = registros
    interfaz = AuraByteApp()
    async with interfaz.run_test(size=(80, 24)) as pilot:
        interfaz.query_one("#switcher-central", ContentSwitcher).current = "panel-trafico"
        interfaz.query_one("#trafico-pestanas", TabbedContent).active = "trafico-lan"
        await pilot.pause()
        interfaz.query_one("#trafico-cidr", Input).value = "192.168.1.0/24"
        interfaz.query_one("#trafico-conn", Input).value = str(conn)
        interfaz.query_one("#trafico-dns", Input).value = str(dns)
        boton = interfaz.query_one("#trafico-analizar", Button)
        assert await pilot.click(boton, offset=(3, 1))
        await interfaz.workers.wait_for_complete()
        await pilot.pause()
        assert not boton.disabled
        contenido = interfaz.query_one("#trafico-resumen").render()
        assert "Group" in repr(contenido)
