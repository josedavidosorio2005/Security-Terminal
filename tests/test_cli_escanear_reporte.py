from __future__ import annotations

import json
import socket

from eurabyte_security.cli.app import app


def _puerto_libre() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _preparar_proyecto_con_alcance(runner, nombre="laboratorio", red="127.0.0.1/32"):
    runner.invoke(app, ["proyecto", "crear", nombre])
    runner.invoke(app, ["alcance", "agregar", red])


def test_escanear_tcp_objetivo_fuera_de_alcance_es_rechazado(runner):
    _preparar_proyecto_con_alcance(runner, red="10.0.0.0/24")
    resultado = runner.invoke(
        app, ["escanear", "tcp", "127.0.0.1", "--puertos", "80"]
    )
    assert resultado.exit_code != 0


def test_escanear_tcp_dentro_de_alcance_y_resultados(runner):
    _preparar_proyecto_con_alcance(runner)
    puerto = _puerto_libre()

    resultado = runner.invoke(
        app,
        ["escanear", "tcp", "127.0.0.1", "--puertos", str(puerto), "--timeout", "0.5"],
    )
    assert resultado.exit_code == 0

    resultado = runner.invoke(app, ["resultados"])
    assert resultado.exit_code == 0
    assert str(puerto) in resultado.stdout


def test_escanear_tcp_puertos_invalidos_falla(runner):
    _preparar_proyecto_con_alcance(runner)
    resultado = runner.invoke(app, ["escanear", "tcp", "127.0.0.1", "--puertos", "no-valido"])
    assert resultado.exit_code != 0


def test_reporte_json(runner, tmp_path):
    _preparar_proyecto_con_alcance(runner)
    puerto = _puerto_libre()
    runner.invoke(
        app, ["escanear", "tcp", "127.0.0.1", "--puertos", str(puerto), "--timeout", "0.5"]
    )

    salida = tmp_path / "informe.json"
    resultado = runner.invoke(
        app, ["reporte", "generar", "--formato", "json", "--salida", str(salida)]
    )
    assert resultado.exit_code == 0
    assert salida.exists()

    datos = json.loads(salida.read_text(encoding="utf-8"))
    assert datos["proyecto"] == "laboratorio"
    # 'reporte generar' produce el informe GLOBAL (todas las herramientas): con solo un
    # escaneo TCP guardado, debe haber exactamente un resultado, de fuente 'tcp'.
    assert datos["total_resultados"] == 1
    assert datos["resultados"][0]["fuente"] == "tcp"
    assert datos["resultados"][0]["severidad"] is None


def test_reporte_html(runner, tmp_path):
    _preparar_proyecto_con_alcance(runner)
    puerto = _puerto_libre()
    runner.invoke(
        app, ["escanear", "tcp", "127.0.0.1", "--puertos", str(puerto), "--timeout", "0.5"]
    )

    salida = tmp_path / "informe.html"
    resultado = runner.invoke(
        app, ["reporte", "generar", "--formato", "html", "--salida", str(salida)]
    )
    assert resultado.exit_code == 0
    contenido = salida.read_text(encoding="utf-8")
    assert "<html" in contenido
    assert f"Puerto {puerto}" in contenido


def test_reporte_formato_invalido_falla(runner):
    _preparar_proyecto_con_alcance(runner)
    resultado = runner.invoke(app, ["reporte", "generar", "--formato", "xml"])
    assert resultado.exit_code != 0


def test_explicar_tema_conocido(runner):
    resultado = runner.invoke(app, ["explicar", "tcp"])
    assert resultado.exit_code == 0
    assert "connect scan" in resultado.stdout.lower() or "tcp" in resultado.stdout.lower()


def test_explicar_tema_desconocido(runner):
    resultado = runner.invoke(app, ["explicar", "no-existe"])
    assert resultado.exit_code == 0
    assert "No hay una explicacion" in resultado.stdout
