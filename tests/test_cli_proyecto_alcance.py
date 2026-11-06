from __future__ import annotations

from eurabyte_security.cli.app import app


def test_ayuda_en_espanol(runner):
    resultado = runner.invoke(app, ["--ayuda"])
    assert resultado.exit_code == 0
    assert "Eurabyte" in resultado.stdout


def test_crear_y_listar_proyecto(runner):
    resultado = runner.invoke(app, ["proyecto", "crear", "laboratorio"])
    assert resultado.exit_code == 0
    assert "laboratorio" in resultado.stdout

    resultado = runner.invoke(app, ["proyecto", "listar"])
    assert resultado.exit_code == 0
    assert "laboratorio" in resultado.stdout


def test_crear_proyecto_duplicado_falla(runner):
    runner.invoke(app, ["proyecto", "crear", "laboratorio"])
    resultado = runner.invoke(app, ["proyecto", "crear", "laboratorio"])
    assert resultado.exit_code != 0


def test_usar_proyecto_inexistente_falla(runner):
    resultado = runner.invoke(app, ["proyecto", "usar", "fantasma"])
    assert resultado.exit_code != 0


def test_agregar_alcance_valido(runner):
    runner.invoke(app, ["proyecto", "crear", "laboratorio"])
    resultado = runner.invoke(app, ["alcance", "agregar", "127.0.0.1/32"])
    assert resultado.exit_code == 0

    resultado = runner.invoke(app, ["alcance", "listar"])
    assert "127.0.0.1/32" in resultado.stdout


def test_agregar_alcance_invalido_falla(runner):
    runner.invoke(app, ["proyecto", "crear", "laboratorio"])
    resultado = runner.invoke(app, ["alcance", "agregar", "no-es-una-red"])
    assert resultado.exit_code != 0


def test_alcance_sin_proyecto_activo_falla(runner):
    resultado = runner.invoke(app, ["alcance", "agregar", "127.0.0.1/32"])
    assert resultado.exit_code != 0
