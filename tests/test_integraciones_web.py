"""Pruebas de extremo a extremo de la auditoria web: comando, persistencia y CLI.

Usa siempre un servidor HTTP local (``tests/ayudantes_web.py``) en 127.0.0.1, nunca
un objetivo remoto. La verificacion de alcance ocurre antes de abrir ninguna conexion,
igual que en ``escanear tcp``/``nmap``.
"""

from __future__ import annotations

import pytest

from eurabyte_security.commands.proyecto import crear_proyecto
from eurabyte_security.commands.web import auditar_web, generar_reporte_web
from eurabyte_security.core.errores import (
    ErrorAuditoriaWeb,
    ErrorFueraDeAlcance,
    ErrorValidacion,
)
from eurabyte_security.storage.database import BaseDatos

from .ayudantes_web import RespuestaConfigurada, servidor_prueba

_RESPUESTA_INSEGURA = RespuestaConfigurada(
    200,
    [("Set-Cookie", "sesion=abc")],
    b"<html>sin cabeceras de seguridad</html>",
)


def test_auditar_web_fuera_de_alcance_no_hace_ninguna_peticion(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "web-rechazo")
    base_datos.agregar_alcance(proyecto.id, "10.0.0.0/24")

    # Ni siquiera hay un servidor escuchando en este puerto: si AST intentara
    # conectarse, fallaria por conexion rechazada en vez de ErrorFueraDeAlcance.
    with pytest.raises(ErrorFueraDeAlcance):
        auditar_web(base_datos, proyecto, "http://127.0.0.1:65000/", "auditar")

    assert base_datos.listar_resultados_web(proyecto.id) == []


def test_auditar_web_rechaza_nombre_de_dominio(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "web-dominio")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    with pytest.raises(ErrorValidacion):
        auditar_web(base_datos, proyecto, "https://example.com/", "auditar")


def test_auditar_web_dentro_de_alcance_persiste_hallazgos(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "web-ok")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    with servidor_prueba({"/": _RESPUESTA_INSEGURA}) as (host, puerto):
        resultado, guardados = auditar_web(
            base_datos, proyecto, f"http://{host}:{puerto}/", "auditar"
        )

    assert len(resultado.hallazgos) > 0
    assert len(guardados) == len(resultado.hallazgos)
    assert len(base_datos.listar_resultados_web(proyecto.id)) == len(resultado.hallazgos)
    # El tipo_analisis persistido es el del comando invocado.
    assert all(g.tipo_analisis == "auditar" for g in guardados)


def test_auditar_web_cancelado_no_persiste_nada(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "web-cancelado")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    with servidor_prueba({"/": _RESPUESTA_INSEGURA}) as (host, puerto):
        with pytest.raises(ErrorAuditoriaWeb):
            auditar_web(
                base_datos, proyecto, f"http://{host}:{puerto}/", "auditar",
                debe_cancelar=lambda: True,
            )

    assert base_datos.listar_resultados_web(proyecto.id) == []


def test_auditar_web_solo_tipo_cabeceras_no_guarda_hallazgos_de_cookies(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "web-solo-cabeceras")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    with servidor_prueba({"/": _RESPUESTA_INSEGURA}) as (host, puerto):
        _resultado, guardados = auditar_web(
            base_datos, proyecto, f"http://{host}:{puerto}/", "cabeceras",
            tipos=frozenset({"cabeceras"}),
        )

    assert all(g.categoria == "cabecera" for g in guardados)


def test_redireccion_fuera_de_alcance_se_detiene_y_no_hace_segunda_peticion(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "web-redireccion")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    respuestas = {
        "/": RespuestaConfigurada(302, [("Location", "http://192.168.99.99/secreto")], b"")
    }
    with servidor_prueba(respuestas) as (host, puerto):
        resultado, _guardados = auditar_web(
            base_datos, proyecto, f"http://{host}:{puerto}/", "auditar",
            seguir_redirecciones=True,
        )

    assert resultado.saltos_seguidos == ()
    redireccion = next(h for h in resultado.hallazgos if h.categoria == "redireccion")
    assert redireccion.severidad == "alta"


def test_reporte_web_html_y_json(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "web-reporte")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    with servidor_prueba({"/": _RESPUESTA_INSEGURA}) as (host, puerto):
        auditar_web(base_datos, proyecto, f"http://{host}:{puerto}/", "auditar")

    ruta_html = generar_reporte_web(base_datos, proyecto, "html", tmp_path / "informe.html")
    ruta_json = generar_reporte_web(base_datos, proyecto, "json", tmp_path / "informe.json")

    assert ruta_html.exists() and "AURABYTE" in ruta_html.read_text(encoding="utf-8")
    assert ruta_json.exists()
    import json

    datos = json.loads(ruta_json.read_text(encoding="utf-8"))
    assert datos["total_hallazgos"] > 0
    # Los valores de cookies nunca aparecen en claro en el informe.
    assert "abc" not in ruta_json.read_text(encoding="utf-8")


def test_reporte_web_formato_invalido(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "web-formato-invalido")
    with pytest.raises(ErrorValidacion):
        generar_reporte_web(base_datos, proyecto, "pdf")


# ---------------------------------------------------------------------------
# CLI: est web cabeceras|tls|cookies|auditar|reporte
# ---------------------------------------------------------------------------


def test_cli_web_fuera_de_alcance_falla(runner):
    from eurabyte_security.cli.app import app

    runner.invoke(app, ["proyecto", "crear", "cli-web-rechazo"])
    resultado = runner.invoke(app, ["web", "cabeceras", "http://127.0.0.1:65000/"])
    assert resultado.exit_code != 0


def test_cli_web_auditar_dentro_de_alcance(runner):
    from eurabyte_security.cli.app import app

    runner.invoke(app, ["proyecto", "crear", "cli-web-ok"])
    runner.invoke(app, ["alcance", "agregar", "127.0.0.1/32"])

    with servidor_prueba({"/": _RESPUESTA_INSEGURA}) as (host, puerto):
        resultado = runner.invoke(app, ["web", "auditar", f"http://{host}:{puerto}/"])

    assert resultado.exit_code == 0
    assert "cabecera" in resultado.stdout.lower()


def test_cli_web_reporte(runner, tmp_path):
    from eurabyte_security.cli.app import app

    runner.invoke(app, ["proyecto", "crear", "cli-web-reporte"])
    runner.invoke(app, ["alcance", "agregar", "127.0.0.1/32"])

    with servidor_prueba({"/": _RESPUESTA_INSEGURA}) as (host, puerto):
        runner.invoke(app, ["web", "auditar", f"http://{host}:{puerto}/"])

    salida = tmp_path / "informe-cli.json"
    resultado = runner.invoke(app, ["web", "reporte", "--formato", "json", "--salida", str(salida)])
    assert resultado.exit_code == 0
    assert salida.exists()


def test_cli_explicar_web():
    from typer.testing import CliRunner

    from eurabyte_security.cli.app import app

    resultado = CliRunner().invoke(app, ["explicar", "web"])
    assert resultado.exit_code == 0
    assert "SSRF" in resultado.stdout
