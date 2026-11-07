"""Pruebas de extremo a extremo de la auditoria web: comando, persistencia y CLI.

Usa siempre un servidor HTTP local (``tests/ayudantes_web.py``) en 127.0.0.1, nunca
un objetivo remoto. La verificacion de alcance ocurre antes de abrir ninguna conexion,
igual que en ``escanear tcp``/``nmap``.
"""

from __future__ import annotations

import pytest

import eurabyte_security.commands.web as modulo_comando_web
from eurabyte_security.commands.proyecto import crear_proyecto
from eurabyte_security.commands.web import auditar_web, generar_reporte_web
from eurabyte_security.core.errores import (
    ErrorAuditoriaWeb,
    ErrorFueraDeAlcance,
    ErrorValidacion,
)
from eurabyte_security.core.validation import validar_url_web
from eurabyte_security.modules.web.auditor import ResultadoAuditoriaWeb
from eurabyte_security.modules.web.modelos import Hallazgo
from eurabyte_security.storage.database import BaseDatos

from .ayudantes_web import RespuestaConfigurada, generar_certificado_autofirmado, servidor_prueba

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


# ---------------------------------------------------------------------------
# est web tls contra certificados no confiables: prueba de extremo a extremo
# (no solo de las funciones internas de modules/web/tls.py).
# ---------------------------------------------------------------------------


def test_cli_web_tls_certificado_autofirmado_muestra_hallazgos_sin_fallar(runner):
    from eurabyte_security.cli.app import app

    runner.invoke(app, ["proyecto", "crear", "cli-web-tls-autofirmado"])
    runner.invoke(app, ["alcance", "agregar", "127.0.0.1/32"])

    cert_pem, key_pem = generar_certificado_autofirmado("127.0.0.1")
    with servidor_prueba(
        {"/": RespuestaConfigurada(200, [], b"ok")}, https=True, cert_pem=cert_pem, key_pem=key_pem
    ) as (host, puerto):
        resultado = runner.invoke(
            app, ["web", "tls", "--detallado", f"https://{host}:{puerto}/"]
        )

    assert resultado.exit_code == 0
    assert "no confiable" in resultado.stdout.lower()
    assert "tls" in resultado.stdout.lower()


def test_cli_web_tls_certificado_vencido_muestra_hallazgos_sin_fallar(runner):
    from eurabyte_security.cli.app import app

    runner.invoke(app, ["proyecto", "crear", "cli-web-tls-vencido"])
    runner.invoke(app, ["alcance", "agregar", "127.0.0.1/32"])

    cert_pem, key_pem = generar_certificado_autofirmado("127.0.0.1", vencido=True)
    with servidor_prueba(
        {"/": RespuestaConfigurada(200, [], b"ok")}, https=True, cert_pem=cert_pem, key_pem=key_pem
    ) as (host, puerto):
        resultado = runner.invoke(app, ["web", "tls", f"https://{host}:{puerto}/"])

    assert resultado.exit_code == 0
    assert "vencido" in resultado.stdout.lower()


def test_auditar_web_certificado_no_confiable_persiste_hallazgos_tls(tmp_path):
    """El comando persiste los hallazgos de TLS aunque la parte HTTP no se complete."""
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "web-tls-no-confiable")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    cert_pem, key_pem = generar_certificado_autofirmado("127.0.0.1")
    with servidor_prueba(
        {"/": RespuestaConfigurada(200, [], b"ok")}, https=True, cert_pem=cert_pem, key_pem=key_pem
    ) as (host, puerto):
        resultado, guardados = auditar_web(
            base_datos, proyecto, f"https://{host}:{puerto}/", "tls", tipos=frozenset({"tls"})
        )

    assert resultado.codigo_estado is None
    assert any(g.categoria == "tls" and g.severidad == "alta" for g in guardados)
    assert len(base_datos.listar_resultados_web(proyecto.id)) == len(guardados)


# ---------------------------------------------------------------------------
# Cancelacion justo antes de la transaccion SQLite (no solo durante la red).
# ---------------------------------------------------------------------------


def _resultado_auditoria_falso() -> ResultadoAuditoriaWeb:
    componentes = validar_url_web("http://127.0.0.1/")
    return ResultadoAuditoriaWeb(
        componentes_inicial=componentes,
        componentes_final=componentes,
        codigo_estado=200,
        saltos_seguidos=(),
        hallazgos=[
            Hallazgo(
                categoria="cabecera",
                id_="x-frame-options",
                nombre="X-Frame-Options",
                significado="s",
                proposito="p",
                valor_detectado=None,
                severidad="media",
                estado="Ausente",
                riesgo="r",
                recomendacion="r",
                referencia="https://example.test",
            )
        ],
    )


def test_auditar_web_cancelado_justo_antes_de_persistir_no_guarda_nada(tmp_path, monkeypatch):
    """La red ya termino (con exito) cuando se detecta la cancelacion: no debe guardarse nada."""
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "web-cancelado-post-red")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    resultado_falso = _resultado_auditoria_falso()
    monkeypatch.setattr(
        modulo_comando_web, "ejecutar_auditoria_web", lambda *a, **k: resultado_falso
    )

    with pytest.raises(ErrorAuditoriaWeb):
        auditar_web(
            base_datos, proyecto, "http://127.0.0.1/", "auditar", debe_cancelar=lambda: True
        )

    assert base_datos.listar_resultados_web(proyecto.id) == []


def test_auditar_web_no_cancelado_si_guardar_persiste_normalmente(tmp_path, monkeypatch):
    """Control: con debe_cancelar() devolviendo False, la misma ruta SI persiste."""
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "web-no-cancelado-post-red")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    resultado_falso = _resultado_auditoria_falso()
    monkeypatch.setattr(
        modulo_comando_web, "ejecutar_auditoria_web", lambda *a, **k: resultado_falso
    )

    _resultado, guardados = auditar_web(
        base_datos, proyecto, "http://127.0.0.1/", "auditar", debe_cancelar=lambda: False
    )

    assert len(guardados) == 1
    assert len(base_datos.listar_resultados_web(proyecto.id)) == 1


def test_cli_web_fuera_de_alcance_no_persiste_nada(runner):
    """La URL rechazada por alcance ni siquiera llega a validar el tiempo limite."""
    from eurabyte_security.cli.app import app

    runner.invoke(app, ["proyecto", "crear", "cli-web-alcance-persistencia"])
    resultado = runner.invoke(app, ["web", "auditar", "http://127.0.0.1:65000/"])
    assert resultado.exit_code != 0


# ---------------------------------------------------------------------------
# Proteccion de datos sensibles en URLs (parametros de consulta, Location, errores).
# ---------------------------------------------------------------------------


def test_url_con_parametro_sensible_se_redacta_al_persistir(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "web-url-sensible")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    with servidor_prueba({"/reset": _RESPUESTA_INSEGURA}) as (host, puerto):
        _resultado, guardados = auditar_web(
            base_datos, proyecto,
            f"http://{host}:{puerto}/reset?token=secreto-de-prueba-123",
            "auditar",
        )

    assert guardados, "deberia haber al menos un hallazgo guardado"
    for g in guardados:
        assert "secreto-de-prueba-123" not in g.objetivo

    filas_crudas = base_datos.listar_resultados_web(proyecto.id)
    for fila in filas_crudas:
        assert "secreto-de-prueba-123" not in fila.objetivo
        assert fila.valor_detectado is None or "secreto-de-prueba-123" not in fila.valor_detectado


def test_url_con_parametro_sensible_no_aparece_en_salida_cli(runner):
    from eurabyte_security.cli.app import app

    runner.invoke(app, ["proyecto", "crear", "cli-web-url-sensible"])
    runner.invoke(app, ["alcance", "agregar", "127.0.0.1/32"])

    with servidor_prueba({"/reset": _RESPUESTA_INSEGURA}) as (host, puerto):
        resultado = runner.invoke(
            app,
            ["web", "auditar", f"http://{host}:{puerto}/reset?password=otro-secreto-456"],
        )

    assert resultado.exit_code == 0
    assert "otro-secreto-456" not in resultado.stdout


def test_url_con_parametro_sensible_no_aparece_en_informe(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "web-url-sensible-informe")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    with servidor_prueba({"/reset": _RESPUESTA_INSEGURA}) as (host, puerto):
        auditar_web(
            base_datos, proyecto,
            f"http://{host}:{puerto}/reset?api_key=tercer-secreto-789",
            "auditar",
        )

    ruta_html = generar_reporte_web(base_datos, proyecto, "html", tmp_path / "informe.html")
    ruta_json = generar_reporte_web(base_datos, proyecto, "json", tmp_path / "informe.json")

    assert "tercer-secreto-789" not in ruta_html.read_text(encoding="utf-8")
    assert "tercer-secreto-789" not in ruta_json.read_text(encoding="utf-8")


def test_mensaje_de_error_fuera_de_alcance_no_filtra_parametro_sensible(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "web-url-sensible-error")
    base_datos.agregar_alcance(proyecto.id, "10.0.0.0/24")

    with pytest.raises(ErrorFueraDeAlcance) as info:
        auditar_web(
            base_datos, proyecto,
            "http://127.0.0.1:65000/?session_id=secreto-en-el-error",
            "auditar",
        )

    assert "secreto-en-el-error" not in str(info.value)


def test_redireccion_con_parametro_sensible_en_location_se_redacta(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "web-redireccion-sensible")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    respuestas = {
        "/": RespuestaConfigurada(
            302, [("Location", "/callback?code=codigo-oauth-secreto")], b""
        )
    }
    with servidor_prueba(respuestas) as (host, puerto):
        resultado, guardados = auditar_web(
            base_datos, proyecto, f"http://{host}:{puerto}/", "auditar"
        )

    redireccion = next(h for h in resultado.hallazgos if h.categoria == "redireccion")
    assert "codigo-oauth-secreto" not in (redireccion.valor_detectado or "")
    for g in guardados:
        assert g.valor_detectado is None or "codigo-oauth-secreto" not in g.valor_detectado


# ---------------------------------------------------------------------------
# Limites operativos: --tiempo-limite (1-30s) y su distincion del limite total.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("valor", [0.1, 0.9, 30.1, 60.0, 999.0])
def test_tiempo_limite_fuera_de_rango_se_rechaza(tmp_path, valor):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, f"web-tiempo-invalido-{str(valor).replace('.', '_')}")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    with pytest.raises(ErrorValidacion):
        auditar_web(
            base_datos, proyecto, "http://127.0.0.1:65000/", "auditar", tiempo_limite=valor
        )


@pytest.mark.parametrize("valor", [1.0, 10.0, 30.0])
def test_tiempo_limite_en_rango_no_se_rechaza_por_validacion(tmp_path, valor):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, f"web-tiempo-valido-{int(valor)}")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    with servidor_prueba({"/": _RESPUESTA_INSEGURA}) as (host, puerto):
        resultado, _guardados = auditar_web(
            base_datos, proyecto, f"http://{host}:{puerto}/", "auditar", tiempo_limite=valor
        )
    assert resultado.codigo_estado == 200


def test_cli_tiempo_limite_fuera_de_rango_falla(runner):
    from eurabyte_security.cli.app import app

    runner.invoke(app, ["proyecto", "crear", "cli-web-tiempo-invalido"])
    runner.invoke(app, ["alcance", "agregar", "127.0.0.1/32"])

    resultado = runner.invoke(
        app, ["web", "cabeceras", "http://127.0.0.1:65000/", "--tiempo-limite", "999"]
    )
    assert resultado.exit_code != 0
