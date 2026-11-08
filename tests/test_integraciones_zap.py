"""Pruebas del modulo OWASP ZAP (analisis pasivo) y del comando asociado.

Ninguna de estas pruebas llama a una instancia de ZAP real: se sustituye
``modules/vulnerability/zap.py:_peticion_zap`` (el unico punto que habla HTTP con la
API de ZAP) por un doble que simula sus respuestas JSON, exactamente con la forma que
documenta la API oficial (https://www.zaproxy.org/docs/api/).
"""

from __future__ import annotations

import itertools

import pytest

from eurabyte_security.commands.proyecto import crear_proyecto
from eurabyte_security.commands.zap import ejecutar_zap_pasivo, generar_reporte_zap
from eurabyte_security.core.errores import (
    ErrorEscaneoCancelado,
    ErrorFueraDeAlcance,
    ErrorIntegracion,
    ErrorValidacion,
    ErrorZAPNoDisponible,
)
from eurabyte_security.core.redaccion import VALOR_REDACTADO
from eurabyte_security.integrations.zap import AdaptadorZAP
from eurabyte_security.modules.vulnerability import zap as zap_modulo
from eurabyte_security.modules.vulnerability.zap import (
    ConfiguracionZAP,
    _validar_endpoint_administracion,
    diagnosticar_zap,
    ejecutar_analisis_pasivo,
    validar_objetivo_zap,
)
from eurabyte_security.storage.database import BaseDatos

CONFIG_PRUEBA = ConfiguracionZAP(url_base="http://127.0.0.1:8080", api_key="clave-secreta-prueba")


def _alerta(
    plugin_id: str = "10020",
    nombre: str = "Missing Anti-clickjacking Header",
    riesgo: str = "Medium",
    confianza: str = "High",
    url: str = "http://127.0.0.1/pagina",
    evidencia: str = "",
    descripcion: str = "El servidor no incluye X-Frame-Options.",
    solucion: str = "Agrega la cabecera X-Frame-Options.",
    referencia: str = "https://owasp.org/",
) -> dict:
    return {
        "pluginId": plugin_id,
        "name": nombre,
        "risk": riesgo,
        "confidence": confianza,
        "url": url,
        "evidence": evidencia,
        "description": descripcion,
        "solution": solucion,
        "reference": referencia,
    }


def _instalar_zap_falso(
    monkeypatch,
    *,
    alertas: list[dict] | None = None,
    registros_pendientes: tuple[int, ...] = (0,),
    version: str = "2.14.0",
    capturar: dict | None = None,
):
    """Sustituye ``_peticion_zap`` por un doble fiel a la forma de la API real de ZAP."""
    secuencia = iter(registros_pendientes)

    def _peticion_falsa(configuracion, ruta, parametros, *, tiempo_limite):
        if capturar is not None:
            capturar.setdefault("llamadas", []).append((ruta, dict(parametros)))
        if ruta == "/JSON/core/view/version/":
            return {"version": version}
        if ruta == "/JSON/core/action/accessUrl/":
            return {"accessUrl": "OK"}
        if ruta == "/JSON/pscan/view/recordsToScan/":
            try:
                return {"recordsToScan": str(next(secuencia))}
            except StopIteration:
                return {"recordsToScan": "0"}
        if ruta == "/JSON/core/view/alerts/":
            return {"alerts": alertas if alertas is not None else []}
        raise AssertionError(f"ruta inesperada llamada en la prueba: {ruta}")

    monkeypatch.setattr(zap_modulo, "_peticion_zap", _peticion_falsa)
    monkeypatch.setattr(zap_modulo.time, "sleep", lambda *_a, **_k: None)


# ---------------------------------------------------------------------------
# Endpoint de administracion: loopback literal, nunca 'localhost' ni remoto.
# ---------------------------------------------------------------------------


def test_endpoint_localhost_se_rechaza():
    with pytest.raises(ErrorZAPNoDisponible):
        _validar_endpoint_administracion("http://localhost:8080")


def test_endpoint_remoto_se_rechaza():
    with pytest.raises(ErrorZAPNoDisponible):
        _validar_endpoint_administracion("http://192.168.1.50:8080")


def test_endpoint_https_se_rechaza():
    with pytest.raises(ErrorZAPNoDisponible):
        _validar_endpoint_administracion("https://127.0.0.1:8080")


def test_endpoint_loopback_literal_se_acepta():
    host, puerto = _validar_endpoint_administracion("http://127.0.0.1:8090")
    assert host == "127.0.0.1"
    assert puerto == 8090


# ---------------------------------------------------------------------------
# Validacion del objetivo: reutiliza validar_url_web (IPv4 literal, sin credenciales).
# ---------------------------------------------------------------------------


def test_objetivo_con_dominio_se_rechaza():
    with pytest.raises(ErrorValidacion):
        validar_objetivo_zap("http://example.com/")


def test_objetivo_con_credenciales_se_rechaza():
    with pytest.raises(ErrorValidacion):
        validar_objetivo_zap("http://usuario:clave@127.0.0.1/")


# ---------------------------------------------------------------------------
# Diagnostico: disponible / no disponible, nunca lanza por "no disponible".
# ---------------------------------------------------------------------------


def test_diagnostico_no_disponible_no_lanza_excepcion(monkeypatch):
    def _peticion_falla(configuracion, ruta, parametros, *, tiempo_limite):
        raise ErrorZAPNoDisponible("No se pudo conectar con la API de ZAP en 127.0.0.1:8080.")

    monkeypatch.setattr(zap_modulo, "_peticion_zap", _peticion_falla)
    info = diagnosticar_zap(CONFIG_PRUEBA)
    assert info.disponible is False
    assert info.version is None


def test_diagnostico_disponible_devuelve_version(monkeypatch):
    _instalar_zap_falso(monkeypatch)
    info = diagnosticar_zap(CONFIG_PRUEBA)
    assert info.disponible is True
    assert info.version == "2.14.0"


def test_adaptador_zap_info_no_lanza_cuando_no_disponible(monkeypatch):
    def _peticion_falla(configuracion, ruta, parametros, *, tiempo_limite):
        raise ErrorZAPNoDisponible("sin conexion")

    monkeypatch.setattr(zap_modulo, "_peticion_zap", _peticion_falla)
    info = AdaptadorZAP().info()
    assert info.disponible is False


# ---------------------------------------------------------------------------
# Analisis pasivo: flujo feliz, accessUrl sin seguir redirecciones, filtrado por
# objetivo, descarte de alertas malformadas, redaccion de datos sensibles.
# ---------------------------------------------------------------------------


def test_analisis_pasivo_completo_devuelve_hallazgos(monkeypatch):
    captura: dict = {}
    _instalar_zap_falso(monkeypatch, alertas=[_alerta()], capturar=captura)

    resultado = ejecutar_analisis_pasivo(CONFIG_PRUEBA, "http://127.0.0.1/pagina")

    assert len(resultado.hallazgos) == 1
    h = resultado.hallazgos[0]
    assert h.plugin_id == "10020"
    assert h.riesgo == "Medium"
    assert resultado.alertas_descartadas == 0


def test_analisis_pasivo_usa_accessurl_sin_seguir_redirecciones(monkeypatch):
    captura: dict = {}
    _instalar_zap_falso(monkeypatch, alertas=[], capturar=captura)

    ejecutar_analisis_pasivo(CONFIG_PRUEBA, "http://127.0.0.1/pagina")

    llamadas_accessurl = [p for r, p in captura["llamadas"] if r == "/JSON/core/action/accessUrl/"]
    assert len(llamadas_accessurl) == 1
    assert llamadas_accessurl[0]["followRedirects"] == "false"
    assert llamadas_accessurl[0]["url"] == "http://127.0.0.1/pagina"


def test_analisis_pasivo_filtra_alertas_por_baseurl(monkeypatch):
    captura: dict = {}
    _instalar_zap_falso(monkeypatch, alertas=[], capturar=captura)

    ejecutar_analisis_pasivo(CONFIG_PRUEBA, "http://127.0.0.1/pagina")

    llamadas_alerts = [p for r, p in captura["llamadas"] if r == "/JSON/core/view/alerts/"]
    assert len(llamadas_alerts) == 1
    assert llamadas_alerts[0]["baseurl"] == "http://127.0.0.1/pagina"


def test_analisis_pasivo_descarta_alertas_sin_plugin_id_o_nombre(monkeypatch):
    alertas = [_alerta(), {"risk": "Low"}, {"pluginId": "1"}]
    _instalar_zap_falso(monkeypatch, alertas=alertas)

    resultado = ejecutar_analisis_pasivo(CONFIG_PRUEBA, "http://127.0.0.1/pagina")

    assert len(resultado.hallazgos) == 1
    assert resultado.alertas_descartadas == 2


def test_analisis_pasivo_redacta_secreto_en_url(monkeypatch):
    alerta = _alerta(url="http://admin:clave-secreta@127.0.0.1/panel?token=abc123secreto")
    _instalar_zap_falso(monkeypatch, alertas=[alerta])

    resultado = ejecutar_analisis_pasivo(CONFIG_PRUEBA, "http://127.0.0.1/pagina")

    url_guardada = resultado.hallazgos[0].url
    assert "clave-secreta" not in url_guardada
    assert "abc123secreto" not in url_guardada
    assert "admin" not in url_guardada


def test_analisis_pasivo_redacta_secreto_en_evidencia_y_descripcion(monkeypatch):
    alerta = _alerta(
        evidencia="session_token=secreto-de-sesion-123",
        descripcion="Se detecto api_key: clave-filtrada-en-descripcion",
    )
    _instalar_zap_falso(monkeypatch, alertas=[alerta])

    resultado = ejecutar_analisis_pasivo(CONFIG_PRUEBA, "http://127.0.0.1/pagina")

    hallazgo = resultado.hallazgos[0]
    assert "secreto-de-sesion-123" not in hallazgo.evidencia
    assert "clave-filtrada-en-descripcion" not in hallazgo.descripcion
    assert VALOR_REDACTADO in hallazgo.evidencia
    assert VALOR_REDACTADO in hallazgo.descripcion


def test_analisis_pasivo_timeout_si_no_termina_a_tiempo(monkeypatch):
    _instalar_zap_falso(monkeypatch, registros_pendientes=tuple(itertools.repeat(5, 100)))

    reloj = iter([0.0, 0.0, 1000.0])
    monkeypatch.setattr(zap_modulo.time, "monotonic", lambda: next(reloj, 1000.0))

    with pytest.raises(ErrorIntegracion):
        ejecutar_analisis_pasivo(CONFIG_PRUEBA, "http://127.0.0.1/pagina", tiempo_limite=5.0)


def test_analisis_pasivo_cancelado_durante_espera(monkeypatch):
    _instalar_zap_falso(monkeypatch, registros_pendientes=tuple(itertools.repeat(5, 100)))
    estado = {"llamadas": 0}

    def _debe_cancelar() -> bool:
        estado["llamadas"] += 1
        return estado["llamadas"] > 1

    with pytest.raises(ErrorEscaneoCancelado):
        ejecutar_analisis_pasivo(
            CONFIG_PRUEBA, "http://127.0.0.1/pagina", debe_cancelar=_debe_cancelar
        )


def test_analisis_pasivo_no_disponible_lanza_error_claro(monkeypatch):
    def _peticion_falla(configuracion, ruta, parametros, *, tiempo_limite):
        raise ErrorZAPNoDisponible("No se pudo conectar con la API de ZAP.")

    monkeypatch.setattr(zap_modulo, "_peticion_zap", _peticion_falla)
    with pytest.raises(ErrorZAPNoDisponible):
        ejecutar_analisis_pasivo(CONFIG_PRUEBA, "http://127.0.0.1/pagina")


# ---------------------------------------------------------------------------
# La API key nunca aparece en un mensaje de error, nunca se registra en claro.
# ---------------------------------------------------------------------------


def test_api_key_nunca_aparece_en_mensaje_de_error_por_key_invalida(monkeypatch):
    import http.client
    import json as json_mod

    class _RespuestaFalsa:
        status = 403

        def read(self) -> bytes:
            return json_mod.dumps({"code": "bad_api_key", "message": "no"}).encode()

    class _ConexionFalsa:
        def __init__(self, host, puerto, timeout=None):
            pass

        def request(self, metodo, ruta):
            self._ruta = ruta

        def getresponse(self):
            return _RespuestaFalsa()

        def close(self):
            pass

    monkeypatch.setattr(http.client, "HTTPConnection", _ConexionFalsa)

    config = ConfiguracionZAP(url_base="http://127.0.0.1:8080", api_key="MARCADOR-UNICO-DE-PRUEBA")

    # _peticion_zap() es el unico punto que construye la peticion real (y, por tanto, el
    # unico que podria llegar a interpolar la API key en un mensaje); diagnosticar_zap()
    # llama a esta misma funcion pero deliberadamente ABSORBE la excepcion para nunca
    # lanzar por "no disponible" (se prueba por separado en
    # test_diagnostico_no_disponible_no_lanza_excepcion).
    with pytest.raises(ErrorZAPNoDisponible) as info:
        zap_modulo._peticion_zap(config, "/JSON/core/view/version/", {}, tiempo_limite=5.0)
    assert "MARCADOR-UNICO-DE-PRUEBA" not in str(info.value)

    info_diagnostico = diagnosticar_zap(config)
    assert info_diagnostico.disponible is False
    assert "MARCADOR-UNICO-DE-PRUEBA" not in info_diagnostico.mensaje


def test_modulo_zap_nunca_menciona_funciones_activas():
    """Defensa en profundidad: el codigo fuente nunca debe referenciar active scan/spider."""
    texto = zap_modulo.__file__
    contenido = open(texto, encoding="utf-8").read().lower()
    for prohibido in ("ascan", "spider", "ajaxspider", "fuzz"):
        # Se permite mencionarlas en comentarios/docstrings explicando que NUNCA se usan,
        # pero nunca como parte de una ruta de API ("/json/ascan/..." o "/json/spider/...").
        assert f"/json/{prohibido}" not in contenido, f"se encontro una ruta de API '{prohibido}'"


# ---------------------------------------------------------------------------
# commands/zap.py: verificacion de alcance, persistencia atomica, cancelacion.
# ---------------------------------------------------------------------------


def test_ejecutar_zap_fuera_de_alcance_no_llega_a_llamar_la_api(tmp_path, monkeypatch):
    def _nunca_deberia_llamarse(*_a, **_k):
        raise AssertionError("_peticion_zap no deberia llamarse fuera de alcance")

    monkeypatch.setattr(zap_modulo, "_peticion_zap", _nunca_deberia_llamarse)

    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "zap-rechazo")
    base_datos.agregar_alcance(proyecto.id, "10.0.0.0/24")

    with pytest.raises(ErrorFueraDeAlcance):
        ejecutar_zap_pasivo(base_datos, proyecto, "http://127.0.0.1/pagina")

    assert base_datos.listar_resultados_zap(proyecto.id) == []


def test_ejecutar_zap_dentro_de_alcance_persiste_atomicamente(tmp_path, monkeypatch):
    _instalar_zap_falso(monkeypatch, alertas=[_alerta(), _alerta(plugin_id="90001")])

    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "zap-ok")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    resultado, guardados = ejecutar_zap_pasivo(base_datos, proyecto, "http://127.0.0.1/pagina")

    assert len(guardados) == 2
    assert len(base_datos.listar_resultados_zap(proyecto.id)) == 2
    assert all(g.estado_revision == "nuevo" for g in guardados)
    assert resultado.objetivo == "http://127.0.0.1/pagina"


def test_ejecutar_zap_cancelado_durante_espera_no_persiste_nada(tmp_path, monkeypatch):
    _instalar_zap_falso(monkeypatch, registros_pendientes=tuple(itertools.repeat(5, 100)))

    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "zap-cancelado")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    estado = {"llamadas": 0}

    def _debe_cancelar() -> bool:
        estado["llamadas"] += 1
        return estado["llamadas"] > 1

    with pytest.raises(ErrorEscaneoCancelado):
        ejecutar_zap_pasivo(
            base_datos, proyecto, "http://127.0.0.1/pagina", debe_cancelar=_debe_cancelar
        )

    assert base_datos.listar_resultados_zap(proyecto.id) == []


def test_ejecutar_zap_cancelado_justo_antes_de_guardar_no_persiste(tmp_path, monkeypatch):
    """El analisis termina con exito, pero la cancelacion se detecta justo antes de guardar."""
    estado_cancelado = {"cancelado": False}

    def _peticion_falsa(configuracion, ruta, parametros, *, tiempo_limite):
        if ruta == "/JSON/core/view/version/":
            return {"version": "2.14.0"}
        if ruta == "/JSON/core/action/accessUrl/":
            return {"accessUrl": "OK"}
        if ruta == "/JSON/pscan/view/recordsToScan/":
            return {"recordsToScan": "0"}
        if ruta == "/JSON/core/view/alerts/":
            estado_cancelado["cancelado"] = True
            return {"alerts": [_alerta()]}
        raise AssertionError(ruta)

    monkeypatch.setattr(zap_modulo, "_peticion_zap", _peticion_falsa)
    monkeypatch.setattr(zap_modulo.time, "sleep", lambda *_a, **_k: None)

    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "zap-cancel-tarde")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    with pytest.raises(ErrorEscaneoCancelado):
        ejecutar_zap_pasivo(
            base_datos,
            proyecto,
            "http://127.0.0.1/pagina",
            debe_cancelar=lambda: estado_cancelado["cancelado"],
        )

    assert base_datos.listar_resultados_zap(proyecto.id) == []


def test_ejecutar_zap_sin_guardar_evidencia(tmp_path, monkeypatch):
    _instalar_zap_falso(monkeypatch, alertas=[_alerta()])
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "zap-sin-evidencia")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    _resultado, guardados = ejecutar_zap_pasivo(
        base_datos, proyecto, "http://127.0.0.1/pagina", guardar_evidencia=False
    )
    assert guardados == []
    assert base_datos.listar_resultados_zap(proyecto.id) == []


# ---------------------------------------------------------------------------
# Reportes HTML/JSON.
# ---------------------------------------------------------------------------


def test_reporte_zap_html_y_json(tmp_path, monkeypatch):
    _instalar_zap_falso(monkeypatch, alertas=[_alerta()])
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "zap-reporte")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")
    ejecutar_zap_pasivo(base_datos, proyecto, "http://127.0.0.1/pagina")

    ruta_html = generar_reporte_zap(base_datos, proyecto, "html", tmp_path / "informe.html")
    ruta_json = generar_reporte_zap(base_datos, proyecto, "json", tmp_path / "informe.json")

    assert ruta_html.exists() and "AURABYTE" in ruta_html.read_text(encoding="utf-8")
    assert ruta_json.exists()
    import json as json_mod

    datos = json_mod.loads(ruta_json.read_text(encoding="utf-8"))
    assert datos["total_hallazgos"] == 1


def test_reporte_zap_formato_invalido(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "zap-formato-invalido")
    with pytest.raises(ErrorValidacion):
        generar_reporte_zap(base_datos, proyecto, "pdf")


# ---------------------------------------------------------------------------
# CLI: est zap estado|pasivo|resultados|revisar|reporte
# ---------------------------------------------------------------------------


def test_cli_zap_estado_no_disponible(runner, monkeypatch):
    from eurabyte_security.cli.app import app

    def _peticion_falla(configuracion, ruta, parametros, *, tiempo_limite):
        raise ErrorZAPNoDisponible("sin conexion")

    monkeypatch.setattr(zap_modulo, "_peticion_zap", _peticion_falla)
    resultado = runner.invoke(app, ["zap", "estado"])
    assert resultado.exit_code == 0
    assert "no esta disponible" in resultado.stdout


def test_cli_zap_pasivo_fuera_de_alcance_falla(runner):
    from eurabyte_security.cli.app import app

    runner.invoke(app, ["proyecto", "crear", "cli-zap"])
    resultado = runner.invoke(app, ["zap", "pasivo", "http://127.0.0.1/pagina"])
    assert resultado.exit_code != 0


def test_cli_zap_pasivo_dentro_de_alcance(runner, monkeypatch):
    from eurabyte_security.cli.app import app

    _instalar_zap_falso(monkeypatch, alertas=[_alerta()])
    runner.invoke(app, ["proyecto", "crear", "cli-zap-ok"])
    runner.invoke(app, ["alcance", "agregar", "127.0.0.1/32"])

    resultado = runner.invoke(app, ["zap", "pasivo", "http://127.0.0.1/pagina"])
    assert resultado.exit_code == 0
    assert "Hallazgos guardados: 1" in resultado.stdout


def test_cli_zap_resultados_y_revisar(runner, monkeypatch):
    from eurabyte_security.cli.app import app

    _instalar_zap_falso(monkeypatch, alertas=[_alerta()])
    runner.invoke(app, ["proyecto", "crear", "cli-zap-resultados"])
    runner.invoke(app, ["alcance", "agregar", "127.0.0.1/32"])
    runner.invoke(app, ["zap", "pasivo", "http://127.0.0.1/pagina"])

    resultado = runner.invoke(app, ["zap", "resultados"])
    assert resultado.exit_code == 0

    base_datos = BaseDatos()
    proyecto = base_datos.obtener_proyecto_por_nombre("cli-zap-resultados")
    guardados = base_datos.listar_resultados_zap(proyecto.id)
    assert len(guardados) == 1
    assert guardados[0].estado_revision == "nuevo"

    revisar = runner.invoke(app, ["zap", "revisar", str(guardados[0].id), "--estado", "confirmado"])
    assert revisar.exit_code == 0
    actualizado = base_datos.listar_resultados_zap(proyecto.id)[0]
    assert actualizado.estado_revision == "confirmado"


def test_cli_zap_revisar_estado_invalido(runner):
    from eurabyte_security.cli.app import app

    resultado = runner.invoke(app, ["zap", "revisar", "1", "--estado", "no-valido"])
    assert resultado.exit_code != 0


def test_cli_zap_reporte(runner, tmp_path, monkeypatch):
    from eurabyte_security.cli.app import app

    _instalar_zap_falso(monkeypatch, alertas=[_alerta()])
    runner.invoke(app, ["proyecto", "crear", "cli-zap-reporte"])
    runner.invoke(app, ["alcance", "agregar", "127.0.0.1/32"])
    runner.invoke(app, ["zap", "pasivo", "http://127.0.0.1/pagina"])

    salida = tmp_path / "informe-cli.json"
    resultado = runner.invoke(app, ["zap", "reporte", "--formato", "json", "--salida", str(salida)])
    assert resultado.exit_code == 0
    assert salida.exists()


def test_cli_explicar_zap():
    from typer.testing import CliRunner

    from eurabyte_security.cli.app import app

    resultado = CliRunner().invoke(app, ["explicar", "zap"])
    assert resultado.exit_code == 0
    assert "pasivo" in resultado.stdout.lower()
