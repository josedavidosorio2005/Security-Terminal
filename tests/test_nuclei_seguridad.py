"""Pruebas de la revision de seguridad de la PR #7 (Nuclei).

Cubren, de forma deterministas y sin ejecutar Nuclei real:

1. Validacion estructural de plantillas en lista blanca estricta (campos
   desconocidos, rutas no relativas a ``{{BaseURL}}``, limites de bloques/rutas,
   tipos de matcher permitidos) y el hash SHA-256 aprobado de cada plantilla.
2. Que la copia que se le pasa a Nuclei con ``-t`` nunca es la ruta original del
   catalogo (mitigacion TOCTOU) y que las opciones de aislamiento solo se agregan
   cuando ``nuclei -h`` confirma que existen.
3. Que un codigo de salida distinto de cero se trata siempre como un error real
   (nunca como "analisis exitoso sin hallazgos") y que no deja nada persistido.
4. Que una cancelacion detectada justo antes de guardar los resultados (no solo
   durante la ejecucion) tampoco persiste nada.
5. Que la salida JSONL de Nuclei se trata como no confiable: un ``template-id`` que
   no pertenece al conjunto de plantillas que AST pidio ejecutar en esa misma
   invocacion se descarta, los campos tienen una longitud maxima y una salida
   demasiado grande (por linea o en total) se rechaza sin usarla.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from rich.console import Console

from eurabyte_security.commands.nuclei import _tabla_hallazgos_nuclei, ejecutar_nuclei
from eurabyte_security.commands.proyecto import crear_proyecto
from eurabyte_security.core.errores import ErrorEscaneoCancelado, ErrorIntegracion
from eurabyte_security.integrations.nuclei import (
    _LONGITUD_MAXIMA_CAMPO_CORTO,
    PLANTILLAS_APROBADAS,
    AdaptadorNuclei,
    _analizar_jsonl_nuclei,
    _cargar_y_validar_plantilla,
    _opciones_aislamiento_disponibles,
    _variables_entorno_aisladas,
    ruta_plantilla,
    validar_plantilla_estructura,
)
from eurabyte_security.integrations.proceso import ResultadoProceso
from eurabyte_security.storage.database import BaseDatos

AYUDA_COMPLETA = " ".join(
    ["-target", "-t", "-jsonl", "-timeout", "-rate-limit", "-duc", "-ni", "-silent", "-nc"]
)


def _resultado_ayuda_ok() -> ResultadoProceso:
    return ResultadoProceso(
        codigo_salida=0, stdout=AYUDA_COMPLETA, stderr="", agotado_por_tiempo=False
    )


def _linea_hallazgo(
    template_id: str = "exposed-env-file",
    nombre: str = "Archivo .env expuesto",
    severidad: str = "high",
    matched_at: str = "http://127.0.0.1/.env",
) -> str:
    return json.dumps(
        {
            "template-id": template_id,
            "info": {"name": nombre, "severity": severidad, "description": "desc"},
            "matched-at": matched_at,
            "matcher-name": "word",
        }
    )


def _plantilla_base(**overrides: object) -> dict:
    datos = {
        "id": "prueba",
        "info": {"name": "x", "severity": "info"},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/"]}],
    }
    datos.update(overrides)
    return datos


def _escribir_yaml(tmp_path: Path, nombre: str, datos: dict) -> Path:
    import yaml

    ruta = tmp_path / nombre
    ruta.write_text(yaml.safe_dump(datos), encoding="utf-8")
    return ruta


# ---------------------------------------------------------------------------
# (1) Validacion estructural en lista blanca + hash SHA-256 aprobado.
# ---------------------------------------------------------------------------


def test_todas_las_plantillas_aprobadas_cargan_con_hash_e_id_correctos():
    for plantilla_id in PLANTILLAS_APROBADAS:
        texto = _cargar_y_validar_plantilla(plantilla_id)
        assert texto == ruta_plantilla(plantilla_id).read_text(encoding="utf-8")


def test_plantilla_con_hash_modificado_se_rechaza(monkeypatch):
    """Si el archivo en disco no coincide con el hash revisado, se rechaza."""
    info_original = PLANTILLAS_APROBADAS["exposed-env-file"]
    info_falsificado = replace(info_original, sha256="0" * 64)
    monkeypatch.setitem(PLANTILLAS_APROBADAS, "exposed-env-file", info_falsificado)
    with pytest.raises(ErrorIntegracion, match="hash"):
        _cargar_y_validar_plantilla("exposed-env-file")


def test_plantilla_con_id_no_coincidente_con_el_catalogo_se_rechaza(tmp_path):
    ruta = _escribir_yaml(tmp_path, "mismatch.yaml", _plantilla_base(id="otro-id"))
    with pytest.raises(ErrorIntegracion, match="esperaba"):
        validar_plantilla_estructura(ruta, plantilla_id_esperado="prueba")


def test_plantilla_con_campo_nivel_superior_desconocido_se_rechaza(tmp_path):
    ruta = _escribir_yaml(tmp_path, "extra.yaml", _plantilla_base(**{"self-contained": True}))
    with pytest.raises(ErrorIntegracion):
        validar_plantilla_estructura(ruta)


def test_plantilla_con_campo_info_desconocido_se_rechaza(tmp_path):
    datos = _plantilla_base()
    datos["info"]["reference"] = ["http://evil.example.com"]
    ruta = _escribir_yaml(tmp_path, "info-extra.yaml", datos)
    with pytest.raises(ErrorIntegracion):
        validar_plantilla_estructura(ruta)


def test_plantilla_con_campo_bloque_http_desconocido_se_rechaza(tmp_path):
    datos = _plantilla_base()
    datos["http"][0]["raw"] = ["GET / HTTP/1.1"]
    ruta = _escribir_yaml(tmp_path, "raw.yaml", datos)
    with pytest.raises(ErrorIntegracion):
        validar_plantilla_estructura(ruta)


def test_plantilla_con_ruta_absoluta_a_otro_host_se_rechaza(tmp_path):
    datos = _plantilla_base()
    datos["http"][0]["path"] = ["http://evil.example.com/"]
    ruta = _escribir_yaml(tmp_path, "absoluta.yaml", datos)
    with pytest.raises(ErrorIntegracion, match="ruta no permitida"):
        validar_plantilla_estructura(ruta)


def test_plantilla_con_variable_distinta_de_baseurl_se_rechaza(tmp_path):
    datos = _plantilla_base()
    datos["http"][0]["path"] = ["{{RootURL}}/x"]
    ruta = _escribir_yaml(tmp_path, "rootvar.yaml", datos)
    with pytest.raises(ErrorIntegracion, match="ruta no permitida"):
        validar_plantilla_estructura(ruta)


def test_plantilla_con_demasiadas_rutas_se_rechaza(tmp_path):
    datos = _plantilla_base()
    datos["http"][0]["path"] = [f"{{{{BaseURL}}}}/r{i}" for i in range(5)]
    ruta = _escribir_yaml(tmp_path, "muchasrutas.yaml", datos)
    with pytest.raises(ErrorIntegracion, match="rutas"):
        validar_plantilla_estructura(ruta)


def test_plantilla_con_demasiados_bloques_http_se_rechaza(tmp_path):
    datos = _plantilla_base()
    datos["http"].append({"method": "GET", "path": ["{{BaseURL}}/otra"]})
    ruta = _escribir_yaml(tmp_path, "dosbloques.yaml", datos)
    with pytest.raises(ErrorIntegracion, match="bloques HTTP"):
        validar_plantilla_estructura(ruta)


def test_plantilla_con_tipo_de_matcher_no_permitido_se_rechaza(tmp_path):
    datos = _plantilla_base()
    datos["http"][0]["matchers"] = [{"type": "dsl", "dsl": ["1==1"]}]
    ruta = _escribir_yaml(tmp_path, "dsl.yaml", datos)
    with pytest.raises(ErrorIntegracion):
        validar_plantilla_estructura(ruta)


def test_plantilla_con_condicion_de_matchers_no_permitida_se_rechaza(tmp_path):
    datos = _plantilla_base()
    datos["http"][0]["matchers-condition"] = "xor"
    datos["http"][0]["matchers"] = [{"type": "status", "status": [200]}]
    ruta = _escribir_yaml(tmp_path, "xor.yaml", datos)
    with pytest.raises(ErrorIntegracion, match="condicion"):
        validar_plantilla_estructura(ruta)


# ---------------------------------------------------------------------------
# (1, continuacion) TOCTOU: la ruta que recibe Nuclei no es la del catalogo.
# ---------------------------------------------------------------------------


def test_ejecutar_pasa_una_copia_validada_no_la_ruta_original_del_catalogo(monkeypatch):
    capturado: dict = {}

    monkeypatch.setattr(AdaptadorNuclei, "esta_instalado", lambda self: True)
    monkeypatch.setattr(AdaptadorNuclei, "ruta_binario", lambda self: "/usr/bin/nuclei")

    def _ejecutar_binario_falso(
        self, argumentos, *, tiempo_limite, debe_cancelar=None, variables_entorno=None
    ):
        if argumentos == ["-h"]:
            return _resultado_ayuda_ok()
        capturado["argumentos"] = list(argumentos)
        ruta_salida = Path(argumentos[argumentos.index("-o") + 1])
        ruta_salida.write_text("", encoding="utf-8")
        return ResultadoProceso(codigo_salida=0, stdout="", stderr="", agotado_por_tiempo=False)

    monkeypatch.setattr(AdaptadorNuclei, "_ejecutar_binario", _ejecutar_binario_falso)

    AdaptadorNuclei().ejecutar(objetivo="127.0.0.1", plantillas_ids=["exposed-env-file"])

    argumentos = capturado["argumentos"]
    ruta_usada = Path(argumentos[argumentos.index("-t") + 1])
    ruta_original = ruta_plantilla("exposed-env-file")

    assert ruta_usada != ruta_original
    assert "ast-nuclei-" in str(ruta_usada.parent.parent) or "ast-nuclei-" in str(
        ruta_usada.parent
    )
    # La copia ya fue borrada (el directorio temporal se limpia al salir del 'with'):
    # la proteccion es que NUNCA se uso la ruta original del catalogo, no que la
    # copia siga existiendo despues.
    assert not ruta_usada.exists()


# ---------------------------------------------------------------------------
# (2) Configuracion aislada: opciones opcionales y entorno de proceso.
# ---------------------------------------------------------------------------


def test_opciones_aislamiento_no_se_agregan_si_no_estan_disponibles(tmp_path):
    extra = _opciones_aislamiento_disponibles(AYUDA_COMPLETA, ruta_config_aislada=tmp_path / "c")
    assert extra == []


def test_opciones_aislamiento_se_agregan_cuando_estan_disponibles(tmp_path):
    ayuda = AYUDA_COMPLETA + " -config -dr -nh -no-stdin"
    ruta_config = tmp_path / "config.yaml"
    extra = _opciones_aislamiento_disponibles(ayuda, ruta_config_aislada=ruta_config)
    assert "-config" in extra
    assert str(ruta_config) in extra
    assert "-dr" in extra
    assert "-nh" in extra
    assert "-no-stdin" in extra


def test_entorno_aislado_limpia_proxy_y_redirige_configuracion(tmp_path, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy-corporativo:8080")
    monkeypatch.setenv("NUCLEI_TEMPLATES_STATS", "algo")
    destino = tmp_path / "aislado"
    entorno = _variables_entorno_aisladas(destino)
    assert "HTTP_PROXY" not in entorno
    assert not any(k.upper().startswith("NUCLEI_") for k in entorno)
    assert entorno["HOME"] == str(destino)
    assert entorno["XDG_CONFIG_HOME"] == str(destino)
    assert destino.exists()


def test_ejecutar_invoca_el_proceso_con_entorno_aislado(monkeypatch):
    capturado: dict = {}
    monkeypatch.setenv("HTTP_PROXY", "http://proxy-corporativo:8080")
    monkeypatch.setattr(AdaptadorNuclei, "esta_instalado", lambda self: True)
    monkeypatch.setattr(AdaptadorNuclei, "ruta_binario", lambda self: "/usr/bin/nuclei")

    def _ejecutar_binario_falso(
        self, argumentos, *, tiempo_limite, debe_cancelar=None, variables_entorno=None
    ):
        if argumentos == ["-h"]:
            return _resultado_ayuda_ok()
        capturado["variables_entorno"] = variables_entorno
        ruta_salida = Path(argumentos[argumentos.index("-o") + 1])
        ruta_salida.write_text("", encoding="utf-8")
        return ResultadoProceso(codigo_salida=0, stdout="", stderr="", agotado_por_tiempo=False)

    monkeypatch.setattr(AdaptadorNuclei, "_ejecutar_binario", _ejecutar_binario_falso)
    AdaptadorNuclei().ejecutar(objetivo="127.0.0.1", plantillas_ids=["exposed-env-file"])

    assert capturado["variables_entorno"] is not None
    assert "HTTP_PROXY" not in capturado["variables_entorno"]


# ---------------------------------------------------------------------------
# (3) Errores reales del proceso: codigo de salida distinto de cero.
# ---------------------------------------------------------------------------


def test_nuclei_codigo_salida_no_cero_lanza_error_y_no_reporta_exito(monkeypatch):
    monkeypatch.setattr(AdaptadorNuclei, "esta_instalado", lambda self: True)
    monkeypatch.setattr(AdaptadorNuclei, "ruta_binario", lambda self: "/usr/bin/nuclei")

    def _ejecutar_binario_falso(
        self, argumentos, *, tiempo_limite, debe_cancelar=None, variables_entorno=None
    ):
        if argumentos == ["-h"]:
            return _resultado_ayuda_ok()
        # Simula que Nuclei escribio un hallazgo ANTES de fallar (p. ej. un error de
        # argumentos incompatibles a mitad de la ejecucion): no debe usarse.
        ruta_salida = Path(argumentos[argumentos.index("-o") + 1])
        ruta_salida.write_text(_linea_hallazgo() + "\n", encoding="utf-8")
        return ResultadoProceso(
            codigo_salida=1, stdout="", stderr="error: argumento invalido", agotado_por_tiempo=False
        )

    monkeypatch.setattr(AdaptadorNuclei, "_ejecutar_binario", _ejecutar_binario_falso)

    with pytest.raises(ErrorIntegracion, match="codigo de salida"):
        AdaptadorNuclei().ejecutar(objetivo="127.0.0.1", plantillas_ids=["exposed-env-file"])


def test_ejecutar_nuclei_codigo_salida_no_cero_no_persiste_nada(tmp_path, monkeypatch):
    monkeypatch.setattr(AdaptadorNuclei, "esta_instalado", lambda self: True)
    monkeypatch.setattr(AdaptadorNuclei, "ruta_binario", lambda self: "/usr/bin/nuclei")

    def _ejecutar_binario_falso(
        self, argumentos, *, tiempo_limite, debe_cancelar=None, variables_entorno=None
    ):
        if argumentos == ["-h"]:
            return _resultado_ayuda_ok()
        ruta_salida = Path(argumentos[argumentos.index("-o") + 1])
        ruta_salida.write_text(_linea_hallazgo() + "\n", encoding="utf-8")
        return ResultadoProceso(
            codigo_salida=2, stdout="", stderr="fallo", agotado_por_tiempo=False
        )

    monkeypatch.setattr(AdaptadorNuclei, "_ejecutar_binario", _ejecutar_binario_falso)

    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "nuclei-codigo-error")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    with pytest.raises(ErrorIntegracion):
        ejecutar_nuclei(base_datos, proyecto, "127.0.0.1", ["exposed-env-file"])

    assert base_datos.listar_resultados_nuclei(proyecto.id) == []


# ---------------------------------------------------------------------------
# (4) Cancelacion justo antes de persistir (no solo durante la ejecucion).
# ---------------------------------------------------------------------------


def test_ejecutar_nuclei_cancelado_justo_antes_de_guardar_no_persiste(tmp_path, monkeypatch):
    """Nuclei termina con exito, pero la cancelacion se detecta justo antes de guardar."""
    estado = {"cancelado": False}

    monkeypatch.setattr(AdaptadorNuclei, "esta_instalado", lambda self: True)
    monkeypatch.setattr(AdaptadorNuclei, "ruta_binario", lambda self: "/usr/bin/nuclei")

    def _ejecutar_binario_falso(
        self, argumentos, *, tiempo_limite, debe_cancelar=None, variables_entorno=None
    ):
        if argumentos == ["-h"]:
            return _resultado_ayuda_ok()
        ruta_salida = Path(argumentos[argumentos.index("-o") + 1])
        ruta_salida.write_text(_linea_hallazgo() + "\n", encoding="utf-8")
        # La cancelacion "llega" justo cuando Nuclei ya habia terminado de verdad.
        estado["cancelado"] = True
        return ResultadoProceso(codigo_salida=0, stdout="", stderr="", agotado_por_tiempo=False)

    monkeypatch.setattr(AdaptadorNuclei, "_ejecutar_binario", _ejecutar_binario_falso)

    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "nuclei-cancel-tarde")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    with pytest.raises(ErrorEscaneoCancelado):
        ejecutar_nuclei(
            base_datos,
            proyecto,
            "127.0.0.1",
            ["exposed-env-file"],
            debe_cancelar=lambda: estado["cancelado"],
        )

    assert base_datos.listar_resultados_nuclei(proyecto.id) == []


# ---------------------------------------------------------------------------
# (5) JSONL no confiable: ids no ejecutados, longitudes y tamanos maximos.
# ---------------------------------------------------------------------------


def test_jsonl_con_template_id_no_ejecutado_en_esta_corrida_se_descarta():
    jsonl = _linea_hallazgo(template_id="exposed-phpinfo") + "\n"
    hallazgos, descartadas = _analizar_jsonl_nuclei(
        jsonl, ids_ejecutados=frozenset({"exposed-env-file"})
    )
    assert hallazgos == []
    assert descartadas == 1


def test_jsonl_con_nombre_extremadamente_largo_se_trunca():
    jsonl = _linea_hallazgo(nombre="X" * 10_000) + "\n"
    hallazgos, _ = _analizar_jsonl_nuclei(jsonl, ids_ejecutados=frozenset({"exposed-env-file"}))
    assert len(hallazgos) == 1
    assert len(hallazgos[0].plantilla_nombre) <= _LONGITUD_MAXIMA_CAMPO_CORTO


def test_jsonl_linea_demasiado_larga_se_descarta_sin_analizar():
    linea_enorme = _linea_hallazgo(matched_at="http://127.0.0.1/" + "a" * 250_000)
    hallazgos, descartadas = _analizar_jsonl_nuclei(
        linea_enorme, ids_ejecutados=frozenset({"exposed-env-file"})
    )
    assert hallazgos == []
    assert descartadas == 1


def test_jsonl_total_supera_tamano_maximo_se_rechaza_sin_persistir(tmp_path, monkeypatch):
    monkeypatch.setattr(AdaptadorNuclei, "esta_instalado", lambda self: True)
    monkeypatch.setattr(AdaptadorNuclei, "ruta_binario", lambda self: "/usr/bin/nuclei")

    def _ejecutar_binario_falso(
        self, argumentos, *, tiempo_limite, debe_cancelar=None, variables_entorno=None
    ):
        if argumentos == ["-h"]:
            return _resultado_ayuda_ok()
        ruta_salida = Path(argumentos[argumentos.index("-o") + 1])
        # Una sola linea JSON valida, pero el archivo completo supera el maximo
        # admitido (simulando una salida desproporcionada/corrupta de Nuclei).
        relleno = _linea_hallazgo(matched_at="http://127.0.0.1/" + "a" * (11 * 1024 * 1024))
        ruta_salida.write_text(relleno, encoding="utf-8")
        return ResultadoProceso(codigo_salida=0, stdout="", stderr="", agotado_por_tiempo=False)

    monkeypatch.setattr(AdaptadorNuclei, "_ejecutar_binario", _ejecutar_binario_falso)

    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "nuclei-jsonl-enorme")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    with pytest.raises(ErrorIntegracion, match="bytes"):
        ejecutar_nuclei(base_datos, proyecto, "127.0.0.1", ["exposed-env-file"])

    assert base_datos.listar_resultados_nuclei(proyecto.id) == []


def test_jsonl_con_marcado_rich_en_los_campos_no_rompe_la_tabla_cli():
    jsonl = _linea_hallazgo(
        template_id="exposed-env-file",
        nombre="[bold red]x[/bold red]",
        matched_at="http://127.0.0.1/[red]inyectado[/red]",
    )
    hallazgos, _ = _analizar_jsonl_nuclei(jsonl, ids_ejecutados=frozenset({"exposed-env-file"}))
    assert len(hallazgos) == 1
    tabla = _tabla_hallazgos_nuclei(hallazgos, "prueba")
    # No debe lanzar rich.errors.MarkupError al renderizarla con un Console real.
    Console().print(tabla)
