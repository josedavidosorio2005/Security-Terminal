"""Pruebas del adaptador Nuclei y del comando asociado.

Ninguna de estas pruebas ejecuta Nuclei de verdad: se sustituye
``AdaptadorNuclei._ejecutar_binario`` (el unico punto de la clase que invoca un
proceso externo) por un doble que simula su comportamiento, escribiendo una
salida JSONL de ejemplo exactamente como lo haria el binario real con
``-jsonl -o <archivo>``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from eurabyte_security.commands.nuclei import ejecutar_nuclei, generar_reporte_nuclei
from eurabyte_security.commands.proyecto import crear_proyecto
from eurabyte_security.core.errores import (
    ErrorEscaneoCancelado,
    ErrorFueraDeAlcance,
    ErrorHerramientaNoDisponible,
    ErrorIntegracion,
    ErrorParametrosIntegracion,
    ErrorValidacion,
)
from eurabyte_security.integrations.nuclei import (
    PLANTILLAS_APROBADAS,
    AdaptadorNuclei,
    validar_plantilla_estructura,
)
from eurabyte_security.integrations.proceso import ResultadoProceso
from eurabyte_security.storage.database import BaseDatos

AYUDA_COMPLETA = " ".join(
    ["-target", "-t", "-jsonl", "-timeout", "-rate-limit", "-duc", "-ni", "-silent", "-nc"]
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


def _resultado_ayuda_ok() -> ResultadoProceso:
    return ResultadoProceso(
        codigo_salida=0, stdout=AYUDA_COMPLETA, stderr="", agotado_por_tiempo=False
    )


def _instalar_nuclei_falso(
    monkeypatch, *, jsonl: str | None = "", ayuda: str = AYUDA_COMPLETA
) -> None:
    """Simula que Nuclei esta instalado, responde a '-h' y escribe ``jsonl`` al ejecutarse."""
    monkeypatch.setattr(AdaptadorNuclei, "esta_instalado", lambda self: True)
    monkeypatch.setattr(AdaptadorNuclei, "ruta_binario", lambda self: "/usr/bin/nuclei")

    def _ejecutar_binario_falso(
        self, argumentos, *, tiempo_limite, debe_cancelar=None, variables_entorno=None
    ):
        if argumentos == ["-h"]:
            return ResultadoProceso(
                codigo_salida=0, stdout=ayuda, stderr="", agotado_por_tiempo=False
            )
        ruta_salida = Path(argumentos[argumentos.index("-o") + 1])
        if jsonl is not None:
            ruta_salida.write_text(jsonl, encoding="utf-8")
        return ResultadoProceso(codigo_salida=0, stdout="", stderr="", agotado_por_tiempo=False)

    monkeypatch.setattr(AdaptadorNuclei, "_ejecutar_binario", _ejecutar_binario_falso)


# ---------------------------------------------------------------------------
# AdaptadorNuclei: deteccion, validacion, catalogo, JSONL (con el proceso simulado).
# ---------------------------------------------------------------------------


def test_nuclei_no_instalado_lanza_error_claro(monkeypatch):
    monkeypatch.setattr(AdaptadorNuclei, "esta_instalado", lambda self: False)
    with pytest.raises(ErrorHerramientaNoDisponible):
        AdaptadorNuclei().ejecutar(objetivo="127.0.0.1", plantillas_ids=["exposed-env-file"])


def test_nuclei_rechaza_objetivo_con_dominio(monkeypatch):
    _instalar_nuclei_falso(monkeypatch)
    with pytest.raises(ErrorValidacion):
        AdaptadorNuclei().ejecutar(objetivo="example.com", plantillas_ids=["exposed-env-file"])


def test_nuclei_rechaza_objetivo_con_ruta(monkeypatch):
    _instalar_nuclei_falso(monkeypatch)
    with pytest.raises(ErrorValidacion):
        AdaptadorNuclei().ejecutar(
            objetivo="http://127.0.0.1/algo", plantillas_ids=["exposed-env-file"]
        )


def test_nuclei_rechaza_plantilla_no_aprobada(monkeypatch):
    _instalar_nuclei_falso(monkeypatch)
    with pytest.raises(ErrorParametrosIntegracion):
        AdaptadorNuclei().ejecutar(objetivo="127.0.0.1", plantillas_ids=["ruta/arbitraria"])


def test_nuclei_rechaza_sin_plantillas(monkeypatch):
    _instalar_nuclei_falso(monkeypatch)
    with pytest.raises(ErrorParametrosIntegracion):
        AdaptadorNuclei().ejecutar(objetivo="127.0.0.1", plantillas_ids=[])


def test_nuclei_rechaza_tiempo_limite_fuera_de_rango(monkeypatch):
    _instalar_nuclei_falso(monkeypatch)
    with pytest.raises(ErrorParametrosIntegracion):
        AdaptadorNuclei().ejecutar(
            objetivo="127.0.0.1", plantillas_ids=["exposed-env-file"], tiempo_limite=1.0
        )


def test_nuclei_rechaza_version_sin_opciones_compatibles(monkeypatch):
    """Si 'nuclei -h' no reconoce una opcion requerida, no se intenta ejecutar nada."""
    _instalar_nuclei_falso(monkeypatch, ayuda="-target -t -jsonl")  # faltan varias opciones
    with pytest.raises(ErrorIntegracion):
        AdaptadorNuclei().ejecutar(objetivo="127.0.0.1", plantillas_ids=["exposed-env-file"])


def test_nuclei_analiza_el_jsonl_correctamente(monkeypatch):
    jsonl = _linea_hallazgo() + "\n"
    _instalar_nuclei_falso(monkeypatch, jsonl=jsonl)
    resultado = AdaptadorNuclei().ejecutar(
        objetivo="127.0.0.1", plantillas_ids=["exposed-env-file"]
    )
    assert resultado.objetivo == "http://127.0.0.1:80"
    assert len(resultado.hallazgos) == 1
    hallazgo = resultado.hallazgos[0]
    assert hallazgo.plantilla_id == "exposed-env-file"
    assert hallazgo.severidad == "high"
    assert resultado.lineas_jsonl_descartadas == 0


def test_nuclei_descarta_lineas_jsonl_malformadas_sin_fallar(monkeypatch):
    jsonl = "\n".join(
        [
            _linea_hallazgo(),
            "esto no es json",
            json.dumps({"template-id": "x"}),  # sin 'info': se descarta
            json.dumps({"info": {"name": "y", "severity": "low"}}),  # sin template-id
        ]
    )
    _instalar_nuclei_falso(monkeypatch, jsonl=jsonl)
    resultado = AdaptadorNuclei().ejecutar(
        objetivo="127.0.0.1", plantillas_ids=["exposed-env-file"]
    )
    assert len(resultado.hallazgos) == 1
    assert resultado.lineas_jsonl_descartadas == 3


def test_nuclei_hallazgo_nunca_incluye_request_response_ni_cookies(monkeypatch):
    linea = json.dumps(
        {
            "template-id": "exposed-env-file",
            "info": {"name": "n", "severity": "high", "description": "d"},
            "matched-at": "http://127.0.0.1/.env",
            "matcher-name": "word",
            "request": "GET /.env HTTP/1.1\r\nAuthorization: Bearer secreto-prueba",
            "response": "HTTP/1.1 200 OK\r\nSet-Cookie: session=secreto-cookie",
        }
    )
    _instalar_nuclei_falso(monkeypatch, jsonl=linea + "\n")
    resultado = AdaptadorNuclei().ejecutar(
        objetivo="127.0.0.1", plantillas_ids=["exposed-env-file"]
    )
    texto_completo = str(resultado.hallazgos)
    assert "secreto-prueba" not in texto_completo
    assert "secreto-cookie" not in texto_completo
    assert "Authorization" not in texto_completo


def test_nuclei_sin_jsonl_de_salida_no_falla_sin_hallazgos(monkeypatch):
    _instalar_nuclei_falso(monkeypatch, jsonl=None)
    resultado = AdaptadorNuclei().ejecutar(
        objetivo="127.0.0.1", plantillas_ids=["exposed-env-file"]
    )
    assert resultado.hallazgos == []


def test_nuclei_tiempo_agotado_lanza_error_integracion(monkeypatch):
    _instalar_nuclei_falso(monkeypatch)

    def _agotado(self, argumentos, *, tiempo_limite, debe_cancelar=None, variables_entorno=None):
        if argumentos == ["-h"]:
            return _resultado_ayuda_ok()
        return ResultadoProceso(codigo_salida=-1, stdout="", stderr="", agotado_por_tiempo=True)

    monkeypatch.setattr(AdaptadorNuclei, "_ejecutar_binario", _agotado)
    with pytest.raises(ErrorIntegracion):
        AdaptadorNuclei().ejecutar(objetivo="127.0.0.1", plantillas_ids=["exposed-env-file"])


def test_nuclei_cancelado_lanza_error_escaneo_cancelado(monkeypatch):
    _instalar_nuclei_falso(monkeypatch)

    def _cancelado(self, argumentos, *, tiempo_limite, debe_cancelar=None, variables_entorno=None):
        if argumentos == ["-h"]:
            return _resultado_ayuda_ok()
        return ResultadoProceso(
            codigo_salida=-1, stdout="", stderr="", agotado_por_tiempo=False, cancelado=True
        )

    monkeypatch.setattr(AdaptadorNuclei, "_ejecutar_binario", _cancelado)
    with pytest.raises(ErrorEscaneoCancelado):
        AdaptadorNuclei().ejecutar(
            objetivo="127.0.0.1", plantillas_ids=["exposed-env-file"], debe_cancelar=lambda: True
        )


def test_nuclei_info_cuando_no_esta_instalado(monkeypatch):
    monkeypatch.setattr(AdaptadorNuclei, "esta_instalado", lambda self: False)
    monkeypatch.setattr(AdaptadorNuclei, "ruta_binario", lambda self: None)
    info = AdaptadorNuclei().info()
    assert info.instalada is False
    assert info.version is None


# ---------------------------------------------------------------------------
# Catalogo de plantillas y validacion estructural (defensa en profundidad).
# ---------------------------------------------------------------------------


def test_todas_las_plantillas_aprobadas_pasan_la_validacion_estructural():
    from eurabyte_security.integrations.nuclei import ruta_plantilla

    for plantilla_id in PLANTILLAS_APROBADAS:
        validar_plantilla_estructura(ruta_plantilla(plantilla_id))


def test_plantilla_con_protocolo_prohibido_se_rechaza(tmp_path):
    ruta = tmp_path / "maliciosa.yaml"
    ruta.write_text(
        "id: maliciosa\ninfo:\n  name: x\n  severity: info\nnetwork:\n  - host: ['{{Hostname}}']\n",
        encoding="utf-8",
    )
    with pytest.raises(ErrorIntegracion):
        validar_plantilla_estructura(ruta)


def test_plantilla_que_sigue_redirecciones_se_rechaza(tmp_path):
    ruta = tmp_path / "redirige.yaml"
    ruta.write_text(
        "id: redirige\ninfo:\n  name: x\n  severity: info\n"
        "http:\n  - method: GET\n    redirects: true\n    path: ['{{BaseURL}}']\n",
        encoding="utf-8",
    )
    with pytest.raises(ErrorIntegracion):
        validar_plantilla_estructura(ruta)


def test_plantilla_con_interactsh_se_rechaza(tmp_path):
    ruta = tmp_path / "oast.yaml"
    ruta.write_text(
        "id: oast\ninfo:\n  name: x\n  severity: info\n"
        "http:\n  - method: GET\n    path: ['{{BaseURL}}']\n"
        "    matchers:\n      - type: word\n        part: interactsh_protocol\n"
        "        words: ['http']\n",
        encoding="utf-8",
    )
    with pytest.raises(ErrorIntegracion):
        validar_plantilla_estructura(ruta)


def test_plantilla_con_metodo_distinto_de_get_se_rechaza(tmp_path):
    ruta = tmp_path / "post.yaml"
    ruta.write_text(
        "id: post\ninfo:\n  name: x\n  severity: info\n"
        "http:\n  - method: POST\n    path: ['{{BaseURL}}']\n",
        encoding="utf-8",
    )
    with pytest.raises(ErrorIntegracion):
        validar_plantilla_estructura(ruta)


def test_plantilla_sin_bloque_http_se_rechaza(tmp_path):
    ruta = tmp_path / "vacia.yaml"
    ruta.write_text("id: vacia\ninfo:\n  name: x\n  severity: info\n", encoding="utf-8")
    with pytest.raises(ErrorIntegracion):
        validar_plantilla_estructura(ruta)


def test_plantilla_yaml_invalido_se_rechaza(tmp_path):
    ruta = tmp_path / "roto.yaml"
    ruta.write_text("esto: [no cierra", encoding="utf-8")
    with pytest.raises(ErrorIntegracion):
        validar_plantilla_estructura(ruta)


def test_plantilla_inexistente_se_rechaza(tmp_path):
    with pytest.raises(ErrorIntegracion):
        validar_plantilla_estructura(tmp_path / "no-existe.yaml")


# ---------------------------------------------------------------------------
# commands/nuclei.py: verificacion de alcance, persistencia atomica.
# ---------------------------------------------------------------------------


def test_ejecutar_nuclei_fuera_de_alcance_no_llega_a_ejecutar_nada(tmp_path):
    """Sin alcance registrado, se rechaza antes de siquiera comprobar si Nuclei existe."""
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "nuclei-rechazo")
    base_datos.agregar_alcance(proyecto.id, "10.0.0.0/24")

    with pytest.raises(ErrorFueraDeAlcance):
        ejecutar_nuclei(base_datos, proyecto, "127.0.0.1", ["exposed-env-file"])

    assert base_datos.listar_resultados_nuclei(proyecto.id) == []


def test_ejecutar_nuclei_dentro_de_alcance_persiste_atomicamente(tmp_path, monkeypatch):
    _instalar_nuclei_falso(monkeypatch, jsonl=_linea_hallazgo() + "\n" + _linea_hallazgo(
        template_id="exposed-git-config", nombre="Archivo .git/config expuesto"
    ) + "\n")

    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "nuclei-ok")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    resultado, guardados = ejecutar_nuclei(
        base_datos, proyecto, "127.0.0.1", ["exposed-env-file", "exposed-git-config"]
    )

    assert len(guardados) == 2
    assert len(base_datos.listar_resultados_nuclei(proyecto.id)) == 2
    assert all(g.estado_revision == "nuevo" for g in guardados)
    assert all(g.plantilla_version == "1" for g in guardados)
    assert resultado.objetivo == "http://127.0.0.1:80"


def test_ejecutar_nuclei_cancelado_no_persiste_nada(tmp_path, monkeypatch):
    def _cancelado(self, argumentos, *, tiempo_limite, debe_cancelar=None, variables_entorno=None):
        if argumentos == ["-h"]:
            return _resultado_ayuda_ok()
        return ResultadoProceso(
            codigo_salida=-1, stdout="", stderr="", agotado_por_tiempo=False, cancelado=True
        )

    monkeypatch.setattr(AdaptadorNuclei, "esta_instalado", lambda self: True)
    monkeypatch.setattr(AdaptadorNuclei, "ruta_binario", lambda self: "/usr/bin/nuclei")
    monkeypatch.setattr(AdaptadorNuclei, "_ejecutar_binario", _cancelado)

    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "nuclei-cancelado")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    with pytest.raises(ErrorEscaneoCancelado):
        ejecutar_nuclei(
            base_datos, proyecto, "127.0.0.1", ["exposed-env-file"], debe_cancelar=lambda: True
        )

    assert base_datos.listar_resultados_nuclei(proyecto.id) == []


def test_ejecutar_nuclei_sin_guardar_evidencia(tmp_path, monkeypatch):
    _instalar_nuclei_falso(monkeypatch, jsonl=_linea_hallazgo() + "\n")
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "nuclei-sin-evidencia")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    _resultado, guardados = ejecutar_nuclei(
        base_datos, proyecto, "127.0.0.1", ["exposed-env-file"], guardar_evidencia=False
    )
    assert guardados == []
    assert base_datos.listar_resultados_nuclei(proyecto.id) == []


# ---------------------------------------------------------------------------
# Reportes HTML/JSON.
# ---------------------------------------------------------------------------


def test_reporte_nuclei_html_y_json(tmp_path, monkeypatch):
    _instalar_nuclei_falso(monkeypatch, jsonl=_linea_hallazgo() + "\n")
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "nuclei-reporte")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")
    ejecutar_nuclei(base_datos, proyecto, "127.0.0.1", ["exposed-env-file"])

    ruta_html = generar_reporte_nuclei(base_datos, proyecto, "html", tmp_path / "informe.html")
    ruta_json = generar_reporte_nuclei(base_datos, proyecto, "json", tmp_path / "informe.json")

    assert ruta_html.exists() and "AURABYTE" in ruta_html.read_text(encoding="utf-8")
    assert ruta_json.exists()
    datos = json.loads(ruta_json.read_text(encoding="utf-8"))
    assert datos["total_hallazgos"] == 1


def test_reporte_nuclei_formato_invalido(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "nuclei-formato-invalido")
    with pytest.raises(ErrorValidacion):
        generar_reporte_nuclei(base_datos, proyecto, "pdf")


# ---------------------------------------------------------------------------
# CLI: est nuclei version|plantillas|analizar|resultados|revisar|reporte
# ---------------------------------------------------------------------------


def test_cli_nuclei_version_no_instalado(runner, monkeypatch):
    from eurabyte_security.cli.app import app

    monkeypatch.setattr(AdaptadorNuclei, "esta_instalado", lambda self: False)
    monkeypatch.setattr(AdaptadorNuclei, "ruta_binario", lambda self: None)

    resultado = runner.invoke(app, ["nuclei", "version"])
    assert resultado.exit_code == 0
    assert "no esta instalado" in resultado.stdout


def test_cli_nuclei_plantillas_lista_el_catalogo(runner):
    from eurabyte_security.cli.app import app

    resultado = runner.invoke(app, ["nuclei", "plantillas"])
    assert resultado.exit_code == 0
    assert "exposed" in resultado.stdout.lower()


def test_cli_nuclei_analizar_fuera_de_alcance_falla(runner):
    from eurabyte_security.cli.app import app

    runner.invoke(app, ["proyecto", "crear", "cli-nuclei"])
    resultado = runner.invoke(
        app, ["nuclei", "analizar", "127.0.0.1", "--plantillas", "exposed-env-file"]
    )
    assert resultado.exit_code != 0


def test_cli_nuclei_analizar_plantilla_no_aprobada_falla(runner, monkeypatch):
    from eurabyte_security.cli.app import app

    _instalar_nuclei_falso(monkeypatch)
    runner.invoke(app, ["proyecto", "crear", "cli-nuclei-plantilla"])
    runner.invoke(app, ["alcance", "agregar", "127.0.0.1/32"])

    resultado = runner.invoke(
        app, ["nuclei", "analizar", "127.0.0.1", "--plantillas", "ruta/arbitraria"]
    )
    assert resultado.exit_code != 0


def test_cli_nuclei_analizar_dentro_de_alcance(runner, monkeypatch):
    from eurabyte_security.cli.app import app

    _instalar_nuclei_falso(monkeypatch, jsonl=_linea_hallazgo() + "\n")
    runner.invoke(app, ["proyecto", "crear", "cli-nuclei-ok"])
    runner.invoke(app, ["alcance", "agregar", "127.0.0.1/32"])

    resultado = runner.invoke(
        app, ["nuclei", "analizar", "127.0.0.1", "--plantillas", "exposed-env-file"]
    )
    assert resultado.exit_code == 0
    assert "Hallazgos guardados: 1" in resultado.stdout


def test_cli_nuclei_resultados_y_revisar(runner, monkeypatch):
    from eurabyte_security.cli.app import app

    _instalar_nuclei_falso(monkeypatch, jsonl=_linea_hallazgo() + "\n")
    runner.invoke(app, ["proyecto", "crear", "cli-nuclei-resultados"])
    runner.invoke(app, ["alcance", "agregar", "127.0.0.1/32"])
    runner.invoke(app, ["nuclei", "analizar", "127.0.0.1", "--plantillas", "exposed-env-file"])

    resultado = runner.invoke(app, ["nuclei", "resultados"])
    assert resultado.exit_code == 0
    # La tabla Rich puede truncar columnas largas en una terminal angosta (como la
    # que usa CliRunner): se verifica el contenido real en la base de datos, no una
    # subcadena fragil contra la salida ya renderizada.
    base_datos = BaseDatos()
    proyecto = base_datos.obtener_proyecto_por_nombre("cli-nuclei-resultados")
    guardados = base_datos.listar_resultados_nuclei(proyecto.id)
    assert len(guardados) == 1
    assert guardados[0].plantilla_id == "exposed-env-file"
    assert guardados[0].estado_revision == "nuevo"

    revisar = runner.invoke(
        app, ["nuclei", "revisar", str(guardados[0].id), "--estado", "falso_positivo"]
    )
    assert revisar.exit_code == 0
    actualizado = base_datos.listar_resultados_nuclei(proyecto.id)[0]
    assert actualizado.estado_revision == "falso_positivo"


def test_cli_nuclei_revisar_estado_invalido(runner):
    from eurabyte_security.cli.app import app

    resultado = runner.invoke(app, ["nuclei", "revisar", "1", "--estado", "no-valido"])
    assert resultado.exit_code != 0


def test_cli_nuclei_reporte(runner, tmp_path, monkeypatch):
    from eurabyte_security.cli.app import app

    _instalar_nuclei_falso(monkeypatch, jsonl=_linea_hallazgo() + "\n")
    runner.invoke(app, ["proyecto", "crear", "cli-nuclei-reporte"])
    runner.invoke(app, ["alcance", "agregar", "127.0.0.1/32"])
    runner.invoke(app, ["nuclei", "analizar", "127.0.0.1", "--plantillas", "exposed-env-file"])

    salida = tmp_path / "informe-cli.json"
    resultado = runner.invoke(
        app, ["nuclei", "reporte", "--formato", "json", "--salida", str(salida)]
    )
    assert resultado.exit_code == 0
    assert salida.exists()


def test_cli_explicar_nuclei():
    from typer.testing import CliRunner

    from eurabyte_security.cli.app import app

    resultado = CliRunner().invoke(app, ["explicar", "nuclei"])
    assert resultado.exit_code == 0
    assert "catalogo" in resultado.stdout.lower() or "catalog" in resultado.stdout.lower()
