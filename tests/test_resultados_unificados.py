"""Pruebas del motor de resultados/informes unificado (las cinco herramientas).

Todas usan datos simulados insertados directamente en la base de datos (igual que
``tests/test_storage.py``): ninguna requiere Nmap, Nuclei ni OWASP ZAP instalados, ni
toca una red de terceros.
"""

from __future__ import annotations

import json

from eurabyte_security.cli.app import app
from eurabyte_security.commands._comun import obtener_base_datos
from eurabyte_security.commands.reporte import generar_reporte
from eurabyte_security.commands.resultados import obtener_resultados_unificados
from eurabyte_security.core.errores import ErrorValidacion
from eurabyte_security.storage.database import BaseDatos


def _proyecto_con_las_cinco_fuentes(base_datos: BaseDatos, nombre: str = "laboratorio"):
    proyecto = base_datos.crear_proyecto(nombre)
    base_datos.agregar_resultado(proyecto.id, "127.0.0.1", 22, "abierto")
    base_datos.agregar_resultados_nmap(
        proyecto.id, "127.0.0.1", [(80, "tcp", "open", "http", "1.0")]
    )
    base_datos.agregar_resultados_web(
        proyecto.id,
        "https://127.0.0.1/",
        "cabeceras",
        [
            (
                "cabeceras",
                "Falta Strict-Transport-Security",
                "alta",
                "detectado",
                None,
                "Permite downgrade a HTTP",
                "Agrega la cabecera HSTS",
                "https://owasp.org/",
            )
        ],
    )
    base_datos.agregar_resultados_nuclei(
        proyecto.id,
        "127.0.0.1",
        [("CVE-2021-0001", "v1", "Falta Strict-Transport-Security", "high", "desc", "ev")],
    )
    base_datos.agregar_resultados_zap(
        proyecto.id,
        "http://127.0.0.1/",
        [
            (
                "10035",
                "Falta Strict-Transport-Security",
                "High",
                "High",
                "desc",
                "ev",
                "Agrega HSTS",
                "https://owasp.org/",
            )
        ],
    )
    return proyecto


# -- Unificacion de las cinco fuentes ------------------------------------


def test_unifica_las_cinco_fuentes(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_las_cinco_fuentes(base_datos)

    resultados = base_datos.listar_resultados_unificados(proyecto.id)
    assert {r.fuente for r in resultados} == {"tcp", "nmap", "web", "nuclei", "zap"}
    assert len(resultados) == 5


def test_tcp_y_nmap_nunca_tienen_severidad_fabricada(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_las_cinco_fuentes(base_datos)

    resultados = base_datos.listar_resultados_unificados(proyecto.id)
    por_fuente = {r.fuente: r for r in resultados}
    assert por_fuente["tcp"].severidad is None
    assert por_fuente["nmap"].severidad is None
    assert por_fuente["web"].severidad is not None
    assert por_fuente["nuclei"].severidad is not None
    assert por_fuente["zap"].severidad is not None


def test_persistencia_de_datos_previos_no_se_pierde(tmp_path):
    """Agregar hallazgos nuevos no borra ni migra los que ya existian por herramienta."""
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_las_cinco_fuentes(base_datos)

    assert len(base_datos.listar_resultados(proyecto.id)) == 1
    assert len(base_datos.listar_resultados_nmap(proyecto.id)) == 1
    assert len(base_datos.listar_resultados_web(proyecto.id)) == 1
    assert len(base_datos.listar_resultados_nuclei(proyecto.id)) == 1
    assert len(base_datos.listar_resultados_zap(proyecto.id)) == 1


# -- Filtros y orden ------------------------------------------------------


def test_filtro_por_fuente(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_las_cinco_fuentes(base_datos)

    resultados = base_datos.listar_resultados_unificados(proyecto.id, fuentes=frozenset({"nuclei"}))
    assert {r.fuente for r in resultados} == {"nuclei"}


def test_filtro_por_severidad_agrupa_equivalentes_entre_herramientas(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_las_cinco_fuentes(base_datos)

    # web usa 'alta', nuclei usa 'high', zap usa 'High': las tres deben agruparse.
    resultados = base_datos.listar_resultados_unificados(proyecto.id, severidad="alta")
    assert {r.fuente for r in resultados} == {"web", "nuclei", "zap"}


def test_filtro_por_estado_revision(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_las_cinco_fuentes(base_datos)
    hallazgo_nuclei = base_datos.listar_resultados_nuclei(proyecto.id)[0]
    base_datos.actualizar_estado_revision_nuclei(hallazgo_nuclei.id, "confirmado")

    resultados = base_datos.listar_resultados_unificados(proyecto.id, estado="confirmado")
    assert len(resultados) == 1
    assert resultados[0].fuente == "nuclei"
    assert resultados[0].estado_revision == "confirmado"


def test_filtro_por_estado_de_puerto(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = base_datos.crear_proyecto("laboratorio")
    base_datos.agregar_resultado(proyecto.id, "127.0.0.1", 22, "abierto")
    base_datos.agregar_resultado(proyecto.id, "127.0.0.1", 81, "cerrado")

    resultados = base_datos.listar_resultados_unificados(proyecto.id, estado="abierto")
    assert len(resultados) == 1
    assert resultados[0].estado == "abierto"


def test_filtro_por_fecha_desde_y_hasta(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_las_cinco_fuentes(base_datos)

    assert base_datos.listar_resultados_unificados(proyecto.id, desde="2999-01-01") == []
    assert base_datos.listar_resultados_unificados(proyecto.id, hasta="2000-01-01") == []
    assert len(
        base_datos.listar_resultados_unificados(
            proyecto.id, desde="2000-01-01", hasta="2999-01-01"
        )
    ) == 5


def test_orden_estable_mas_reciente_primero(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_las_cinco_fuentes(base_datos)

    resultados = base_datos.listar_resultados_unificados(proyecto.id)
    assert resultados == sorted(resultados, key=lambda r: r.creado_en, reverse=True)


def test_limite_se_aplica_despues_de_filtrar(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = base_datos.crear_proyecto("laboratorio")
    for puerto in (10, 11, 12):
        base_datos.agregar_resultado(proyecto.id, "127.0.0.1", puerto, "abierto")
    base_datos.agregar_resultado(proyecto.id, "127.0.0.1", 13, "cerrado")

    resultados = base_datos.listar_resultados_unificados(
        proyecto.id, estado="abierto", limite=2
    )
    assert len(resultados) == 2
    assert all(r.estado == "abierto" for r in resultados)


# -- Separacion de proyectos ----------------------------------------------


def test_separacion_de_proyectos(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto_a = _proyecto_con_las_cinco_fuentes(base_datos, "proyecto-a")
    proyecto_b = base_datos.crear_proyecto("proyecto-b")
    base_datos.agregar_resultado(proyecto_b.id, "10.0.0.5", 443, "abierto")

    resultados_a = base_datos.listar_resultados_unificados(proyecto_a.id)
    resultados_b = base_datos.listar_resultados_unificados(proyecto_b.id)

    assert len(resultados_a) == 5
    assert len(resultados_b) == 1
    assert all(r.objetivo == "127.0.0.1" or r.proyecto_id == proyecto_a.id for r in resultados_a)
    assert resultados_b[0].proyecto_id == proyecto_b.id


# -- Hallazgos con el mismo titulo en distintas herramientas: nunca se fusionan ----


def test_hallazgos_con_mismo_titulo_en_distintas_herramientas_no_se_fusionan(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_las_cinco_fuentes(base_datos)

    # web, nuclei y zap comparten el mismo 'nombre_hallazgo' ("Falta Strict-...") en la
    # fixture: deben seguir apareciendo como TRES registros distintos, nunca como uno.
    resultados = base_datos.listar_resultados_unificados(proyecto.id)
    mismo_titulo = [r for r in resultados if r.nombre == "Falta Strict-Transport-Security"]
    assert len(mismo_titulo) == 3
    identificadores = {(r.fuente, r.id_origen) for r in mismo_titulo}
    assert len(identificadores) == 3


# -- commands/resultados.py: validacion y wrapper -------------------------


def test_obtener_resultados_unificados_rechaza_fuente_invalida(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_las_cinco_fuentes(base_datos)

    try:
        obtener_resultados_unificados(base_datos, proyecto, fuentes=frozenset({"ftp"}))
    except ErrorValidacion:
        pass
    else:
        raise AssertionError("Deberia haber rechazado una fuente desconocida.")


# -- CLI: 'est resultados' unificado y compatibilidad con comandos por herramienta --


def _preparar_cli(runner) -> None:
    runner.invoke(app, ["proyecto", "crear", "laboratorio"])
    runner.invoke(app, ["alcance", "agregar", "127.0.0.1/32"])


def test_cli_resultados_muestra_las_cinco_fuentes(runner):
    _preparar_cli(runner)
    base_datos = obtener_base_datos()
    proyecto = base_datos.obtener_proyecto_por_nombre("laboratorio")
    base_datos.agregar_resultado(proyecto.id, "127.0.0.1", 22, "abierto")
    base_datos.agregar_resultados_nmap(
        proyecto.id, "127.0.0.1", [(80, "tcp", "open", "http", None)]
    )
    base_datos.agregar_resultados_nuclei(
        proyecto.id, "127.0.0.1", [("CVE-2021-0001", "v1", "Hallazgo X", "high", "d", None)]
    )

    resultado = runner.invoke(app, ["resultados"])
    assert resultado.exit_code == 0
    assert "TCP" in resultado.stdout
    assert "Nmap" in resultado.stdout
    assert "Nuclei" in resultado.stdout


def test_cli_resultados_filtra_por_fuente(runner):
    # La tabla Rich puede envolver columnas largas en una terminal angosta (como la que
    # usa CliRunner): se verifica el filtrado via la funcion subyacente, no una
    # subcadena fragil contra la salida ya renderizada (ver
    # 'tests/test_integraciones_nuclei.py:test_cli_nuclei_resultados_y_revisar').
    _preparar_cli(runner)
    base_datos = obtener_base_datos()
    proyecto = base_datos.obtener_proyecto_por_nombre("laboratorio")
    base_datos.agregar_resultado(proyecto.id, "127.0.0.1", 22, "abierto")
    base_datos.agregar_resultados_nuclei(
        proyecto.id, "127.0.0.1", [("CVE-2021-0001", "v1", "Hallazgo X", "high", "d", None)]
    )

    resultado = runner.invoke(app, ["resultados", "--fuente", "nuclei"])
    assert resultado.exit_code == 0

    filtrados = obtener_resultados_unificados(
        base_datos, proyecto, fuentes=frozenset({"nuclei"})
    )
    assert len(filtrados) == 1
    assert filtrados[0].nombre == "Hallazgo X"


def test_cli_resultados_fuente_invalida_falla(runner):
    _preparar_cli(runner)
    resultado = runner.invoke(app, ["resultados", "--fuente", "ftp"])
    assert resultado.exit_code != 0


def test_cli_nuclei_resultados_sigue_funcionando(runner):
    _preparar_cli(runner)
    base_datos = obtener_base_datos()
    proyecto = base_datos.obtener_proyecto_por_nombre("laboratorio")
    base_datos.agregar_resultados_nuclei(
        proyecto.id, "127.0.0.1", [("CVE-2021-0001", "v1", "Hallazgo Nuclei", "high", "d", None)]
    )

    resultado = runner.invoke(app, ["nuclei", "resultados"])
    assert resultado.exit_code == 0
    guardados = base_datos.listar_resultados_nuclei(proyecto.id)
    assert len(guardados) == 1
    assert guardados[0].nombre_hallazgo == "Hallazgo Nuclei"


def test_cli_zap_resultados_sigue_funcionando(runner):
    _preparar_cli(runner)
    base_datos = obtener_base_datos()
    proyecto = base_datos.obtener_proyecto_por_nombre("laboratorio")
    base_datos.agregar_resultados_zap(
        proyecto.id,
        "http://127.0.0.1/",
        [("10020", "Hallazgo ZAP", "Medium", "High", "d", None, "s", "r")],
    )

    resultado = runner.invoke(app, ["zap", "resultados"])
    assert resultado.exit_code == 0
    guardados = base_datos.listar_resultados_zap(proyecto.id)
    assert len(guardados) == 1
    assert guardados[0].nombre_hallazgo == "Hallazgo ZAP"


# -- Informe global: JSON y HTML ------------------------------------------


def test_reporte_global_json(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_las_cinco_fuentes(base_datos)

    ruta = generar_reporte(base_datos, proyecto, "json", tmp_path / "informe.json")
    datos = json.loads(ruta.read_text(encoding="utf-8"))

    assert datos["proyecto"] == proyecto.nombre
    assert datos["total_resultados"] == 5
    assert set(datos["resumen_por_herramienta"].keys()) == {"tcp", "nmap", "web", "nuclei", "zap"}
    fuentes_en_resultados = {r["fuente"] for r in datos["resultados"]}
    assert fuentes_en_resultados == {"tcp", "nmap", "web", "nuclei", "zap"}
    # Los registros de red nunca llevan severidad fabricada en el informe tampoco.
    for r in datos["resultados"]:
        if r["fuente"] in ("tcp", "nmap"):
            assert r["severidad"] is None


def test_reporte_global_html_contiene_las_dos_tablas(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_las_cinco_fuentes(base_datos)

    ruta = generar_reporte(base_datos, proyecto, "html", tmp_path / "informe.html")
    contenido = ruta.read_text(encoding="utf-8")

    assert "<html" in contenido
    assert "Resultados de red y reconocimiento" in contenido
    assert "Hallazgos de vulnerabilidad" in contenido
    assert "Falta Strict-Transport-Security" in contenido


def test_reporte_global_escapa_html_en_campos_de_herramientas(tmp_path):
    """Un 'nombre_hallazgo' hostil nunca debe convertirse en HTML/script activo."""
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = base_datos.crear_proyecto("laboratorio")
    base_datos.agregar_resultados_web(
        proyecto.id,
        "https://127.0.0.1/",
        "cabeceras",
        [
            (
                "cabeceras",
                "<script>alert(1)</script>",
                "alta",
                "detectado",
                None,
                "r",
                "rec",
                "ref",
            )
        ],
    )

    ruta = generar_reporte(base_datos, proyecto, "html", tmp_path / "informe.html")
    contenido = ruta.read_text(encoding="utf-8")

    assert "<script>alert(1)</script>" not in contenido
    assert "&lt;script&gt;" in contenido


def test_reporte_global_redacta_secretos_en_texto_libre(tmp_path):
    """El informe global aplica su propia pasada de redaccion antes de exportar."""
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = base_datos.crear_proyecto("laboratorio")
    base_datos.agregar_resultados_nuclei(
        proyecto.id,
        "127.0.0.1",
        [
            (
                "CVE-2021-0001",
                "v1",
                "Hallazgo con secreto",
                "high",
                "d",
                "Authorization: Bearer secreto-super-confidencial",
            )
        ],
    )

    ruta = generar_reporte(base_datos, proyecto, "json", tmp_path / "informe.json")
    contenido = ruta.read_text(encoding="utf-8")

    assert "secreto-super-confidencial" not in contenido
    assert "<redactado>" in contenido


def test_reporte_formato_invalido_sigue_fallando(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = base_datos.crear_proyecto("laboratorio")
    try:
        generar_reporte(base_datos, proyecto, "xml")
    except ErrorValidacion:
        pass
    else:
        raise AssertionError("Deberia haber rechazado un formato no soportado.")
