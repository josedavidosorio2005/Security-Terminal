"""Pruebas del informe OSINT (``modules/reporting/generador.py``)."""

from __future__ import annotations

import json

from eurabyte_security.modules.reporting.generador import (
    construir_datos_informe_osint,
    generar_html_osint,
    generar_json_osint,
)
from eurabyte_security.storage.database import BaseDatos


def _hallazgo(categoria="dns", titulo="H", indicador=None):
    return {
        "categoria": categoria,
        "titulo": titulo,
        "descripcion": "descripcion de prueba",
        "nivel_confianza": "confirmado",
        "indicador_exposicion": indicador,
        "evidencias": [
            {
                "fuente": categoria,
                "fecha_consulta": "2026-01-01T00:00:00+00:00",
                "referencia": None,
                "valor": "x",
            }
        ],
    }


def _preparar_investigacion(tmp_path, *, tipo="dominio", objetivo="ejemplo.com", autorizado=False):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = base_datos.crear_proyecto("laboratorio")
    investigacion = base_datos.crear_investigacion_osint(
        proyecto.id, tipo, objetivo, objetivo, autorizado, ["dns"]
    )
    base_datos.actualizar_investigacion_osint(
        investigacion.id,
        etapas=[{"fuente": "dns", "estado": "completada", "detalle": "1 hallazgo(s)."}],
        limitaciones=["Una limitacion de ejemplo."],
    )
    return base_datos, proyecto, base_datos.obtener_investigacion_osint(investigacion.id)


def test_construir_datos_informe_sin_minimizar(tmp_path):
    base_datos, proyecto, investigacion = _preparar_investigacion(
        tmp_path, tipo="correo", objetivo="usuario@ejemplo.com", autorizado=True
    )
    base_datos.agregar_hallazgos_osint(
        investigacion.id, proyecto.id, "dns", [_hallazgo(categoria="correo", indicador="Sin SPF")]
    )
    hallazgos = base_datos.listar_hallazgos_osint(investigacion_id=investigacion.id)

    datos = construir_datos_informe_osint(proyecto.nombre, investigacion, hallazgos)

    assert datos.objetivo_mostrado == "usuario@ejemplo.com"
    assert datos.autorizado_datos_personales is True
    assert datos.fuentes_utilizadas == ("dns",)
    assert datos.limitaciones == ("Una limitacion de ejemplo.",)
    assert datos.resumen_exposicion.total_indicadores == 1
    assert any("SPF" in r for r in datos.recomendaciones)


def test_construir_datos_informe_minimiza_correo(tmp_path):
    base_datos, proyecto, investigacion = _preparar_investigacion(
        tmp_path, tipo="correo", objetivo="usuario@ejemplo.com", autorizado=True
    )
    hallazgos = base_datos.listar_hallazgos_osint(investigacion_id=investigacion.id)

    datos = construir_datos_informe_osint(proyecto.nombre, investigacion, hallazgos, minimizar=True)

    assert datos.objetivo_mostrado != "usuario@ejemplo.com"
    assert datos.objetivo_mostrado.endswith("@ejemplo.com")


def test_construir_datos_informe_dominio_nunca_se_minimiza(tmp_path):
    base_datos, proyecto, investigacion = _preparar_investigacion(tmp_path, tipo="dominio")
    hallazgos = base_datos.listar_hallazgos_osint(investigacion_id=investigacion.id)

    datos = construir_datos_informe_osint(proyecto.nombre, investigacion, hallazgos, minimizar=True)

    assert datos.objetivo_mostrado == "ejemplo.com"


def test_generar_json_osint_contiene_hallazgos_y_resumen(tmp_path):
    base_datos, proyecto, investigacion = _preparar_investigacion(tmp_path)
    base_datos.agregar_hallazgos_osint(
        investigacion.id, proyecto.id, "dns", [_hallazgo(titulo="Registros A")]
    )
    hallazgos = base_datos.listar_hallazgos_osint(investigacion_id=investigacion.id)
    datos = construir_datos_informe_osint(proyecto.nombre, investigacion, hallazgos)

    cuerpo = json.loads(generar_json_osint(datos))
    assert cuerpo["proyecto"] == proyecto.nombre
    assert cuerpo["tipo_objetivo"] == "dominio"
    assert cuerpo["hallazgos"][0]["titulo"] == "Registros A"
    assert cuerpo["resumen_exposicion"]["total_hallazgos"] == 1


def test_generar_html_osint_escapa_contenido_hostil(tmp_path):
    base_datos, proyecto, investigacion = _preparar_investigacion(tmp_path)
    base_datos.agregar_hallazgos_osint(
        investigacion.id,
        proyecto.id,
        "dns",
        [_hallazgo(titulo="<script>alert(1)</script>")],
    )
    hallazgos = base_datos.listar_hallazgos_osint(investigacion_id=investigacion.id)
    datos = construir_datos_informe_osint(proyecto.nombre, investigacion, hallazgos)

    html = generar_html_osint(datos)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_generar_html_osint_sin_hallazgos_muestra_mensaje(tmp_path):
    _base_datos, proyecto, investigacion = _preparar_investigacion(tmp_path)
    datos = construir_datos_informe_osint(proyecto.nombre, investigacion, [])

    html = generar_html_osint(datos)
    assert "No hay hallazgos OSINT registrados" in html
    assert "Sin indicadores de exposicion" in html


def test_minimizar_tambien_oculta_el_objetivo_dentro_de_cada_hallazgo(tmp_path):
    """Regresion: --minimizar debe ocultar el objetivo en TODO el texto de cada
    hallazgo (titulo, descripcion, evidencia), no solo en el campo 'objetivo'
    superior del informe -- un hallazgo de perfil publico repite el nombre de
    usuario investigado en su titulo y en la URL de evidencia."""
    base_datos, proyecto, investigacion = _preparar_investigacion(
        tmp_path, tipo="usuario", objetivo="torvalds", autorizado=True
    )
    base_datos.agregar_hallazgos_osint(
        investigacion.id,
        proyecto.id,
        "perfiles_publicos",
        [
            {
                "categoria": "perfil_publico",
                "titulo": "Coincidencia en GitHub",
                "descripcion": (
                    "Perfil publico de GitHub: https://github.com/torvalds. "
                    "Coincidencia de nombre de usuario, no una identidad confirmada."
                ),
                "nivel_confianza": "probable",
                "indicador_exposicion": None,
                "evidencias": [
                    {
                        "fuente": "perfiles_publicos",
                        "fecha_consulta": "2026-01-01T00:00:00+00:00",
                        "referencia": "https://github.com/torvalds",
                        "valor": "torvalds",
                    }
                ],
            }
        ],
    )
    hallazgos = base_datos.listar_hallazgos_osint(investigacion_id=investigacion.id)

    datos = construir_datos_informe_osint(proyecto.nombre, investigacion, hallazgos, minimizar=True)

    assert datos.objetivo_mostrado != "torvalds"
    hallazgo = datos.hallazgos[0]
    assert "torvalds" not in hallazgo.titulo
    assert "torvalds" not in hallazgo.descripcion
    assert "torvalds" not in hallazgo.evidencias_json

    # Tambien no debe aparecer en ninguna de las dos exportaciones completas.
    cuerpo_json = generar_json_osint(datos)
    assert "torvalds" not in cuerpo_json
    html = generar_html_osint(datos)
    assert "torvalds" not in html


def test_minimizar_es_insensible_a_mayusculas(tmp_path):
    base_datos, proyecto, investigacion = _preparar_investigacion(
        tmp_path, tipo="usuario", objetivo="torvalds", autorizado=True
    )
    base_datos.agregar_hallazgos_osint(
        investigacion.id,
        proyecto.id,
        "perfiles_publicos",
        [_hallazgo(categoria="perfil_publico", titulo="Perfil de Torvalds encontrado")],
    )
    hallazgos = base_datos.listar_hallazgos_osint(investigacion_id=investigacion.id)

    datos = construir_datos_informe_osint(proyecto.nombre, investigacion, hallazgos, minimizar=True)

    assert "torvalds" not in datos.hallazgos[0].titulo.lower()


def test_minimizar_tambien_oculta_el_objetivo_en_limitaciones(tmp_path):
    base_datos, proyecto, investigacion = _preparar_investigacion(
        tmp_path, tipo="correo", objetivo="usuario@ejemplo.com", autorizado=True
    )
    base_datos.actualizar_investigacion_osint(
        investigacion.id,
        limitaciones=["hibp: 'usuario@ejemplo.com' fallo con un error inesperado."],
    )
    investigacion = base_datos.obtener_investigacion_osint(investigacion.id)

    datos = construir_datos_informe_osint(proyecto.nombre, investigacion, [], minimizar=True)

    assert "usuario@ejemplo.com" not in datos.limitaciones[0]


def test_minimizar_cubre_el_objetivo_codificado_para_url(tmp_path):
    base_datos, proyecto, investigacion = _preparar_investigacion(
        tmp_path, tipo="correo", objetivo="usuario@ejemplo.com", autorizado=True
    )
    codificado = "usuario%40ejemplo.com"
    base_datos.actualizar_investigacion_osint(
        investigacion.id,
        limitaciones=[
            f"hibp: 'https://haveibeenpwned.com/api/v3/breachedaccount/{codificado}' "
            "respondio con el codigo HTTP 500."
        ],
    )
    investigacion = base_datos.obtener_investigacion_osint(investigacion.id)

    datos = construir_datos_informe_osint(proyecto.nombre, investigacion, [], minimizar=True)

    assert codificado not in datos.limitaciones[0]
    assert "usuario@ejemplo.com" not in datos.limitaciones[0]
