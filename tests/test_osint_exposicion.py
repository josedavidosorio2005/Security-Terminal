"""Pruebas de ``modules/osint/exposicion.py`` (resumen de indicadores de exposicion)."""

from __future__ import annotations

from eurabyte_security.modules.osint.exposicion import construir_resumen_exposicion
from eurabyte_security.storage.database import BaseDatos


def _hallazgo(titulo="H", indicador=None):
    return {
        "categoria": "dns",
        "titulo": titulo,
        "descripcion": "d",
        "nivel_confianza": "confirmado",
        "indicador_exposicion": indicador,
        "evidencias": [],
    }


def test_resumen_sin_indicadores(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = base_datos.crear_proyecto("laboratorio")
    investigacion = base_datos.crear_investigacion_osint(
        proyecto.id, "dominio", "ejemplo.com", "ejemplo.com", False, []
    )
    base_datos.agregar_hallazgos_osint(
        investigacion.id, proyecto.id, "dns", [_hallazgo("A"), _hallazgo("B")]
    )
    guardados = base_datos.listar_hallazgos_osint(investigacion_id=investigacion.id)

    resumen = construir_resumen_exposicion(guardados)
    assert resumen.total_hallazgos == 2
    assert resumen.total_indicadores == 0
    assert resumen.fuentes_con_indicador == ()
    assert resumen.indicadores == ()


def test_resumen_con_indicadores_de_varias_fuentes(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = base_datos.crear_proyecto("laboratorio")
    investigacion = base_datos.crear_investigacion_osint(
        proyecto.id, "correo", "usuario@ejemplo.com", "usuario@ejemplo.com", True, []
    )
    base_datos.agregar_hallazgos_osint(
        investigacion.id, proyecto.id, "dns", [_hallazgo("SPF ausente", "sin SPF")]
    )
    base_datos.agregar_hallazgos_osint(
        investigacion.id, proyecto.id, "hibp", [_hallazgo("Brecha", "correo en brecha")]
    )
    guardados = base_datos.listar_hallazgos_osint(investigacion_id=investigacion.id)

    resumen = construir_resumen_exposicion(guardados)
    assert resumen.total_hallazgos == 2
    assert resumen.total_indicadores == 2
    assert resumen.fuentes_con_indicador == ("dns", "hibp")
    assert set(resumen.indicadores) == {"sin SPF", "correo en brecha"}
