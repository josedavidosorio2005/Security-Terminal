"""Pruebas de persistencia OSINT (``storage/database.py``)."""

from __future__ import annotations

import pytest

from eurabyte_security.core.errores import ErrorInvestigacionOSINTNoEncontrada
from eurabyte_security.storage.database import BaseDatos


def _hallazgo(titulo: str = "Hallazgo de prueba") -> dict:
    return {
        "categoria": "dns",
        "titulo": titulo,
        "descripcion": "Descripcion de prueba.",
        "nivel_confianza": "confirmado",
        "indicador_exposicion": None,
        "evidencias": [
            {
                "fuente": "dns",
                "fecha_consulta": "2026-01-01T00:00:00+00:00",
                "referencia": None,
                "valor": "x",
            }
        ],
    }


def test_crear_y_obtener_investigacion_osint(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = base_datos.crear_proyecto("laboratorio")
    investigacion = base_datos.crear_investigacion_osint(
        proyecto.id, "dominio", "Ejemplo.com", "ejemplo.com", False, ["dns", "rdap_dominio"]
    )
    assert investigacion.estado_general == "ejecutando"
    assert investigacion.autorizado_datos_personales is False

    obtenida = base_datos.obtener_investigacion_osint(investigacion.id)
    assert obtenida.objetivo_saneado == "ejemplo.com"


def test_obtener_investigacion_inexistente_falla(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    with pytest.raises(ErrorInvestigacionOSINTNoEncontrada):
        base_datos.obtener_investigacion_osint(999)


def test_actualizar_investigacion_osint_conserva_campos_no_indicados(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = base_datos.crear_proyecto("laboratorio")
    investigacion = base_datos.crear_investigacion_osint(
        proyecto.id, "dominio", "ejemplo.com", "ejemplo.com", False, ["dns"]
    )
    base_datos.actualizar_investigacion_osint(investigacion.id, limitaciones=["una limitacion"])
    actualizada = base_datos.actualizar_investigacion_osint(
        investigacion.id, estado_general="completada"
    )

    assert actualizada.estado_general == "completada"
    assert "una limitacion" in actualizada.limitaciones_json


def test_agregar_y_listar_hallazgos_osint(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = base_datos.crear_proyecto("laboratorio")
    investigacion = base_datos.crear_investigacion_osint(
        proyecto.id, "dominio", "ejemplo.com", "ejemplo.com", False, ["dns"]
    )
    guardados = base_datos.agregar_hallazgos_osint(
        investigacion.id, proyecto.id, "dns", [_hallazgo("A"), _hallazgo("B")]
    )
    assert len(guardados) == 2

    por_investigacion = base_datos.listar_hallazgos_osint(investigacion_id=investigacion.id)
    assert len(por_investigacion) == 2

    por_proyecto = base_datos.listar_hallazgos_osint(proyecto_id=proyecto.id)
    assert len(por_proyecto) == 2


def test_listar_investigaciones_osint_filtra_por_proyecto(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto_a = base_datos.crear_proyecto("alfa")
    proyecto_b = base_datos.crear_proyecto("beta")
    base_datos.crear_investigacion_osint(proyecto_a.id, "dominio", "a.com", "a.com", False, [])
    base_datos.crear_investigacion_osint(proyecto_b.id, "dominio", "b.com", "b.com", False, [])

    solo_a = base_datos.listar_investigaciones_osint(proyecto_a.id)
    assert len(solo_a) == 1
    assert solo_a[0].objetivo_saneado == "a.com"


def test_eliminar_investigacion_osint_borra_hallazgos_asociados(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = base_datos.crear_proyecto("laboratorio")
    investigacion = base_datos.crear_investigacion_osint(
        proyecto.id, "dominio", "ejemplo.com", "ejemplo.com", False, ["dns"]
    )
    base_datos.agregar_hallazgos_osint(investigacion.id, proyecto.id, "dns", [_hallazgo()])

    base_datos.eliminar_investigacion_osint(investigacion.id)

    with pytest.raises(ErrorInvestigacionOSINTNoEncontrada):
        base_datos.obtener_investigacion_osint(investigacion.id)
    assert base_datos.listar_hallazgos_osint(investigacion_id=investigacion.id) == []


def test_eliminar_investigacion_inexistente_falla(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    with pytest.raises(ErrorInvestigacionOSINTNoEncontrada):
        base_datos.eliminar_investigacion_osint(999)
