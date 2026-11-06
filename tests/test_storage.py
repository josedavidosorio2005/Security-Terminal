from __future__ import annotations

import pytest

from eurabyte_security.core.errores import ErrorProyectoDuplicado, ErrorProyectoNoEncontrado
from eurabyte_security.storage.database import BaseDatos


def test_crear_y_obtener_proyecto(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = base_datos.crear_proyecto("laboratorio")

    assert proyecto.nombre == "laboratorio"
    assert base_datos.obtener_proyecto_por_nombre("laboratorio").id == proyecto.id


def test_crear_proyecto_duplicado_falla(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    base_datos.crear_proyecto("laboratorio")
    with pytest.raises(ErrorProyectoDuplicado):
        base_datos.crear_proyecto("laboratorio")


def test_obtener_proyecto_inexistente_falla(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    with pytest.raises(ErrorProyectoNoEncontrado):
        base_datos.obtener_proyecto_por_nombre("no-existe")


def test_listar_proyectos_orden_alfabetico(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    base_datos.crear_proyecto("zeta")
    base_datos.crear_proyecto("alfa")
    nombres = [p.nombre for p in base_datos.listar_proyectos()]
    assert nombres == ["alfa", "zeta"]


def test_agregar_alcance_es_idempotente(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = base_datos.crear_proyecto("laboratorio")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")
    assert len(base_datos.listar_alcance(proyecto.id)) == 1


def test_agregar_y_listar_resultados(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = base_datos.crear_proyecto("laboratorio")
    base_datos.agregar_resultado(proyecto.id, "127.0.0.1", 22, "abierto")
    base_datos.agregar_resultado(proyecto.id, "127.0.0.1", 80, "cerrado")

    resultados = base_datos.listar_resultados(proyecto.id)
    assert len(resultados) == 2
    assert {r.puerto for r in resultados} == {22, 80}


def test_listar_resultados_de_otro_proyecto_vacio(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto_a = base_datos.crear_proyecto("a")
    base_datos.crear_proyecto("b")
    base_datos.agregar_resultado(proyecto_a.id, "127.0.0.1", 22, "abierto")

    proyecto_b = base_datos.obtener_proyecto_por_nombre("b")
    assert base_datos.listar_resultados(proyecto_b.id) == []
