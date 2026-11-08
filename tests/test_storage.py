from __future__ import annotations

import json

import pytest

from eurabyte_security.core.errores import (
    ErrorProyectoDuplicado,
    ErrorProyectoNoEncontrado,
    ErrorSesionReconocimientoNoEncontrada,
)
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


# -- Sesiones de reconocimiento automatico --------------------------------------


def test_crear_sesion_reconocimiento_inicia_en_ejecutando(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = base_datos.crear_proyecto("laboratorio")
    sesion = base_datos.crear_sesion_reconocimiento(proyecto.id, "127.0.0.1", "rapido")

    assert sesion.proyecto_id == proyecto.id
    assert sesion.objetivo_original == "127.0.0.1"
    assert sesion.perfil == "rapido"
    assert sesion.estado_general == "ejecutando"
    assert sesion.nombre_host is None
    assert sesion.ip is None
    assert sesion.etapas_json == "[]"
    assert sesion.limitaciones_json == "[]"


def test_actualizar_sesion_reconocimiento_solo_cambia_los_campos_indicados(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = base_datos.crear_proyecto("laboratorio")
    sesion = base_datos.crear_sesion_reconocimiento(proyecto.id, "127.0.0.1", "rapido")

    actualizada = base_datos.actualizar_sesion_reconocimiento(sesion.id, ip="127.0.0.1")
    assert actualizada.ip == "127.0.0.1"
    assert actualizada.estado_general == "ejecutando"  # sin cambios

    actualizada = base_datos.actualizar_sesion_reconocimiento(
        sesion.id,
        estado_general="completada",
        etapas=[{"nombre": "verificacion", "estado": "completada", "detalle": "ok"}],
        limitaciones=["algo no estaba disponible"],
    )
    assert actualizada.estado_general == "completada"
    assert actualizada.ip == "127.0.0.1"  # se conserva, no se pidio cambiarlo
    assert json.loads(actualizada.etapas_json) == [
        {"nombre": "verificacion", "estado": "completada", "detalle": "ok"}
    ]
    assert json.loads(actualizada.limitaciones_json) == ["algo no estaba disponible"]


def test_obtener_sesion_reconocimiento_inexistente_falla(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    with pytest.raises(ErrorSesionReconocimientoNoEncontrada):
        base_datos.obtener_sesion_reconocimiento(999)


def test_listar_sesiones_reconocimiento_separa_por_proyecto(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto_a = base_datos.crear_proyecto("a")
    proyecto_b = base_datos.crear_proyecto("b")
    base_datos.crear_sesion_reconocimiento(proyecto_a.id, "127.0.0.1", "rapido")
    base_datos.crear_sesion_reconocimiento(proyecto_a.id, "127.0.0.2", "rapido")
    base_datos.crear_sesion_reconocimiento(proyecto_b.id, "10.0.0.1", "rapido")

    assert len(base_datos.listar_sesiones_reconocimiento(proyecto_a.id)) == 2
    assert len(base_datos.listar_sesiones_reconocimiento(proyecto_b.id)) == 1


def test_listar_sesiones_reconocimiento_orden_mas_reciente_primero(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = base_datos.crear_proyecto("laboratorio")
    primera = base_datos.crear_sesion_reconocimiento(proyecto.id, "127.0.0.1", "rapido")
    segunda = base_datos.crear_sesion_reconocimiento(proyecto.id, "127.0.0.2", "rapido")

    sesiones = base_datos.listar_sesiones_reconocimiento(proyecto.id)
    assert sesiones[0].id == segunda.id
    assert sesiones[1].id == primera.id
