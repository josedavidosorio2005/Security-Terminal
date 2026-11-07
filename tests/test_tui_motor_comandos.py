from __future__ import annotations

from eurabyte_security.commands._comun import obtener_base_datos
from eurabyte_security.commands.proyecto import crear_proyecto
from eurabyte_security.ui.tui.motor_comandos import MotorComandos, completar


def test_completar_unico_candidato_de_alto_nivel():
    assert completar("pro") == "proyecto "


def test_completar_sin_candidatos_devuelve_none():
    assert completar("xyz") is None


def test_completar_ambiguo_devuelve_none():
    # 'r' empata entre 'resultados' y 'reporte': no completa (igual que una shell).
    assert completar("r") is None


def test_completar_subnivel():
    assert completar("proyecto cr") == "proyecto crear "


def test_completar_texto_vacio_devuelve_none():
    assert completar("") is None


def test_completar_despues_de_espacio_final():
    assert completar("proyecto ") is None  # "crear", "listar", "usar" son ambiguos


def test_motor_ejecutar_vacio():
    resultado = MotorComandos().ejecutar("   ")
    assert resultado is not None
    assert resultado.exito


def test_motor_ejecutar_salir_devuelve_none():
    assert MotorComandos().ejecutar("salir") is None


def test_motor_comando_desconocido():
    resultado = MotorComandos().ejecutar("volar a la luna")
    assert resultado is not None
    assert not resultado.exito


def test_motor_proyecto_crear_y_listar():
    motor = MotorComandos()
    creado = motor.ejecutar("proyecto crear demo")
    assert creado is not None and creado.exito
    listado = motor.ejecutar("proyecto listar")
    assert listado is not None and listado.exito


def test_motor_alcance_sin_proyecto_activo_falla():
    resultado = MotorComandos().ejecutar("alcance agregar 127.0.0.1/32")
    assert resultado is not None
    assert not resultado.exito


def test_motor_alcance_agregar_y_listar():
    motor = MotorComandos()
    motor.ejecutar("proyecto crear demo")
    agregado = motor.ejecutar("alcance agregar 127.0.0.1/32")
    assert agregado is not None and agregado.exito
    listado = motor.ejecutar("alcance listar")
    assert listado is not None and listado.exito


def test_motor_escanear_fuera_de_alcance_rechazado():
    motor = MotorComandos()
    motor.ejecutar("proyecto crear demo")
    motor.ejecutar("alcance agregar 10.0.0.0/24")
    resultado = motor.ejecutar("escanear tcp 127.0.0.1 --puertos 80")
    assert resultado is not None
    assert not resultado.exito
    assert "alcance" in resultado.contenido.lower()


def test_motor_explicar_tema_conocido():
    resultado = MotorComandos().ejecutar("explicar tcp")
    assert resultado is not None and resultado.exito


def test_motor_explicar_tema_desconocido():
    resultado = MotorComandos().ejecutar("explicar no-existe")
    assert resultado is not None and resultado.exito
    assert "No hay una explicacion" in resultado.contenido


def test_motor_reporte_formato_invalido():
    motor = MotorComandos()
    motor.ejecutar("proyecto crear demo")
    resultado = motor.ejecutar("reporte generar --formato xml")
    assert resultado is not None
    assert not resultado.exito


def test_motor_comando_con_comillas_sin_cerrar_no_rompe():
    resultado = MotorComandos().ejecutar('proyecto crear "sin cerrar')
    assert resultado is not None
    assert not resultado.exito


def test_motor_reutiliza_base_de_datos_existente():
    base_datos = obtener_base_datos()
    crear_proyecto(base_datos, "preexistente")
    resultado = MotorComandos().ejecutar("proyecto listar")
    assert resultado is not None and resultado.exito
