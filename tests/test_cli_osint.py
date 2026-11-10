"""Pruebas de la CLI de OSINT (``est osint ...``).

El motor (``ejecutar_investigacion_osint``) se sustituye por un doble: estas pruebas
verifican el cableado de la CLI (parseo de argumentos, autorizacion, salida), no las
fuentes externas (ya cubiertas en ``test_osint_motor.py`` y
``test_osint_integraciones*.py``). Ninguna prueba toca una red de terceros.
"""

from __future__ import annotations

from eurabyte_security import commands
from eurabyte_security.cli.app import app
from eurabyte_security.modules.osint.modelos import EtapaFuenteOSINT, ResultadoInvestigacionOSINT


def _resultado_falso(investigacion_id=1, total_hallazgos=0, limitaciones=()):
    return ResultadoInvestigacionOSINT(
        investigacion_id=investigacion_id,
        tipo_objetivo="dominio",
        objetivo_original="ejemplo.com",
        objetivo_saneado="ejemplo.com",
        estado_general="completada",
        etapas=(EtapaFuenteOSINT("dns", "completada", "1 hallazgo(s)."),),
        limitaciones=tuple(limitaciones),
        total_hallazgos=total_hallazgos,
    )


def _preparar_proyecto(runner, nombre="laboratorio"):
    runner.invoke(app, ["proyecto", "crear", nombre])


def test_osint_dominio_ejecuta_y_muestra_resumen(runner, monkeypatch):
    _preparar_proyecto(runner)
    monkeypatch.setattr(
        commands.osint, "ejecutar_investigacion_osint", lambda *_a, **_k: _resultado_falso()
    )
    resultado = runner.invoke(app, ["osint", "dominio", "ejemplo.com"])
    assert resultado.exit_code == 0
    assert "Investigacion OSINT #1" in resultado.stdout


def test_osint_correo_sin_autorizar_falla(runner):
    _preparar_proyecto(runner)
    resultado = runner.invoke(app, ["osint", "correo", "usuario@ejemplo.com"])
    assert resultado.exit_code != 0


def test_osint_correo_autorizado_ejecuta(runner, monkeypatch):
    _preparar_proyecto(runner)
    recibido = {}

    def _fake(_base_datos, _proyecto, tipo, objetivo, **kwargs):
        recibido["tipo"] = tipo
        recibido["objetivo"] = objetivo
        recibido["autorizado"] = kwargs["autorizado_datos_personales"]
        return _resultado_falso()

    monkeypatch.setattr(commands.osint, "ejecutar_investigacion_osint", _fake)
    resultado = runner.invoke(
        app, ["osint", "correo", "usuario@ejemplo.com", "--autorizo"]
    )
    assert resultado.exit_code == 0
    assert recibido["tipo"] == "correo"
    assert recibido["autorizado"] is True


def test_osint_telefono_sin_autorizar_falla(runner):
    _preparar_proyecto(runner)
    resultado = runner.invoke(app, ["osint", "telefono", "+573001234567"])
    assert resultado.exit_code != 0


def test_osint_usuario_sin_autorizar_falla(runner):
    _preparar_proyecto(runner)
    resultado = runner.invoke(app, ["osint", "usuario", "alguien"])
    assert resultado.exit_code != 0


def test_osint_fuentes_lista_catalogo(runner):
    resultado = runner.invoke(app, ["osint", "fuentes"])
    assert resultado.exit_code == 0
    assert "dns" in resultado.stdout


def test_osint_fuentes_filtra_por_tipo(runner):
    resultado = runner.invoke(app, ["osint", "fuentes", "--tipo", "usuario"])
    assert resultado.exit_code == 0
    assert "perfiles_publicos" in resultado.stdout
    assert "certificados" not in resultado.stdout


def test_osint_investigaciones_y_resultados_vacios(runner):
    _preparar_proyecto(runner)
    resultado = runner.invoke(app, ["osint", "investigaciones"])
    assert resultado.exit_code == 0
    assert "no tiene investigaciones" in resultado.stdout

    resultado = runner.invoke(app, ["osint", "resultados"])
    assert resultado.exit_code == 0
    assert "No hay hallazgos" in resultado.stdout


def test_osint_eliminar_sin_confirmar_no_borra(runner):
    from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto

    _preparar_proyecto(runner)
    base_datos = obtener_base_datos()
    proyecto = resolver_proyecto(base_datos, None)
    investigacion = base_datos.crear_investigacion_osint(
        proyecto.id, "dominio", "ejemplo.com", "ejemplo.com", False, []
    )

    resultado = runner.invoke(app, ["osint", "eliminar", str(investigacion.id)])
    assert resultado.exit_code != 0

    resultado = runner.invoke(app, ["osint", "investigaciones"])
    assert "no tiene investigaciones" not in resultado.stdout


def test_osint_eliminar_investigacion_inexistente_falla(runner):
    resultado = runner.invoke(app, ["osint", "eliminar", "999", "--confirmar"])
    assert resultado.exit_code != 0
