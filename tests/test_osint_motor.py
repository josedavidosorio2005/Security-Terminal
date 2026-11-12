"""Pruebas del orquestador OSINT (``modules/osint/motor.py``).

Las fuentes reales se sustituyen por adaptadores de prueba (ver ``_FuenteFalsa``):
ninguna prueba consulta DNS, RDAP ni ninguna API externa real.
"""

from __future__ import annotations

import pytest

from eurabyte_security.core.errores import (
    ErrorAutorizacionOSINTRequerida,
    ErrorFuenteOSINTError,
    ErrorFuenteOSINTNoDisponible,
    ErrorInvestigacionOSINTCancelada,
    ErrorValidacion,
)
from eurabyte_security.integrations.osint.base import AdaptadorFuenteOSINT
from eurabyte_security.modules.osint import motor
from eurabyte_security.modules.osint.modelos import EvidenciaOSINT, HallazgoOSINT
from eurabyte_security.storage.database import BaseDatos


class _FuenteFalsa(AdaptadorFuenteOSINT):
    def __init__(
        self,
        id_fuente,
        *,
        configurada=True,
        hallazgos=None,
        error=None,
        requiere_objetivo_original=False,
    ):
        self.id_fuente = id_fuente
        self.nombre = f"Fuente {id_fuente}"
        self.tipos_objetivo = frozenset({"dominio", "correo", "telefono", "usuario"})
        self.requiere_objetivo_original = requiere_objetivo_original
        self._configurada = configurada
        self._hallazgos = hallazgos or []
        self._error = error
        self.llamadas = 0
        self.objetivos_recibidos: list[str] = []

    def configurada(self) -> bool:
        return self._configurada

    def investigar(self, objetivo, *, tipo_objetivo, tiempo_limite, debe_cancelar):
        self.llamadas += 1
        self.objetivos_recibidos.append(objetivo)
        if self._error is not None:
            raise self._error
        return self._hallazgos


def _hallazgo(titulo="H") -> HallazgoOSINT:
    return HallazgoOSINT(
        categoria="dns",
        titulo=titulo,
        descripcion="d",
        nivel_confianza="confirmado",
        indicador_exposicion=None,
        evidencias=(
            EvidenciaOSINT(
                fuente="dns",
                fecha_consulta="2026-01-01T00:00:00+00:00",
                referencia=None,
                valor="x",
            ),
        ),
    )


def _proyecto(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = base_datos.crear_proyecto("laboratorio")
    return base_datos, proyecto


def test_tipo_objetivo_desconocido_rechazado(tmp_path):
    base_datos, proyecto = _proyecto(tmp_path)
    with pytest.raises(ErrorValidacion):
        motor.ejecutar_investigacion_osint(base_datos, proyecto, "desconocido", "x")


def test_correo_sin_autorizacion_rechazado(tmp_path):
    base_datos, proyecto = _proyecto(tmp_path)
    with pytest.raises(ErrorAutorizacionOSINTRequerida):
        motor.ejecutar_investigacion_osint(base_datos, proyecto, "correo", "a@ejemplo.com")


def test_dominio_no_requiere_autorizacion(tmp_path, monkeypatch):
    base_datos, proyecto = _proyecto(tmp_path)
    monkeypatch.setattr(motor, "fuentes_para_tipo", lambda tipo: {})
    resultado = motor.ejecutar_investigacion_osint(base_datos, proyecto, "dominio", "ejemplo.com")
    assert resultado.estado_general == "completada"


def test_fuente_exitosa_persiste_hallazgos(tmp_path, monkeypatch):
    base_datos, proyecto = _proyecto(tmp_path)
    fuente = _FuenteFalsa("f1", hallazgos=[_hallazgo("A"), _hallazgo("B")])
    monkeypatch.setattr(motor, "fuentes_para_tipo", lambda tipo: {"f1": fuente})

    resultado = motor.ejecutar_investigacion_osint(base_datos, proyecto, "dominio", "ejemplo.com")

    assert resultado.total_hallazgos == 2
    guardados = base_datos.listar_hallazgos_osint(investigacion_id=resultado.investigacion_id)
    assert len(guardados) == 2
    assert fuente.llamadas == 1


def test_fuente_no_configurada_se_omite_sin_detener_las_demas(tmp_path, monkeypatch):
    base_datos, proyecto = _proyecto(tmp_path)
    fuente_omitida = _FuenteFalsa("f1", configurada=False)
    fuente_ok = _FuenteFalsa("f2", hallazgos=[_hallazgo()])
    monkeypatch.setattr(
        motor, "fuentes_para_tipo", lambda tipo: {"f1": fuente_omitida, "f2": fuente_ok}
    )

    resultado = motor.ejecutar_investigacion_osint(base_datos, proyecto, "dominio", "ejemplo.com")

    estados = {e.fuente: e.estado for e in resultado.etapas}
    assert estados["f1"] == "omitida"
    assert estados["f2"] == "completada"
    assert resultado.total_hallazgos == 1
    assert len(resultado.limitaciones) == 1


def test_fuente_fallida_no_detiene_las_demas(tmp_path, monkeypatch):
    base_datos, proyecto = _proyecto(tmp_path)
    fuente_falla = _FuenteFalsa("f1", error=ErrorFuenteOSINTError("fallo simulado"))
    fuente_ok = _FuenteFalsa("f2", hallazgos=[_hallazgo()])
    monkeypatch.setattr(
        motor, "fuentes_para_tipo", lambda tipo: {"f1": fuente_falla, "f2": fuente_ok}
    )

    resultado = motor.ejecutar_investigacion_osint(base_datos, proyecto, "dominio", "ejemplo.com")

    estados = {e.fuente: e.estado for e in resultado.etapas}
    assert estados["f1"] == "fallida"
    assert estados["f2"] == "completada"


def test_fuente_no_disponible_para_objetivo_se_omite(tmp_path, monkeypatch):
    base_datos, proyecto = _proyecto(tmp_path)
    fuente = _FuenteFalsa("f1", error=ErrorFuenteOSINTNoDisponible("no aplica"))
    monkeypatch.setattr(motor, "fuentes_para_tipo", lambda tipo: {"f1": fuente})

    resultado = motor.ejecutar_investigacion_osint(base_datos, proyecto, "dominio", "ejemplo.com")

    assert resultado.etapas[0].estado == "omitida"


def test_fuentes_seleccionadas_filtra_el_catalogo(tmp_path, monkeypatch):
    base_datos, proyecto = _proyecto(tmp_path)
    fuente_a = _FuenteFalsa("f1", hallazgos=[_hallazgo()])
    fuente_b = _FuenteFalsa("f2", hallazgos=[_hallazgo()])
    monkeypatch.setattr(motor, "fuentes_para_tipo", lambda tipo: {"f1": fuente_a, "f2": fuente_b})

    resultado = motor.ejecutar_investigacion_osint(
        base_datos, proyecto, "dominio", "ejemplo.com", fuentes_seleccionadas=frozenset({"f1"})
    )

    assert len(resultado.etapas) == 1
    assert resultado.etapas[0].fuente == "f1"
    assert fuente_b.llamadas == 0


def test_fuente_de_seleccion_explicita_no_corre_por_defecto(tmp_path, monkeypatch):
    """Una fuente que factura por consulta (``requiere_seleccion_explicita = True``,
    ver integrations/osint/base.py) nunca debe ejecutarse solo porque este configurada:
    sin que el usuario la nombre con '--fuentes', queda fuera del conjunto por defecto."""
    base_datos, proyecto = _proyecto(tmp_path)
    fuente_gratuita = _FuenteFalsa("f1", hallazgos=[_hallazgo()])
    fuente_de_pago = _FuenteFalsa("f2", hallazgos=[_hallazgo()])
    fuente_de_pago.requiere_seleccion_explicita = True
    monkeypatch.setattr(
        motor, "fuentes_para_tipo", lambda tipo: {"f1": fuente_gratuita, "f2": fuente_de_pago}
    )

    resultado = motor.ejecutar_investigacion_osint(base_datos, proyecto, "dominio", "ejemplo.com")

    assert fuente_gratuita.llamadas == 1
    assert fuente_de_pago.llamadas == 0
    assert all(e.fuente != "f2" for e in resultado.etapas)


def test_fuente_de_seleccion_explicita_corre_si_se_nombra(tmp_path, monkeypatch):
    base_datos, proyecto = _proyecto(tmp_path)
    fuente_de_pago = _FuenteFalsa("f2", hallazgos=[_hallazgo()])
    fuente_de_pago.requiere_seleccion_explicita = True
    monkeypatch.setattr(motor, "fuentes_para_tipo", lambda tipo: {"f2": fuente_de_pago})

    resultado = motor.ejecutar_investigacion_osint(
        base_datos, proyecto, "dominio", "ejemplo.com", fuentes_seleccionadas=frozenset({"f2"})
    )

    assert fuente_de_pago.llamadas == 1
    assert resultado.etapas[0].fuente == "f2"


def test_fuente_seleccionada_no_aplicable_rechazada(tmp_path, monkeypatch):
    base_datos, proyecto = _proyecto(tmp_path)
    monkeypatch.setattr(motor, "fuentes_para_tipo", lambda tipo: {})
    with pytest.raises(ErrorValidacion):
        motor.ejecutar_investigacion_osint(
            base_datos,
            proyecto,
            "dominio",
            "ejemplo.com",
            fuentes_seleccionadas=frozenset({"no-existe"}),
        )


def test_cancelacion_antes_de_una_fuente_no_persiste_nada(tmp_path, monkeypatch):
    base_datos, proyecto = _proyecto(tmp_path)
    fuente = _FuenteFalsa("f1", hallazgos=[_hallazgo()])
    monkeypatch.setattr(motor, "fuentes_para_tipo", lambda tipo: {"f1": fuente})

    with pytest.raises(ErrorInvestigacionOSINTCancelada):
        motor.ejecutar_investigacion_osint(
            base_datos, proyecto, "dominio", "ejemplo.com", debe_cancelar=lambda: True
        )

    investigaciones = base_datos.listar_investigaciones_osint(proyecto.id)
    assert investigaciones[0].estado_general == "cancelada"
    assert base_datos.listar_hallazgos_osint(proyecto_id=proyecto.id) == []
    assert fuente.llamadas == 0


def test_callback_de_progreso_se_invoca_por_fuente(tmp_path, monkeypatch):
    base_datos, proyecto = _proyecto(tmp_path)
    fuente = _FuenteFalsa("f1", hallazgos=[_hallazgo()])
    monkeypatch.setattr(motor, "fuentes_para_tipo", lambda tipo: {"f1": fuente})

    estados_vistos = []
    motor.ejecutar_investigacion_osint(
        base_datos,
        proyecto,
        "dominio",
        "ejemplo.com",
        callback_progreso=lambda etapa: estados_vistos.append(etapa.estado),
    )
    assert "ejecutando" in estados_vistos
    assert "completada" in estados_vistos


def test_fuente_que_requiere_objetivo_original_recibe_el_correo_completo(tmp_path, monkeypatch):
    """Regresion: una fuente de tipo 'correo' que necesita la cuenta completa (p. ej.
    Have I Been Pwned) debe recibir el correo entero, nunca solo el dominio derivado
    que si usan DNS/RDAP/Certificate Transparency (ver integrations/osint/base.py)."""
    base_datos, proyecto = _proyecto(tmp_path)
    fuente_correo_completo = _FuenteFalsa(
        "hibp", hallazgos=[_hallazgo()], requiere_objetivo_original=True
    )
    fuente_dominio = _FuenteFalsa("dns", hallazgos=[_hallazgo()])
    monkeypatch.setattr(
        motor,
        "fuentes_para_tipo",
        lambda tipo: {"hibp": fuente_correo_completo, "dns": fuente_dominio},
    )

    motor.ejecutar_investigacion_osint(
        base_datos,
        proyecto,
        "correo",
        "usuario@ejemplo.com",
        autorizado_datos_personales=True,
    )

    assert fuente_correo_completo.objetivos_recibidos == ["usuario@ejemplo.com"]
    assert fuente_dominio.objetivos_recibidos == ["ejemplo.com"]
