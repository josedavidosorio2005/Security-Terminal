"""Snapshot de estado agregado para la interfaz (cabecera, pie, paneles).

No contiene logica de negocio propia: solo lee datos ya existentes en
``core/config.py`` y ``storage/database.py`` para presentarlos en la TUI.
"""

from __future__ import annotations

import platform
from dataclasses import dataclass

from eurabyte_security.core import config
from eurabyte_security.core.errores import ErrorEST
from eurabyte_security.storage.database import BaseDatos


@dataclass(frozen=True, slots=True)
class EstadoAST:
    proyecto_activo: str | None
    total_alcances: int
    total_resultados: int
    base_datos_ok: bool
    ruta_base_datos: str
    sistema_operativo: str


def construir_estado() -> EstadoAST:
    proyecto_activo = config.obtener_proyecto_activo()
    total_alcances = 0
    total_resultados = 0
    base_datos_ok = True

    try:
        base_datos = BaseDatos()
        if proyecto_activo:
            try:
                proyecto = base_datos.obtener_proyecto_por_nombre(proyecto_activo)
                total_alcances = len(base_datos.listar_alcance(proyecto.id))
                total_resultados = len(
                    base_datos.listar_resultados(proyecto.id, limite=100_000)
                )
            except ErrorEST:
                pass
    except Exception:
        base_datos_ok = False

    return EstadoAST(
        proyecto_activo=proyecto_activo,
        total_alcances=total_alcances,
        total_resultados=total_resultados,
        base_datos_ok=base_datos_ok,
        ruta_base_datos=str(config.ruta_base_datos()),
        sistema_operativo=f"{platform.system()} {platform.release()}".strip(),
    )
