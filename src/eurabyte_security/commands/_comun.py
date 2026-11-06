"""Utilidades compartidas por los comandos: acceso a BD y resolucion de proyecto."""

from __future__ import annotations

from eurabyte_security.core import config
from eurabyte_security.core.errores import ErrorSinProyectoActivo
from eurabyte_security.storage.database import BaseDatos, Proyecto


def obtener_base_datos() -> BaseDatos:
    return BaseDatos()


def resolver_proyecto(base_datos: BaseDatos, nombre: str | None) -> Proyecto:
    """Devuelve el proyecto indicado, o el proyecto activo si ``nombre`` es None."""
    if nombre:
        return base_datos.obtener_proyecto_por_nombre(nombre)

    activo = config.obtener_proyecto_activo()
    if not activo:
        raise ErrorSinProyectoActivo(
            "No hay un proyecto activo. Usa --proyecto NOMBRE o crea uno con "
            "'est proyecto crear NOMBRE'."
        )
    return base_datos.obtener_proyecto_por_nombre(activo)
