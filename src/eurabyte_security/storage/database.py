"""Repositorio SQLite para proyectos, alcances y resultados de EST."""

from __future__ import annotations

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from eurabyte_security.core.config import ruta_base_datos
from eurabyte_security.core.errores import ErrorProyectoDuplicado, ErrorProyectoNoEncontrado

ESQUEMA = """
CREATE TABLE IF NOT EXISTS proyectos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT UNIQUE NOT NULL,
    creado_en TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alcances (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proyecto_id INTEGER NOT NULL REFERENCES proyectos(id) ON DELETE CASCADE,
    red TEXT NOT NULL,
    creado_en TEXT NOT NULL,
    UNIQUE(proyecto_id, red)
);

CREATE TABLE IF NOT EXISTS resultados (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proyecto_id INTEGER NOT NULL REFERENCES proyectos(id) ON DELETE CASCADE,
    objetivo TEXT NOT NULL,
    puerto INTEGER NOT NULL,
    estado TEXT NOT NULL,
    creado_en TEXT NOT NULL
);
"""


def _ahora() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True, slots=True)
class Proyecto:
    id: int
    nombre: str
    creado_en: str


@dataclass(frozen=True, slots=True)
class Alcance:
    id: int
    proyecto_id: int
    red: str
    creado_en: str


@dataclass(frozen=True, slots=True)
class Resultado:
    id: int
    proyecto_id: int
    objetivo: str
    puerto: int
    estado: str
    creado_en: str


class BaseDatos:
    """Repositorio de acceso a los datos persistentes de EST."""

    def __init__(self, ruta: Path | None = None) -> None:
        self._ruta = ruta or ruta_base_datos()
        with self._conectar() as conexion:
            conexion.executescript(ESQUEMA)

    @contextmanager
    def _conectar(self) -> Generator[sqlite3.Connection, None, None]:
        conexion = sqlite3.connect(self._ruta)
        conexion.row_factory = sqlite3.Row
        try:
            yield conexion
            conexion.commit()
        finally:
            conexion.close()

    # -- Proyectos ---------------------------------------------------
    def crear_proyecto(self, nombre: str) -> Proyecto:
        try:
            with self._conectar() as conexion:
                cursor = conexion.execute(
                    "INSERT INTO proyectos (nombre, creado_en) VALUES (?, ?)",
                    (nombre, _ahora()),
                )
                nuevo_id = cursor.lastrowid
        except sqlite3.IntegrityError as exc:
            raise ErrorProyectoDuplicado(
                f"Ya existe un proyecto llamado '{nombre}'."
            ) from exc
        return self.obtener_proyecto_por_id(nuevo_id)  # type: ignore[arg-type]

    def obtener_proyecto_por_id(self, id_: int) -> Proyecto:
        with self._conectar() as conexion:
            fila = conexion.execute(
                "SELECT id, nombre, creado_en FROM proyectos WHERE id = ?", (id_,)
            ).fetchone()
        if fila is None:
            raise ErrorProyectoNoEncontrado(f"No existe un proyecto con id {id_}.")
        return Proyecto(**fila)

    def obtener_proyecto_por_nombre(self, nombre: str) -> Proyecto:
        with self._conectar() as conexion:
            fila = conexion.execute(
                "SELECT id, nombre, creado_en FROM proyectos WHERE nombre = ?", (nombre,)
            ).fetchone()
        if fila is None:
            raise ErrorProyectoNoEncontrado(f"No existe un proyecto llamado '{nombre}'.")
        return Proyecto(**fila)

    def listar_proyectos(self) -> list[Proyecto]:
        with self._conectar() as conexion:
            filas = conexion.execute(
                "SELECT id, nombre, creado_en FROM proyectos ORDER BY nombre"
            ).fetchall()
        return [Proyecto(**fila) for fila in filas]

    # -- Alcances ------------------------------------------------------
    def agregar_alcance(self, proyecto_id: int, red: str) -> Alcance:
        with self._conectar() as conexion:
            try:
                cursor = conexion.execute(
                    "INSERT INTO alcances (proyecto_id, red, creado_en) VALUES (?, ?, ?)",
                    (proyecto_id, red, _ahora()),
                )
            except sqlite3.IntegrityError:
                fila = conexion.execute(
                    "SELECT id, proyecto_id, red, creado_en FROM alcances "
                    "WHERE proyecto_id = ? AND red = ?",
                    (proyecto_id, red),
                ).fetchone()
                return Alcance(**fila)
            fila = conexion.execute(
                "SELECT id, proyecto_id, red, creado_en FROM alcances WHERE id = ?",
                (cursor.lastrowid,),
            ).fetchone()
            return Alcance(**fila)

    def listar_alcance(self, proyecto_id: int) -> list[Alcance]:
        with self._conectar() as conexion:
            filas = conexion.execute(
                "SELECT id, proyecto_id, red, creado_en FROM alcances "
                "WHERE proyecto_id = ? ORDER BY creado_en",
                (proyecto_id,),
            ).fetchall()
        return [Alcance(**fila) for fila in filas]

    # -- Resultados ----------------------------------------------------
    def agregar_resultado(
        self, proyecto_id: int, objetivo: str, puerto: int, estado: str
    ) -> Resultado:
        with self._conectar() as conexion:
            cursor = conexion.execute(
                "INSERT INTO resultados (proyecto_id, objetivo, puerto, estado, creado_en) "
                "VALUES (?, ?, ?, ?, ?)",
                (proyecto_id, objetivo, puerto, estado, _ahora()),
            )
            fila = conexion.execute(
                "SELECT id, proyecto_id, objetivo, puerto, estado, creado_en "
                "FROM resultados WHERE id = ?",
                (cursor.lastrowid,),
            ).fetchone()
            return Resultado(**fila)

    def listar_resultados(
        self, proyecto_id: int | None = None, limite: int = 200
    ) -> list[Resultado]:
        with self._conectar() as conexion:
            if proyecto_id is None:
                filas = conexion.execute(
                    "SELECT id, proyecto_id, objetivo, puerto, estado, creado_en "
                    "FROM resultados ORDER BY creado_en DESC LIMIT ?",
                    (limite,),
                ).fetchall()
            else:
                filas = conexion.execute(
                    "SELECT id, proyecto_id, objetivo, puerto, estado, creado_en "
                    "FROM resultados WHERE proyecto_id = ? ORDER BY creado_en DESC LIMIT ?",
                    (proyecto_id, limite),
                ).fetchall()
        return [Resultado(**fila) for fila in filas]
