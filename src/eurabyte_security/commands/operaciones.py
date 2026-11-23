"""Seguimiento de casos Red/Blue Team y telemetría defensiva local."""

import json
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Annotated

import typer

from eurabyte_security.commands._comun import resolver_proyecto
from eurabyte_security.core.config import ruta_reportes
from eurabyte_security.modules.network.trafico import medir_equipo
from eurabyte_security.storage.operaciones import Operaciones
from eurabyte_security.ui.consola import consola

operaciones_app = typer.Typer(help="Casos Red/Blue Team del proyecto activo.")


def contexto():
    db = Operaciones()
    return db, resolver_proyecto(db, None)


def exportar_caso(db, proyecto, caso) -> Path:
    contenido = json.dumps(db.detalle(proyecto, caso), ensure_ascii=False, indent=2)
    with NamedTemporaryFile(
        dir=ruta_reportes(), prefix=f"caso-{caso}-", suffix=".json", delete=False,
        mode="w", encoding="utf-8",
    ) as archivo:
        try:
            archivo.write(contenido)
        except OSError:
            archivo.close()
            Path(archivo.name).unlink(missing_ok=True)
            raise
    return Path(archivo.name)


@operaciones_app.command("crear")
def crear(activo: str, titulo: str, evidencia: str, gravedad: str = "media"):
    """Abre un caso con evidencia inicial e identificador permanente."""
    db, p = contexto()
    identificador = db.crear(p.id, activo, titulo, gravedad, evidencia)
    consola.print(f"Caso #{identificador} abierto.")


@operaciones_app.command("listar")
def listar(activo: str | None = None):
    """Lista casos. Usa --activo para comparar el historial de un activo."""
    db, p = contexto()
    consola.print_json(data=db.listar(p.id, activo))


@operaciones_app.command("vincular")
def vincular(caso: int, fuente: str, origen: int):
    """Vincula el resultado FUENTE e ID del proyecto al caso."""
    db, p = contexto()
    db.vincular(p.id, caso, fuente, origen)
    consola.print("Evidencia vinculada.")


@operaciones_app.command("registrar")
def registrar(caso: int, accion: str, detalle: str, fecha: str | None = None,
              ejercicio: int | None = None):
    """Registra asignar, corregir, verificar, reabrir, nota, ejercicio o deteccion."""
    db, p = contexto()
    evento = db.registrar(p.id, caso, accion, detalle, fecha, ejercicio)
    consola.print(f"Evento #{evento} registrado.")


@operaciones_app.command("ver")
def ver(caso: int):
    """Muestra la cronología del caso con fuentes y tiempos de detección."""
    db, p = contexto()
    consola.print_json(data=db.detalle(p.id, caso))


@operaciones_app.command("informe")
def informe(caso: int):
    """Exporta el antes y el después en JSON."""
    db, p = contexto()
    consola.print(str(exportar_caso(db, p.id, caso)), markup=False)


@operaciones_app.command("vigilar")
def vigilar(
    umbral: Annotated[float, typer.Option("--umbral", min=0.001, max=1_000_000)] = 100,
    segundos: Annotated[float, typer.Option("--segundos", min=0.2, max=10)] = 2,
    muestras: Annotated[int | None, typer.Option("--muestras", min=1)] = None,
):
    """Guarda tasas de las interfaces locales hasta Ctrl+C o el número de muestras."""
    db, p = contexto()
    n = 0
    try:
        while muestras is None or n < muestras:
            medicion = medir_equipo(segundos)
            db.guardar_muestra(p.id, medicion, umbral)
            n += 1
            consola.print(f"Muestra {n}: {len(medicion.interfaces)} interfaces.")
    except KeyboardInterrupt:
        consola.print("Monitoreo detenido.")


@operaciones_app.command("mediciones")
def mediciones():
    """Consulta las últimas 100 mediciones del proyecto y su umbral."""
    db, p = contexto()
    consola.print_json(data=db.muestras(p.id))
