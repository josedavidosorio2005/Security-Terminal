"""Aplicacion CLI principal de AURABYTE Security Terminal (comando ``est``)."""

from __future__ import annotations

import sys

import typer

from eurabyte_security import __version__
from eurabyte_security.commands.alcance import alcance_app
from eurabyte_security.commands.escanear import escanear_app
from eurabyte_security.commands.explicar import explicar_cmd
from eurabyte_security.commands.nmap import nmap_app
from eurabyte_security.commands.nuclei import nuclei_app
from eurabyte_security.commands.proyecto import proyecto_app
from eurabyte_security.commands.reporte import reporte_app
from eurabyte_security.commands.resultados import resultados_cmd
from eurabyte_security.core.errores import ErrorEST
from eurabyte_security.marca import ABREVIATURA, NOMBRE_PRODUCTO, encabezado_version
from eurabyte_security.ui.consola import consola, mostrar_error

app = typer.Typer(
    name="est",
    help=f"{NOMBRE_PRODUCTO} ({ABREVIATURA}): plataforma de pentesting en espanol.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["--ayuda", "--help", "-h"]},
)

app.add_typer(proyecto_app, name="proyecto")
app.add_typer(alcance_app, name="alcance")
app.add_typer(escanear_app, name="escanear")
app.add_typer(reporte_app, name="reporte")
app.add_typer(nmap_app, name="nmap")
app.add_typer(nuclei_app, name="nuclei")
app.command("explicar")(explicar_cmd)
app.command("resultados")(resultados_cmd)


@app.command("interactivo")
def interactivo_cmd() -> None:
    """Abre la terminal interactiva de linea de comandos (autocompletado e historial)."""
    from eurabyte_security.ui.repl import iniciar

    iniciar()


@app.command("interfaz")
def interfaz_cmd() -> None:
    """Abre la interfaz visual de AST (panel completo con teclado y raton)."""
    from eurabyte_security.ui.tui.app import AuraByteApp

    AuraByteApp().run()


def _version_callback(valor: bool) -> None:
    if valor:
        consola.print(encabezado_version(__version__))
        raise typer.Exit()


@app.callback()
def _raiz(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Muestra la version de AST y termina.",
    ),
) -> None:
    """AURABYTE Security Terminal (AST)."""


def main() -> None:
    """Punto de entrada del script ``est``."""
    try:
        app()
    except ErrorEST as exc:
        mostrar_error(str(exc))
        sys.exit(1)


if __name__ == "__main__":
    main()
