"""Aplicacion CLI principal de Eurabyte Security Terminal (comando ``est``)."""

from __future__ import annotations

import sys

import typer

from eurabyte_security import __version__
from eurabyte_security.commands.alcance import alcance_app
from eurabyte_security.commands.escanear import escanear_app
from eurabyte_security.commands.explicar import explicar_cmd
from eurabyte_security.commands.proyecto import proyecto_app
from eurabyte_security.commands.reporte import reporte_app
from eurabyte_security.commands.resultados import resultados_cmd
from eurabyte_security.core.errores import ErrorEST
from eurabyte_security.ui.consola import consola, mostrar_error

app = typer.Typer(
    name="est",
    help="Eurabyte Security Terminal (EST): plataforma de pentesting en espanol.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["--ayuda", "--help", "-h"]},
)

app.add_typer(proyecto_app, name="proyecto")
app.add_typer(alcance_app, name="alcance")
app.add_typer(escanear_app, name="escanear")
app.add_typer(reporte_app, name="reporte")
app.command("explicar")(explicar_cmd)
app.command("resultados")(resultados_cmd)


@app.command("interactivo")
def interactivo_cmd() -> None:
    """Abre la terminal interactiva de EST (autocompletado e historial)."""
    from eurabyte_security.ui.repl import iniciar

    iniciar()


def _version_callback(valor: bool) -> None:
    if valor:
        consola.print(f"Eurabyte Security Terminal (EST) version {__version__}")
        raise typer.Exit()


@app.callback()
def _raiz(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Muestra la version de EST y termina.",
    ),
) -> None:
    """Eurabyte Security Terminal (EST)."""


def main() -> None:
    """Punto de entrada del script ``est``."""
    try:
        app()
    except ErrorEST as exc:
        mostrar_error(str(exc))
        sys.exit(1)


if __name__ == "__main__":
    main()
