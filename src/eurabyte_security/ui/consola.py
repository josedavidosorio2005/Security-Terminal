"""Consola enriquecida compartida por todos los comandos."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape

consola = Console()
consola_error = Console(stderr=True)


def texto_seguro(valor: object) -> str:
    """Escapa ``valor`` para que nunca se interprete como marcado Rich.

    Usar siempre que se interpole texto que pueda contener lo que el usuario
    escribio (un objetivo invalido, un tema desconocido, etc.) dentro de un
    mensaje que se va a imprimir con Rich/Textual (``markup`` habilitado). Sin
    este escape, algo como ``escanear tcp "[red]x[/red]"`` podria mostrarse
    con un color que no corresponde, o directamente lanzar un error de Rich
    al intentar interpretar una etiqueta que no existe.
    """
    return escape(str(valor))


def mostrar_error(mensaje: str) -> None:
    consola_error.print(f"[bold red]Error:[/bold red] {texto_seguro(mensaje)}")


def mostrar_exito(mensaje: str) -> None:
    consola.print(f"[bold green]OK[/bold green] {texto_seguro(mensaje)}")


def mostrar_aviso(mensaje: str) -> None:
    consola.print(f"[bold yellow]Aviso:[/bold yellow] {texto_seguro(mensaje)}")
