"""Consola enriquecida compartida por todos los comandos."""

from __future__ import annotations

from rich.console import Console

consola = Console()
consola_error = Console(stderr=True)


def mostrar_error(mensaje: str) -> None:
    consola_error.print(f"[bold red]Error:[/bold red] {mensaje}")


def mostrar_exito(mensaje: str) -> None:
    consola.print(f"[bold green]OK[/bold green] {mensaje}")


def mostrar_aviso(mensaje: str) -> None:
    consola.print(f"[bold yellow]Aviso:[/bold yellow] {mensaje}")
