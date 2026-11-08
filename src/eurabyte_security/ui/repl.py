"""Terminal interactiva de linea de comandos: autocompletado con Tab e historial."""

from __future__ import annotations

import shlex

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.history import FileHistory

from eurabyte_security.core.config import ruta_historial
from eurabyte_security.marca import ABREVIATURA, NOMBRE_PRODUCTO
from eurabyte_security.ui.consola import consola, mostrar_error

COMANDOS_SALIDA = {"salir", "exit", "quit"}

_ARBOL_COMPLETADO = {
    "proyecto": {"crear": None, "listar": None, "usar": None},
    "alcance": {"agregar": None, "listar": None},
    "escanear": {"tcp": None},
    "web": {
        "cabeceras": None,
        "tls": None,
        "cookies": None,
        "auditar": None,
        "reporte": None,
    },
    "nuclei": {
        "version": None,
        "plantillas": None,
        "analizar": None,
        "resultados": None,
        "revisar": None,
        "reporte": None,
    },
    "zap": {
        "estado": None,
        "pasivo": None,
        "resultados": None,
        "revisar": None,
        "reporte": None,
    },
    "explicar": {
        tema: None
        for tema in (
            "proyecto",
            "alcance",
            "tcp",
            "escanear",
            "resultados",
            "reporte",
            "interactivo",
            "web",
            "nuclei",
            "zap",
        )
    },
    "resultados": None,
    "reporte": {"generar": None},
    "ayuda": None,
    "salir": None,
}


def _construir_sesion() -> PromptSession:
    return PromptSession(
        history=FileHistory(str(ruta_historial())),
        completer=NestedCompleter.from_nested_dict(_ARBOL_COMPLETADO),
    )


def iniciar() -> None:
    """Inicia el bucle de la terminal interactiva de EST."""
    import typer

    from eurabyte_security.cli.app import app  # evita import circular

    cli_click = typer.main.get_command(app)

    try:
        sesion = _construir_sesion()
    except Exception as exc:
        mostrar_error(
            "No se pudo iniciar la terminal interactiva en esta consola "
            f"({exc}). En Windows, ejecuta 'est interactivo' desde cmd.exe o "
            "PowerShell (no desde Git Bash/MinTTY ni con la entrada redirigida)."
        )
        return

    consola.print(
        f"[bold cyan]{NOMBRE_PRODUCTO} ({ABREVIATURA})[/bold cyan] - modo interactivo.\n"
        "Escribe un comando (Tab para autocompletar) o 'salir' para terminar.\n"
        "Tambien puedes usar 'est interfaz' para la interfaz visual completa."
    )

    while True:
        try:
            texto = sesion.prompt("est> ")
        except KeyboardInterrupt:
            continue
        except EOFError:
            break

        texto = texto.strip()
        if not texto:
            continue
        if texto in COMANDOS_SALIDA:
            break
        if texto in ("ayuda", "--ayuda", "-h", "--help"):
            texto = "--ayuda"

        try:
            argumentos = shlex.split(texto)
        except ValueError as exc:
            mostrar_error(f"No se pudo interpretar el comando: {exc}")
            continue

        try:
            cli_click.main(args=argumentos, prog_name="est", standalone_mode=False)
        except SystemExit:
            pass
        except Exception as exc:  # noqa: BLE001 - frontera de la terminal interactiva
            mostrar_error(str(exc))

    consola.print("Hasta pronto.")
