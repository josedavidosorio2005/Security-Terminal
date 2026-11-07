"""Identidad de marca de AURABYTE Security Terminal (AST).

El paquete Python, el nombre de distribucion y el comando de consola siguen
llamandose ``eurabyte_security`` / ``eurabyte-security`` / ``est`` por
compatibilidad con instalaciones existentes de la Fase 1 (ver CLAUDE.md). Lo
que cambia en la Fase 2 es la identidad visible para quien usa la
herramienta: nombre de producto, empresa y abreviatura.
"""

from __future__ import annotations

EMPRESA = "AURABYTE"
NOMBRE_PRODUCTO = "AURABYTE Security Terminal"
ABREVIATURA = "AST"
COMANDO = "est"

# Escudo minimalista (sin mascotas ni robots) usado en la barra superior y en
# el banner de la terminal interactiva/TUI.
ESCUDO_COMPACTO = "◢◤"

BANNER_ASCII = r"""
   █████╗ ██╗   ██╗██████╗  █████╗ ██████╗ ██╗   ██╗████████╗███████╗
  ██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝╚══██╔══╝██╔════╝
  ███████║██║   ██║██████╔╝███████║██████╔╝ ╚████╔╝    ██║   █████╗
  ██╔══██║██║   ██║██╔══██╗██╔══██║██╔══██╗  ╚██╔╝     ██║   ██╔══╝
  ██║  ██║╚██████╔╝██║  ██║██║  ██║██████╔╝   ██║      ██║   ███████╗
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝    ╚═╝      ╚═╝   ╚══════╝
                     S E C U R I T Y   T E R M I N A L
""".strip("\n")


def encabezado_version(version: str) -> str:
    return f"{NOMBRE_PRODUCTO} ({ABREVIATURA}) version {version}"
