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

# ---------------------------------------------------------------------------
# Escudo de marca: un escudo azul/cian con un simbolo de terminal dentro
# (sin mascotas ni robots). Este repositorio todavia no incluye el recurso
# grafico oficial (SVG/PNG), asi que se usa una alternativa en texto ASCII
# puro -- sin caracteres fuera del rango ASCII basico -- para garantizar que
# se vea igual en cualquier terminal de Windows o Linux, incluidas consolas
# antiguas sin soporte Unicode completo.
#
# Punto unico de sustitucion: cuando exista el recurso oficial, basta con
# cambiar los valores de ESCUDO_COMPACTO y/o ESCUDO_ASCII en este archivo.
# Ningun otro modulo construye su propio glifo de marca
# (ui/tui/widgets/navegacion.py y ui/tui/widgets/paneles.py importan estas
# constantes). El color azul/cian se aplica aparte, en ui/tui/estilos.tcss
# (clase ``.logo`` sobre la variable ``$ast-borde``): no hace falta tocar
# los estilos al reemplazar el glifo por el recurso oficial.
# ---------------------------------------------------------------------------

# Version compacta (una sola linea), para la barra superior.
ESCUDO_COMPACTO = "<[>_]>"

# Version ampliada (varias lineas), para el panel de inicio.
ESCUDO_ASCII = r"""
   ___
  /   \
 | >_  |
  \   /
   \_/
""".strip("\n")

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
