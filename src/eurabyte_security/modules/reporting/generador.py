"""Construccion de informes de auditoria en JSON y HTML."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape

from eurabyte_security.storage.database import Resultado


@dataclass(frozen=True, slots=True)
class DatosInforme:
    proyecto: str
    generado_en: str
    resultados: list[Resultado]


def construir_datos_informe(proyecto: str, resultados: list[Resultado]) -> DatosInforme:
    return DatosInforme(
        proyecto=proyecto,
        generado_en=datetime.now(UTC).isoformat(),
        resultados=resultados,
    )


def generar_json(datos: DatosInforme) -> str:
    cuerpo = {
        "proyecto": datos.proyecto,
        "generado_en": datos.generado_en,
        "total_resultados": len(datos.resultados),
        "resultados": [
            {
                "objetivo": r.objetivo,
                "puerto": r.puerto,
                "estado": r.estado,
                "creado_en": r.creado_en,
            }
            for r in datos.resultados
        ],
    }
    return json.dumps(cuerpo, ensure_ascii=False, indent=2)


_ESTILOS = """
body {
  font-family: 'Segoe UI', Arial, sans-serif;
  background: #0f1117;
  color: #e6e6e6;
  margin: 2rem;
}
h1 { color: #4fd1c5; }
table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
th, td { padding: 0.5rem 0.75rem; border-bottom: 1px solid #2d2f36; text-align: left; }
th { background: #1a1d26; }
.abierto { color: #68d391; font-weight: bold; }
.cerrado { color: #a0aec0; }
.error { color: #fc8181; }
.resumen { color: #a0aec0; margin-bottom: 1rem; }
"""


def generar_html(datos: DatosInforme) -> str:
    filas = "\n".join(
        f"<tr><td>{escape(r.objetivo)}</td><td>{r.puerto}</td>"
        f"<td class=\"{escape(r.estado)}\">{escape(r.estado)}</td>"
        f"<td>{escape(r.creado_en)}</td></tr>"
        for r in datos.resultados
    )
    if not filas:
        filas = "<tr><td colspan=\"4\">No hay resultados registrados.</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Informe AST - {escape(datos.proyecto)}</title>
<style>{_ESTILOS}</style>
</head>
<body>
<h1>AURABYTE Security Terminal - Informe de auditoria</h1>
<p class="resumen">Proyecto: <strong>{escape(datos.proyecto)}</strong> &middot;
Generado: {escape(datos.generado_en)} &middot;
Total de resultados: {len(datos.resultados)}</p>
<table>
<thead><tr><th>Objetivo</th><th>Puerto</th><th>Estado</th><th>Fecha</th></tr></thead>
<tbody>
{filas}
</tbody>
</table>
</body>
</html>
"""
