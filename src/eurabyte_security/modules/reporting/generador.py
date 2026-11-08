"""Construccion de informes de auditoria en JSON y HTML."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape

from eurabyte_security.storage.database import Resultado, ResultadoNuclei, ResultadoWeb


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
.severidad-info, .severidad-unknown { color: #a0aec0; }
.severidad-baja, .severidad-low { color: #4fd1c5; }
.severidad-media, .severidad-medium { color: #f6e05e; font-weight: bold; }
.severidad-alta, .severidad-high, .severidad-critical { color: #fc8181; font-weight: bold; }
"""


def _pagina_html(titulo: str, resumen: str, cuerpo_tabla: str) -> str:
    """Esqueleto HTML comun a todos los informes de AST (mismo CSS y cabecera)."""
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>{escape(titulo)}</title>
<style>{_ESTILOS}</style>
</head>
<body>
<h1>AURABYTE Security Terminal - Informe de auditoria</h1>
<p class="resumen">{resumen}</p>
{cuerpo_tabla}
</body>
</html>
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

    cuerpo_tabla = (
        "<table>\n"
        "<thead><tr><th>Objetivo</th><th>Puerto</th><th>Estado</th><th>Fecha</th></tr></thead>\n"
        f"<tbody>\n{filas}\n</tbody>\n</table>"
    )
    resumen = (
        f"Proyecto: <strong>{escape(datos.proyecto)}</strong> &middot; "
        f"Generado: {escape(datos.generado_en)} &middot; "
        f"Total de resultados: {len(datos.resultados)}"
    )
    return _pagina_html(f"Informe AST - {datos.proyecto}", resumen, cuerpo_tabla)


@dataclass(frozen=True, slots=True)
class DatosInformeWeb:
    proyecto: str
    generado_en: str
    hallazgos: list[ResultadoWeb]


def construir_datos_informe_web(proyecto: str, hallazgos: list[ResultadoWeb]) -> DatosInformeWeb:
    return DatosInformeWeb(
        proyecto=proyecto,
        generado_en=datetime.now(UTC).isoformat(),
        hallazgos=hallazgos,
    )


def generar_json_web(datos: DatosInformeWeb) -> str:
    cuerpo = {
        "proyecto": datos.proyecto,
        "generado_en": datos.generado_en,
        "total_hallazgos": len(datos.hallazgos),
        "hallazgos": [
            {
                "objetivo": h.objetivo,
                "tipo_analisis": h.tipo_analisis,
                "categoria": h.categoria,
                "nombre_hallazgo": h.nombre_hallazgo,
                "severidad": h.severidad,
                "estado": h.estado,
                "valor_detectado": h.valor_detectado,
                "riesgo": h.riesgo,
                "recomendacion": h.recomendacion,
                "referencia": h.referencia,
                "creado_en": h.creado_en,
            }
            for h in datos.hallazgos
        ],
    }
    return json.dumps(cuerpo, ensure_ascii=False, indent=2)


def generar_html_web(datos: DatosInformeWeb) -> str:
    filas = "\n".join(
        f"<tr><td>{escape(h.objetivo)}</td><td>{escape(h.categoria)}</td>"
        f"<td>{escape(h.nombre_hallazgo)}</td><td>{escape(h.estado)}</td>"
        f"<td class=\"severidad-{escape(h.severidad)}\">{escape(h.severidad)}</td>"
        f"<td>{escape(h.valor_detectado or '-')}</td>"
        f"<td>{escape(h.recomendacion)}</td><td>{escape(h.creado_en)}</td></tr>"
        for h in datos.hallazgos
    )
    if not filas:
        filas = "<tr><td colspan=\"8\">No hay hallazgos de auditoria web registrados.</td></tr>"

    cuerpo_tabla = (
        "<table>\n<thead><tr><th>Objetivo</th><th>Categoria</th><th>Hallazgo</th>"
        "<th>Estado</th><th>Severidad</th><th>Valor detectado</th><th>Recomendacion</th>"
        "<th>Fecha</th></tr></thead>\n"
        f"<tbody>\n{filas}\n</tbody>\n</table>"
    )
    resumen = (
        f"Proyecto: <strong>{escape(datos.proyecto)}</strong> &middot; "
        f"Generado: {escape(datos.generado_en)} &middot; "
        f"Total de hallazgos: {len(datos.hallazgos)}"
    )
    return _pagina_html(f"Informe web AST - {datos.proyecto}", resumen, cuerpo_tabla)


@dataclass(frozen=True, slots=True)
class DatosInformeNuclei:
    proyecto: str
    generado_en: str
    hallazgos: list[ResultadoNuclei]


def construir_datos_informe_nuclei(
    proyecto: str, hallazgos: list[ResultadoNuclei]
) -> DatosInformeNuclei:
    return DatosInformeNuclei(
        proyecto=proyecto,
        generado_en=datetime.now(UTC).isoformat(),
        hallazgos=hallazgos,
    )


def generar_json_nuclei(datos: DatosInformeNuclei) -> str:
    cuerpo = {
        "proyecto": datos.proyecto,
        "generado_en": datos.generado_en,
        "total_hallazgos": len(datos.hallazgos),
        "hallazgos": [
            {
                "objetivo": h.objetivo,
                "plantilla_id": h.plantilla_id,
                "plantilla_version": h.plantilla_version,
                "nombre_hallazgo": h.nombre_hallazgo,
                "severidad": h.severidad,
                "descripcion": h.descripcion,
                "evidencia": h.evidencia,
                "estado_revision": h.estado_revision,
                "creado_en": h.creado_en,
            }
            for h in datos.hallazgos
        ],
    }
    return json.dumps(cuerpo, ensure_ascii=False, indent=2)


def generar_html_nuclei(datos: DatosInformeNuclei) -> str:
    filas = "\n".join(
        f"<tr><td>{escape(h.objetivo)}</td><td>{escape(h.plantilla_id)}</td>"
        f"<td>{escape(h.plantilla_version)}</td><td>{escape(h.nombre_hallazgo)}</td>"
        f"<td class=\"severidad-{escape(h.severidad)}\">{escape(h.severidad)}</td>"
        f"<td>{escape(h.descripcion)}</td><td>{escape(h.evidencia or '-')}</td>"
        f"<td>{escape(h.estado_revision)}</td><td>{escape(h.creado_en)}</td></tr>"
        for h in datos.hallazgos
    )
    if not filas:
        filas = "<tr><td colspan=\"9\">No hay hallazgos de Nuclei registrados.</td></tr>"

    cuerpo_tabla = (
        "<table>\n<thead><tr><th>Objetivo</th><th>Plantilla</th><th>Version</th>"
        "<th>Hallazgo</th><th>Severidad</th><th>Descripcion</th><th>Evidencia</th>"
        "<th>Revision</th><th>Fecha</th></tr></thead>\n"
        f"<tbody>\n{filas}\n</tbody>\n</table>"
    )
    resumen = (
        f"Proyecto: <strong>{escape(datos.proyecto)}</strong> &middot; "
        f"Generado: {escape(datos.generado_en)} &middot; "
        f"Total de hallazgos: {len(datos.hallazgos)}"
    )
    return _pagina_html(f"Informe Nuclei AST - {datos.proyecto}", resumen, cuerpo_tabla)
