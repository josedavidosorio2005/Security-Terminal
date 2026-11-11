"""Pruebas de ``integrations/osint/perfiles_publicos.py`` (GitHub, GitLab)."""

from __future__ import annotations

from eurabyte_security.core.errores import ErrorFuenteOSINTError
from eurabyte_security.integrations.osint import perfiles_publicos


def test_usuario_encontrado_en_ambas_plataformas(monkeypatch):
    def _falso(url, **_kwargs):
        if "github.com" in url:
            return {"html_url": "https://github.com/ejemplo", "created_at": "2020-01-01T00:00:00Z"}
        return [{"web_url": "https://gitlab.com/ejemplo"}]

    monkeypatch.setattr(perfiles_publicos, "peticion_json", _falso)
    hallazgos = perfiles_publicos.AdaptadorPerfilesPublicos().investigar(
        "ejemplo", tipo_objetivo="usuario", tiempo_limite=5.0, debe_cancelar=None
    )
    titulos = {h.titulo for h in hallazgos}
    assert titulos == {"Coincidencia en GitHub", "Coincidencia en GitLab"}
    for h in hallazgos:
        assert h.nivel_confianza == "probable"
        assert "no una identidad confirmada" in h.descripcion


def test_usuario_no_encontrado_en_github_se_omite_sin_error(monkeypatch):
    def _falso(url, **_kwargs):
        if "github.com" in url:
            raise ErrorFuenteOSINTError(
                "'api.github.com' respondio con el codigo HTTP 404.", codigo_http=404
            )
        return []

    monkeypatch.setattr(perfiles_publicos, "peticion_json", _falso)
    hallazgos = perfiles_publicos.AdaptadorPerfilesPublicos().investigar(
        "noexiste12345", tipo_objetivo="usuario", tiempo_limite=5.0, debe_cancelar=None
    )
    assert hallazgos == []


def test_cancelacion_entre_plataformas_evita_segunda_consulta(monkeypatch):
    llamadas = []

    def _falso(url, **_kwargs):
        llamadas.append(url)
        return {"html_url": "https://github.com/ejemplo"}

    monkeypatch.setattr(perfiles_publicos, "peticion_json", _falso)
    hallazgos = perfiles_publicos.AdaptadorPerfilesPublicos().investigar(
        "ejemplo", tipo_objetivo="usuario", tiempo_limite=5.0, debe_cancelar=lambda: True
    )
    assert len(llamadas) == 1
    assert len(hallazgos) == 1
