"""Pruebas de ``integrations/osint/dns_publico.py``.

``dns_publico._crear_resolver`` se sustituye por un resolver falso: ninguna prueba
resuelve un dominio real (ver CLAUDE.md, regla 5).
"""

from __future__ import annotations

import dns.exception
import dns.resolver

from eurabyte_security.integrations.osint import dns_publico
from eurabyte_security.integrations.osint.dns_publico import AdaptadorDNSPublico


class _RegistroFalso:
    def __init__(self, texto: str) -> None:
        self._texto = texto

    def to_text(self) -> str:
        return self._texto


class _ResolverFalso:
    """Simula ``dns.resolver.Resolver.resolve`` a partir de un mapa fijo de respuestas."""

    def __init__(self, respuestas: dict[tuple[str, str], object]) -> None:
        self._respuestas = respuestas

    def resolve(self, dominio: str, tipo: str):
        clave = (dominio, tipo)
        if clave not in self._respuestas:
            raise dns.resolver.NoAnswer()
        valor = self._respuestas[clave]
        if isinstance(valor, Exception):
            raise valor
        return [_RegistroFalso(v) for v in valor]


def _usar_resolver_falso(monkeypatch, respuestas: dict[tuple[str, str], object]) -> None:
    monkeypatch.setattr(
        dns_publico, "_crear_resolver", lambda tiempo_limite: _ResolverFalso(respuestas)
    )


def test_dominio_inexistente_produce_un_unico_hallazgo(monkeypatch):
    _usar_resolver_falso(monkeypatch, {("noexiste.invalido", "A"): dns.resolver.NXDOMAIN()})
    hallazgos = AdaptadorDNSPublico().investigar(
        "noexiste.invalido", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
    )
    assert len(hallazgos) == 1
    assert "no existe" in hallazgos[0].titulo.lower()


def test_registros_presentes_se_reportan_con_evidencias(monkeypatch):
    _usar_resolver_falso(
        monkeypatch,
        {
            ("ejemplo.com", "A"): ["93.184.216.34"],
            ("ejemplo.com", "MX"): ["10 mail.ejemplo.com."],
            ("ejemplo.com", "NS"): ["ns1.ejemplo.com."],
            ("ejemplo.com", "TXT"): ["v=spf1 include:_spf.ejemplo.com ~all"],
        },
    )
    hallazgos = AdaptadorDNSPublico().investigar(
        "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
    )
    categorias_titulos = {h.titulo for h in hallazgos}
    assert "Registros A" in categorias_titulos
    assert "Registros MX" in categorias_titulos
    assert "SPF configurado" in categorias_titulos
    assert "DMARC no configurado" in categorias_titulos  # no se registro _dmarc.ejemplo.com


def test_spf_ausente_marca_indicador_de_exposicion(monkeypatch):
    _usar_resolver_falso(monkeypatch, {("ejemplo.com", "A"): ["93.184.216.34"]})
    hallazgos = AdaptadorDNSPublico().investigar(
        "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
    )
    spf = next(h for h in hallazgos if h.titulo == "SPF no configurado")
    assert spf.indicador_exposicion is not None
    assert spf.nivel_confianza == "confirmado"


def test_dmarc_configurado_en_modo_none_marca_indicador(monkeypatch):
    _usar_resolver_falso(
        monkeypatch,
        {
            ("ejemplo.com", "A"): ["93.184.216.34"],
            ("_dmarc.ejemplo.com", "TXT"): ["v=DMARC1; p=none;"],
        },
    )
    hallazgos = AdaptadorDNSPublico().investigar(
        "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
    )
    dmarc = next(h for h in hallazgos if h.titulo == "DMARC configurado")
    assert dmarc.indicador_exposicion is not None


def test_cancelacion_antes_de_consultar_devuelve_sin_hallazgos(monkeypatch):
    _usar_resolver_falso(monkeypatch, {("ejemplo.com", "A"): ["93.184.216.34"]})
    hallazgos = AdaptadorDNSPublico().investigar(
        "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=lambda: True
    )
    assert hallazgos == []


def test_timeout_en_una_consulta_se_traduce_a_error_de_fuente(monkeypatch):
    from eurabyte_security.core.errores import ErrorFuenteOSINTError

    _usar_resolver_falso(monkeypatch, {("ejemplo.com", "A"): dns.exception.Timeout()})
    try:
        AdaptadorDNSPublico().investigar(
            "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
        )
    except ErrorFuenteOSINTError:
        pass
    else:
        raise AssertionError("se esperaba ErrorFuenteOSINTError")
