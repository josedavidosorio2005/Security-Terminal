from __future__ import annotations

from eurabyte_security.modules.web.cabeceras import evaluar_cabeceras


def _severidad(hallazgos, id_: str) -> str:
    return next(h.severidad for h in hallazgos if h.id_ == id_)


def test_cabeceras_completas_y_seguras_dan_severidad_baja_o_informativa():
    cabeceras = (
        ("Content-Security-Policy", "default-src 'self'"),
        ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ("Permissions-Policy", "geolocation=()"),
    )
    hallazgos = evaluar_cabeceras(cabeceras, esquema="https")
    assert all(h.severidad in ("info", "baja") for h in hallazgos)


def test_cabeceras_ausentes_no_se_marcan_todas_como_criticas():
    hallazgos = evaluar_cabeceras((), esquema="https")
    # No existe "critica" en la escala: ninguna cabecera ausente por si sola llega
    # al nivel mas alto definido (ver modules/web/modelos.py).
    assert all(h.severidad in ("info", "baja", "media") for h in hallazgos)
    assert _severidad(hallazgos, "content-security-policy") == "media"
    assert _severidad(hallazgos, "strict-transport-security") == "media"


def test_hsts_no_aplica_sobre_http():
    hallazgos = evaluar_cabeceras((), esquema="http")
    hsts = next(h for h in hallazgos if h.id_ == "strict-transport-security")
    assert hsts.severidad == "info"
    assert "No aplica" in hsts.estado


def test_x_frame_options_ausente_pero_csp_con_frame_ancestors_reduce_severidad():
    cabeceras = (("Content-Security-Policy", "frame-ancestors 'self'"),)
    hallazgos = evaluar_cabeceras(cabeceras, esquema="https")
    xfo = next(h for h in hallazgos if h.id_ == "x-frame-options")
    assert xfo.severidad == "info"


def test_csp_permisiva_se_detecta():
    cabeceras = (("Content-Security-Policy", "default-src *; script-src 'unsafe-inline'"),)
    hallazgos = evaluar_cabeceras(cabeceras, esquema="https")
    csp = next(h for h in hallazgos if h.id_ == "content-security-policy")
    assert csp.severidad == "baja"
    assert "permisiv" in csp.estado.lower()


def test_divulgacion_de_servidor_se_detecta_como_hallazgo_adicional():
    cabeceras = (("Server", "nginx/1.18.0"), ("X-Powered-By", "PHP/7.2.1"))
    hallazgos = evaluar_cabeceras(cabeceras, esquema="https")
    divulgacion = next(h for h in hallazgos if h.id_ == "divulgacion-servidor")
    assert "nginx/1.18.0" in divulgacion.valor_detectado
    assert "PHP/7.2.1" in divulgacion.valor_detectado


def test_cors_permisivo_se_detecta():
    cabeceras = (("Access-Control-Allow-Origin", "*"),)
    hallazgos = evaluar_cabeceras(cabeceras, esquema="https")
    cors = next(h for h in hallazgos if h.id_ == "access-control-allow-origin")
    assert cors.severidad == "media"


def test_cache_control_solo_se_evalua_si_hay_cookies():
    sin_cookies = evaluar_cabeceras((), esquema="https")
    assert not any(h.id_ == "cache-control" for h in sin_cookies)

    con_cookies_inseguro = evaluar_cabeceras(
        (("Set-Cookie", "sesion=abc"),), esquema="https"
    )
    cache = next(h for h in con_cookies_inseguro if h.id_ == "cache-control")
    assert cache.severidad == "baja"

    con_cookies_seguro = evaluar_cabeceras(
        (("Set-Cookie", "sesion=abc"), ("Cache-Control", "no-store")), esquema="https"
    )
    cache_ok = next(h for h in con_cookies_seguro if h.id_ == "cache-control")
    assert cache_ok.severidad == "info"
