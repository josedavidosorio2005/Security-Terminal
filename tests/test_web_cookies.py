from __future__ import annotations

from eurabyte_security.modules.web.cookies import evaluar_cookies


def test_cookie_segura_no_genera_hallazgos_de_secure_httponly_samesite():
    cabeceras = (("Set-Cookie", "pref=valor; Secure; HttpOnly; SameSite=Lax"),)
    hallazgos = evaluar_cookies(cabeceras)
    ids = {h.id_ for h in hallazgos}
    assert "cookie-pref-secure" not in ids
    assert "cookie-pref-httponly" not in ids
    assert "cookie-pref-samesite" not in ids


def test_cookie_sin_atributos_genera_hallazgos_con_valor_redactado():
    cabeceras = (("Set-Cookie", "sesion=secreto-super-sensible"),)
    hallazgos = evaluar_cookies(cabeceras)
    ids = {h.id_ for h in hallazgos}
    assert "cookie-sesion-secure" in ids
    assert "cookie-sesion-httponly" in ids
    assert "cookie-sesion-samesite" in ids

    # Ningun hallazgo debe contener el valor real de la cookie en texto plano.
    for h in hallazgos:
        assert "secreto-super-sensible" not in (h.valor_detectado or "")
        assert "<redactado>" in (h.valor_detectado or "")


def test_cookie_sensible_sin_secure_tiene_severidad_alta():
    cabeceras = (("Set-Cookie", "auth_token=xyz"),)
    hallazgos = evaluar_cookies(cabeceras)
    secure = next(h for h in hallazgos if h.id_ == "cookie-auth_token-secure")
    httponly = next(h for h in hallazgos if h.id_ == "cookie-auth_token-httponly")
    assert secure.severidad == "alta"
    assert httponly.severidad == "alta"


def test_cookie_no_sensible_sin_secure_tiene_severidad_media():
    cabeceras = (("Set-Cookie", "tema=oscuro"),)
    hallazgos = evaluar_cookies(cabeceras)
    secure = next(h for h in hallazgos if h.id_ == "cookie-tema-secure")
    assert secure.severidad == "media"


def test_samesite_none_sin_secure_es_configuracion_invalida():
    cabeceras = (("Set-Cookie", "x=1; SameSite=None"),)
    hallazgos = evaluar_cookies(cabeceras)
    assert any(h.id_ == "cookie-x-samesite-none" for h in hallazgos)


def test_cookie_sin_expiracion_es_informativa_no_un_riesgo():
    cabeceras = (("Set-Cookie", "x=1; Secure; HttpOnly; SameSite=Strict"),)
    hallazgos = evaluar_cookies(cabeceras)
    expiracion = next(h for h in hallazgos if h.id_ == "cookie-x-expiracion")
    assert expiracion.severidad == "info"


def test_varias_cabeceras_set_cookie_se_evaluan_todas():
    cabeceras = (
        ("Set-Cookie", "a=1; Secure; HttpOnly; SameSite=Strict"),
        ("Set-Cookie", "b=2"),
    )
    hallazgos = evaluar_cookies(cabeceras)
    nombres = {h.id_.split("-")[1] for h in hallazgos}
    assert "b" in nombres


def test_sin_set_cookie_no_hay_hallazgos():
    assert evaluar_cookies((("Content-Type", "text/html"),)) == []
