from __future__ import annotations

from eurabyte_security.modules.web.redaccion import redactar_url


def test_redacta_parametros_sensibles_conocidos():
    url = "https://127.0.0.1:8443/reset?token=supersecreto123&usuario=ana"
    resultado = redactar_url(url)
    assert "supersecreto123" not in resultado
    assert "token=%3Credactado%3E" in resultado or "token=<redactado>" in resultado
    assert "usuario=ana" in resultado


def test_no_modifica_url_sin_parametros_sensibles():
    url = "https://127.0.0.1:8443/panel?pagina=2&orden=asc"
    assert redactar_url(url) == url


def test_no_modifica_url_sin_query():
    url = "https://127.0.0.1:8443/panel"
    assert redactar_url(url) == url


def test_preserva_esquema_host_puerto_y_ruta():
    url = "https://127.0.0.1:8443/area/segura?api_key=xyz"
    resultado = redactar_url(url)
    assert resultado.startswith("https://127.0.0.1:8443/area/segura?")
    assert "xyz" not in resultado


def test_varios_parametros_sensibles_distintos():
    url = "http://127.0.0.1/cb?code=abc&password=def&session_id=ghi&pagina=1"
    resultado = redactar_url(url)
    for secreto in ("abc", "def", "ghi"):
        assert secreto not in resultado
    assert "pagina=1" in resultado


def test_insensible_a_mayusculas_en_el_nombre_del_parametro():
    url = "http://127.0.0.1/?Token=secreto&API_KEY=otrosecreto"
    resultado = redactar_url(url)
    assert "secreto" not in resultado
    assert "otrosecreto" not in resultado


def test_url_malformada_se_devuelve_sin_cambios_en_vez_de_fallar():
    url = "no es una url valida"
    assert redactar_url(url) == url


def test_url_con_puerto_invalido_se_devuelve_sin_cambios_en_vez_de_fallar():
    url = "http://127.0.0.1:no-es-un-puerto/"
    assert redactar_url(url) == url


def test_elimina_credenciales_del_host():
    url = "http://admin:supersecreta@127.0.0.1:8080/panel"
    resultado = redactar_url(url)
    assert "admin" not in resultado
    assert "supersecreta" not in resultado
    assert resultado == "http://127.0.0.1:8080/panel"


def test_elimina_credenciales_del_host_aunque_no_haya_query_ni_fragmento():
    url = "http://usuario:clave@127.0.0.1/"
    resultado = redactar_url(url)
    assert "usuario" not in resultado
    assert "clave" not in resultado


def test_redacta_fragmento_con_forma_de_parametros_tipo_oauth_implicito():
    url = "https://127.0.0.1/callback#access_token=secreto-fragmento&expires_in=3600"
    resultado = redactar_url(url)
    assert "secreto-fragmento" not in resultado
    assert "expires_in=3600" in resultado


def test_no_modifica_un_fragmento_que_no_tiene_forma_de_parametros():
    url = "https://127.0.0.1/doc#seccion-2"
    assert redactar_url(url) == url


def test_coincidencia_por_substring_captura_variantes_no_exactas():
    url = "http://127.0.0.1/?auth_token=secreto1&my_api_key=secreto2&x_session_id=secreto3"
    resultado = redactar_url(url)
    for secreto in ("secreto1", "secreto2", "secreto3"):
        assert secreto not in resultado
