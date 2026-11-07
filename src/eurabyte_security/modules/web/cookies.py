"""Auditoria de atributos de cookies (``Set-Cookie``).

Nunca se guarda ni se muestra el valor real de una cookie: solo su nombre y sus
atributos. ``_redactar`` es el unico punto que construye la representacion visible de
una cookie, precisamente para que ningun otro codigo pueda filtrar un valor de sesion o
un token por error en un log, un hallazgo o un informe.
"""

from __future__ import annotations

from http.cookies import SimpleCookie

from eurabyte_security.modules.web.modelos import Hallazgo, Severidad

_REFERENCIA_MDN = "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie"

# Nombres que sugieren una cookie de autenticacion/sesion: sus problemas de
# configuracion se evaluan con mayor severidad que una cookie generica.
_PATRONES_SENSIBLES = ("sess", "auth", "token", "sid", "csrf", "login", "jwt")


def _es_sensible(nombre: str) -> bool:
    nombre_bajo = nombre.lower()
    return any(patron in nombre_bajo for patron in _PATRONES_SENSIBLES)


def _redactar(nombre: str, atributos: list[str]) -> str:
    partes = [f"{nombre}=<redactado>", *atributos]
    return "; ".join(partes)


def _analizar_una_cookie(set_cookie_valor: str) -> list[Hallazgo]:
    cocina: SimpleCookie = SimpleCookie()
    try:
        cocina.load(set_cookie_valor)
    except Exception:  # noqa: BLE001 - cookie malformada: se reporta, no se interrumpe la auditoria
        return [
            Hallazgo(
                categoria="cookie",
                id_="cookie-malformada",
                nombre="Cookie malformada",
                significado="La cabecera Set-Cookie no se pudo interpretar.",
                proposito="Detectar configuraciones de cookies invalidas o inesperadas.",
                valor_detectado="(valor de la cookie omitido/redactado)",
                severidad="baja",
                estado="Malformada",
                riesgo="Un cliente real podria interpretarla de forma distinta a la esperada.",
                recomendacion="Revisa la sintaxis de la cabecera Set-Cookie en el servidor.",
                referencia=_REFERENCIA_MDN,
            )
        ]

    hallazgos: list[Hallazgo] = []
    for nombre, morsel in cocina.items():
        sensible = _es_sensible(nombre)
        atributos_presentes = [
            etiqueta
            for etiqueta, clave in (("Secure", "secure"), ("HttpOnly", "httponly"))
            if morsel[clave]
        ]
        same_site = (morsel["samesite"] or "").strip()
        if same_site:
            atributos_presentes.append(f"SameSite={same_site}")
        expira = morsel["expires"] or morsel["max-age"]
        valor_redactado = _redactar(nombre, atributos_presentes)

        if not morsel["secure"]:
            severidad: Severidad = "alta" if sensible else "media"
            hallazgos.append(
                Hallazgo(
                    categoria="cookie",
                    id_=f"cookie-{nombre}-secure",
                    nombre=f"Cookie '{nombre}': atributo Secure",
                    significado=(
                        "Secure impide que la cookie se envie por una conexion HTTP sin cifrar."
                    ),
                    proposito=(
                        "Evitar que la cookie se filtre en texto claro en una red no confiable."
                    ),
                    valor_detectado=valor_redactado,
                    severidad=severidad,
                    estado="Ausente",
                    riesgo=(
                        "Esta cookie parece de autenticacion/sesion y puede enviarse por HTTP, "
                        "exponiendola a cualquiera en la red."
                        if sensible
                        else "La cookie puede enviarse por HTTP sin cifrar."
                    ),
                    recomendacion="Agrega el atributo 'Secure' (y sirve el sitio solo por HTTPS).",
                    referencia=_REFERENCIA_MDN,
                )
            )

        if not morsel["httponly"]:
            severidad = "alta" if sensible else "media"
            hallazgos.append(
                Hallazgo(
                    categoria="cookie",
                    id_=f"cookie-{nombre}-httponly",
                    nombre=f"Cookie '{nombre}': atributo HttpOnly",
                    significado="HttpOnly impide que JavaScript en la pagina lea esta cookie.",
                    proposito=(
                        "Reducir el impacto de un XSS: un script inyectado no podria "
                        "robar la cookie."
                    ),
                    valor_detectado=valor_redactado,
                    severidad=severidad,
                    estado="Ausente",
                    riesgo=(
                        "Un XSS en la pagina podria robar esta cookie de sesion/autenticacion."
                        if sensible
                        else "Un XSS en la pagina podria leer esta cookie desde JavaScript."
                    ),
                    recomendacion=(
                        "Agrega el atributo 'HttpOnly' si JavaScript no necesita leer esta cookie."
                    ),
                    referencia=_REFERENCIA_MDN,
                )
            )

        same_site_normalizado = same_site.lower()
        if not same_site_normalizado:
            hallazgos.append(
                Hallazgo(
                    categoria="cookie",
                    id_=f"cookie-{nombre}-samesite",
                    nombre=f"Cookie '{nombre}': atributo SameSite",
                    significado=(
                        "SameSite controla si la cookie se envia en peticiones de otros sitios."
                    ),
                    proposito=(
                        "Mitigar CSRF al no enviar la cookie en peticiones iniciadas "
                        "desde otro origen."
                    ),
                    valor_detectado=valor_redactado,
                    severidad="media",
                    estado="Ausente",
                    riesgo=(
                        "La cookie puede enviarse en peticiones iniciadas desde otros "
                        "sitios (riesgo de CSRF)."
                    ),
                    recomendacion="Define 'SameSite=Lax' (o 'Strict' si la aplicacion lo permite).",
                    referencia=_REFERENCIA_MDN,
                )
            )
        elif same_site_normalizado == "none" and not morsel["secure"]:
            hallazgos.append(
                Hallazgo(
                    categoria="cookie",
                    id_=f"cookie-{nombre}-samesite-none",
                    nombre=f"Cookie '{nombre}': SameSite=None sin Secure",
                    significado=(
                        "SameSite=None permite enviar la cookie entre sitios, pero exige Secure."
                    ),
                    proposito="Los navegadores modernos rechazan 'SameSite=None' sin 'Secure'.",
                    valor_detectado=valor_redactado,
                    severidad="media",
                    estado="Configuracion invalida",
                    riesgo="Navegadores actuales pueden descartar esta cookie por completo.",
                    recomendacion=(
                        "Agrega 'Secure' junto con 'SameSite=None', o usa 'Lax'/'Strict'."
                    ),
                    referencia=_REFERENCIA_MDN,
                )
            )

        if not expira:
            hallazgos.append(
                Hallazgo(
                    categoria="cookie",
                    id_=f"cookie-{nombre}-expiracion",
                    nombre=f"Cookie '{nombre}': sin expiracion explicita",
                    significado=(
                        "Sin 'Expires'/'Max-Age', la cookie es de sesion (se borra al "
                        "cerrar el navegador)."
                    ),
                    proposito="Informativo: confirma el ciclo de vida esperado de la cookie.",
                    valor_detectado=valor_redactado,
                    severidad="info",
                    estado="Cookie de sesion",
                    riesgo="Ninguno por si solo; revisa si este es el comportamiento esperado.",
                    recomendacion=(
                        "Ninguna accion necesaria si se espera que sea una cookie de sesion."
                    ),
                    referencia=_REFERENCIA_MDN,
                )
            )

    return hallazgos


def evaluar_cookies(cabeceras_crudas: tuple[tuple[str, str], ...]) -> list[Hallazgo]:
    """Evalua todas las cabeceras ``Set-Cookie`` de una respuesta (puede haber varias)."""
    hallazgos: list[Hallazgo] = []
    for nombre, valor in cabeceras_crudas:
        if nombre.lower() == "set-cookie":
            hallazgos.extend(_analizar_una_cookie(valor))
    return hallazgos
