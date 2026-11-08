"""Auditoria de cabeceras HTTP de seguridad.

Cada cabecera se evalua con su propio contexto (p. ej. HSTS no aplica sobre HTTP, y la
ausencia de una cabecera defensiva no siempre es critica) en vez de marcar toda cabecera
ausente como la misma severidad, tal como pide la auditoria.
"""

from __future__ import annotations

from eurabyte_security.modules.web.modelos import Hallazgo, Severidad

_REFERENCIA_MDN = "https://developer.mozilla.org/docs/Web/HTTP/Headers/{}"


def _buscar(cabeceras: dict[str, str], nombre: str) -> str | None:
    return cabeceras.get(nombre.lower())


def _hallazgo_csp(valor: str | None) -> Hallazgo:
    if valor is None:
        severidad: Severidad = "media"
        estado = "Ausente"
        riesgo = (
            "Sin CSP, el navegador no tiene una capa adicional de defensa contra XSS/"
            "inyeccion de contenido: cualquier script inyectado se ejecuta sin restriccion."
        )
        recomendacion = (
            "Define una Content-Security-Policy que al menos restrinja 'default-src' a "
            "origenes conocidos; evita 'unsafe-inline'/'unsafe-eval' si es posible."
        )
    else:
        permisiva = "unsafe-inline" in valor or "unsafe-eval" in valor or "*" in valor
        severidad = "baja" if permisiva else "info"
        estado = "Presente (con directivas permisivas)" if permisiva else "Presente"
        riesgo = (
            "La politica presente incluye comodines o permite scripts/eval inline, lo "
            "que reduce la proteccion real de la CSP."
            if permisiva
            else "Ninguno detectado: la politica no usa comodines ni directivas permisivas comunes."
        )
        recomendacion = (
            "Evita '*', 'unsafe-inline' y 'unsafe-eval'; usa nonces o hashes para scripts "
            "en linea si son necesarios."
            if permisiva
            else "Ninguna accion necesaria."
        )
    return Hallazgo(
        categoria="cabecera",
        id_="content-security-policy",
        nombre="Content-Security-Policy",
        significado=(
            "Declara que origenes y comportamientos puede usar la pagina (scripts, "
            "estilos, imagenes, conexiones...)."
        ),
        proposito="Mitigar XSS y otros ataques de inyeccion de contenido en el navegador.",
        valor_detectado=valor,
        severidad=severidad,
        estado=estado,
        riesgo=riesgo,
        recomendacion=recomendacion,
        referencia=_REFERENCIA_MDN.format("Content-Security-Policy"),
    )


def _hallazgo_hsts(valor: str | None, *, esquema: str) -> Hallazgo:
    if esquema != "https":
        return Hallazgo(
            categoria="cabecera",
            id_="strict-transport-security",
            nombre="Strict-Transport-Security (HSTS)",
            significado="Indica al navegador que solo debe hablar HTTPS con este sitio.",
            proposito="Evitar ataques de downgrade a HTTP y el robo de sesion por sslstrip.",
            valor_detectado=None,
            severidad="info",
            estado="No aplica (HTTP)",
            riesgo="No aplica: esta respuesta no fue servida por HTTPS.",
            recomendacion="Si este servicio tambien se sirve por HTTPS, agrega HSTS alli.",
            referencia=_REFERENCIA_MDN.format("Strict-Transport-Security"),
        )
    if valor is None:
        severidad: Severidad = "media"
        estado = "Ausente"
        riesgo = (
            "Sin HSTS, un usuario que escriba o siga un enlace http:// puede ser "
            "interceptado antes de llegar a la version HTTPS (downgrade/sslstrip)."
        )
        recomendacion = (
            "Agrega 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
            "(y 'preload' si aplica a todo el dominio)."
        )
    else:
        max_age_bajo = "max-age=0" in valor.replace(" ", "")
        severidad = "baja" if max_age_bajo else "info"
        estado = "Presente (max-age muy bajo)" if max_age_bajo else "Presente"
        riesgo = (
            "Un 'max-age' muy bajo (o 0) limita la proteccion real de HSTS."
            if max_age_bajo
            else "Ninguno detectado."
        )
        recomendacion = (
            "Aumenta 'max-age' a al menos un ano (31536000 segundos)."
            if max_age_bajo
            else "Ninguna accion necesaria."
        )
    return Hallazgo(
        categoria="cabecera",
        id_="strict-transport-security",
        nombre="Strict-Transport-Security (HSTS)",
        significado="Indica al navegador que solo debe hablar HTTPS con este sitio.",
        proposito="Evitar ataques de downgrade a HTTP y el robo de sesion por sslstrip.",
        valor_detectado=valor,
        severidad=severidad,
        estado=estado,
        riesgo=riesgo,
        recomendacion=recomendacion,
        referencia=_REFERENCIA_MDN.format("Strict-Transport-Security"),
    )


def _hallazgo_x_content_type_options(valor: str | None) -> Hallazgo:
    correcto = valor is not None and valor.strip().lower() == "nosniff"
    return Hallazgo(
        categoria="cabecera",
        id_="x-content-type-options",
        nombre="X-Content-Type-Options",
        significado="Evita que el navegador intente adivinar (sniff) el tipo de contenido.",
        proposito="Evitar que un archivo subido como imagen/texto se interprete como script.",
        valor_detectado=valor,
        severidad="info" if correcto else "baja",
        estado=(
            "Presente (nosniff)"
            if correcto
            else ("Presente con otro valor" if valor else "Ausente")
        ),
        riesgo=(
            "Ninguno detectado."
            if correcto
            else (
                "El navegador puede reinterpretar el tipo de un recurso (MIME sniffing), "
                "lo que facilita XSS si la aplicacion permite subir/servir contenido de "
                "usuarios."
            )
        ),
        recomendacion=(
            "Agrega 'X-Content-Type-Options: nosniff'."
            if not correcto
            else "Ninguna accion necesaria."
        ),
        referencia=_REFERENCIA_MDN.format("X-Content-Type-Options"),
    )


def _hallazgo_x_frame_options(valor: str | None, *, csp: str | None) -> Hallazgo:
    tiene_frame_ancestors = csp is not None and "frame-ancestors" in csp.lower()
    if valor is not None:
        severidad: Severidad = "info"
        estado = "Presente"
        riesgo = "Ninguno detectado."
        recomendacion = "Ninguna accion necesaria."
    elif tiene_frame_ancestors:
        severidad = "info"
        estado = "Ausente, pero CSP define 'frame-ancestors'"
        riesgo = "Bajo: la proteccion equivalente ya la cubre la CSP presente."
        recomendacion = (
            "Ninguna accion obligatoria; X-Frame-Options sigue siendo util como "
            "respaldo en navegadores antiguos."
        )
    else:
        severidad = "media"
        estado = "Ausente"
        riesgo = (
            "La pagina puede incrustarse en un <iframe> de otro sitio, habilitando "
            "ataques de clickjacking."
        )
        recomendacion = (
            "Agrega 'X-Frame-Options: DENY' o 'SAMEORIGIN' (o 'frame-ancestors' en la CSP)."
        )
    return Hallazgo(
        categoria="cabecera",
        id_="x-frame-options",
        nombre="X-Frame-Options",
        significado="Controla si la pagina puede mostrarse dentro de un <iframe>.",
        proposito=(
            "Prevenir clickjacking (enganar al usuario para que haga clic sobre "
            "contenido oculto)."
        ),
        valor_detectado=valor,
        severidad=severidad,
        estado=estado,
        riesgo=riesgo,
        recomendacion=recomendacion,
        referencia=_REFERENCIA_MDN.format("X-Frame-Options"),
    )


def _hallazgo_referrer_policy(valor: str | None) -> Hallazgo:
    if valor is None:
        severidad: Severidad = "baja"
        estado = "Ausente"
        riesgo = (
            "Con el valor por defecto del navegador, la URL completa de esta pagina "
            "puede filtrarse como 'Referer' a sitios de terceros enlazados."
        )
        recomendacion = (
            "Agrega 'Referrer-Policy: strict-origin-when-cross-origin' (o mas restrictivo)."
        )
    else:
        permisiva = valor.strip().lower() in {"unsafe-url", "no-referrer-when-downgrade"}
        severidad = "baja" if permisiva else "info"
        estado = "Presente (valor permisivo)" if permisiva else "Presente"
        riesgo = (
            "El valor configurado puede filtrar la URL completa a sitios externos."
            if permisiva
            else "Ninguno detectado."
        )
        recomendacion = (
            "Usa 'strict-origin-when-cross-origin' o 'no-referrer' salvo que la aplicacion "
            "dependa explicitamente del Referer completo."
            if permisiva
            else "Ninguna accion necesaria."
        )
    return Hallazgo(
        categoria="cabecera",
        id_="referrer-policy",
        nombre="Referrer-Policy",
        significado="Controla que informacion de la URL de origen se envia al navegar fuera.",
        proposito="Evitar fugas de informacion (rutas, tokens en la URL) hacia sitios externos.",
        valor_detectado=valor,
        severidad=severidad,
        estado=estado,
        riesgo=riesgo,
        recomendacion=recomendacion,
        referencia=_REFERENCIA_MDN.format("Referrer-Policy"),
    )


def _hallazgo_permissions_policy(valor: str | None) -> Hallazgo:
    return Hallazgo(
        categoria="cabecera",
        id_="permissions-policy",
        nombre="Permissions-Policy",
        significado=(
            "Restringe que APIs del navegador (camara, geolocalizacion...) puede "
            "usar la pagina."
        ),
        proposito="Reducir la superficie de ataque frente a scripts de terceros comprometidos.",
        valor_detectado=valor,
        severidad="info" if valor is not None else "baja",
        estado="Presente" if valor is not None else "Ausente",
        riesgo=(
            "Ninguno detectado."
            if valor is not None
            else (
                "Sin esta cabecera, cualquier script con acceso a la pagina puede intentar "
                "usar APIs sensibles del navegador sin restriccion explicita. Impacto bajo "
                "en la mayoria de sitios que no usan esas APIs."
            )
        ),
        recomendacion=(
            "Ninguna accion necesaria."
            if valor is not None
            else "Define 'Permissions-Policy' deshabilitando las APIs que la aplicacion no use."
        ),
        referencia=_REFERENCIA_MDN.format("Permissions-Policy"),
    )


def _hallazgo_cache_control(valor: str | None, *, tiene_cookies: bool) -> Hallazgo | None:
    """Solo se evalua cuando la respuesta da indicios de contenido sensible (hay cookies).

    Evita marcar como hallazgo el Cache-Control de una pagina estatica sin estado: ahi no
    hay nada sensible que cachear de forma insegura.
    """
    if not tiene_cookies:
        return None

    valor_normalizado = (valor or "").lower()
    seguro = "no-store" in valor_normalizado or "private" in valor_normalizado
    severidad: Severidad = "info" if seguro else "baja"
    return Hallazgo(
        categoria="cabecera",
        id_="cache-control",
        nombre="Cache-Control",
        significado="Indica a navegadores y caches intermedias si pueden guardar la respuesta.",
        proposito=(
            "Evitar que respuestas con datos de sesion queden cacheadas (p. ej. en "
            "un proxy compartido)."
        ),
        valor_detectado=valor,
        severidad=severidad,
        estado="Adecuado" if seguro else ("Presente, pero permisivo" if valor else "Ausente"),
        riesgo=(
            "Ninguno detectado."
            if seguro
            else (
                "Esta respuesta establece cookies pero no indica 'no-store'/'private': un "
                "cache compartido (proxy, CDN) podria almacenar una respuesta con datos "
                "ligados a la sesion de un usuario."
            )
        ),
        recomendacion=(
            "Ninguna accion necesaria."
            if seguro
            else "Agrega 'Cache-Control: no-store' en respuestas que incluyan datos de sesion."
        ),
        referencia=_REFERENCIA_MDN.format("Cache-Control"),
    )


def _hallazgo_divulgacion_servidor(cabeceras: dict[str, str]) -> Hallazgo | None:
    valores: list[str] = [
        valor for n in ("server", "x-powered-by") if (valor := cabeceras.get(n))
    ]
    if not valores:
        return None
    return Hallazgo(
        categoria="cabecera",
        id_="divulgacion-servidor",
        nombre="Divulgacion de version del servidor",
        significado="Cabeceras 'Server'/'X-Powered-By' que anuncian el software y su version.",
        proposito=(
            "Minimizar la informacion que un atacante puede usar para buscar "
            "exploits conocidos."
        ),
        valor_detectado=" | ".join(valores),
        severidad="baja",
        estado="Presente",
        riesgo=(
            "Un atacante puede usar la version exacta anunciada para buscar vulnerabilidades "
            "conocidas de ese software."
        ),
        recomendacion=(
            "Oculta o genericiza estas cabeceras en la configuracion del servidor/framework."
        ),
        referencia=_REFERENCIA_MDN.format("Server"),
    )


def _hallazgo_cors_permisivo(valor: str | None) -> Hallazgo | None:
    if valor is None or valor.strip() != "*":
        return None
    return Hallazgo(
        categoria="cabecera",
        id_="access-control-allow-origin",
        nombre="Access-Control-Allow-Origin",
        significado="Declara que origenes pueden leer la respuesta via CORS desde JavaScript.",
        proposito=(
            "Restringir que sitios externos pueden consumir esta API/recurso desde "
            "el navegador."
        ),
        valor_detectado=valor,
        severidad="media",
        estado="Permisivo ('*')",
        riesgo=(
            "Cualquier sitio puede leer esta respuesta desde el navegador del usuario. Si el "
            "recurso devuelve datos sensibles o depende de cookies, esto facilita robo de "
            "datos entre sitios."
        ),
        recomendacion=(
            "Restringe 'Access-Control-Allow-Origin' a los origenes que realmente lo necesiten."
        ),
        referencia=_REFERENCIA_MDN.format("Access-Control-Allow-Origin"),
    )


def evaluar_cabeceras(
    cabeceras_crudas: tuple[tuple[str, str], ...], *, esquema: str
) -> list[Hallazgo]:
    """Evalua las cabeceras de seguridad de una respuesta HTTP ya obtenida."""
    cabeceras = {nombre.lower(): valor for nombre, valor in cabeceras_crudas}
    tiene_cookies = any(nombre.lower() == "set-cookie" for nombre, _ in cabeceras_crudas)
    csp = _buscar(cabeceras, "content-security-policy")

    hallazgos = [
        _hallazgo_csp(csp),
        _hallazgo_hsts(_buscar(cabeceras, "strict-transport-security"), esquema=esquema),
        _hallazgo_x_content_type_options(_buscar(cabeceras, "x-content-type-options")),
        _hallazgo_x_frame_options(_buscar(cabeceras, "x-frame-options"), csp=csp),
        _hallazgo_referrer_policy(_buscar(cabeceras, "referrer-policy")),
        _hallazgo_permissions_policy(_buscar(cabeceras, "permissions-policy")),
    ]

    opcionales = [
        _hallazgo_cache_control(_buscar(cabeceras, "cache-control"), tiene_cookies=tiene_cookies),
        _hallazgo_divulgacion_servidor(cabeceras),
        _hallazgo_cors_permisivo(_buscar(cabeceras, "access-control-allow-origin")),
    ]
    hallazgos.extend(h for h in opcionales if h is not None)
    return hallazgos
