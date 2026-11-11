"""Fuente OSINT: coincidencia de nombre de usuario en APIs publicas documentadas.

Consulta exclusivamente APIs REST publicas y oficiales que devuelven 404/lista vacia de
forma documentada cuando un nombre de usuario no existe (GitHub, GitLab): nunca
"scrapea" una pagina de perfil ni intenta eludir un CAPTCHA o un bloqueo de otra
plataforma (ver seccion 2.D de la especificacion: "no eludir restricciones de acceso").
Ambas son de uso anonimo con limite de tasa generoso para este volumen de uso
(GitHub: 60 peticiones/hora sin autenticar; GitLab: sin limite especifico documentado
para este endpoint a fecha de redaccion).

**Una coincidencia de nombre de usuario NUNCA implica una identidad confirmada**: cada
hallazgo se marca con nivel de confianza 'probable' y su descripcion lo dice
explicitamente, porque dos personas distintas pueden compartir el mismo nombre de
usuario en plataformas distintas.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from eurabyte_security.core.errores import ErrorFuenteOSINTError
from eurabyte_security.integrations.osint.base import AdaptadorFuenteOSINT
from eurabyte_security.integrations.osint.cliente_http import peticion_json
from eurabyte_security.modules.osint.modelos import EvidenciaOSINT, HallazgoOSINT

URL_DOCUMENTACION_GITHUB = "https://docs.github.com/en/rest/users/users#get-a-user"
URL_DOCUMENTACION_GITLAB = "https://docs.gitlab.com/ee/api/users.html"

AVISO_COINCIDENCIA = (
    "Coincidencia de nombre de usuario, no una identidad confirmada: dos personas "
    "distintas pueden usar el mismo nombre de usuario en plataformas distintas."
)


def _ahora() -> str:
    return datetime.now(UTC).isoformat()


def _buscar_github(usuario: str, tiempo_limite: float, debe_cancelar) -> HallazgoOSINT | None:
    url = f"https://api.github.com/users/{usuario}"
    try:
        datos = peticion_json(url, tiempo_limite=tiempo_limite, debe_cancelar=debe_cancelar)
    except ErrorFuenteOSINTError as exc:
        if "404" in str(exc):
            return None
        raise
    if not isinstance(datos, dict):
        raise ErrorFuenteOSINTError("GitHub devolvio una respuesta con formato inesperado.")

    perfil_url = datos.get("html_url") or f"https://github.com/{usuario}"
    creado = datos.get("created_at")
    detalle = f"Perfil publico de GitHub: {perfil_url}."
    if creado:
        detalle += f" Creado: {creado}."
    return HallazgoOSINT(
        categoria="perfil_publico",
        titulo="Coincidencia en GitHub",
        descripcion=f"{detalle} {AVISO_COINCIDENCIA}",
        nivel_confianza="probable",
        indicador_exposicion=None,
        evidencias=(
            EvidenciaOSINT(
                fuente="perfiles_publicos",
                fecha_consulta=_ahora(),
                referencia=perfil_url,
                valor=usuario,
            ),
        ),
    )


def _buscar_gitlab(usuario: str, tiempo_limite: float, debe_cancelar) -> HallazgoOSINT | None:
    url = f"https://gitlab.com/api/v4/users?username={usuario}"
    datos = peticion_json(url, tiempo_limite=tiempo_limite, debe_cancelar=debe_cancelar)
    if not isinstance(datos, list) or not datos:
        return None
    perfil = datos[0]
    perfil_url = perfil.get("web_url") or f"https://gitlab.com/{usuario}"
    return HallazgoOSINT(
        categoria="perfil_publico",
        titulo="Coincidencia en GitLab",
        descripcion=f"Perfil publico de GitLab: {perfil_url}. {AVISO_COINCIDENCIA}",
        nivel_confianza="probable",
        indicador_exposicion=None,
        evidencias=(
            EvidenciaOSINT(
                fuente="perfiles_publicos",
                fecha_consulta=_ahora(),
                referencia=perfil_url,
                valor=usuario,
            ),
        ),
    )


class AdaptadorPerfilesPublicos(AdaptadorFuenteOSINT):
    id_fuente = "perfiles_publicos"
    nombre = "Perfiles publicos (GitHub, GitLab)"
    tipos_objetivo = frozenset({"usuario"})
    url_documentacion = URL_DOCUMENTACION_GITHUB

    def investigar(
        self,
        objetivo: str,
        *,
        tipo_objetivo: str,
        tiempo_limite: float,
        debe_cancelar: Callable[[], bool] | None,
    ) -> list[HallazgoOSINT]:
        hallazgos: list[HallazgoOSINT] = []

        hallazgo_github = _buscar_github(objetivo, tiempo_limite, debe_cancelar)
        if hallazgo_github:
            hallazgos.append(hallazgo_github)

        if debe_cancelar is not None and debe_cancelar():
            return hallazgos

        hallazgo_gitlab = _buscar_gitlab(objetivo, tiempo_limite, debe_cancelar)
        if hallazgo_gitlab:
            hallazgos.append(hallazgo_gitlab)

        return hallazgos
