"""Catalogo de fuentes OSINT disponibles.

Punto unico de registro: ``est osint fuentes``, el motor (``modules/osint/motor.py``) y
la futura pestana "Fuentes" de la interfaz visual leen todos de aqui, nunca mantienen su
propia lista por separado. Anadir una fuente nueva (p. ej. un proveedor opcional en una
entrega futura) es instanciarla aqui una vez; ningun otro modulo necesita cambios.
"""

from __future__ import annotations

from eurabyte_security.integrations.osint.base import AdaptadorFuenteOSINT
from eurabyte_security.integrations.osint.certificados import AdaptadorCertificateTransparency
from eurabyte_security.integrations.osint.dns_publico import AdaptadorDNSPublico
from eurabyte_security.integrations.osint.hibp import AdaptadorHIBP
from eurabyte_security.integrations.osint.perfiles_publicos import AdaptadorPerfilesPublicos
from eurabyte_security.integrations.osint.rdap import (
    AdaptadorInfraestructuraIP,
    AdaptadorRDAPDominio,
)
from eurabyte_security.integrations.osint.telefono_metadatos import AdaptadorMetadatosTelefono
from eurabyte_security.integrations.osint.twilio_lookup import AdaptadorTwilioLookup
from eurabyte_security.integrations.osint.urlscan import AdaptadorUrlscan
from eurabyte_security.integrations.osint.virustotal import AdaptadorVirusTotal

FUENTES_OSINT: dict[str, AdaptadorFuenteOSINT] = {
    "dns": AdaptadorDNSPublico(),
    "rdap_dominio": AdaptadorRDAPDominio(),
    "infraestructura_ip": AdaptadorInfraestructuraIP(),
    "certificados": AdaptadorCertificateTransparency(),
    "perfiles_publicos": AdaptadorPerfilesPublicos(),
    "urlscan_historial": AdaptadorUrlscan(),
    "hibp": AdaptadorHIBP(),
    "virustotal": AdaptadorVirusTotal(),
    "telefono_metadatos": AdaptadorMetadatosTelefono(),
    "twilio_lookup": AdaptadorTwilioLookup(),
}


def fuentes_para_tipo(tipo_objetivo: str) -> dict[str, AdaptadorFuenteOSINT]:
    """Subconjunto del catalogo que admite ``tipo_objetivo``, en el orden del catalogo."""
    return {
        id_fuente: adaptador
        for id_fuente, adaptador in FUENTES_OSINT.items()
        if tipo_objetivo in adaptador.tipos_objetivo
    }
