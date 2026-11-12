"""Dataclasses compartidas por el motor OSINT, sus fuentes y su persistencia.

Sin dependencias de Typer, Rich ni Textual (igual que ``modules/reconocimiento``, salvo
que aqui vive directamente en ``commands/reconocimiento.py``): tanto la CLI como la
futura interfaz visual importan y ejecutan ``modules/osint/motor.py`` con los mismos
tipos definidos aqui.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Estados reales de una fuente dentro de una investigacion -- nunca un porcentaje
# inventado, mismo principio que ``commands/reconocimiento.py:EtapaReconocimiento``.
ESTADOS_FUENTE_OSINT_VALIDOS: frozenset[str] = frozenset(
    {"pendiente", "ejecutando", "completada", "omitida", "fallida", "cancelada"}
)

# Nivel de confianza de un hallazgo: 'confirmado' (dato leido directamente de una fuente
# autoritativa, ej. un registro DNS o RDAP), 'probable' (evidencia indirecta o con margen
# de error, ej. una coincidencia de nombre de usuario o un registro de Certificate
# Transparency que no garantiza que el subdominio siga activo) o 'no_verificado'
# (asociacion que la propia fuente marca como no confirmada). Nunca se inventa un nivel
# mas alto que el que la fuente puede respaldar.
NIVELES_CONFIANZA_OSINT: frozenset[str] = frozenset({"confirmado", "probable", "no_verificado"})


@dataclass(frozen=True, slots=True)
class EvidenciaOSINT:
    """Un dato concreto, ya saneado, observado en una fuente, con su procedencia.

    ``fecha_consulta`` es SIEMPRE cuando AST consulto la fuente (momento de la
    investigacion). ``fecha_observada`` es la fecha que la propia fuente le atribuye al
    dato en si -- p. ej. cuando crt.sh registro un certificado, o cuando urlscan.io
    escaneo una pagina -- que casi siempre es anterior a ``fecha_consulta`` y que una
    fuente puramente local (sin consulta de red, p. ej. metadatos de numeracion
    telefonica) no tiene: ``None`` cuando la fuente no distingue ambos momentos.
    """

    fuente: str
    fecha_consulta: str  # ISO-8601 (UTC)
    referencia: str | None  # URL de la fuente/documentacion oficial, si existe
    valor: str
    fecha_observada: str | None = None  # fecha historica que reporta la propia fuente

    def como_dict(self) -> dict[str, str | None]:
        return {
            "fuente": self.fuente,
            "fecha_consulta": self.fecha_consulta,
            "referencia": self.referencia,
            "valor": self.valor,
            "fecha_observada": self.fecha_observada,
        }

    @staticmethod
    def desde_dict(datos: dict) -> EvidenciaOSINT:
        return EvidenciaOSINT(
            fuente=datos["fuente"],
            fecha_consulta=datos["fecha_consulta"],
            referencia=datos.get("referencia"),
            valor=datos["valor"],
            fecha_observada=datos.get("fecha_observada"),
        )


@dataclass(frozen=True, slots=True)
class HallazgoOSINT:
    """Un hallazgo de una fuente OSINT, con su evidencia y nivel de confianza.

    ``indicador_exposicion`` es ``None`` cuando el hallazgo es informativo (p. ej. un
    registro DNS normal) y solo lleva texto cuando describe una posible exposicion o
    desviacion de buenas practicas (p. ej. SPF/DMARC ausente, un subdominio expuesto en
    Certificate Transparency). Nunca se inventa un indicador cuando no hay una razon
    concreta que lo respalde.
    """

    categoria: str
    titulo: str
    descripcion: str
    nivel_confianza: str
    indicador_exposicion: str | None
    evidencias: tuple[EvidenciaOSINT, ...] = field(default_factory=tuple)

    def como_dict(self) -> dict:
        return {
            "categoria": self.categoria,
            "titulo": self.titulo,
            "descripcion": self.descripcion,
            "nivel_confianza": self.nivel_confianza,
            "indicador_exposicion": self.indicador_exposicion,
            "evidencias": [e.como_dict() for e in self.evidencias],
        }

    @staticmethod
    def desde_dict(datos: dict) -> HallazgoOSINT:
        return HallazgoOSINT(
            categoria=datos["categoria"],
            titulo=datos["titulo"],
            descripcion=datos["descripcion"],
            nivel_confianza=datos["nivel_confianza"],
            indicador_exposicion=datos.get("indicador_exposicion"),
            evidencias=tuple(EvidenciaOSINT.desde_dict(e) for e in datos.get("evidencias", [])),
        )


@dataclass(frozen=True, slots=True)
class EtapaFuenteOSINT:
    """Estado de una sola fuente dentro de una investigacion en curso."""

    fuente: str
    estado: str
    detalle: str

    def como_dict(self) -> dict[str, str]:
        return {"fuente": self.fuente, "estado": self.estado, "detalle": self.detalle}

    @staticmethod
    def desde_dict(datos: dict) -> EtapaFuenteOSINT:
        return EtapaFuenteOSINT(
            fuente=datos["fuente"], estado=datos["estado"], detalle=datos["detalle"]
        )


@dataclass(frozen=True, slots=True)
class ResultadoInvestigacionOSINT:
    """Resultado final (o parcial, si se cancelo) de una investigacion OSINT completa."""

    investigacion_id: int
    tipo_objetivo: str
    objetivo_original: str
    objetivo_saneado: str
    estado_general: str
    etapas: tuple[EtapaFuenteOSINT, ...]
    limitaciones: tuple[str, ...]
    total_hallazgos: int
    ruta_informe_html: str | None = None
    ruta_informe_json: str | None = None
