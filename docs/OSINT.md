# OSINT: investigacion de fuentes publicas

El modulo OSINT investiga fuentes publicas verificables sobre un dominio/empresa, un
correo, un telefono o un nombre de usuario, dentro de un proyecto de AST. **Nunca
ejecuta un escaneo activo contra el objetivo**: toda consulta va contra una fuente
publica de terceros ya documentada (DNS, RDAP, Certificate Transparency, APIs publicas
de GitHub/GitLab, Have I Been Pwned...), nunca contra el propio dominio/IP/telefono
investigado.

Arquitectura en `src/eurabyte_security/`:

```text
core/osint/
└── validacion.py      Valida cada tipo de objetivo y exige autorizacion sobre datos
                        personales (correo, telefono, usuario) antes de consultar nada.

modules/osint/
├── modelos.py          Dataclasses compartidas (HallazgoOSINT, EvidenciaOSINT...).
└── motor.py            Orquesta: valida, autoriza, recorre las fuentes aplicables y
                         persiste los hallazgos de cada una (sin dependencias de
                         Typer/Rich/Textual, igual que el orquestador de reconocimiento).

integrations/osint/
├── base.py             Contrato comun (AdaptadorFuenteOSINT): que tipos de objetivo
│                        admite, si requiere una clave opcional, timeout/cancelacion.
├── cliente_http.py      Unico punto de peticion HTTP(S): timeout, reintentos acotados
│                        que respetan `Retry-After`, cancelable, sin filtrar la URL
│                        completa (con posibles secretos) en un mensaje de error.
├── cache.py             Cache con caducidad en disco (bajo EST_HOME), por fuente/clave.
├── limitador.py          Limitador de tasa simple, por fuente, dentro del mismo proceso.
├── registro.py           Catalogo unico de fuentes (``FUENTES_OSINT``).
├── dns_publico.py        Registros DNS (A/AAAA/MX/NS/TXT/CNAME) + SPF/DMARC.
├── rdap.py                RDAP del dominio y de la infraestructura IP.
├── certificados.py        Certificate Transparency (crt.sh): subdominios observados.
└── perfiles_publicos.py   Coincidencia de nombre de usuario (GitHub, GitLab).

commands/osint.py        Comandos `est osint ...` (ver docs/COMANDOS.md).
storage/database.py      Tablas `investigaciones_osint` y `hallazgos_osint`.
```

## Principios que no se negocian

1. **Nunca se inventa un dato.** Si una fuente falla, no esta configurada o no aplica
   al objetivo, su etapa queda en `omitida`/`fallida` con el motivo explicito; nunca se
   sustituye por un dato simulado.
2. **Nivel de confianza explicito en cada hallazgo** (`confirmado`, `probable`,
   `no_verificado`): un registro DNS/RDAP leido directamente es `confirmado`; una
   coincidencia de nombre de usuario o un nombre observado en Certificate Transparency
   es `probable` (evidencia indirecta, nunca una identidad o un servicio activo
   confirmado). AST nunca presenta una asociacion no verificada como si lo fuera.
3. **Autorizacion explicita sobre datos personales.** `correo`, `telefono` y `usuario`
   exigen `--autorizo` (CLI) antes de consultar ninguna fuente
   (`core/osint/validacion.py:verificar_autorizacion_datos_personales`); `dominio` se
   trata como informacion corporativa y no la exige.
4. **Minimizacion deliberada de datos personales de terceros.** Al consultar RDAP de un
   dominio, AST extrae unicamente el nombre de la organizacion registrante (si no esta
   oculto tras un servicio de privacidad), nunca el nombre, correo ni telefono de una
   persona que pudiera aparecer en el registro WHOIS/RDAP.
5. **Ninguna fuente elude restricciones de acceso.** Las fuentes de perfiles publicos
   (GitHub, GitLab) usan unicamente sus APIs REST publicas y documentadas, que
   devuelven 404/lista vacia de forma estandar cuando el usuario no existe; AST nunca
   intenta "scrapear" una pagina ni eludir un CAPTCHA o un bloqueo.
6. **Una investigacion cancelada nunca persiste nada parcial de la fuente en curso**
   (regla general de AST, ver CLAUDE.md): cada fuente se persiste en una unica
   transaccion atomica justo despues de completarse; las fuentes ya completadas antes
   de cancelar se conservan.
7. **Ninguna clave de API aparece en la CLI, la TUI, un log ni un informe.** Las claves
   se leen de variables de entorno (ver tabla de fuentes opcionales mas abajo) y nunca
   se guardan en el repositorio ni en la base de datos.

## Tipos de objetivo

| Tipo | Validacion | Exige `--autorizo` |
|---|---|---|
| `dominio` | `core/osint/validacion.py:validar_dominio_osint` (RFC 1035/1123). | No |
| `correo` | Sintaxis (local + dominio) + validacion del dominio. | Si |
| `telefono` | Normalizacion E.164 con `phonenumbers` (libphonenumber). | Si |
| `usuario` | Caracteres permitidos (letras, numeros, `.`, `-`, `_`; maximo 39). | Si |

`telefono` solo describe region y tipo de numero segun los metadatos publicos de
numeracion: **nunca afirma que el prefijo identifica con certeza al operador actual**
(los numeros portados o reasignados pueden no coincidir con esos metadatos).

## Fuentes incluidas sin configuracion (gratuitas)

| Id | Fuente | Tipos de objetivo | Que aporta |
|---|---|---|---|
| `dns` | DNS publico | `dominio`, `correo` | A/AAAA/MX/NS/TXT/CNAME, SPF y DMARC. |
| `rdap_dominio` | RDAP (ICANN) | `dominio`, `correo` | Estado del registro, fechas, organizacion registrante (si es publica). |
| `infraestructura_ip` | RDAP (ICANN) | `dominio`, `correo` | Red/ASN/organizacion de la primera IP publicada por el dominio. |
| `certificados` | Certificate Transparency (crt.sh) | `dominio`, `correo` | Subdominios observados en certificados TLS emitidos (pasivo, nunca confirma que esten activos). |
| `perfiles_publicos` | API publica de GitHub/GitLab | `usuario` | Coincidencia de nombre de usuario (nunca una identidad confirmada). |

Ninguna de estas fuentes necesita credenciales ni suscripcion: `est osint fuentes`
las muestra siempre como "Disponible".

## Fuentes opcionales (pendientes de credenciales)

Previstas para una entrega posterior del modulo (ver `docs/ROADMAP.md`), siguiendo el
mismo contrato (`AdaptadorFuenteOSINT`) que las fuentes gratuitas: cuando no esten
configuradas, `est osint fuentes` las mostrara como "Requiere configuracion" con la
variable de entorno exacta que falta, nunca con un resultado simulado.

| Fuente | Uso previsto | Variable de entorno prevista |
|---|---|---|
| Have I Been Pwned (API v3) | Brechas conocidas de un correo. | `EST_HIBP_API_KEY` |
| VirusTotal | Reputacion/indicadores de un dominio. | `EST_VIRUSTOTAL_API_KEY` |
| urlscan.io | Historial de escaneos de un dominio. | `EST_URLSCAN_API_KEY` |

## Lo que este modulo NO hace

- No descarga, compra, indexa ni almacena volcados de bases de datos filtradas.
- No enumera cuentas ajenas de forma masiva ni automatiza consultas contra aplicaciones
  de mensajeria para identificar a un abonado.
- No asume que dos perfiles con el mismo nombre de usuario pertenecen a la misma
  persona.
- No promete cobertura total de Internet ni de las filtraciones existentes: solo
  reporta lo que las fuentes configuradas devuelven en el momento de la consulta.
- No elude CAPTCHAs, bloqueos ni limites de ninguna plataforma.

## Persistencia

Dos tablas nuevas, aditivas (no modifican ninguna tabla existente):

- `investigaciones_osint`: una fila por investigacion (tipo, objetivo saneado,
  autorizacion, fuentes seleccionadas, estado general, etapas, limitaciones, rutas de
  informe).
- `hallazgos_osint`: una fila por hallazgo, con su fuente, categoria, nivel de
  confianza, indicador de exposicion (si aplica) y evidencias (ya saneadas).

`est osint eliminar INVESTIGACION_ID --confirmar` borra una investigacion y todos sus
hallazgos de forma permanente (`BaseDatos.eliminar_investigacion_osint`).

## Limitaciones conocidas

- Los adaptadores de RDAP/Certificate Transparency/GitHub-GitLab dependen de servicios
  publicos de terceros fuera del control de AST: su disponibilidad y formato de
  respuesta pueden cambiar. Cada adaptador valida la forma de la respuesta y falla de
  forma explicita (nunca en silencio) si no la reconoce.
- `rdap.org` es un servicio de redireccion ("bootstrap") comunitario: si no esta
  disponible, las fuentes RDAP se marcan como fallidas para esa investigacion, sin
  detener las demas.
- La fuente de perfiles publicos solo cubre GitHub y GitLab en esta entrega (ambas con
  API publica documentada que no requiere autenticacion para esta consulta). Otras
  plataformas quedan pendientes de una fuente opcional con credenciales propias.
- El informe HTML/JSON dedicado de OSINT y la pestana de la interfaz visual se entregan
  en una iteracion posterior (ver `docs/ROADMAP.md`); por ahora, los hallazgos se
  consultan con `est osint resultados`.
