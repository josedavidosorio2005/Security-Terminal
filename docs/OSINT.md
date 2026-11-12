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
├── validacion.py      Valida cada tipo de objetivo y exige autorizacion sobre datos
│                       personales (correo, telefono, usuario) antes de consultar nada.
└── redaccion.py        Minimizacion: enmascara un correo/telefono/usuario propio para
                         una vista o exportacion que no deba mostrarlo completo.

modules/osint/
├── modelos.py          Dataclasses compartidas (HallazgoOSINT, EvidenciaOSINT...).
├── motor.py            Orquesta: valida, autoriza, recorre las fuentes aplicables y
│                        persiste los hallazgos de cada una (sin dependencias de
│                        Typer/Rich/Textual, igual que el orquestador de reconocimiento).
└── exposicion.py        Resumen de indicadores de exposicion de una investigacion
                          (conteo y listado; nunca una puntuacion de riesgo inventada).

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
├── perfiles_publicos.py   Coincidencia de nombre de usuario (GitHub, GitLab).
├── urlscan.py             Historial de escaneos publicos (urlscan.io, sin clave).
├── hibp.py                Brechas conocidas de un correo (Have I Been Pwned, opcional).
└── virustotal.py          Reputacion de un dominio (VirusTotal, opcional).

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
8. **Minimizacion deliberada de lo que se guarda de una brecha.** Have I Been Pwned solo
   aporta el nombre de la brecha, su fecha y las CATEGORIAS de datos reportadas (p. ej.
   "Email addresses", "Passwords"): nunca una contrasena, hash, cookie, token ni el
   contenido real de la brecha (ver `integrations/osint/hibp.py`).
9. **Retencion explicita, nunca automatica en silencio.** `est osint purgar` borra
   investigaciones antiguas solo cuando se invoca y se confirma; AST nunca borra datos
   por su cuenta en segundo plano.

## Tipos de objetivo

| Tipo | Validacion | Exige `--autorizo` |
|---|---|---|
| `dominio` | `core/osint/validacion.py:validar_dominio_osint` (RFC 1035/1123). | No |
| `correo` | Sintaxis (local + dominio) + validacion del dominio. | Si |
| `telefono` | Normalizacion E.164 con `phonenumbers` (libphonenumber). | Si |
| `usuario` | Caracteres permitidos (letras, numeros, `.`, `-`, `_`; maximo 39). | Si |

`telefono` describe region, tipo de numero, formato E.164/nacional/internacional, zona
horaria y (si `phonenumbers` lo tiene en su catalogo) una descripcion geografica
aproximada y un operador sugerido -- este ultimo SIEMPRE en un hallazgo separado con
nivel de confianza `no_verificado`: **nunca afirma que el prefijo identifica con
certeza al operador actual** (los numeros portados o reasignados pueden no coincidir
con esos metadatos), y nunca identifica al titular de la linea.

## Fuentes incluidas sin configuracion (gratuitas)

| Id | Fuente | Tipos de objetivo | Que aporta |
|---|---|---|---|
| `dns` | DNS publico | `dominio`, `correo` | A/AAAA/MX/NS/TXT/CNAME, SPF y DMARC. |
| `rdap_dominio` | RDAP (ICANN) | `dominio`, `correo` | Estado del registro, fechas, organizacion registrante (si es publica). |
| `infraestructura_ip` | RDAP (ICANN) | `dominio`, `correo` | Red/ASN/organizacion de la primera IP publicada por el dominio. |
| `certificados` | Certificate Transparency (crt.sh) | `dominio`, `correo` | Subdominios observados en certificados TLS emitidos (pasivo, nunca confirma que esten activos). |
| `perfiles_publicos` | API publica de GitHub/GitLab | `usuario` | Coincidencia de nombre de usuario (nunca una identidad confirmada). |
| `urlscan_historial` | Busqueda publica de urlscan.io | `dominio`, `correo` | Escaneos publicos ya existentes del dominio (pasivo, nivel `probable`, con paginacion acotada -- ver limitaciones). |
| `telefono_metadatos` | Catalogo local de `phonenumbers` (libphonenumber) | `telefono` | E.164, formato nacional/internacional, codigo de pais, region, prefijo nacional, posibilidad/validez, tipo de linea, descripcion geografica aproximada y zona(s) horaria(s). Nunca hace una peticion de red. |

`infraestructura_ip` tambien intenta resolver el ASN y la organizacion de la IP via el
servicio DNS publico y pasivo de Team Cymru (`origin.asn.cymru.com`): si Cymru no
responde, el resto del hallazgo de infraestructura sigue siendo valido sin esa
evidencia adicional (nunca bloquea ni falla la investigacion por esto).

Ninguna de estas fuentes necesita credenciales ni suscripcion: `est osint fuentes`
las muestra siempre como "Disponible".

## Fuentes opcionales (requieren clave propia)

Siguen el mismo contrato (`AdaptadorFuenteOSINT`) que las fuentes gratuitas: cuando no
esten configuradas, `est osint fuentes` las muestra como "Requiere configuracion" con
la variable de entorno exacta que falta, nunca con un resultado simulado. El usuario
decide que proveedor recibe la consulta al configurar (o no) cada variable.

| Fuente | Que aporta | Variable de entorno | Documentacion |
|---|---|---|---|
| `hibp` (Have I Been Pwned) | Brechas conocidas de un correo: nombre, fecha y categorias de datos expuestas (nunca contrasenas/hashes). | `EST_HIBP_API_KEY` | https://haveibeenpwned.com/API/v3 |
| `virustotal` (VirusTotal) | Reputacion de un dominio (motores que lo marcan como malicioso/sospechoso). | `EST_VIRUSTOTAL_API_KEY` | https://docs.virustotal.com/reference/domain-info |
| `twilio_lookup` (Twilio Lookup v2) | Validacion de un telefono y tipo de linea/operador segun Twilio. **Factura por consulta.** | `EST_TWILIO_ACCOUNT_SID` + `EST_TWILIO_AUTH_TOKEN` | https://www.twilio.com/docs/lookup/v2-api |

`hibp` y `virustotal` requieren suscripcion/registro propio en el proveedor
correspondiente: AST nunca incluye una clave propia ni comparte una clave entre
usuarios. `twilio_lookup` ademas **nunca se ejecuta automaticamente aunque este
configurada**: al facturar por consulta, exige nombrarla explicitamente cada vez con
`--fuentes twilio_lookup` (`AdaptadorFuenteOSINT.requiere_seleccion_explicita`, ver
`modules/osint/motor.py`); la CLI muestra un aviso de costo potencial antes de
ejecutarla.

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
`est osint purgar --dias N --confirmar` aplica una politica de retencion explicita:
borra toda investigacion (y sus hallazgos) creada hace mas de `N` dias.

## Resumen de exposicion y minimizacion

Cada investigacion muestra, al terminar, cuantos hallazgos llevan un
`indicador_exposicion` y de que fuentes vienen (`modules/osint/exposicion.py`): un
conteo y un listado literal de esos indicadores, nunca una puntuacion de riesgo
inventada ni una clasificacion "alto/medio/bajo" sin respaldo de la fuente.

`core/osint/redaccion.py` ofrece funciones de enmascarado (`enmascarar_correo`,
`enmascarar_telefono`, `enmascarar_usuario`) para cuando una vista o exportacion no
deba mostrar el objetivo completo (p. ej. un informe compartido con un publico mas
amplio que el propio proyecto). `est osint reporte INVESTIGACION_ID --minimizar` (y la
casilla equivalente en la pestana "Informe" de la interfaz visual) las aplica al
generar el informe de esa investigacion; un dominio nunca se minimiza (se trata como
informacion corporativa, no personal).

## Resultados detallados desde la CLI

`est osint resultados --investigacion ID [--limite N] [--pagina N]` muestra una tabla
resumen (paginada con `--limite`/`--pagina` si hay mas hallazgos de los que caben en
una pagina). Dos modos adicionales, pensados para no perder ninguna evidencia:

- `--detallado`: un panel Rich por hallazgo con su descripcion integra, indicador de
  exposicion, nivel de confianza, **estado de verificacion** (una frase que explica que
  implica "confirmado"/"probable"/"no_verificado") y la tabla completa de evidencias
  (fuente, fecha de consulta, fecha observada por la fuente si es distinta, valor y
  referencia/URL).
- `--solo-urls`: lista, una por linea y sin duplicados, unicamente las URL
  REALMENTE observadas y guardadas (nunca convierte un subdominio o un metadato en una
  URL inventada).

Ambos modos admiten `--guardar RUTA.txt` o `--guardar RUTA.json` para exportar la
salida completa (con todas las evidencias) a un archivo, sin necesidad de generar el
informe completo.

## Informe (HTML/JSON)

`est osint reporte INVESTIGACION_ID [--formato html|json] [--minimizar] [--salida RUTA]`
genera el informe de UNA investigacion OSINT concreta -- siempre separado del informe
global de hallazgos tecnicos (`est reporte generar`), nunca mezclado. Contiene: tipo de
objetivo, objetivo (saneado o minimizado), estado de autorizacion sobre datos
personales, **fuentes consultadas con su estado real** (completada/omitida/fallida/
cancelada, nunca "sin informacion" cuando en realidad una fuente fallo o no estaba
configurada), totales de hallazgos por categoria, resumen ejecutivo, cada hallazgo
verificado con su descripcion completa, TODAS sus evidencias (URL como enlaces reales
y seguros -- solo `http`/`https`, cualquier otro esquema se escapa como texto plano,
nunca como enlace clicable -- y la fecha en que la fuente observo el dato frente a
cuando AST la consulto), su estado de verificacion, recomendaciones generales (segun
las categorias de hallazgos presentes), limitaciones de la investigacion y una nota
metodologica. Reutiliza el mismo esqueleto HTML/CSS que el resto de informes de AST
(`modules/reporting/generador.py`), sin duplicarlo. El JSON conserva la misma
informacion de forma estructurada (incluye `fuentes_consultadas`,
`totales_por_categoria` y `estado_verificacion` por hallazgo).

## Interfaz visual

La seccion "OSINT" de `est interfaz` (ver [docs/INTERFAZ.md](INTERFAZ.md)) ofrece el
mismo formulario y el mismo motor que la CLI, con los resultados organizados en
pestanas (Resumen, Infraestructura, Perfiles publicos, Exposicion, Fuentes, Informe).
Todas las llamadas al motor OSINT corren en un worker (`@work(thread=True)`), nunca en
el hilo principal de Textual.

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
- `hibp` y `virustotal` no tienen nivel gratuito sin registro: cada usuario debe crear
  su propia suscripcion/clave en el proveedor correspondiente (AST nunca la incluye ni
  la comparte). Sin esa variable de entorno configurada, la fuente se omite con un
  mensaje explicito (no es un error de AST).
- `est osint purgar` borra por fecha de creacion de la investigacion, no por fecha del
  hallazgo individual: todos los hallazgos de una investigacion se borran juntos.
- Las recomendaciones del informe son generales por categoria de hallazgo (no una
  recomendacion tecnica individual por cada uno): sirven como punto de partida, no
  como un analisis de riesgo completo.
- `certificados` (Certificate Transparency) reporta hasta 500 subdominios por
  investigacion; `urlscan_historial` recorre hasta 3 paginas de 100 resultados (300 en
  total). crt.sh no pagina su respuesta (la devuelve completa en una sola peticion), asi
  que su limite es solo sobre cuantos se MUESTRAN; si alguno de los dos recorta
  resultados, el propio hallazgo lo dice explicitamente (nunca en silencio).
- El operador sugerido por `telefono_metadatos`/`twilio_lookup` depende de que la
  biblioteca o el proveedor tengan ese bloque numerico en su catalogo: para muchos
  numeros simplemente no hay dato (no se inventa uno).
- El ASN de `infraestructura_ip` depende de que Team Cymru tenga esa IP en su tabla de
  rutas BGP en el momento de la consulta; si no, el resto del hallazgo de
  infraestructura sigue siendo valido sin esa evidencia.
