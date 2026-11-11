# Referencia de comandos de AST

Esta referencia documenta los comandos realmente implementados en las Fases 1 y 2. Todos los
comandos aceptan `--ayuda` (o `--help`/`-h`) para mostrar su ayuda.

## `est --ayuda`

Muestra la ayuda general y la lista de comandos disponibles.

## `est --version`

Muestra la version instalada de AST.

## `est interfaz`

Abre la interfaz visual completa de AST (Fase 2), construida con Textual: barra lateral de
secciones, terminal integrada, formularios y tablas de resultados, con teclado y raton. Ver el
manual completo en [docs/INTERFAZ.md](INTERFAZ.md).

## `est interactivo`

Abre la terminal interactiva de linea de comandos (Fase 1): autocompletado con Tab, historial de
comandos (flechas arriba/abajo, persistido entre sesiones) y acceso a todos los comandos
descritos aqui sin el prefijo `est`. Para salir: `salir`, `exit`, `quit` o Ctrl+D.

> Requiere una consola real (cmd.exe, PowerShell o una terminal Linux interactiva). Si se
> ejecuta con la entrada/salida redirigida, AST lo detecta y muestra un mensaje explicando como
> ejecutarlo correctamente en lugar de fallar con un error tecnico.

## `est proyecto`

Gestiona proyectos de auditoria.

| Comando | Descripcion |
|---|---|
| `est proyecto crear NOMBRE` | Crea un proyecto y lo marca como activo. |
| `est proyecto listar` | Lista todos los proyectos (el activo se marca con `*`). |
| `est proyecto usar NOMBRE` | Cambia el proyecto activo. |

El nombre solo admite letras, numeros, puntos, guiones y guiones bajos (maximo 64 caracteres).

## `est alcance`

Gestiona el alcance autorizado (IP o red CIDR) de un proyecto. **Ningun escaneo puede ejecutarse
contra un objetivo que no este aqui registrado.**

| Comando | Descripcion |
|---|---|
| `est alcance agregar OBJETIVO [--proyecto NOMBRE]` | Registra una IP (`127.0.0.1`) o red CIDR (`192.168.1.0/24`) autorizada. |
| `est alcance listar [--proyecto NOMBRE]` | Lista el alcance autorizado de un proyecto. |

Si no se indica `--proyecto`, se usa el proyecto activo.

## `est escanear tcp`

Comprueba el estado de una lista de puertos TCP mediante conexion directa (`connect scan`).

```bash
est escanear tcp OBJETIVO --puertos 22,80,443 [--proyecto NOMBRE] [--timeout 1.0] [--concurrencia 50]
```

| Parametro | Descripcion |
|---|---|
| `OBJETIVO` | Direccion IPv4 (no se admiten nombres de dominio en la Fase 1). |
| `--puertos` | Lista separada por comas, maximo 1024 puertos, cada uno entre 1 y 65535. |
| `--proyecto` | Proyecto a usar (por defecto, el activo). |
| `--timeout` | Segundos de espera por puerto, entre 0.1 y 10 (por defecto 1.0). |
| `--concurrencia` | Conexiones simultaneas, entre 1 y 200 (por defecto 50). |

El comando rechaza el escaneo si el objetivo no esta dentro de una red registrada con
`est alcance agregar`. Los resultados (`abierto`, `cerrado` o `error`) se guardan automaticamente.

## `est nmap`

Integracion con Nmap (Fase 3): descubrimiento de puertos y, si se autoriza explicitamente,
identificacion de servicios/version. Detalle completo (parametros, resultados, evidencia,
limitaciones) en [docs/INTEGRACIONES.md](INTEGRACIONES.md).

```bash
est nmap version
est nmap descubrir OBJETIVO --puertos 22,80,443 [--proyecto NOMBRE] \
    [--deteccion-version] [--tiempo-limite 120]
est nmap descubrir OBJETIVO --puertos completo --tiempo-limite 600
```

| Comando | Descripcion |
|---|---|
| `est nmap version` | Muestra si Nmap esta instalado y su version. |
| `est nmap descubrir OBJETIVO --puertos ...` | Ejecuta Nmap dentro del alcance autorizado. |

`--puertos` admite, a diferencia de `escanear tcp` (que abre una conexion por puerto desde el
propio proceso de AST y por eso sigue acotado a 1024 puertos por ejecucion): una lista
(`22,80,443`), un rango (`1-1024`), una mezcla de ambos (`22,80,1000-2000`), o uno de los
perfiles predefinidos `rapido` (puertos comunes) o `completo` (`1-65535`). Nmap expande el
rango de forma nativa; AST nunca construye una lista de 65535 puertos individuales para
pasarsela. Un escaneo de `completo` puede tardar bastante: ajusta `--tiempo-limite` segun
corresponda (maximo 600 segundos).

Al igual que `escanear tcp`, rechaza cualquier objetivo que no este en el alcance autorizado del
proyecto. Requiere tener Nmap instalado.

## `est web`

Auditoria web no intrusiva (Fase 3): cabeceras HTTP de seguridad, certificado/TLS, cookies y
redirecciones. Detalle completo (que evalua cada comprobacion, severidad, SSRF) en
[docs/AUDITORIA_WEB.md](AUDITORIA_WEB.md).

```bash
est web cabeceras URL [--proyecto NOMBRE] [--tiempo-limite 10] [--seguir-redirecciones] [--detallado]
est web tls URL [...]
est web cookies URL [...]
est web auditar URL [...]
est web reporte --formato html|json [--proyecto NOMBRE] [--salida RUTA]
```

| Comando | Descripcion |
|---|---|
| `est web cabeceras URL` | Audita solo las cabeceras HTTP de seguridad. |
| `est web tls URL` | Audita solo el certificado y la configuracion TLS. |
| `est web cookies URL` | Audita solo los atributos de las cookies (`Set-Cookie`). |
| `est web auditar URL` | Ejecuta las cuatro categorias (cabeceras, TLS, cookies, redirecciones). |
| `est web reporte` | Exporta a HTML/JSON los hallazgos guardados de auditoria web. |

`URL` debe usar una direccion IPv4 literal ya autorizada en el alcance del proyecto (no se
admiten nombres de dominio en esta entrega, igual que `escanear tcp`/`nmap`).

## `est nuclei`

Integracion con Nuclei (Fase 3): solo plantillas HTTP de bajo impacto, de un catalogo aprobado
por AST (nunca una ruta de plantilla arbitraria). Detalle completo (catalogo, validacion de
plantillas, limitaciones) en [docs/NUCLEI.md](NUCLEI.md).

```bash
est nuclei version
est nuclei plantillas
est nuclei analizar OBJETIVO --plantillas id1,id2 [--proyecto NOMBRE] [--tiempo-limite 60]
est nuclei resultados [--proyecto NOMBRE] [--limite 50]
est nuclei revisar ID --estado nuevo|confirmado|falso_positivo
est nuclei reporte --formato html|json [--proyecto NOMBRE] [--salida RUTA]
```

| Comando | Descripcion |
|---|---|
| `est nuclei version` | Muestra si Nuclei esta instalado y su version. |
| `est nuclei plantillas` | Lista el catalogo de plantillas aprobadas, con su explicacion. |
| `est nuclei analizar OBJETIVO --plantillas ...` | Ejecuta Nuclei dentro del alcance autorizado. |
| `est nuclei resultados` | Muestra los hallazgos guardados de un proyecto. |
| `est nuclei revisar ID --estado ...` | Marca un hallazgo como confirmado o falso positivo. |
| `est nuclei reporte` | Exporta los hallazgos guardados a HTML o JSON. |

Al igual que `escanear tcp`/`nmap`, rechaza cualquier objetivo que no este en el alcance
autorizado del proyecto. Requiere tener Nuclei instalado.

## `est zap`

Integracion con OWASP ZAP (Fase 3): solo analisis pasivo, nunca active scan/spider/fuzzing.
ZAP no lo instala AST: debe estar ya corriendo por tu cuenta, con su API en loopback. Detalle
completo (configuracion, limitaciones) en [docs/OWASP_ZAP.md](OWASP_ZAP.md).

```bash
est zap estado
est zap pasivo URL [--proyecto NOMBRE] [--tiempo-limite 60]
est zap resultados [--proyecto NOMBRE] [--limite 50]
est zap revisar ID --estado nuevo|confirmado|falso_positivo
est zap reporte --formato html|json [--proyecto NOMBRE] [--salida RUTA]
```

| Comando | Descripcion |
|---|---|
| `est zap estado` | Muestra si la API de ZAP responde en el endpoint configurado. |
| `est zap pasivo URL` | Ejecuta un analisis pasivo dentro del alcance autorizado. |
| `est zap resultados` | Muestra los hallazgos guardados de un proyecto. |
| `est zap revisar ID --estado ...` | Marca un hallazgo como confirmado o falso positivo. |
| `est zap reporte` | Exporta los hallazgos guardados a HTML o JSON. |

`URL` debe ser una IPv4 literal ya autorizada en el alcance (misma regla que `est web
auditar`). Configuracion mediante las variables de entorno `EST_ZAP_URL` (por defecto
`http://127.0.0.1:8080`, siempre loopback) y `EST_ZAP_API_KEY` (opcional; nunca se muestra
en pantalla, logs ni informes).

## `est reconocimiento`

Orquestador de reconocimiento automatico (Fase 3): escribe el objetivo (IPv4, dominio o
URL) una sola vez y AST encadena automaticamente Nmap, deteccion de servicios
HTTP/HTTPS, auditoria web, Nuclei y OWASP ZAP -- reutilizando exactamente los mismos
comandos que ya existen (`est nmap`, `est web`, `est nuclei`, `est zap`), sin duplicar su
logica. Detalle completo del flujo en [docs/ARQUITECTURA.md](ARQUITECTURA.md).

```bash
est reconocimiento ejecutar OBJETIVO [--perfil rapido|completo|personalizado] \
    [--puertos ESPECIFICACION] [--proyecto NOMBRE] [--tiempo-limite-nmap 120]
est reconocimiento sesiones [--proyecto NOMBRE] [--limite 20]
est reconocimiento estado SESION_ID
```

| Comando | Descripcion |
|---|---|
| `est reconocimiento ejecutar OBJETIVO` | Ejecuta el flujo completo contra un unico objetivo. |
| `est reconocimiento sesiones` | Lista las sesiones guardadas de un proyecto. |
| `est reconocimiento estado SESION_ID` | Muestra el detalle de etapas/limitaciones de una sesion. |

`OBJETIVO` acepta una IPv4 (`127.0.0.1`), un dominio (`ejemplo.com`) o una URL completa
(`https://ejemplo.com`, `http://127.0.0.1:8765`) -- ver `core/objetivo.py`. Si es un
dominio, AST lo resuelve una sola vez y fija la IP autorizada para toda la sesion (nunca
vuelve a resolverlo); las etapas de auditoria web, Nuclei y OWASP ZAP se **omiten** en ese
caso (ver limitaciones en la salida del comando), porque ninguna herramienta HTTP de AST
sabe hoy conservar el `Host`/SNI del dominio mientras se conecta a una IP fijada por
separado.

Cada etapa queda en uno de seis estados reales (nunca un porcentaje inventado):
`pendiente`, `ejecutando`, `completada`, `omitida` (la herramienta no esta
instalada/disponible), `fallida` o `cancelada`. Los resultados de cada etapa se guardan
exactamente igual que si se hubieran ejecutado por separado (`est resultados`, `est nuclei
resultados`, `est zap resultados`...), y el informe final es el mismo informe global de
`est reporte generar`.

## `est osint`

Investiga fuentes publicas (OSINT) sobre un dominio, correo, telefono o nombre de
usuario. Las investigaciones OSINT se guardan por separado de los hallazgos tecnicos
(nunca se mezclan en `est resultados`). Detalle completo, fuentes disponibles y
limitaciones en [docs/OSINT.md](OSINT.md).

```bash
est osint dominio DOMINIO [--proyecto NOMBRE] [--fuentes dns,rdap_dominio,...]
est osint correo CORREO --autorizo [--proyecto NOMBRE] [--fuentes ...]
est osint telefono "+573000000000" --autorizo [--region CO] [--proyecto NOMBRE]
est osint usuario NOMBRE_USUARIO --autorizo [--proyecto NOMBRE] [--fuentes ...]
est osint fuentes [--tipo dominio|correo|telefono|usuario]
est osint investigaciones [--proyecto NOMBRE] [--limite 20]
est osint resultados [--proyecto NOMBRE] [--investigacion ID] [--limite 100]
est osint eliminar INVESTIGACION_ID --confirmar
est osint purgar [--dias 90] --confirmar
```

| Comando | Descripcion |
|---|---|
| `est osint dominio` | DNS publico, RDAP, infraestructura IP, Certificate Transparency y urlscan.io. |
| `est osint correo` | Sintaxis del correo, MX/SPF/DMARC de su dominio y brechas conocidas (si `EST_HIBP_API_KEY` esta configurada). |
| `est osint telefono` | Normaliza a E.164 y describe region/tipo de numero (sin red, sin afirmar operador). |
| `est osint usuario` | Coincidencias de nombre de usuario en perfiles publicos (GitHub, GitLab). |
| `est osint fuentes` | Lista el catalogo de fuentes y si cada una esta configurada. |
| `est osint investigaciones` | Lista las investigaciones guardadas de un proyecto. |
| `est osint resultados` | Muestra los hallazgos guardados (de un proyecto o de una investigacion). |
| `est osint eliminar` | Borra una investigacion y todos sus hallazgos (irreversible; exige `--confirmar`). |
| `est osint purgar` | Aplica retencion: borra investigaciones mas antiguas que `--dias` (irreversible; exige `--confirmar`). |

`--autorizo` es obligatorio para `correo`, `telefono` y `usuario` (datos potencialmente
personales): sin esa confirmacion explicita, el comando se rechaza con
`ErrorAutorizacionOSINTRequerida` antes de consultar ninguna fuente. `dominio` no lo
exige (se trata como informacion corporativa).

Las fuentes opcionales (`hibp`, `virustotal`) requieren una clave propia del usuario
(`EST_HIBP_API_KEY`, `EST_VIRUSTOTAL_API_KEY`); sin ella se omiten con un mensaje
explicito. Detalle en [docs/OSINT.md](OSINT.md).

## `est explicar TEMA`

Muestra una explicacion en espanol de un comando y sus parametros. Temas disponibles: `proyecto`,
`alcance`, `tcp`, `escanear`, `nmap`, `web`, `nuclei`, `zap`, `resultados`, `reporte`,
`interactivo`, `interfaz`.

```bash
est explicar tcp
```

## `est resultados`

Muestra los resultados y hallazgos guardados de un proyecto, combinando las **cinco**
herramientas (`escanear tcp`, `nmap`, `web`, `nuclei`, `zap`) en una sola vista. Es una
consulta de solo lectura: reutiliza las tablas de cada herramienta sin modificarlas.

```bash
est resultados [--proyecto NOMBRE] [--fuente tcp,nmap,web,nuclei,zap] \
    [--severidad alta|media|baja|info] [--estado ESTADO] \
    [--desde FECHA_ISO] [--hasta FECHA_ISO] [--limite 50]
```

| Parametro | Descripcion |
|---|---|
| `--fuente` | Una o varias herramientas, separadas por comas (por defecto, todas). |
| `--severidad` | Agrupa severidades equivalentes entre herramientas (`alta` incluye `high`/`critical`, etc.; ver [docs/SEGURIDAD.md](SEGURIDAD.md)). No aplica a `tcp`/`nmap`: ver la nota mas abajo. |
| `--estado` | Compara contra el estado del resultado (`abierto`/`cerrado`/`error`) o, para Nuclei/ZAP, contra el estado de revision (`nuevo`/`confirmado`/`falso_positivo`). |
| `--desde` / `--hasta` | Filtran por fecha/hora (ISO-8601) de creacion del registro, inclusive. |

**Resultados de red vs. hallazgos de vulnerabilidad**: `tcp` y `nmap` reportan
conectividad/puertos (abierto, cerrado, filtrado) y **nunca** llevan una severidad -- un
puerto abierto no es, por si mismo, una vulnerabilidad. `web`, `nuclei` y `zap` reportan
hallazgos de auditoria/vulnerabilidad, con severidad/riesgo propio de cada herramienta.
AST nunca fusiona ni deduplica hallazgos de distintas herramientas por compartir titulo:
cada fila proviene de un unico registro de una unica herramienta.

Los comandos especificos de cada herramienta (`est nuclei resultados`, `est zap
resultados`) siguen funcionando igual que antes, con su propio detalle completo
(plantilla/regla, evidencia, etc.) que esta vista unificada resume.

## `est reporte generar`

Genera el informe **global** de la auditoria: combina las cinco herramientas en un unico
HTML o JSON (portada, resumen ejecutivo, objetivos/alcance, resultados de red, hallazgos
de vulnerabilidad ordenados por severidad, limitaciones tecnicas). Aplica su propia
verificacion de redaccion antes de exportar (ver [docs/SEGURIDAD.md](SEGURIDAD.md)).

```bash
est reporte generar --formato html|json [--proyecto NOMBRE] [--salida RUTA]
```

Si no se indica `--salida`, el informe se guarda en el directorio de datos de EST
(`~/.eurabyte_security/reportes/`, o `$EST_HOME/reportes/`) con un nombre que incluye el
proyecto y la fecha/hora. Los informes especificos de cada herramienta (`est nuclei
reporte`, `est zap reporte`, `est web reporte`) siguen disponibles sin cambios, para un
detalle centrado en una sola herramienta.
