# Roadmap de AST

AST se desarrolla en fases incrementales. Cada fase solo se considera completa cuando cumple sus
criterios de aceptacion y tiene pruebas automatizadas que lo demuestran.

## Fase 1 - MVP funcional (completada, fusionada en `main`)

**Criterios de aceptacion:**

- [x] Instalacion mediante `pip install -e .`, comando `est` disponible.
- [x] Ayuda en espanol (`est --ayuda`).
- [x] Terminal interactiva (`est interactivo`) con autocompletado y historial.
- [x] Gestion de proyectos (`est proyecto crear|listar|usar`).
- [x] Registro de alcance autorizado (`est alcance agregar|listar`).
- [x] Comprobacion de puertos TCP controlada y restringida al alcance (`est escanear tcp`).
- [x] Persistencia de resultados en SQLite.
- [x] Generacion de informes HTML y JSON (`est reporte generar`).
- [x] Explicaciones interactivas (`est explicar TEMA`).
- [x] Pruebas automatizadas (`pytest`) y analisis estatico (`ruff`).
- [x] Documentacion de instalacion para Windows y Linux.
- [x] CI verificado en GitHub Actions sobre `windows-latest` y `ubuntu-latest`.

## Fase 2 - Interfaz profesional (implementada en este PR)

**Criterios de aceptacion:**

- [x] Comando `est interfaz` que abre una aplicacion Textual real (no una maqueta estatica).
- [x] `est interactivo` (Fase 1) sigue funcionando sin cambios.
- [x] Barra superior (logo, version, proyecto activo, sistema operativo), barra lateral con las
      14 secciones acordadas, panel de informacion contextual y barra de estado inferior.
- [x] Terminal AST integrada: autocompletado contextual (Tab), sugerencias mientras se escribe,
      historial con flechas, salida coloreada y comandos reales (no un shell del sistema).
- [x] Navegacion y accion completas con teclado y con raton.
- [x] Conectada a la logica real: proyectos, alcance, escaneo TCP (con cancelacion en un
      worker en segundo plano; semantica todo-o-nada: un escaneo cancelado nunca persiste
      resultados, y dos escaneos consecutivos nunca mezclan los suyos en la interfaz),
      resultados y generacion de informes.
- [x] Texto introducido por el usuario siempre se escapa (`ui/consola.py:texto_seguro`) antes
      de mostrarse con marcado Rich, y los errores inesperados de un comando se capturan sin
      cerrar la interfaz.
- [x] Deteccion (sin ejecucion) de herramientas externas de la Fase 3 (Nmap, Nuclei, OWASP ZAP,
      tshark).
- [x] Secciones todavia no implementadas (Modulos, Reconocimiento, Analisis web,
      Vulnerabilidades, Aprendizaje) marcadas explicitamente como "Proximamente".
- [x] Interfaz adaptable: oculta/compacta paneles secundarios en terminales pequenas sin perder
      acceso a sus funcionalidades.
- [x] Pruebas automatizadas con el framework de testing de Textual (arranque, renderizado,
      navegacion, autocompletado, formularios, rechazo fuera de alcance, estados vacios/errores,
      adaptacion responsiva, cancelacion/persistencia, no-mezcla de escaneos concurrentes y
      escape de marcado Rich) manteniendo en verde las 52 pruebas de la Fase 1 (104 en total).
- [x] Documentacion: manual de usuario (`docs/INTERFAZ.md`), capturas reales generadas con
      `App.save_screenshot`, atajos de teclado y solucion de problemas.

Pendiente explicito para fases futuras (no entra en el alcance de la Fase 2):

- Tema claro/oscuro configurable por el usuario (por ahora el tema es fijo).
- Indicadores de progreso detallados durante un escaneo largo (hoy se muestra "Escaneando...").
- Historial de auditorias persistente entre sesiones de la interfaz visual (hoy se apoya en los
  resultados guardados en SQLite, pero no hay una vista de "sesiones" separada).

## Fase 3 - Herramientas de ciberseguridad (en curso, por pasos/PR)

La Fase 3 se entrega de forma incremental, un modulo por pull request. Este PR cubre el Paso 0
(robustez) y los Pasos 1-2 (motor de integraciones + Nmap).

### Paso 0 - Robustez de los escaneos existentes (completado en este PR)

- [x] `BaseDatos.agregar_resultados()`/`agregar_resultados_nmap()`: persistencia atomica (una
      sola transaccion SQLite por escaneo; un fallo a mitad de camino no deja nada guardado).
- [x] `escanear_puertos_tcp()` sondea la cancelacion cada 50ms (no solo cuando un puerto
      termina), para que nunca se programen conexiones nuevas mas alla del limite de
      concurrencia tras detectar una cancelacion.
- [x] Pruebas deterministas (`tests/test_fase3_robustez.py`): rollback atomico, limite de
      concurrencia respetado tras cancelar, y escrituras concurrentes de dos escaneos distintos
      sin perdida ni mezcla de datos.
- [x] Las 110 pruebas anteriores (Fases 1 y 2) siguen en verde.

### Pasos 1-2 - Motor de integraciones y Nmap (completado en este PR)

- [x] `integrations/base.py`: contrato comun (deteccion, version, validacion de parametros,
      ejecucion sin shell).
- [x] `integrations/proceso.py`: unico punto de ejecucion de un binario externo -- sin
      `shell=True` ni interpolacion, con limite de tiempo y cancelacion real
      (`Popen.kill()`, no solo esperar a que termine).
- [x] `integrations/nmap.py` + `commands/nmap.py`: descubrimiento de puertos (`est nmap
      descubrir`), deteccion de servicios/version opcional (`--deteccion-version`), lectura de
      XML con `defusedxml`, persistencia atomica, evidencia guardada sin modificar.
- [x] Gestionable desde la CLI (`est nmap ...`) y desde la interfaz visual (seccion
      "Reconocimiento", que deja de ser un marcador "Proximamente").
- [x] Explicacion en espanol (`est explicar nmap`).
- [x] Pruebas con mocks, sin ejecutar Nmap real ni tocar sistemas de terceros
      (`tests/test_integraciones_nmap.py`, `tests/test_integraciones_proceso.py`,
      `tests/test_tui_nmap.py`): deteccion, validacion, analisis de XML, tiempo agotado,
      cancelacion real, verificacion de alcance, persistencia + evidencia, y los mismos
      paneles-UI (ejecutar, cancelar, dos analisis consecutivos sin mezclar, error inesperado
      sin cerrar la interfaz).
- [x] CI verificado en Windows y Linux.

**Limitaciones conocidas** (ver tambien [docs/INTEGRACIONES.md](INTEGRACIONES.md)): los
resultados de Nmap tienen su propia tabla (`resultados_nmap`) con su propio informe
dedicado; tambien aparecen en la vista unificada de `est resultados` y en el informe
global de `est reporte generar` (ver "Consolidacion de resultados y reportes" mas abajo).

### Paso 3 - Auditoria web no intrusiva (completado en PR independiente)

- [x] Cabeceras HTTP de seguridad (`Content-Security-Policy`, `Strict-Transport-Security`,
      `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`,
      `Cache-Control` condicional, divulgacion de version del servidor, CORS permisivo), cada
      una con severidad evaluada en contexto (nunca "toda cabecera ausente = critica").
- [x] Auditoria HTTPS/TLS (`modules/web/tls.py`): version negociada, suite de cifrado,
      confianza del certificado, vencimiento y coincidencia de nombre de host -- sin desactivar
      nunca la validacion TLS para fingir un resultado exitoso; si el certificado no es
      confiable, se reporta el hecho y se distinguen los metadatos confirmados de los leidos
      sin verificar.
- [x] Auditoria de cookies (`modules/web/cookies.py`): `Secure`, `HttpOnly`, `SameSite`,
      expiracion; el valor real de la cookie nunca se registra ni se muestra.
- [x] Redirecciones y SSRF (`modules/web/redirecciones.py`): ninguna redireccion se sigue
      automaticamente; solo se sigue con `--seguir-redirecciones` y unicamente si el destino es
      una IP IPv4 literal autorizada en el alcance (maximo 5 saltos).
- [x] `est web cabeceras|tls|cookies|auditar|reporte`, seccion "Analisis web" de la interfaz
      visual (formulario completo con cancelacion) y Terminal AST (`web cabeceras|tls|cookies|
      auditar`), con autocompletado.
- [x] Persistencia atomica en `resultados_web` y exportacion a HTML/JSON reutilizando el mismo
      esqueleto de informe que `est reporte generar`.
- [x] Pruebas con un servidor HTTP(S) local y certificados generados por la propia suite
      (nunca contra servidores publicos): cabeceras presentes/ausentes, certificados vencidos y
      no confiables, validacion TLS, cookies, redirecciones fuera de alcance, prevencion de
      SSRF, limites de tiempo/respuesta, cancelacion, persistencia, reportes, CLI y Textual.
- [x] Las 199 pruebas anteriores siguen en verde.

**Correcciones de una revision posterior de la misma PR**:

- [x] `est web tls` contra un certificado no confiable (autofirmado/vencido/nombre equivocado)
      ya no termina en un error generico sin hallazgos: la peticion HTTP real sigue validando
      TLS por completo (nunca se desactiva en silencio), pero si falla por confianza, los
      hallazgos de TLS ya diagnosticados se devuelven igual, junto con un hallazgo informativo
      que explica que la parte HTTP no se completo.
- [x] El estado "seguida"/"no seguida" de una redireccion ahora refleja lo que realmente
      ocurrio (antes quedaba siempre en "no seguida" aunque AST si la siguiera).
- [x] `debe_cancelar` se vuelve a comprobar justo antes de la transaccion SQLite (no solo
      durante la peticion de red): una cancelacion detectada en ese momento tampoco persiste
      nada.
- [x] Los parametros de URL que suelen llevar un secreto (token, contrasena, API key...) se
      ocultan (`core/redaccion.py`, movido desde `modules/web/` para que `core/validation.py`
      tambien pueda reutilizarlo) antes de guardarse o mostrarse -- en la URL del objetivo, en
      el destino de una redireccion, en mensajes de error y en los informes -- sin modificar la
      URL real usada para la peticion autorizada.
- [x] `--tiempo-limite` ahora se valida realmente contra el rango 1-30s
      (`core/validation.py:validar_tiempo_limite_web`); el tiempo total de una auditoria
      completa (al seguir redirecciones) tiene su propio presupuesto cooperativo de 60s
      (`modules/web/auditor.py:TIEMPO_LIMITE_TOTAL_MAXIMO`).
- [x] 38 pruebas nuevas (237 en total): `est web tls` de extremo a extremo contra certificados
      no confiables/vencidos, estado real de cada tipo de redireccion (seguida/no seguida/fuera
      de alcance/limite de saltos/limite de tiempo total), cancelacion justo antes de persistir,
      redaccion de parametros sensibles (persistencia, CLI, informes, mensajes de error) y
      validacion de `--tiempo-limite`.

**Segunda revision de la misma PR**:

- [x] Ningun mensaje de error de `validar_url_web()` (esquema no admitido, credenciales en la
      URL, puerto invalido, host vacio, URL no interpretable) interpola ya la URL cruda: todos
      pasan por `redactar_url()`, movida a `core/redaccion.py` precisamente para que
      `core/validation.py` pudiera reutilizarla sin invertir la direccion de dependencias del
      proyecto (`core/` nunca depende de `modules/`).
- [x] El presupuesto de tiempo total de la auditoria ahora se mide con reloj monotonico ANTES
      de cada peticion (incluida la primera) y se usa para recortar el `--tiempo-limite`
      efectivo de esa peticion especifica, no solo para decidir si abortar antes de empezarla:
      una peticion en curso ya no puede hacer que la auditoria completa supere el presupuesto
      por mas de lo que le quedaba disponible. Documentado explicitamente como presupuesto
      cooperativo, no como garantia estricta de pared.
- [x] El estado "seguida" de una redireccion ya no puede registrarse un instante antes de que
      el presupuesto de tiempo se agote y la peticion siguiente nunca llegue a intentarse: la
      decision de seguir el salto y el tiempo limite de la peticion que lo sigue se calculan a
      partir de la misma medicion del presupuesto restante, sin otra comprobacion de tiempo
      entre medias que pueda contradecirla.
- [x] 8 pruebas nuevas (252 en total): mensajes de error de `validar_url_web()` sin secretos en
      claro (esquema invalido, credenciales, puerto invalido, host vacio, URL no interpretable),
      un salto cuyo presupuesto se agota justo antes de intentarlo queda como "no seguida" (no
      como "seguida" contradicha despues), y el tiempo limite efectivo de la peticion siguiente
      se recorta segun el presupuesto restante (verificado interceptando la llamada real, sin
      esperas largas).

**Limitaciones conocidas**: solo se admiten objetivos con IP IPv4 literal (no nombres de
dominio); el informe de auditoria web es independiente del de `escanear tcp`/`nmap`; el
presupuesto de tiempo total de la auditoria es cooperativo, no una garantia estricta; cuando el
certificado TLS no es confiable no hay hallazgos de cabeceras/cookies/redirecciones (solo de
TLS), por diseno (ver [docs/AUDITORIA_WEB.md](AUDITORIA_WEB.md)).

### Paso 4 - Nuclei (completado en PR independiente)

- [x] `integrations/nuclei.py` + `commands/nuclei.py`: catalogo cerrado de 5 plantillas HTTP
      de bajo impacto, escritas por AURABYTE (`exposed-env-file`, `exposed-git-config`,
      `directory-listing`, `server-version-disclosure`, `exposed-phpinfo`). El usuario solo
      puede elegir por identificador (`--plantillas id1,id2`); nunca una ruta de plantilla
      propia ni las plantillas publicas de la comunidad.
- [x] Cada plantilla se vuelve a validar estructuralmente en cada ejecucion
      (`validar_plantilla_estructura()`): se rechaza cualquier protocolo distinto de HTTP,
      cualquier redireccion o cualquier mencion a Interactsh/OAST, por si el archivo cambiara
      despues de instalado. Se desactivan ademas `-ni` (Interactsh) y `-duc` (comprobacion de
      actualizaciones) al invocar el binario.
- [x] `verificar_opciones_compatibles()`: comprueba contra `nuclei -h` que la version instalada
      reconoce las opciones que AST necesita antes de construir el comando.
- [x] Lectura de resultados JSONL linea a linea; una linea malformada se descarta sin
      interrumpir el analisis del resto. El `request`/`response`/`curl-command` de Nuclei
      nunca se guardan ni se muestran (solo un resumen saneado).
- [x] Gestionable desde la CLI (`est nuclei version|plantillas|analizar|resultados|revisar|
      reporte`) y desde la interfaz visual (seccion "Vulnerabilidades", que deja de ser un
      marcador "Proximamente"): proyecto activo, deteccion, catalogo con explicacion,
      confirmacion explicita antes de analizar, cancelacion real, tabla de hallazgos con
      severidad/evidencia/recomendacion y marcado de falso positivo/confirmado.
- [x] Persistencia atomica en `resultados_nuclei` (con estado de revision inicial `nuevo`) y
      exportacion a HTML/JSON reutilizando el generador de informes existente.
- [x] Pruebas con mocks, sin ejecutar Nuclei real ni tocar sistemas de terceros
      (`tests/test_integraciones_nuclei.py`, `tests/test_tui_nuclei.py`): deteccion,
      validacion de objetivo/plantillas/tiempo limite, opciones no compatibles, catalogo y
      validacion estructural de plantillas (protocolo prohibido, redirecciones, Interactsh,
      metodo distinto de GET, YAML invalido), JSONL malformado, ausencia de
      request/response/cookies en los hallazgos, cancelacion real, rechazo fuera de alcance,
      persistencia atomica, reportes, CLI y Textual (incluida la revision de falsos
      positivos).
- [x] CI verificado en Windows y Linux.

**Limitaciones conocidas** (ver tambien [docs/NUCLEI.md](NUCLEI.md)): el catalogo aprobado es
deliberadamente pequeno y no se ha podido validar contra un binario de Nuclei real en este
entorno de desarrollo; los resultados de Nuclei tienen su propia tabla (`resultados_nuclei`),
su propio informe dedicado y tambien aparecen en la vista unificada de `est resultados` y en
el informe global (ver "Consolidacion de resultados y reportes" mas abajo); la garantia de
aislamiento es sobre el contenido de la plantilla, no una sandbox de red a nivel de sistema
operativo.

**Revision de seguridad posterior de la misma PR**: lista blanca estricta de estructura de
plantillas (campos conocidos, rutas exclusivamente relativas a `{{BaseURL}}`, limites de
bloques/rutas, tipos de matcher permitidos), hash SHA-256 aprobado por plantilla y ejecucion a
partir de una copia validada (nunca la ruta original del catalogo, para evitar una ventana
TOCTOU entre validar y ejecutar); configuracion y entorno de proceso aislados (sin proxy ni
`NUCLEI_*`, con `HOME`/`XDG_CONFIG_HOME`/`APPDATA` redirigidos); un codigo de salida de Nuclei
distinto de cero se trata siempre como un fallo real (nunca como exito sin hallazgos); segunda
comprobacion de cancelacion justo antes de guardar los hallazgos; la salida JSONL solo acepta un
`template-id` que pertenezca al conjunto de plantillas realmente ejecutadas, con limites de
tamano por linea/total y de longitud por campo; los campos `matched-at`/`host`/`description`/
`matcher-name` y el detalle de un error de proceso se redactan (no solo se truncan) antes de
guardarse o mostrarse. Se replico ademas la correccion de binary planting de la PR #5 en
`integrations/base.py`. Ver [docs/NUCLEI.md](NUCLEI.md) y [docs/SEGURIDAD.md](SEGURIDAD.md).

### Paso 5 - OWASP ZAP, analisis pasivo (completado en PR independiente)

- [x] `integrations/zap.py` + `modules/vulnerability/zap.py` + `commands/zap.py`: solo
      analisis pasivo, nunca active scan, spider, ajaxSpider ni fuzzing. ZAP no lo instala
      AST: debe estar ya corriendo por cuenta del usuario, con su API expuesta en loopback.
      A diferencia de Nmap/Nuclei, no se invoca como subproceso: se habla con su API REST
      via `http.client` directo (igual patron que la auditoria web), sin `urllib.request`
      ni variables de entorno de proxy.
- [x] El endpoint de administracion de ZAP debe ser loopback HTTP **literal**
      (`http://127.0.0.1:<puerto>`): se rechaza explicitamente `localhost` (su resolucion
      depende del archivo de hosts del sistema, no es una garantia), cualquier host remoto
      y cualquier esquema distinto de `http`.
- [x] La unica peticion que llega al objetivo es la que la propia API de ZAP hace a traves
      de `core/action/accessUrl` (`followRedirects=false`), que alimenta el analizador
      pasivo sin explorar nada mas; las alertas se consultan filtradas por `baseurl` para
      nunca mezclar hallazgos de otras auditorias que pudiera tener la misma instancia
      compartida de ZAP (y nunca se borran sesiones ni alertas ajenas).
- [x] La API key se lee de `EST_ZAP_API_KEY` (nunca de un archivo versionado) y nunca
      aparece en un mensaje de error, log o informe.
- [x] Toda la salida de ZAP se trata como no confiable: los campos de texto libre
      (descripcion, evidencia, solucion, referencia) y la URL de cada alerta se redactan
      (`core/redaccion.py:redactar_url`/`redactar_texto_libre`, el mismo mecanismo
      compartido con Nuclei y la auditoria web) y se acotan en longitud antes de guardarse
      o mostrarse.
- [x] Gestionable desde la CLI (`est zap estado|pasivo|resultados|revisar|reporte`) y desde
      la interfaz visual (seccion "OWASP ZAP", con confirmacion explicita antes de
      analizar, cancelacion y tabla de alertas con severidad/confianza/recomendacion y
      marcado de falso positivo/confirmado).
- [x] Persistencia atomica en `resultados_zap` (con estado de revision inicial `nuevo`) y
      exportacion a HTML/JSON reutilizando el generador de informes existente.
- [x] Pruebas con mocks, sin llamar a una instancia de ZAP real
      (`tests/test_integraciones_zap.py`, `tests/test_tui_zap.py`): endpoint de
      administracion (loopback literal, rechazo de `localhost`/remoto/HTTPS), validacion
      del objetivo, diagnostico disponible/no disponible, `accessUrl` sin seguir
      redirecciones, filtrado de alertas por `baseurl`, descarte de alertas malformadas,
      redaccion de datos sensibles (URL/evidencia/descripcion), que la API key nunca
      aparece en un mensaje de error, timeout, cancelacion (durante la espera y justo
      antes de guardar), rechazo fuera de alcance, persistencia atomica, reportes, CLI y
      Textual (incluida la revision de falsos positivos).
- [x] CI verificado en Windows y Linux.

**Limitaciones conocidas** (ver tambien [docs/OWASP_ZAP.md](OWASP_ZAP.md)): el analisis
pasivo no se ha podido validar contra una instancia de ZAP real en este entorno de
desarrollo; los resultados de ZAP tienen su propia tabla (`resultados_zap`), su propio
informe dedicado y tambien aparecen en la vista unificada de `est resultados` y en el
informe global (ver "Consolidacion de resultados y reportes" mas abajo); la garantia de
aislamiento es sobre el contenido de la peticion (solo GET, sin redirecciones, filtrado
por objetivo), no una sandbox de red a nivel de sistema operativo; una instancia de ZAP
compartida con otras auditorias sigue acumulando esa unica peticion GET en su historial
(visible via otras llamadas a su API), aunque AST nunca la mezcle en sus propios
resultados.

### Consolidacion de resultados y reportes (completado en este PR)

Unifica, sin migrar ni borrar ninguna tabla existente, los resultados/hallazgos de las
cinco herramientas (`escanear tcp`, `nmap`, `web`, `nuclei`, `zap`) en una sola vista de
consulta y en un informe global.

- [x] `BaseDatos.listar_resultados_unificados()`: combina las cinco tablas existentes en
      una vista de solo lectura (`ResultadoUnificado`), sin crear ni alterar ninguna
      tabla. `tcp`/`nmap` nunca llevan una severidad fabricada (son resultados de
      conectividad, no vulnerabilidades); `web`/`nuclei`/`zap` conservan su severidad y,
      cuando existe, su estado de revision (`nuevo`/`confirmado`/`falso_positivo`).
- [x] `est resultados` consulta las cinco herramientas con filtros por proyecto,
      herramienta (`--fuente`), severidad agrupada entre herramientas (`--severidad`),
      estado/estado de revision (`--estado`) y fecha (`--desde`/`--hasta`), con limite y
      orden estable (mas reciente primero). `est nuclei resultados`/`est zap resultados`
      (y los informes especificos de cada herramienta) siguen funcionando sin cambios.
- [x] `est reporte generar` produce ahora el informe **global** (HTML/JSON): portada,
      resumen ejecutivo, objetivos/alcance autorizado, resultados de red y reconocimiento
      en una tabla separada de los hallazgos de vulnerabilidad (ordenados por severidad),
      limitaciones tecnicas y una nota metodologica explicita: AST nunca fusiona ni
      deduplica hallazgos de distintas herramientas por compartir titulo (cada fila
      conserva su `fuente` e `id_origen`). Reutiliza el mismo esqueleto HTML/CSS que los
      informes por herramienta (`modules/reporting/generador.py`), sin duplicarlo.
- [x] El informe global aplica una segunda pasada de redaccion (`core/redaccion.py`)
      sobre todo campo de texto libre antes de exportar, independiente de la que ya
      aplica cada herramienta al guardar.
- [x] Interfaz visual: el panel "Resultados" filtra por herramienta y muestra el detalle
      de cualquier hallazgo de las cinco fuentes (solo lectura: marcar
      confirmado/falso positivo sigue siendo exclusivo de los paneles "Vulnerabilidades"
      y "OWASP ZAP"); el panel "Reportes" genera el informe global.
- [x] Pruebas con datos simulados (`tests/test_resultados_unificados.py`,
      `tests/test_tui_resultados_reportes.py`): unificacion de las cinco fuentes, no
      fabricacion de severidad en tcp/nmap, filtros (fuente/severidad/estado/fecha) y
      orden, separacion entre proyectos, persistencia de los datos previos, hallazgos con
      el mismo titulo en herramientas distintas sin fusionarse, redaccion de secretos,
      escape de HTML hostil, informes JSON/HTML, CLI, interfaz visual y compatibilidad
      con los comandos existentes. Ninguna requiere Nmap, Nuclei ni ZAP instalados.
- [x] CI verificado en Windows y Linux.

### Rediseno profesional de la interfaz visual (completado en este PR)

Corrige problemas visuales reales detectados en la interfaz Textual (no solo ajustes
esteticos) y hace el panel contextual derecho plegable a demanda.

- [x] **Bug de layout corregido**: los `Static` del encabezado (logo, nombre, version,
      proyecto, sistema operativo) no tenian `width: auto` explicito, asi que cada uno
      reclamaba todo el ancho restante del contenedor y quedaba empujado casi
      completamente fuera de la pantalla visible -- el nombre AURABYTE realmente
      quedaba oculto, no solo visualmente apretado. Verificado con
      `Widget.region` en las 4 resoluciones de prueba antes y despues del cambio.
- [x] El encabezado oculta primero version y sistema operativo por debajo de 90
      columnas (conserva siempre nombre y proyecto activo); la barra lateral se
      compacta por debajo de 90 columnas (antes 70) para dejar mas espacio a la zona
      central en resoluciones intermedias.
- [x] El panel contextual derecho es plegable a demanda (boton "Info" en el
      encabezado, o tecla `F2`), no solo una columna forzada por el ancho de la
      terminal (`AuraByteApp.action_alternar_info`).
- [x] Panel "Vulnerabilidades" (Nuclei): la lista extensa de descripciones de cada
      plantilla (visible todo el tiempo) se reemplaza por una lista compacta con la
      descripcion completa solo al resaltar/seleccionar una plantilla, mas un boton
      "Seleccionar todas las aprobadas".
- [x] Verificado con Textual Pilot en las 4 resoluciones pedidas (80x24, 100x30,
      120x35, 160x45): sin controles recortados, con scroll funcionando y navegacion
      conservada. Capturas SVG reales (`App.export_screenshot`) antes/despues en
      [docs/capturas/](capturas/).
- [x] Pruebas automatizadas nuevas para el toggle del panel de info y el nuevo flujo
      de plantillas de Nuclei (resaltar para ver descripcion, seleccionar todas).
- [x] CI verificado en Windows y Linux.

Pendiente explicito para una iteracion posterior: el mismo nivel de rediseno aplicado a
Reconocimiento, Analisis web y OWASP ZAP ya seguian el patron de formulario
compacto-arriba/tabla-abajo sin solapamientos, por lo que no requirieron cambios de
fondo en este PR; una revision visual dedicada a esos tres paneles queda abierta si se
detectan problemas especificos.

### Rendimiento de la interfaz: deteccion de herramientas movida a workers (completado)

Diagnostico empirico (no supuesto) de los congelamientos reportados al cambiar de
panel: medido con `time.perf_counter()`, `AdaptadorZAP().info()` sin una instancia de
ZAP corriendo tarda ~2s (timeout de conexion por defecto) y `detectar_herramientas()`
(cuatro binarios/servicios) tarda ~0.6s. Ambas se llamaban de forma **sincrona** justo
en el manejador de evento que cambia de panel (`AuraByteApp._refrescar_panel`) o en
`on_mount`, bloqueando el hilo principal de Textual -- el peor caso, visitar "OWASP
ZAP" sin tener ZAP corriendo, congelaba la interfaz ~2 segundos cada vez.

- [x] `PanelOWASPZAP._refrescar_deteccion`, `PanelVulnerabilidades._refrescar_deteccion`
      y `PanelHerramientas.refrescar` ahora disparan la deteccion en un
      `@work(thread=True, exclusive=True)` y muestran un texto "comprobando..." mientras
      se resuelve, igual que cualquier otra operacion de red/proceso externo en la TUI.
- [x] `AuraByteApp.on_mount` ya no espera a `detectar_herramientas()` antes del primer
      pintado interactivo: se dispara en el mismo tipo de worker.
- [x] Verificado con mediciones reales antes/despues (no solo la ausencia de errores):
      el cambio sincrono a "OWASP ZAP" bajo de ~2s a ~0.004s; a "Herramientas", de ~0.6s
      a ~0.000s.
- [x] Pruebas automatizadas con un doble que simula el retraso
      (`tests/test_tui_rendimiento.py`): confirman que el cambio de panel y el arranque
      de la app no esperan de forma sincrona, y que el resultado real se refleja un
      instante despues sin bloquear la interfaz.
- [x] CI verificado en Windows y Linux.

Pendiente: no se detecto evidencia de otros bloqueos sincronos equivalentes en el resto
de la interfaz (Nmap, auditoria web, Redes no llaman a ninguna deteccion en su
`refrescar()`); si aparece un nuevo caso, el mismo patron (`@work` + placeholder) es el
que corresponde aplicar.

### Entrada unica de objetivo: IP, dominio o URL (completado, motor sin integrar aun)

Primer paso de "Reconocimiento automatico integrado": un modulo nuevo y aditivo
(`core/objetivo.py`) que acepta una IPv4 literal, un dominio o una URL completa como
un unico campo de entrada, con resolucion DNS y autorizacion sobre la IP resultante
(nunca sobre el nombre). Ver el detalle completo de las salvaguardas en
[docs/SEGURIDAD.md](SEGURIDAD.md) (punto 19).

- [x] `interpretar_entrada()`: separa IPv4/dominio/URL en sus partes sin tocar la red.
      Rechaza IPv6, credenciales embebidas, dominios mal formados y una ruta sin
      esquema explicito (ambiguo).
- [x] `resolver_dns()`: resuelve registros A via `socket.getaddrinfo` (delega en el
      resolver del sistema operativo, no implementa uno propio).
- [x] `resolver_y_autorizar()`: si el objetivo es un dominio, lo resuelve UNA sola vez
      y exige que al menos una direccion este dentro del alcance YA registrado del
      proyecto (listas de redes IPv4/CIDR, sin cambios); fija esa direccion en
      `ObjetivoResuelto.ip` para evitar DNS rebinding, y nunca amplia el analisis a
      otra direccion aunque comparta el mismo dominio.
- [x] `core/validation.py` (`validar_objetivo`, `validar_url_web`,
      `validar_objetivo_nuclei`) **no se modifico**: sigue aceptando solo IPv4 para
      cada comando que ya existia; este modulo es una capacidad adicional, no un
      reemplazo.
- [x] Pruebas con DNS simulado (`tests/test_objetivo.py`, 26 casos): las cuatro formas
      de entrada, rechazos (IPv6, credenciales, ruta sin esquema, dominio mal
      formado), resolucion con una/varias direcciones, autorizacion parcial (solo una
      de varias direcciones en el alcance), ninguna direccion autorizada, y que el
      dominio se resuelve exactamente una vez por llamada.
- [x] CI verificado en Windows y Linux.

**Pendiente** (siguiente iteracion): este modulo todavia no esta conectado a ningun
comando ni panel -- ni `escanear tcp`/`nmap`/`web`/`nuclei`/`zap` lo usan, ni existe
todavia un campo de entrada unica en la interfaz visual. Esa integracion es el
orquestador de reconocimiento automatico (motor compartido CLI/TUI, deteccion de
servicios HTTP/HTTPS, encadenamiento con auditoria web/Nuclei/ZAP) mas el rediseno de
los paneles "Reconocimiento" y "Vulnerabilidades", y queda fuera del alcance de este
incremento por su tamano y sensibilidad de seguridad (es, en esencia, construir el
flujo que usara esta pieza en produccion).

## Fase 4 - Asistente inteligente

- Implementacion concreta sobre el contrato de `assistant/base.py`.
- Explicacion de comandos, sugerencia de parametros, interpretacion de resultados.
- Explicacion de vulnerabilidades y recomendacion de mitigaciones.
- Ayuda para redactar informes y guiar procesos de aprendizaje.
- Ningun comando propuesto por el asistente se ejecuta sin revision y autorizacion explicita del
  usuario.

## Fase 5 - Plataforma completa

- Sistema de plugins.
- Modulos de aprendizaje y laboratorios locales.
- Exportacion a PDF.
- Perfiles de configuracion y gestion avanzada de evidencias.
- Instaladores para Windows y Linux, documentacion publica, empaquetado y releases.
- Mecanismos de actualizacion.
