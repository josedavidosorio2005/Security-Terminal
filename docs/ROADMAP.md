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
resultados de Nmap tienen su propia tabla (`resultados_nmap`) y todavia no aparecen en
`est resultados` ni en `est reporte generar` (solo los de `escanear tcp`); eso queda para una
iteracion posterior.

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

### Pasos 4-5 - Pendientes (PRs independientes futuras)

- Adaptador opcional para Nuclei (plantillas de bajo impacto, nunca intrusivas por defecto).
- Integracion opcional con OWASP ZAP (solo analisis pasivo por defecto).
- Cada integracion seguira el mismo motor (`integrations/base.py` + `integrations/proceso.py`)
  descrito arriba: documentacion en espanol, validacion de argumentos, comprobacion de
  instalacion y verificacion de alcance autorizado antes de ejecutar nada.
- Unificar los resultados de `escanear tcp`, `nmap` y `web` en un unico listado/informe
  general (hoy cada uno tiene su propia tabla e informe).

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
