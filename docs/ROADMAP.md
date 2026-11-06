# Roadmap de EST

EST se desarrolla en fases incrementales. Cada fase solo se considera completa cuando cumple sus
criterios de aceptacion y tiene pruebas automatizadas que lo demuestran.

## Fase 1 - MVP funcional (en desarrollo / implementada en este PR)

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
- [ ] CI verificado en GitHub Actions sobre `windows-latest` y `ubuntu-latest` (workflow creado
      en este PR; pendiente de verse ejecutar en GitHub tras el push).

## Fase 2 - Interfaz profesional

- Interfaz TUI con Textual.
- Navegacion por teclado, panel lateral de modulos, paneles de resultados.
- Autocompletado contextual y documentacion integrada en la TUI.
- Tema oscuro profesional, historial de auditorias, indicadores de progreso.
- Sistema de configuracion de usuario.

## Fase 3 - Herramientas de ciberseguridad

- Adaptadores para Nmap, Nuclei, OWASP ZAP y tshark sobre la interfaz definida en
  `integrations/base.py`.
- Analisis de cabeceras HTTP y revision de certificados TLS.
- Auditoria de configuraciones e inspeccion de servicios de red.
- Cada integracion: documentacion en espanol, validacion de argumentos, comprobacion de
  instalacion (con mensajes claros si la herramienta no esta disponible) y verificacion de
  alcance autorizado antes de ejecutar nada.

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
