# Arquitectura de AST

Este documento describe la organizacion del codigo de AURABYTE Security Terminal (AST) y la
responsabilidad de cada paquete. El objetivo es mantener una separacion clara entre interfaz,
logica de negocio e integraciones externas, para que el proyecto siga siendo facil de ampliar.

> El paquete Python sigue llamandose `eurabyte_security` por compatibilidad con instalaciones
> de la Fase 1 (ver CLAUDE.md). La identidad de marca (AURABYTE / AST) vive en
> `eurabyte_security/marca.py`.

## Estructura de paquetes

```text
src/eurabyte_security/
├── marca.py        Identidad de marca (nombre, logo, banner ASCII).
├── cli/            Ensamblaje de la aplicacion Typer (comando `est`).
├── commands/       Logica de cada comando + su exposicion como subcomando Typer.
├── core/           Configuracion (rutas, proyecto activo), validaciones y errores comunes.
├── modules/
│   ├── network/    Comprobaciones de red (Fase 1: escaneo TCP basico).
│   ├── web/        Auditoria web (Fase 3: cabeceras HTTP, TLS...). Vacio en la Fase 1.
│   ├── vulnerability/  Analisis de vulnerabilidades (Fase 3: Nuclei...). Vacio en la Fase 1.
│   └── reporting/  Construccion de informes (HTML/JSON) a partir de resultados.
├── integrations/
│   ├── base.py     Interfaz base para adaptadores externos (Nmap, Nuclei, ZAP...). Fase 3.
│   └── deteccion.py  Comprueba si esas herramientas estan instaladas (nunca las ejecuta).
├── assistant/      Contrato base del futuro asistente de IA. Fase 4.
├── storage/        Repositorio SQLite (proyectos, alcances, resultados).
└── ui/
    ├── consola.py  Consola enriquecida (Rich) compartida por la CLI.
    ├── repl.py     Terminal interactiva de linea de comandos (`est interactivo`).
    └── tui/        Interfaz visual Textual (`est interfaz`, Fase 2). Ver mas abajo.
```

## La interfaz visual (`ui/tui/`, Fase 2)

```text
ui/tui/
├── app.py              AuraByteApp: layout, navegacion y eventos globales.
├── estilos.tcss        Paleta y estilos (Textual CSS).
├── estado.py           Snapshot de estado (proyecto activo, conteos) para la UI.
├── motor_comandos.py   Interprete de la Terminal AST: despacha texto a commands/*.
└── widgets/
    ├── navegacion.py   Encabezado, barra lateral y barra de estado.
    ├── terminal.py     Entrada con historial/autocompletado y panel de ayuda contextual.
    └── paneles.py      Un panel por seccion (Proyectos, Alcance, Redes, Resultados...).
```

`AuraByteApp` reutiliza exactamente la misma logica que la CLI: `motor_comandos.py` y los
paneles importan las funciones puras de `commands/*.py` (las mismas que usa `cli/app.py`), no
una copia. Las operaciones de red (escaneo TCP) se ejecutan en workers de Textual
(`@work(thread=True)`) para no bloquear la interfaz, con cancelacion best-effort desde el panel
"Redes" (ver "Limitaciones conocidas" en `docs/INTERFAZ.md`).

## Flujo de una operacion (ejemplo: `est escanear tcp`)

1. **`cli/app.py`** registra el sub-comando `escanear` (definido en `commands/escanear.py`) en
   la aplicacion Typer raiz.
2. **`commands/escanear.py`** valida la entrada (`core/validation.py`), resuelve el proyecto
   activo (`commands/_comun.py`), comprueba que el objetivo esta dentro del alcance autorizado
   (`storage/database.py`) y delega la comprobacion real al modulo de red.
3. **`modules/network/tcp_scanner.py`** ejecuta la comprobacion TCP con concurrencia y tiempo de
   espera acotados, sin conocer nada sobre proyectos, CLI ni base de datos.
4. El resultado se persiste en SQLite a traves de **`storage/database.py`** y se muestra en
   pantalla con Rich (**`ui/consola.py`**).

Este mismo patron (validar -> resolver proyecto -> ejecutar logica de modulo -> persistir ->
mostrar) se repite en los demas comandos (`proyecto`, `alcance`, `resultados`, `reporte`).

## Por que esta separacion

- **Testabilidad**: `core/validation.py`, `storage/database.py` y
  `modules/network/tcp_scanner.py` no dependen de Typer ni de Rich, por lo que se prueban con
  pytest de forma aislada y rapida (ver `tests/`).
- **Reutilizacion entre interfaces**: la terminal interactiva (`ui/repl.py`) reutiliza el mismo
  arbol de comandos Click/Typer que la CLI no interactiva, por lo que la logica de negocio nunca
  se duplica.
- **Errores controlados**: toda la logica de negocio lanza excepciones de `core/errores.py`
  (`ErrorEST` y subclases) en lugar de llamar a `sys.exit`. Solo `cli/app.py` y `ui/repl.py`
  deciden como mostrar esos errores al usuario.
- **Puntos de extension explicitos**: `integrations/base.py` y `assistant/base.py` documentan el
  contrato que deberan cumplir las futuras integraciones (Fase 3) y el asistente de IA (Fase 4),
  sin necesidad de tocar el resto del codigo cuando se implementen.

## Persistencia

Toda la informacion vive en SQLite, en un unico archivo bajo el directorio de datos del usuario
(`~/.eurabyte_security/est.db` por defecto, o `$EST_HOME/est.db` si se define esa variable de
entorno). El esquema tiene tres tablas: `proyectos`, `alcances` y `resultados` (ver
`storage/database.py`).
