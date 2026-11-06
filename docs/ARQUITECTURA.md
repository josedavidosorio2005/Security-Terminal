# Arquitectura de EST

Este documento describe la organizacion del codigo de Eurabyte Security Terminal (EST) y la
responsabilidad de cada paquete. El objetivo es mantener una separacion clara entre interfaz,
logica de negocio e integraciones externas, para que el proyecto siga siendo facil de ampliar.

## Estructura de paquetes

```text
src/eurabyte_security/
├── cli/            Ensamblaje de la aplicacion Typer (comando `est`).
├── commands/       Logica de cada comando + su exposicion como subcomando Typer.
├── core/           Configuracion (rutas, proyecto activo), validaciones y errores comunes.
├── modules/
│   ├── network/    Comprobaciones de red (Fase 1: escaneo TCP basico).
│   ├── web/        Auditoria web (Fase 3: cabeceras HTTP, TLS...). Vacio en la Fase 1.
│   ├── vulnerability/  Analisis de vulnerabilidades (Fase 3: Nuclei...). Vacio en la Fase 1.
│   └── reporting/  Construccion de informes (HTML/JSON) a partir de resultados.
├── integrations/   Interfaz base para adaptadores externos (Nmap, Nuclei, ZAP...). Fase 3.
├── assistant/      Contrato base del futuro asistente de IA. Fase 4.
├── storage/        Repositorio SQLite (proyectos, alcances, resultados).
└── ui/             Consola enriquecida (Rich) y terminal interactiva (prompt_toolkit).
```

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
