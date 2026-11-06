# Instrucciones para Claude Code en este repositorio

Este archivo persiste contexto para futuras sesiones de desarrollo con Claude Code sobre
**Eurabyte Security Terminal (EST)**.

## Que es este proyecto

EST es una terminal de pentesting en espanol, multiplataforma (Windows/Linux), construida con
Typer + Rich + prompt_toolkit, con persistencia en SQLite. El roadmap completo esta en
[docs/ROADMAP.md](docs/ROADMAP.md); la Fase 1 (MVP) ya esta implementada.

## Reglas que no se negocian

1. **Todo texto visible para el usuario va en espanol**: mensajes, ayuda, nombres de comandos,
   nombres de opciones (`--puertos`, no `--ports`).
2. **Ninguna comprobacion activa de red puede ejecutarse contra un objetivo que no este
   registrado en el alcance autorizado de un proyecto.** Esta verificacion vive en
   `commands/escanear.py` (`escanear_tcp`) y no debe eliminarse ni debilitarse.
3. **El asistente de IA (Fase 4, todavia sin implementar) nunca ejecuta comandos por si
   mismo.** Cualquier sugerencia de comando debe pasar por una estructura tipo
   `assistant.base.SugerenciaAsistente` con `requiere_autorizacion=True` y mostrarse al usuario
   antes de ejecutarse.
4. **No se commitean credenciales, tokens ni datos sensibles.** La configuracion local vive en
   el directorio de datos del usuario (`~/.eurabyte_security`, o `$EST_HOME` en pruebas), nunca
   en el repositorio.
5. **Las pruebas automatizadas nunca tocan redes de terceros.** Usa siempre `127.0.0.1` con un
   socket de prueba abierto por el propio test (ver `tests/test_tcp_scanner.py` como ejemplo).

## Arquitectura (resumen; detalle en docs/ARQUITECTURA.md)

- `cli/app.py`: ensambla la aplicacion Typer raiz. Capa fina, sin logica de negocio.
- `commands/*.py`: logica de cada comando + su exposicion como subcomando Typer. Reutilizada
  tanto por la CLI no interactiva como por `ui/repl.py`.
- `core/`: validaciones (`validation.py`), configuracion/rutas (`config.py`) y excepciones
  propias (`errores.py`, todas heredan de `ErrorEST`).
- `modules/network/tcp_scanner.py`: logica pura del escaneo TCP, sin dependencias de Typer/Rich.
- `modules/reporting/generador.py`: construccion de informes HTML/JSON.
- `storage/database.py`: unico punto de acceso a SQLite (`BaseDatos`).
- `integrations/base.py` y `assistant/base.py`: contratos para las Fases 3 y 4. No implementar
  integraciones reales ahi sin revisar primero `docs/ROADMAP.md`.

## Como verificar que un cambio funciona

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

Las pruebas usan la variable de entorno `EST_HOME` (ver `tests/conftest.py`) para aislar cada
test en un directorio temporal: nunca dependen de `~/.eurabyte_security` real.

## Convenciones de nombres

El codigo (identificadores, docstrings) tambien esta en espanol, para que el codigo y la
experiencia de usuario sean coherentes. Excepciones: nombres de libreria estandar, nombres de
API externas y terminologia tecnica sin traduccion natural (p. ej. "socket", "timeout" como
concepto aunque el parametro se llame `--timeout`/`tiempo_espera`).

## Al terminar una fase o funcionalidad

Antes de decir que algo esta "terminado": ejecuta `pytest` y `ruff check .`, y si el cambio
afecta a un comando, pruebalo manualmente con el comando `est` instalado (no solo con los
tests). Actualiza `docs/COMANDOS.md` y `docs/ROADMAP.md` si agregas o cambias comandos.
