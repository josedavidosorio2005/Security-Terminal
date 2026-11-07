# Instrucciones para Claude Code en este repositorio

Este archivo persiste contexto para futuras sesiones de desarrollo con Claude Code sobre
**AURABYTE Security Terminal (AST)**.

## Que es este proyecto

AST es una terminal de pentesting en espanol, multiplataforma (Windows/Linux), con dos
interfaces: una CLI/REPL (Typer + Rich + prompt_toolkit, Fase 1) y una interfaz visual completa
(Textual, Fase 2), ambas sobre la misma logica y persistencia en SQLite. El roadmap completo
esta en [docs/ROADMAP.md](docs/ROADMAP.md); las Fases 1 y 2 ya estan implementadas.

**Importante sobre nombres**: el paquete Python sigue llamandose `eurabyte_security`, la
distribucion `eurabyte-security` y el comando de consola `est` -- no los renombres. Son
nombres heredados de la Fase 1 que se mantienen por compatibilidad con instalaciones
existentes. La marca visible (AURABYTE / AST) vive en `eurabyte_security/marca.py` y se usa en
textos, titulos y documentacion, no en nombres de paquetes, modulos ni en el comando.

**Sobre el escudo de marca**: `ESCUDO_COMPACTO` y `ESCUDO_ASCII` en `marca.py` son una
alternativa ASCII deliberada (sin mascotas ni robots) mientras no exista el recurso grafico
oficial del escudo azul/cian con simbolo de terminal. Si el equipo de diseno entrega ese
recurso, sustituyelo unicamente ahi (y, si aplica, en `ui/tui/estilos.tcss`, clase `.logo`): no
crees un logo nuevo ni dupliques el glifo en otros widgets.

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
6. **La interfaz visual (`ui/tui/`) nunca ejecuta comandos mediante un shell del sistema.**
   `motor_comandos.py` despacha texto directamente a las funciones puras de `commands/*.py`.
7. **Una seccion sin implementar se marca como "Proximamente", nunca simula datos.** Ver
   `widgets/paneles.py:PanelProximamente` y no le agregues datos de relleno falsos.
8. **Las operaciones de red en la TUI corren en un worker (`@work(thread=True)`), nunca en el
   hilo principal de Textual.** Bloquear ese hilo congela toda la interfaz.

## Arquitectura (resumen; detalle en docs/ARQUITECTURA.md)

- `cli/app.py`: ensambla la aplicacion Typer raiz (incluye `interactivo` e `interfaz`). Capa
  fina, sin logica de negocio.
- `commands/*.py`: logica de cada comando + su exposicion como subcomando Typer. Reutilizada
  por la CLI no interactiva, por `ui/repl.py` y por `ui/tui/motor_comandos.py` y los paneles de
  la interfaz visual -- nunca la dupliques.
- `core/`: validaciones (`validation.py`), configuracion/rutas (`config.py`) y excepciones
  propias (`errores.py`, todas heredan de `ErrorEST`).
- `modules/network/tcp_scanner.py`: logica pura del escaneo TCP, sin dependencias de Typer/Rich.
- `modules/reporting/generador.py`: construccion de informes HTML/JSON.
- `storage/database.py`: unico punto de acceso a SQLite (`BaseDatos`).
- `integrations/base.py` y `assistant/base.py`: contratos para las Fases 3 y 4. No implementar
  integraciones reales ahi sin revisar primero `docs/ROADMAP.md`. `integrations/deteccion.py`
  solo detecta binarios instalados (`shutil.which`); nunca los ejecuta.
- `ui/tui/`: interfaz visual Textual (ver docs/ARQUITECTURA.md y docs/INTERFAZ.md). Al agregar
  un widget nuevo que use `Input` dentro de un `Horizontal` junto a otro control, recuerda que
  `Input` tiene `width: 100%` por defecto (ver regla `Horizontal > Input` en `estilos.tcss`) o
  el control vecino quedara fuera del area clicable.

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
