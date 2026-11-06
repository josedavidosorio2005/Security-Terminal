# Contribuir a EST

Gracias por tu interes en Eurabyte Security Terminal. Este documento resume como preparar tu
entorno y que se espera de un pull request.

## Preparar el entorno

```bash
git clone https://github.com/josedavidosorio2005/Security-Terminal.git
cd Security-Terminal
python -m venv .venv
source .venv/bin/activate   # En Windows: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Flujo de trabajo

1. Crea una rama descriptiva a partir de `main` (por ejemplo, `feat/mi-mejora` o
   `fix/corrige-tal-cosa`).
2. Si vas a trabajar en una nueva funcionalidad, lee primero
   [docs/ARQUITECTURA.md](docs/ARQUITECTURA.md) para ubicar donde encaja tu cambio
   (`core`, `commands`, `modules`, `integrations`, `storage` o `ui`).
3. Escribe o actualiza las pruebas en `tests/` para cualquier cambio de comportamiento.
4. Ejecuta antes de abrir el PR:
   ```bash
   pytest
   ruff check .
   ```
5. Describe en el PR que problema resuelve el cambio y como lo probaste.

## Convenciones del codigo

- Todo el texto visible para la persona que usa EST (mensajes, ayuda, nombres de comandos) debe
  estar en espanol.
- La logica de negocio (validaciones, acceso a datos, modulos de auditoria) debe ser
  independiente de Typer/Rich/prompt_toolkit, para poder probarla sin la CLI.
- Usa las excepciones de `core/errores.py` (`ErrorEST` y subclases) para errores esperables;
  evita `sys.exit` fuera de `cli/app.py`.
- No agregues dependencias nuevas sin justificarlo en el PR.

## Pruebas activas contra objetivos reales

Ninguna prueba automatizada ni ningun ejemplo de este repositorio debe apuntar a un objetivo
real que no sea `127.0.0.1` o un servidor levantado por la propia prueba. Ver
[docs/SEGURIDAD.md](docs/SEGURIDAD.md).

## Reportar errores o proponer ideas

Abre un issue en GitHub describiendo el comportamiento esperado, el actual y los pasos para
reproducirlo. Para vulnerabilidades de seguridad, sigue [SECURITY.md](SECURITY.md) en lugar de
abrir un issue publico.
