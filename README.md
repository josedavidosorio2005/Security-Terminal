# Eurabyte Security Terminal (EST)

**EST** es una terminal profesional de pentesting y analisis de seguridad, pensada para equipos
que auditan sistemas propios o expresamente autorizados. Es modular, extensible, de codigo
abierto y funciona igual en Windows y Linux. Toda la experiencia de usuario esta en espanol.

> ⚠️ **Uso autorizado unicamente.** EST solo permite comprobaciones activas (como el escaneo de
> puertos TCP) contra objetivos que hayas registrado explicitamente en el alcance de un proyecto.
> Ver [docs/SEGURIDAD.md](docs/SEGURIDAD.md).

## Caracteristicas de la Fase 1 (MVP)

- Comando principal `est`, con ayuda en espanol (`est --ayuda`).
- Terminal interactiva (`est interactivo`) con autocompletado (Tab) e historial de comandos.
- Gestion de proyectos de auditoria y de su alcance autorizado (IP/CIDR).
- Comprobacion basica de puertos TCP, controlada: validacion de objetivo, verificacion de
  alcance, limites de concurrencia y de tiempo de espera.
- Persistencia de resultados en SQLite.
- Generacion de informes en HTML y JSON.
- Explicaciones interactivas de cada comando (`est explicar <tema>`).

## Instalacion

Requiere Python 3.11 o superior. Instrucciones detalladas para Windows y Linux en
[docs/INSTALACION.md](docs/INSTALACION.md).

```bash
git clone https://github.com/josedavidosorio2005/Security-Terminal.git
cd Security-Terminal
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows (PowerShell)
.venv\Scripts\Activate.ps1

pip install -e ".[dev]"
```

## Uso rapido

```bash
est --ayuda
est interactivo
est proyecto crear laboratorio
est proyecto listar
est alcance agregar 127.0.0.1/32
est escanear tcp 127.0.0.1 --puertos 22,80,443
est explicar tcp
est resultados
est reporte generar --formato html
```

Referencia completa de comandos en [docs/COMANDOS.md](docs/COMANDOS.md).

## Arquitectura

El codigo esta organizado por responsabilidades (CLI, comandos, nucleo, modulos de auditoria,
integraciones, almacenamiento e interfaz). Ver [docs/ARQUITECTURA.md](docs/ARQUITECTURA.md).

## Roadmap

EST se desarrolla en fases incrementales (MVP, interfaz TUI, integraciones con Nmap/Nuclei/ZAP,
asistente de IA, plataforma de plugins). Ver [docs/ROADMAP.md](docs/ROADMAP.md).

## Pruebas

```bash
pytest
ruff check .
```

## Contribuir

Ver [CONTRIBUTING.md](CONTRIBUTING.md).

## Seguridad

Ver [SECURITY.md](SECURITY.md) y [docs/SEGURIDAD.md](docs/SEGURIDAD.md) para el modelo de
autorizacion y las restricciones de uso.

## Licencia

MIT. Ver [LICENSE](LICENSE).
