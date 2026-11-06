#!/usr/bin/env bash
# Flujo basico de EST: crear un proyecto, autorizar un alcance local y escanear.
# Pensado solo como ejemplo educativo contra 127.0.0.1 (no usar contra terceros).
set -euo pipefail

est proyecto crear laboratorio
est alcance agregar 127.0.0.1/32
est escanear tcp 127.0.0.1 --puertos 22,80,443
est resultados
est reporte generar --formato html
