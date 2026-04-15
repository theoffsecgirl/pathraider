<div align="center">

# pathraider

**Escáner ofensivo de Local File Disclosure y Directory Traversal**

![Language](https://img.shields.io/badge/Python-3.8+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-1.1.0-9E4AFF?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Pentesting-111111?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

> 🇬🇧 [English version](README.md)

</div>

---

```text
┌──────────────────────────────────────────────────────┐
│                                                      │
│  ██████╗  ██████╗ ███████╗██╗  ██╗                │
│  ██╔══██╗██╔════╝ ██╔════╝██║  ██║                │
│  ██████╔╝███████╗█████╗  ███████║                │
│  ██╔═══╝ ██╔══██╗██╔══╝  ██╔══██║                │
│  ██║     ╚██████╔╝███████╗██║  ██║                │
│  ╚═╝      ╚═════╝ ╚══════╝╚═╝  ╚═╝                │
│                                                      │
│  ██████╗  ██████╗ ██╗ █████╗  ██████╗        │
│  ██╔══██╗██╔══██╗██║██╔══██╗██╔════╝        │
│  ██████╔╝██████╔╝██║██║  ██║█████╗          │
│  ██╔═══╝ ██╔══██╗██║██║  ██║██╔══╝          │
│  ██║     ██║  ██║██║╚█████╔╝╚██████╗        │
│  ╚═╝     ╚═╝  ╚═╝╚═╝ ╚════╝  ╚═════╝        │
│                                                      │
│    LFD & Directory Traversal scanner  v1.1.0         │
│    encodings: plain · %2e · doble · unicode · null   │
│    by theoffsecgirl                                  │
└──────────────────────────────────────────────────────┘
```

---

## ¿Qué hace?

Comprueba si un parámetro de una aplicación web permite leer archivos locales del sistema (LFD / Path Traversal). Genera automáticamente variantes de encoding para bypassear filtros y WAFs.

---

## Características

- Un objetivo (`--url`) o múltiples desde archivo (`--list`)
- Inyección con marcador `FUZZ` o parámetro configurable (`--param`)
- **132 rutas de prueba** generadas automáticamente desde 12 rutas base con encodings:
  - Plain, `%2e%2e%2f`, doble encoding, `..%2f`, backslash, `..%5c`, unicode overlong, `%c0%ae`, null byte
- Detección heurística de contenido sensible (`/etc/passwd`, `win.ini`, etc.)
- Escaneo concurrente con hilos
- Exportación a JSON

---

## Instalación

```bash
git clone https://github.com/theoffsecgirl/pathraider.git
cd pathraider
pip install requests colorama
```

---

## Uso

```bash
# Escaneo con FUZZ
python3 pathraider.py -u "https://example.com/download.php?file=FUZZ"

# Con parámetro
python3 pathraider.py -u "https://example.com/get.php" -p file

# Lista de objetivos
python3 pathraider.py -L scope.txt -T 20

# Exportar JSON
python3 pathraider.py -L scope.txt --json-output resultados.json

# Ver versión
python3 pathraider.py --version
```

---

## Parámetros

```text
-u, --url          URL objetivo (puede contener FUZZ)
-L, --list         Archivo con lista de objetivos
--paths            Rutas de traversal personalizadas
-p, --param        Parámetro sin FUZZ (default: file)
-t, --timeout      Timeout por petición (default: 5)
-T, --threads      Hilos por objetivo (default: 10)
-A, --agent        User-Agent personalizado
--insecure         Desactivar verificación TLS
--json-output      Guardar resultados en JSON
-v, --verbose      Más información
    --version      Muestra la versión
```

---

## Uso ético

Solo para bug bounty, laboratorios y auditorías autorizadas.

---

## Licencia

MIT · [theoffsecgirl](https://theoffsecgirl.com)
