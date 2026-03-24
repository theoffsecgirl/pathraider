<div align="center">

# tool-lfdscanner

**Escáner ofensivo de Local File Disclosure y Directory Traversal**

![Language](https://img.shields.io/badge/Python-3.8+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Pentesting-111111?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

</div>

---

## ¿Qué hace?

Comprueba si un parámetro de una aplicación web permite leer archivos locales del sistema (LFD / Path Traversal). Pensado para bug bounty, pentesting web y laboratorios de seguridad.

---

## Características

- Un objetivo (`--url`) o múltiples desde archivo (`--list`)
- Inyección con marcador `FUZZ` en la URL o parámetro configurable (`--param`)
- Rutas de traversal por defecto (Unix y Windows) o personalizadas
- Detección heurística de contenido sensible (`/etc/passwd`, `win.ini`, etc.)
- Escaneo concurrente con hilos por objetivo
- User-Agent configurable y opción `--insecure` para labs
- Exportación de resultados a JSON

---

## Instalación

```bash
git clone https://github.com/theoffsecgirl/tool-lfdscanner.git
cd tool-lfdscanner
pip install requests colorama
chmod +x tool-lfdscanner.py
```

---

## Uso

```bash
# Escaneo con marcador FUZZ
python3 tool-lfdscanner.py -u "https://example.com/download.php?file=FUZZ"

# Escaneo usando parámetro
python3 tool-lfdscanner.py -u "https://example.com/get.php" -p file

# Lista de objetivos
python3 tool-lfdscanner.py -L scope.txt --paths traversal_paths.txt -T 20

# Exportar a JSON
python3 tool-lfdscanner.py -L scope.txt --json-output resultados_lfd.json
```

---

## Parámetros

```text
-u, --url          URL objetivo (puede contener FUZZ)
-L, --list         Archivo con lista de objetivos
--paths            Archivo con rutas de traversal personalizadas
-p, --param        Parámetro cuando no hay FUZZ (default: file)
-t, --timeout      Timeout por petición (default: 5)
-T, --threads      Hilos por objetivo (default: 10)
-A, --agent        User-Agent personalizado
--insecure         No verificar TLS (solo laboratorio)
--json-output      Guardar resultados en JSON
-v, --verbose      Más información
```

---

## Output esperado

```text
[+] Posible LFD/Traversal en https://example.com/get.php?file=../../etc/passwd
    path: ../../etc/passwd
    status: 200
    snippet: root:x:0:0:root:/root:/bin/bash
```

Valida siempre manualmente el contexto y el impacto.

---

## Uso ético

Solo para programas de bug bounty, laboratorios y auditorías autorizadas. El uso sin permiso es ilegal.

---

## Licencia

MIT · [theoffsecgirl](https://theoffsecgirl.com)
