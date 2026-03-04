# tool-lfdscanner

Escáner ofensivo de **Local File Disclosure (LFD)** y **Directory Traversal** escrito en Python.

Pensado para bug bounty, pentesting web y laboratorios de seguridad donde se necesita comprobar rápidamente si un parámetro permite leer archivos locales del sistema.

---

## Características

- Soporte para:
  - un único objetivo (`--url`)
  - múltiples objetivos desde archivo (`--list`)
- Inyección de rutas mediante:
  - marcador `FUZZ` en la URL
  - parámetro configurable (`--param`, por defecto `file`)
- Conjunto de rutas de traversal por defecto (Unix y Windows).
- Soporte para rutas personalizadas desde archivo.
- Detección heurística de contenido interesante:
  - `/etc/passwd`
  - `/etc/hosts`
  - `win.ini`
  - patrones típicos de sistema.
- Escaneo concurrente con hilos por objetivo.
- User-Agent configurable.
- Opción `--insecure` para entornos de prueba.
- Exportación de resultados a JSON.

---

## Requisitos

- Python 3.8 o superior.
- Librerías de Python:

```bash
pip install requests colorama
```

---

## Instalación

```bash
git clone https://github.com/theoffsecgirl/tool-lfdscanner.git
cd tool-lfdscanner
chmod +x tool-lfdscanner.py
```

Si prefieres, renombra el archivo:

```bash
mv tool-lfdscanner.py lfdscanner.py
chmod +x lfdscanner.py
```

---

## Uso básico

### Un solo objetivo

```bash
python3 tool-lfdscanner.py -u "https://example.com/download.php?file=FUZZ"
```

En este caso, `FUZZ` será reemplazado por cada ruta de traversal.

### Lista de objetivos

```bash
python3 tool-lfdscanner.py -L dominios.txt
```

Archivo `dominios.txt`:

```text
https://example.com/download.php?file=FUZZ
https://victima.com/view?path=FUZZ
```

---

## Parámetros principales

```text
-u, --url          URL objetivo (puede contener FUZZ)
-L, --list         Archivo con lista de objetivos
--paths            Archivo con rutas de traversal personalizadas
-p, --param        Nombre del parámetro cuando no hay FUZZ (por defecto: file)
-t, --timeout      Timeout por petición (por defecto: 5)
-T, --threads      Hilos por objetivo (por defecto: 10)
-A, --agent        User-Agent personalizado
--insecure         No verificar TLS (solo entornos de laboratorio)
--json-output      Guardar resultados en JSON
-v, --verbose      Mostrar más información
```

### Ejemplos

```bash
# Escaneo rápido con marcador FUZZ
python3 tool-lfdscanner.py -u "https://example.com/get.php?f=FUZZ"

# Escaneo usando parámetro file
python3 tool-lfdscanner.py -u "https://example.com/get.php" -p file

# Lista de objetivos y rutas personalizadas
python3 tool-lfdscanner.py -L scope.txt --paths traversal_paths.txt -T 20

# Guardar resultados JSON
python3 tool-lfdscanner.py -L scope.txt --json-output resultados_lfd.json
```

---

## Interpretación de resultados

Cuando se detecta una posible vulnerabilidad se mostrará una salida similar a:

```text
[+] Posible LFD/Traversal en https://example.com/get.php?file=../../etc/passwd
    path: ../../etc/passwd
    status: 200
    snippet: root:x:0:0:root:/root:/bin/bash
```

Esto indica que el servidor probablemente está devolviendo contenido del archivo local solicitado.

Siempre valida manualmente el contexto y el impacto.

---

## Uso ético

Esta herramienta está pensada para:

- programas de bug bounty
- pruebas en entornos de laboratorio
- auditorías autorizadas

No la uses contra sistemas sin permiso. El uso indebido es ilegal y va en contra del propósito del proyecto.

---

## Licencia

Consulta el archivo `LICENSE` para más detalles.
