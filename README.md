[README.md](https://github.com/user-attachments/files/29244428/README.md)
# Ghosttag v2.0

**Source Code · Document · Binary Credential Hunter**

Herramienta de reconocimiento pasivo para pentesting y auditorías de seguridad. Analiza URLs y sitios web completos en busca de credenciales, tokens, hashes, datos de infraestructura y PII expuestos en código fuente, documentos y archivos binarios.

> Autor: Tony_ZeroD — [ajromerofg-binary](https://github.com/ajromerofg-binary)

---

## Características

- Análisis de **código fuente** (HTML, JS, CSS, PHP, JSON, XML, .env…)
- Extracción de texto y metadatos de **PDF, Word (.docx/.doc) y Excel (.xlsx/.xls)**
- Metadatos **EXIF** de imágenes: GPS, autor, software, comentarios
- Volcado e inspección de **bases de datos SQLite** locales expuestas
- Análisis de **SQL dumps** (.sql, .dump, .bak) con credenciales en texto plano
- **Spider** configurable (profundidad 0–5) para rastrear sitios completos
- **Auto-instalación de dependencias** al arranque (apt / dnf / yum / pacman)
- Salida simultánea en **pantalla** (coloreada por severidad) y **fichero** (txt o JSON)
- Modo **silencioso** (`-q`) para integración en pipelines y scripts
- Soporte de cookies, headers personalizados y bypass SSL

---

## Instalación

```bash
git clone https://github.com/ajromerofg-binary/ghosttag
cd ghosttag
chmod +x ghosttag.sh
./ghosttag.sh -u https://target.com
```

Al ejecutarse por primera vez, Ghosttag verifica e instala automáticamente las dependencias que falten (requiere `sudo` para los paquetes de sistema).

---

## Dependencias

| Dependencia | Uso | Instalación manual |
|---|---|---|
| `curl` | Peticiones HTTP — **obligatoria** | `apt install curl` |
| `python3` | Motor JSON, módulos Word/Excel — **obligatoria** | `apt install python3` |
| `pdftotext` | Extracción de texto PDF | `apt install poppler-utils` |
| `exiftool` | Metadatos PDF, Word, Excel e imágenes | `apt install libimage-exiftool-perl` |
| `antiword` | Documentos Word legacy (.doc) | `apt install antiword` |
| `sqlite3` | Análisis de bases de datos SQLite | `apt install sqlite3` |
| `python-docx` | Documentos Word modernos (.docx) | `pip3 install python-docx` |
| `openpyxl` | Hojas de cálculo Excel (.xlsx) | `pip3 install openpyxl` |

Las dependencias opcionales ausentes no detienen la ejecución — los módulos afectados se omiten con un aviso.

---

## Uso

```
./ghosttag.sh -u URL [opciones]
```

### Opciones

| Flag | Argumento | Por defecto | Descripción |
|---|---|---|---|
| `-u` | URL | — | URL objetivo (**obligatorio**) |
| `-d` | 0–5 | `0` | Profundidad de spider (0 = solo la URL indicada) |
| `-o` | ruta | Desktop/ghosttag_\<fecha\>.txt | Fichero de reporte de salida |
| `-f` | txt \| json | `txt` | Formato del reporte |
| `-c` | string | — | Cookies de sesión: `"name=val; name2=val2"` |
| `-H` | string | — | Header HTTP extra: `"Authorization: Bearer <token>"` |
| `-a` | string | Firefox/Linux UA | User-Agent personalizado |
| `-t` | 1–60 | `10` | Timeout por petición (segundos) |
| `-k` | — | — | Ignorar errores de certificado SSL |
| `-q` | — | — | Modo silencioso (sin output en pantalla) |
| `-h` | — | — | Mostrar ayuda |

---

## Ejemplos

**Análisis básico de una URL:**
```bash
./ghosttag.sh -u https://target.com
```

**Spider con profundidad 2, reporte en JSON:**
```bash
./ghosttag.sh -u https://target.com -d 2 -f json -o report.json
```

**Con sesión autenticada e ignorar SSL:**
```bash
./ghosttag.sh -u https://target.com/admin -c "PHPSESSID=abc123; token=xyz" -k
```

**Con token Bearer, modo silencioso (para pipelines):**
```bash
./ghosttag.sh -u https://api.target.com -H "Authorization: Bearer eyJ..." -q -o out.txt
```

**Objetivo con profundidad 1 y timeout extendido:**
```bash
./ghosttag.sh -u https://target.com -d 1 -t 30
```

---

## Qué detecta

### Severidades

| Nivel | Color | Descripción |
|---|---|---|
| `CRITICAL` | 🔴 Rojo | Credencial o secreto directamente explotable |
| `HIGH` | 🟠 Naranja | Dato sensible de alto riesgo |
| `MEDIUM` | 🟡 Amarillo | Información de infraestructura o configuración |
| `LOW` | 🟢 Verde | Metadatos y datos de baja criticidad |

### Categorías de patrones (53 regex)

**COMMENT_CRED** — Credenciales en comentarios HTML, JS y CSS

**HARDCODED** — Passwords hardcodeadas en variables, parámetros URL, usernames

**API_KEY** — Tokens y claves de servicios:
- API keys genéricas
- JWT hardcodeados
- Google API Keys (`AIza...`)
- AWS Access Key ID (`AKIA...`) y Secret Access Key
- Stripe (`sk_live_`, `pk_test_`...)
- GitHub tokens (`ghp_`, `gho_`...)
- Slack tokens (`xoxb-`, `xoxp-`...)
- SendGrid API keys

**APP_SECRET** — Secret keys de aplicación (Flask, Django, Laravel), salts, claves de cifrado AES/RSA, claves PEM privadas

**DB_CONN** — Cadenas de conexión completas (MySQL, PostgreSQL, MongoDB, Redis, MSSQL) y campos sueltos de usuario/contraseña de BBDD

**HASH** — Hashes MD5, SHA1, SHA256, bcrypt y htpasswd

**SQLDUMP** — `INSERT INTO` con campos password, `CREATE USER IDENTIFIED BY`, hashes en columnas SQL

**INFRA** — IPs privadas clase A/B/C, localhost, rutas del sistema de ficheros, puertos internos en URLs

**PII** — Direcciones de email (en código y en comentarios HTML)

**CONFIG** — Variables de entorno con secretos (`process.env.SECRET_KEY`), referencias a `.env`, modo debug activo, `phpinfo()` expuesto, claves SMTP, DSN con credenciales, TODO/FIXME con datos sensibles

---

## Módulos de análisis de documentos

### PDF
- Extracción de texto con `pdftotext` + análisis completo con los 53 patrones
- Metadatos con `exiftool`: Author, Creator, Producer, Company, LastModifiedBy, fechas, rutas internas embebidas, emails en metadatos

### Word (.docx / .doc)
- `.docx`: extracción de texto con `python-docx` (incluyendo párrafos, tablas y comentarios) + análisis de patrones
- `.doc` legacy: texto con `antiword`
- Metadatos `exiftool`: Author, LastModifiedBy, Company, rutas de fichero, emails

### Excel (.xlsx / .xls)
- `.xlsx`: volcado de texto de todas las celdas con `openpyxl`, incluyendo hojas ocultas
- Análisis de patrones sobre el contenido de celdas
- Metadatos `exiftool`

### Imágenes (jpg, png, gif, bmp, tiff, webp, svg)
- Solo metadatos EXIF via `exiftool`
- Coordenadas GPS (latitud/longitud) — revelan ubicación física del autor
- Autor, software utilizado, descripción, copyright, comentarios
- URLs o rutas embebidas en metadatos

### SQLite (.db, .sqlite, .sqlite3)
- Validación del magic header antes de analizar
- Volcado del esquema completo (`.schema`)
- Detección de tablas con nombres sensibles (users, passwords, tokens, credentials…)
- Detección de columnas sensibles en el esquema
- Volcado de hasta 5 filas de cada tabla sensible + análisis de patrones sobre los datos

### SQL dumps (.sql, .dump, .bak)
- Análisis directo del texto con los 53 patrones
- Especialmente eficaz en `INSERT INTO`, `CREATE USER`, cadenas de conexión en comentarios SQL y hashes en columnas

---

## Salida

### En pantalla (stderr)

```
[*] Verificando dependencias...
  [OK] curl
  [OK] python3
  [OK] pdftotext
  [!]  exiftool no encontrado — instalando...
  [OK] exiftool instalado correctamente

[*] Iniciando analisis

[DOC] Analizando PDF: https://target.com/doc/manual.pdf

[*]   [!] 3 hallazgo(s) en documento: https://target.com/doc/manual.pdf

  [CRITICAL] Password hardcodeada (asignacion)
             Linea/Campo 42 => password="Sup3rS3cr3t!"

  [HIGH] Autor del documento
         Linea/Campo Author => John Smith (ACME Corp)

======================================================
  GHOSTTAG v2.0 — Resumen
======================================================
  URLs/recursos analizados : 12
  Documentos/binarios      : 3
  Hallazgos totales        : 7
  Reporte                  : /home/user/Desktop/ghosttag_20260623_143022.txt
======================================================

  [!] Se encontraron credenciales o datos sensibles.
```

### Reporte TXT

El fichero incluye cabecera con fecha, target y profundidad, bloques por recurso con todos los hallazgos detallados (severidad, categoría, número de línea, match exacto, fuente) y resumen final con contadores.

### Reporte JSON

```json
{
  "tool": "ghosttag",
  "version": "2.0",
  "date": "2026-06-23T14:30:22",
  "target": "https://target.com",
  "depth": 1,
  "findings": [
    {
      "severity": "CRITICAL",
      "category": "API_KEY",
      "description": "Google API key",
      "line_field": "12",
      "match": "AIzaSyD-9tSrke72PkHHGfNsE9o1MkLhQ6Vz5Ak",
      "source_type": "text",
      "url": "https://target.com/js/app.js"
    }
  ],
  "summary": {
    "urls_analyzed": 12,
    "docs_analyzed": 3,
    "total_findings": 7
  }
}
```

El campo `source_type` indica el origen del hallazgo: `text`, `pdf-text`, `pdf-metadata`, `word-text`, `word-metadata`, `xlsx-text`, `xlsx-metadata`, `image-exif`, `sqlite`, `sqldump`.

---

## Integración en pipelines

Al usar `-q`, todo el output visual va a `stderr` y `stdout` queda completamente limpio, permitiendo encadenar con otras herramientas:

```bash
# Lanzar y procesar el JSON con jq
./ghosttag.sh -u https://target.com -f json -o /tmp/out.json -q
jq '[.findings[] | select(.severity=="CRITICAL")]' /tmp/out.json

# Contar hallazgos críticos y usar como condición de CI/CD
./ghosttag.sh -u https://staging.app.com -f json -o /tmp/scan.json -q
CRITS=$(jq '.summary.total_findings' /tmp/scan.json)
[ "$CRITS" -gt 0 ] && echo "SCAN FAILED: $CRITS findings" && exit 1
```

---

## Aviso legal

Esta herramienta está diseñada para su uso en **entornos autorizados**: auditorías de seguridad propias, Bug Bounty con permiso explícito, pruebas sobre infraestructura propia o en laboratorios controlados.

El uso de Ghosttag contra sistemas sin autorización expresa puede constituir un delito conforme al Código Penal español (art. 197 bis y siguientes) y legislación equivalente en otras jurisdicciones.

**El autor no se responsabiliza del uso indebido de esta herramienta.**

---

## Changelog

### v2.0 (actual)
- Nuevo módulo de análisis: SQLite y SQL dumps
- Módulo de imágenes con detección de coordenadas GPS
- Auto-instalación de dependencias al arranque (apt / dnf / yum / pacman)
- Salida dual pantalla + fichero: todo el output visual redirigido a stderr para compatibilidad con pipelines
- Modo silencioso `-q` con stdout completamente limpio
- Soporte de formato JSON validado en `close_report`
- Fix crítico: separador `\x01` en `analyze_source` — campos de hallazgos correctamente parseados
- Fix: `set -euo pipefail` con condicionales `&&` al final de función causaba exit silencioso
- Fix: `print_summary` y `banner` contaminaban stdout
- Fix: `xdg-user-dir` ausente ya no aborta el script
- Guarda `BASH_SOURCE` para permitir `source` del script sin ejecutar `main`
- 53 patrones de detección organizados en 10 categorías

### v1.0
- Versión inicial con análisis de HTML/JS/CSS, PDF, Word y Excel
- Spider básico con control de profundidad
- Salida en txt y JSON
