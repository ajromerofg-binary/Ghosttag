# 👻 ghosttag

> **Source code, document & binary credential/metadata hunter.**

![Bash](https://img.shields.io/badge/language-Bash-4EAA25?style=flat-square&logo=gnubash&logoColor=white)
![Version](https://img.shields.io/badge/version-2.0-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Kali%20%7C%20Parrot-red?style=flat-square)

ghosttag fetches source code and files from a URL or a full website and hunts for credentials, API keys, tokens, hashes, internal IPs, and sensitive metadata left behind in HTML, JavaScript, CSS, PDF documents, Word files, Excel spreadsheets, images, SQLite databases, and SQL dumps — all from a single command.

It works like **FOCA** or **metagoofil**, but from the terminal, scriptable, and with a report in `txt` or `json`.

---

## What it finds

### 53 regex patterns across 10 categories

| Category | Severity | Examples |
|----------|----------|---------|
| `COMMENT_CRED` | CRITICAL | Credentials inside `<!-- -->`, `//`, `/* */` comments |
| `HARDCODED` | CRITICAL | `password=`, `username=`, `pass=` in JS/HTML variables |
| `API_KEY` | CRITICAL | Google API, AWS, Stripe, GitHub, Slack, SendGrid, JWT |
| `APP_SECRET` | HIGH | Django/Flask/Laravel secret keys, salts, PEM private keys |
| `DB_CONN` | CRITICAL/HIGH | MySQL, PostgreSQL, MongoDB, Redis, MSSQL connection strings |
| `HASH` | HIGH | MD5, SHA1, SHA256, bcrypt, htpasswd hashes |
| `SQLDUMP` | CRITICAL/HIGH | Credentials and hashes in SQL dump files |
| `INFRA` | HIGH/MEDIUM | RFC1918 private IPs, localhost references, internal paths |
| `PII` | MEDIUM | Email addresses, hardcoded usernames |
| `CONFIG` | HIGH/MEDIUM | Debug mode, `.env` references, SMTP passwords, `phpinfo()` |

### 8 file analysis modules

| Module | Extensions | What it extracts |
|--------|-----------|-----------------|
| **HTML/JS/CSS** | `.html` `.php` `.js` `.ts` `.css` `.json` `.xml` `.env` … | Source code — comments, variables, config patterns |
| **PDF** | `.pdf` | Full text via `pdftotext` + author, company, creation tool, embedded paths via `exiftool` |
| **Word (.docx)** | `.docx` | Paragraphs, table cells, core metadata (author, last editor, company, revision count) via `python-docx` |
| **Word (.doc)** | `.doc` | Text via `antiword` + metadata via `exiftool` |
| **Excel** | `.xlsx` `.xls` | Cell values across all sheets, **hidden sheet detection**, creator and description metadata via `openpyxl`. Legacy `.xls` falls back to `xlrd` if available |
| **Images** | `.jpg` `.jpeg` `.png` `.gif` `.bmp` `.tiff` `.webp` `.svg` | GPS coordinates, author, host computer name, software, comments (EXIF + Windows XP tags) via `exiftool` |
| **SQLite** | `.db` `.sqlite` `.sqlite3` | Schema analysis for sensitive column names, row data dump from sensitive tables (`users`, `config`, `auth`…) |
| **SQL dumps** | `.sql` `.dump` `.bak` | Same 53 patterns + SQL-specific: `INSERT` with passwords, `CREATE USER … IDENTIFIED BY`, hashes in columns |

---

## How it works

```
Mode: single (-d 0)   Fetch URL → classify → route to module → report
Mode: spider (-d N)   Fetch URL → extract links → follow N levels deep
                      → each resource classified and routed to its module
```

```
ghosttag.sh -u https://target.com -d 2
      │
      ├── index.html       → analyze_source    (53 regex patterns)
      ├── app.js           → analyze_source
      ├── report.pdf       → analyze_pdf       (pdftotext + exiftool)
      ├── backup.sql       → analyze_sqldump   (SQL-specific patterns)
      ├── config.xlsx      → analyze_excel     (cells + hidden sheets)
      ├── photo.jpg        → analyze_image     (EXIF / GPS)
      └── data.sqlite      → analyze_sqlite    (schema + table dump)
                                    ↓
                           ghosttag_20250619_143200.txt / .json
```

---

## Requirements

| Dependency | Purpose | Install |
|---|---|---|
| `bash` ≥ 4.0 | Core (associative arrays) | pre-installed |
| `curl` | HTTP fetching | pre-installed |
| `python3` | Modules + JSON report | pre-installed |
| `pdftotext` | PDF text extraction | `apt install poppler-utils` |
| `exiftool` | PDF / image / doc metadata | `apt install libimage-exiftool-perl` |
| `antiword` | Word `.doc` legacy text | `apt install antiword` |
| `python3-docx` | Word `.docx` text + metadata | `pip install python-docx` |
| `openpyxl` | Excel `.xlsx` cells + metadata | `pip install openpyxl` |
| `sqlite3` | SQLite schema + data | `apt install sqlite3` |
| `xlrd` | Excel `.xls` legacy (optional) | `pip install xlrd` |

> Designed for **Kali Linux** and **Parrot OS**. Missing dependencies are detected at startup — affected modules are skipped with a warning rather than crashing. SQL dump analysis requires no extra dependencies beyond `bash` and `grep`.

---

## Installation

```bash
git clone https://github.com/ajromerofg-binary/ghosttag.git
cd ghosttag
chmod +x ghosttag.sh

# Install optional dependencies (full feature set)
sudo apt install -y poppler-utils libimage-exiftool-perl antiword sqlite3
pip install python-docx openpyxl xlrd --break-system-packages
```

---

## Usage

```
./ghosttag.sh -u URL [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u URL` | Target URL **(required)** | — |
| `-d DEPTH` | Spider depth: 0 = single page, max 5 | `0` |
| `-o OUTPUT` | Output report path | `~/Desktop/ghosttag_<date>.txt` |
| `-f FORMAT` | Report format: `txt` or `json` | `txt` |
| `-c COOKIES` | Session cookies: `"name=val; name2=val2"` | — |
| `-H HEADER` | Extra header: `"Authorization: Bearer token"` | — |
| `-a USER_AGENT` | Custom User-Agent | Firefox/120 |
| `-t TIMEOUT` | Per-request timeout in seconds (1–60) | `10` |
| `-k` | Skip SSL certificate verification | — |
| `-q` | Quiet mode — output to file only | — |
| `-h` | Show help | — |

---

## Examples

### Single page
```bash
./ghosttag.sh -u https://target.com/login
```

### Spider 2 levels deep, JSON report
```bash
./ghosttag.sh -u https://target.com -d 2 -f json -o report.json
```

### Authenticated scan (session cookie + ignore SSL)
```bash
./ghosttag.sh -u https://target.com/dashboard -c "PHPSESSID=abc123ef" -k
```

### API endpoint with Bearer token, quiet mode
```bash
./ghosttag.sh -u https://api.target.com/docs -H "Authorization: Bearer eyJ..." -q -o api.txt
```

### Scan a document directly
```bash
# PDF
./ghosttag.sh -u https://target.com/files/report.pdf

# Excel — cells, hidden sheets, author metadata
./ghosttag.sh -u https://target.com/files/config.xlsx

# SQLite — schema + sensitive table dump
./ghosttag.sh -u https://target.com/db/data.sqlite -k
```

---

## Sample output

```
[*] Iniciando analisis

[+] Analizando [html/0]: https://target.com/login
[+]   => 312 lineas

[*]   [!] 4 hallazgo(s) en https://target.com/login

  [CRITICAL] Credencial en comentario HTML
             Linea/Campo 7 => <!-- db_password = "mysql_root_2024!" -->

  [CRITICAL] Google API key
             Linea/Campo 16 => AIzaSyD-9tSrke72I6MVS-CRz64iqHp7lL0O8A4

  [HIGH] IP privada clase C
             Linea/Campo 21 => 192.168.1.50

[DOC] Analizando PDF: https://target.com/files/report.pdf
[*]   [!] 3 hallazgo(s) en documento

  [CRITICAL] Cadena conexion MySQL/MariaDB
             Linea/Campo 3 => mysql://admin:secret123@192.168.1.50/prod

  [MEDIUM] Autor del documento
             Linea/Campo meta => Carlos Lopez

[DOC] Analizando Excel XLSX: https://target.com/files/config.xlsx
[*]   [!] 4 hallazgo(s) en documento

  [CRITICAL] AWS Access Key ID
             Linea/Campo Config!3 => AKIAIOSFODNN7EXAMPLE

  [HIGH] Hojas ocultas en el documento
             Linea/Campo meta => 1 hoja(s): _internal

[DOC] Analizando SQLite: https://target.com/db/data.sqlite
[*]   [!] 7 hallazgo(s) en documento

  [CRITICAL] Columna sensible en esquema
             Linea/Campo schema => password TEXT NOT NULL

  [HIGH] Hash bcrypt
             Linea/Campo 1 => $2b$12$LQv3c1yqBWVHxkd0LHAkCO...

======================================================
  GHOSTTAG v2.0 — Resumen
======================================================
  URLs/recursos analizados : 6
  Documentos/binarios      : 3
  Hallazgos totales        : 18
  Reporte                  : ghosttag_20250619_143200.txt
======================================================
```

---

## Report formats

### TXT (default)

```
┌──────────────────────────────────────────────────────────────
│ Recurso  : https://target.com/files/config.xlsx
│ Tipo     : Excel XLSX (celdas)
│ Hallazgos: 4
└──────────────────────────────────────────────────────────────

  [CRITICAL] [API_KEY] Google API key
  Linea/Campo : Config!2
  Match       : AIzaSyD-9tSrke72I6MVS-CRz64iqHp7lL0O8A4
  Fuente      : xlsx-cell
  URL         : https://target.com/files/config.xlsx
  ──────────────────────────────────────────────────────
```

### JSON (`-f json`)

```json
{
  "tool": "ghosttag",
  "version": "2.0",
  "date": "2025-06-19T14:32:00",
  "target": "https://target.com",
  "depth": 2,
  "findings": [
    {
      "severity": "CRITICAL",
      "category": "API_KEY",
      "description": "Google API key",
      "line_field": "Config!2",
      "match": "AIzaSyD-9tSrke72I6MVS-CRz64iqHp7lL0O8A4",
      "source_type": "xlsx-cell",
      "url": "https://target.com/files/config.xlsx"
    }
  ],
  "summary": {
    "urls_analyzed": 6,
    "docs_analyzed": 3,
    "total_findings": 18
  }
}
```

---

## Source types

Each finding includes a `source_type` field indicating exactly where the data was found:

| Source type | Meaning |
|-------------|---------|
| `text` | HTML, JS, CSS, PHP source code |
| `pdf-text` | Text extracted from PDF body |
| `pdf-metadata` | PDF document metadata fields |
| `docx-text` | Word paragraph / table cell text |
| `docx-metadata` | Word core properties (author, company…) |
| `doc-text` | Legacy `.doc` text via antiword |
| `doc-metadata` | Legacy `.doc` metadata via exiftool |
| `xlsx-cell` | Excel cell value (`Sheet!Row` format) |
| `xlsx-hidden` | Hidden sheet detection |
| `xlsx-metadata` | Excel document properties |
| `image-exif` | EXIF / XMP / IPTC metadata field |
| `sqlite` | SQLite schema or table row data |
| `sqldump` | SQL dump file content |

---

## Validated detections

ghosttag was tested against purpose-built files in each format:

| Format | Findings detected |
|--------|------------------|
| HTML/JS | Credentials in comments, Django secret key, Google API key, JWT, Stripe key, MySQL DSN, bcrypt hash, private IP, debug mode |
| PDF | Google API key, MySQL DSN, private IP, email address, author and producer metadata |
| Excel | AWS key ID, Google API key, private IP, hidden sheet (`_internal`), author and description metadata |
| SQLite | Sensitive table schema (`password` column), bcrypt hash in `users`, Stripe key in `config`, email addresses |
| Image | GPS coordinates, author, host computer name, software version, embedded email |

---

## Input validation

| Parameter | Rule |
|-----------|------|
| `URL` | Must start with `http://` or `https://` |
| `DEPTH` | Integer between 0 and 5 |
| `TIMEOUT` | Integer between 1 and 60 |
| `FORMAT` | Must be `txt` or `json` |
| `OUTPUT` directory | Must exist and be writable. Defaults to `~/Desktop` if not specified |

---

## Legal disclaimer

ghosttag is intended for **authorised penetration testing, bug bounty programs, and security audits of systems you own or have explicit written permission to test**. Do not use it against systems you are not authorised to access. The author is not responsible for any misuse or damage caused by this tool.

---

## Author

**Tony_ZeroD** · [ajromerofg-binary](https://github.com/ajromerofg-binary) · [Portfolio](https://ajromerofg-binary.github.io)

*Full-stack developer & cybersecurity professional — Zaragoza, Spain*

---


