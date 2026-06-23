#!/usr/bin/env bash
# =============================================================================
#  ghosttag.sh — Source code, document & binary credential/metadata hunter
#  Autor   : Tony_ZeroD (ajromerofg-binary)
#  Version : 2.0
#
#  DESCRIPCION:
#    Analiza URLs o sitios web completos buscando credenciales y datos sensibles en:
#      · HTML, JS, CSS           — comentarios, variables, patrones conocidos
#      · PDF                     — texto extraido + metadatos (autor, empresa, rutas)
#      · Word (.docx/.doc)       — texto + metadatos + revisiones
#      · Excel (.xlsx/.xls)      — texto de celdas + hojas ocultas + metadatos
#      · Imagenes (jpg/png/...)  — metadatos EXIF (GPS, autor, software, comentarios)
#      · SQLite (.db/.sqlite)    — esquema + datos sensibles en tablas
#      · SQL dumps (.sql/.dump)  — credenciales y hashes en texto plano
#      · Endpoints de BBDD       — deteccion de conexiones expuestas en el codigo
#
#  USO:
#    chmod +x ghosttag.sh
#    ./ghosttag.sh [opciones] -u URL
#
#  OPCIONES:
#    -u  URL             URL objetivo (obligatorio)
#    -d  DEPTH           Profundidad de spider (default: 0 = solo URL dada)
#    -o  OUTPUT          Fichero de reporte (default: ghosttag_<fecha>.txt)
#    -f  FORMAT          Formato de salida: txt | json (default: txt)
#    -c  COOKIES         Cookies de sesion: "name=val; name2=val2"
#    -H  HEADER          Header extra: "Authorization: Bearer <token>"
#    -a  USER_AGENT      User-Agent personalizado
#    -t  TIMEOUT         Timeout por peticion en segundos (default: 10)
#    -k                  Ignorar errores SSL (--insecure)
#    -q                  Modo silencioso (solo salida al fichero)
#    -h                  Mostrar esta ayuda
#
#  DEPENDENCIAS:
#    Obligatorias : curl, python3
#    PDF          : pdftotext (poppler-utils), exiftool
#    Word         : python3-docx (pip), antiword (para .doc legacy)
#    Excel        : openpyxl (pip), exiftool
#    Imagenes     : exiftool
#    SQLite       : sqlite3
#    SQL dumps    : (solo grep/bash, sin dependencias extra)
#
#  EJEMPLOS:
#    ./ghosttag.sh -u https://target.com
#    ./ghosttag.sh -u https://target.com -d 2 -f json -o report.json
#    ./ghosttag.sh -u https://target.com/login -c "PHPSESSID=abc123" -k
#    ./ghosttag.sh -u https://target.com -d 1 -H "Authorization: Bearer eyJ..." -q
# =============================================================================

set -euo pipefail

# ── Colores ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# ── Valores por defecto ───────────────────────────────────────────────────────
TARGET_URL=""
DEPTH=0
OUTPUT_FILE=""
FORMAT="txt"
COOKIES=""
EXTRA_HEADER=""
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
TIMEOUT=10
INSECURE=false
QUIET=false

TOTAL_FINDINGS=0
TOTAL_URLS=0
TOTAL_DOCS=0
declare -A VISITED_URLS

# Directorio temporal para ficheros binarios descargados
WORK_DIR=""

# ── Banner ────────────────────────────────────────────────────────────────────
banner() {
    echo -e "${MAGENTA}${BOLD}" >&2
    echo "   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗████████╗ █████╗  ██████╗ " >&2
    echo "  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝ " >&2
    echo "  ██║  ███╗███████║██║   ██║███████╗   ██║      ██║   ███████║██║  ███╗ " >&2
    echo "  ██║   ██║██╔══██║██║   ██║╚════██║   ██║      ██║   ██╔══██║██║   ██║ " >&2
    echo "  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║      ██║   ██║  ██║╚██████╔╝ " >&2
    echo "   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝ " >&2
    echo "" >&2
    echo "   Source Code + Document + Binary Credential Hunter v2.0" >&2
    echo -e "   Tony_ZeroD // ajromerofg-binary${NC}" >&2
    echo "" >&2
}

# ── Ayuda ─────────────────────────────────────────────────────────────────────
usage() {
    echo -e "${BOLD}USO:${NC}"
    echo "  $0 -u URL [opciones]"
    echo ""
    echo -e "${BOLD}OBLIGATORIO:${NC}"
    echo "  -u  URL             URL objetivo"
    echo ""
    echo -e "${BOLD}OPCIONALES:${NC}"
    echo "  -d  DEPTH           Profundidad spider 0-5 (default: 0)"
    echo "  -o  OUTPUT          Fichero de reporte"
    echo "  -f  FORMAT          Formato: txt | json (default: txt)"
    echo "  -c  COOKIES         Cookies: \"name=val; name2=val2\""
    echo "  -H  HEADER          Header extra: \"Authorization: Bearer token\""
    echo "  -a  USER_AGENT      User-Agent personalizado"
    echo "  -t  TIMEOUT         Timeout por peticion (default: 10s)"
    echo "  -k                  Ignorar errores SSL"
    echo "  -q                  Modo silencioso"
    echo "  -h                  Mostrar esta ayuda"
    echo ""
    echo -e "${BOLD}EJEMPLOS:${NC}"
    echo "  $0 -u https://target.com -d 2 -f json"
    echo "  $0 -u https://target.com/login -c \"PHPSESSID=abc123\" -k"
    exit 0
}

# =============================================================================
# VERIFICACION E INSTALACION DE DEPENDENCIAS
# =============================================================================
check_and_install_deps() {
    echo -e "${CYAN}${BOLD}[*] Verificando dependencias...${NC}" >&2

    # ── Detectar gestor de paquetes del sistema ───────────────────────────────
    local PKG_MGR=""
    local PKG_INSTALL=""
    local PKG_UPDATE=""

    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
        PKG_UPDATE="apt-get update -qq"
        PKG_INSTALL="apt-get install -y -qq"
    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
        PKG_UPDATE="dnf check-update -q || true"
        PKG_INSTALL="dnf install -y -q"
    elif command -v yum &>/dev/null; then
        PKG_MGR="yum"
        PKG_UPDATE="yum check-update -q || true"
        PKG_INSTALL="yum install -y -q"
    elif command -v pacman &>/dev/null; then
        PKG_MGR="pacman"
        PKG_UPDATE="pacman -Sy --noconfirm --quiet"
        PKG_INSTALL="pacman -S --noconfirm --quiet"
    else
        echo -e "${YELLOW}[!]${NC} No se reconoce el gestor de paquetes. Instala manualmente las dependencias." >&2
        PKG_MGR=""
    fi

    # ── Mapa: comando → paquete por gestor ───────────────────────────────────
    # Formato: "comando|paquete_apt|paquete_dnf/yum|paquete_pacman"
    local -a SYS_DEPS=(
        "curl|curl|curl|curl"
        "python3|python3|python3|python3"
        "pdftotext|poppler-utils|poppler-utils|poppler"
        "exiftool|libimage-exiftool-perl|perl-Image-ExifTool|perl-image-exiftool"
        "antiword|antiword|antiword|antiword"
        "sqlite3|sqlite3|sqlite|sqlite"
    )

    local -a PIP_DEPS=(
        "docx|python-docx"
        "openpyxl|openpyxl"
    )

    local pkg_update_done=false
    local needs_install=false

    # ── Comprobar dependencias de sistema ─────────────────────────────────────
    for entry in "${SYS_DEPS[@]}"; do
        IFS='|' read -r cmd pkg_apt pkg_dnf pkg_pacman <<< "$entry"

        if command -v "$cmd" &>/dev/null; then
            echo -e "  ${GREEN}[OK]${NC} $cmd" >&2
            continue
        fi

        echo -e "  ${YELLOW}[!]${NC} $cmd no encontrado — instalando..." >&2

        if [[ -z "$PKG_MGR" ]]; then
            echo -e "  ${RED}[-]${NC} Sin gestor de paquetes. Instala '$cmd' manualmente." >&2
            continue
        fi

        # Seleccionar nombre de paquete según gestor
        local pkg=""
        case "$PKG_MGR" in
            apt)    pkg="$pkg_apt"    ;;
            dnf|yum)pkg="$pkg_dnf"   ;;
            pacman) pkg="$pkg_pacman" ;;
        esac

        # Actualizar índice solo una vez
        if ! $pkg_update_done; then
            echo -e "  ${CYAN}[*]${NC} Actualizando indices de paquetes..." >&2
            { sudo $PKG_UPDATE &>/dev/null 2>&1; } || \
                echo -e "  ${YELLOW}[!]${NC} No se pudo actualizar indices (¿sudo disponible?). Intentando instalar igualmente..." >&2
            pkg_update_done=true
        fi

        local _install_ok=false
        { sudo $PKG_INSTALL "$pkg" &>/dev/null 2>&1 && _install_ok=true; } || true
        if $_install_ok; then
            echo -e "  ${GREEN}[OK]${NC} $cmd instalado correctamente" >&2
        else
            echo -e "  ${RED}[-]${NC} No se pudo instalar '$pkg'. Instala manualmente: sudo $PKG_INSTALL $pkg" >&2
        fi
        needs_install=true
    done

    # ── Comprobar dependencias Python (pip) ───────────────────────────────────
    local pip_cmd=""
    if command -v pip3  &>/dev/null; then pip_cmd="pip3";
    elif command -v pip &>/dev/null; then pip_cmd="pip";
    fi

    for entry in "${PIP_DEPS[@]}"; do
        IFS='|' read -r module pkg <<< "$entry"

        if python3 -c "import $module" &>/dev/null 2>&1; then
            echo -e "  ${GREEN}[OK]${NC} python3:$module" >&2
            continue
        fi

        echo -e "  ${YELLOW}[!]${NC} python3:$module no encontrado — instalando..." >&2

        if [[ -z "$pip_cmd" ]]; then
            echo -e "  ${RED}[-]${NC} pip no disponible. Instala manualmente: pip3 install $pkg" >&2
            continue
        fi

        local _pip_ok=false
        { $pip_cmd install --quiet "$pkg" &>/dev/null 2>&1 && _pip_ok=true; } || true
        if ! $_pip_ok; then
            # Intentar con --break-system-packages en entornos con PEP 668
            { $pip_cmd install --quiet --break-system-packages "$pkg" &>/dev/null 2>&1 && _pip_ok=true; } || true
        fi
        if $_pip_ok; then
            echo -e "  ${GREEN}[OK]${NC} python3:$module instalado correctamente" >&2
        else
            echo -e "  ${RED}[-]${NC} No se pudo instalar '$pkg'. Instala manualmente: $pip_cmd install $pkg" >&2
        fi
        needs_install=true
    done

    echo -e "${CYAN}${BOLD}[*] Verificacion de dependencias completada.${NC}\n" >&2
}

# ── Log helpers ───────────────────────────────────────────────────────────────
log_info()    { $QUIET || echo -e "${GREEN}[+]${NC} $*" >&2; }
log_warn()    { $QUIET || echo -e "${YELLOW}[!]${NC} $*" >&2; }
log_error()   { echo -e "${RED}[-]${NC} $*" >&2; }
log_section() { $QUIET || echo -e "\n${CYAN}${BOLD}[*] $*${NC}" >&2; }
log_doc()     { $QUIET || echo -e "${BLUE}[DOC]${NC} $*" >&2; }

# ── Parseo de argumentos ──────────────────────────────────────────────────────
parse_args() {
    [[ $# -eq 0 ]] && { banner; usage; } || true
    while getopts "u:d:o:f:c:H:a:t:kqh" opt; do
        case $opt in
            u) TARGET_URL="$OPTARG" ;;
            d) DEPTH="$OPTARG" ;;
            o) OUTPUT_FILE="$OPTARG" ;;
            f) FORMAT="$OPTARG" ;;
            c) COOKIES="$OPTARG" ;;
            H) EXTRA_HEADER="$OPTARG" ;;
            a) USER_AGENT="$OPTARG" ;;
            t) TIMEOUT="$OPTARG" ;;
            k) INSECURE=true ;;
            q) QUIET=true ;;
            h) usage ;;
            *) log_error "Opcion desconocida: -$OPTARG"; usage ;;
        esac
    done
}

# ── Validaciones ──────────────────────────────────────────────────────────────
validate() {
    log_section "Validando parametros"

    [[ -z "$TARGET_URL" ]] && { log_error "URL obligatoria (-u)"; exit 1; }

    if ! echo "$TARGET_URL" | grep -qE '^https?://[a-zA-Z0-9]'; then
        log_error "URL invalida. Debe comenzar por http:// o https://"
        exit 1
    fi

    if ! [[ "$DEPTH" =~ ^[0-9]+$ ]] || (( DEPTH > 5 )); then
        log_error "DEPTH debe ser un entero entre 0 y 5. Recibido: $DEPTH"
        exit 1
    fi

    if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || (( TIMEOUT < 1 || TIMEOUT > 60 )); then
        log_error "TIMEOUT debe ser un entero entre 1 y 60. Recibido: $TIMEOUT"
        exit 1
    fi

    if [[ "$FORMAT" != "txt" && "$FORMAT" != "json" ]]; then
        log_error "FORMAT debe ser 'txt' o 'json'. Recibido: $FORMAT"
        exit 1
    fi

    if [[ -n "$OUTPUT_FILE" ]]; then
        local out_dir
        out_dir=$(dirname "$OUTPUT_FILE")
        if [[ ! -d "$out_dir" ]]; then
            log_error "El directorio de OUTPUT no existe: '$out_dir'"
            exit 1
        fi
    else
        # Guardar reporte en el Desktop del usuario por defecto
        local desktop_dir
        local _xdg_out=""
        if command -v xdg-user-dir &>/dev/null; then
            _xdg_out="$(xdg-user-dir DESKTOP 2>/dev/null)" || _xdg_out=""
        fi
        desktop_dir="${_xdg_out:-${HOME}/Desktop}"
        # Fallback a directorio actual si Desktop no existe
        if [[ ! -d "$desktop_dir" ]]; then
            desktop_dir="$(pwd)"
            log_warn "Desktop no encontrado — reporte en directorio actual: $desktop_dir"
        fi
        OUTPUT_FILE="${desktop_dir}/ghosttag_$(date +%Y%m%d_%H%M%S).${FORMAT}"
    fi

    if ! command -v curl &>/dev/null; then
        log_error "curl es obligatorio y no pudo instalarse. Abortando."
        exit 1
    fi

    log_info "URL objetivo  : ${BOLD}$TARGET_URL${NC}"
    log_info "Profundidad   : ${BOLD}$DEPTH${NC}"
    log_info "Formato       : ${BOLD}$FORMAT${NC}"
    log_info "Reporte       : ${BOLD}$OUTPUT_FILE${NC}"
    $INSECURE                && log_warn "SSL check     : DESACTIVADO (-k)" || true
    [[ -n "$COOKIES" ]]      && log_info "Cookies       : configuradas"    || true
    [[ -n "$EXTRA_HEADER" ]] && log_info "Header extra  : configurado"     || true
}

# ── Construir flags de curl ───────────────────────────────────────────────────
build_curl_flags() {
    CURL_FLAGS=(
        --silent
        --max-time "$TIMEOUT"
        --user-agent "$USER_AGENT"
        --location
        --compressed
    )
    $INSECURE                && CURL_FLAGS+=(--insecure)             || true
    [[ -n "$COOKIES" ]]      && CURL_FLAGS+=(--cookie "$COOKIES")    || true
    [[ -n "$EXTRA_HEADER" ]] && CURL_FLAGS+=(--header "$EXTRA_HEADER") || true
}

# ── Descargar URL como texto ──────────────────────────────────────────────────
fetch_url() {
    curl "${CURL_FLAGS[@]}" "$1" 2>/dev/null || true
}

# ── Descargar URL como fichero binario ────────────────────────────────────────
fetch_binary() {
    local url="$1"
    local dest="$2"
    curl "${CURL_FLAGS[@]}" -o "$dest" "$url" 2>/dev/null || true
}

# ── Obtener Content-Type de una URL ──────────────────────────────────────────
get_content_type() {
    curl "${CURL_FLAGS[@]}" --head -o /dev/null -w '%{content_type}' "$1" 2>/dev/null || true
}

# ── Extraer dominio base ──────────────────────────────────────────────────────
get_base_domain() {
    echo "$TARGET_URL" | grep -oE '^https?://[^/]+'
}

# ── Extraer extension de URL ──────────────────────────────────────────────────
get_url_ext() {
    echo "$1" | grep -oE '\.[a-zA-Z0-9]{1,8}(\?.*)?$' | grep -oE '^\.[a-zA-Z0-9]+' | tr '[:upper:]' '[:lower:]' || true
}

# ── Clasificar tipo de recurso ────────────────────────────────────────────────
# Devuelve: html | pdf | word | excel | image | sqlite | sqldump | unknown
classify_resource() {
    local url="$1"
    local ext
    ext=$(get_url_ext "$url")

    case "$ext" in
        .pdf)                          echo "pdf"     ; return ;;
        .docx)                         echo "word"    ; return ;;
        .doc)                          echo "word_legacy" ; return ;;
        .xlsx)                         echo "excel"   ; return ;;
        .xls)                          echo "excel_legacy" ; return ;;
        .jpg|.jpeg|.png|.gif|.bmp|.tiff|.webp|.svg) echo "image" ; return ;;
        .db|.sqlite|.sqlite3)          echo "sqlite"  ; return ;;
        .sql|.dump|.bak)               echo "sqldump" ; return ;;
        .html|.htm|.php|.asp|.aspx|.jsp|.js|.css|.ts|.xml|.json|.env|.txt|.md) echo "html" ; return ;;
        *)                             echo "html"    ; return ;;  # tratar como texto por defecto
    esac
}

# =============================================================================
# PATRONES DE TEXTO (HTML / JS / CSS / SQL dumps / contenido extraido de docs)
# =============================================================================
declare -a PATTERNS=(
    # Credenciales en comentarios
    "CRITICAL|COMMENT_CRED|Credencial en comentario HTML|<!--[^>]*(pass(word)?|pwd|cred|login|user|auth|secret|key|token)[^>]*=[^>]*-->"
    "CRITICAL|COMMENT_CRED|Credencial en comentario JS/CSS|/\*[^*]*(pass(word)?|pwd|cred|secret|key|token|auth)[^*]*=[^\n]*\*/"
    "CRITICAL|COMMENT_CRED|Credencial en comentario de linea|//[[:space:]]*[a-zA-Z_]*(api[_-]?key|password|pass|secret|token|auth)[a-zA-Z_]*[[:space:]]*[:=][[:space:]]*['\"]?[^'\"[:space:]]{3,}"

    # Passwords hardcodeadas
    "CRITICAL|HARDCODED|Password hardcodeada (asignacion)|['\"]?(password|passwd|pwd|pass)['\"]?[[:space:]]*[:=][[:space:]]*['\"][^'\"]{3,}['\"]"
    "CRITICAL|HARDCODED|Password en variable JS|var[[:space:]]+[a-zA-Z_]*(pass|pwd|password|secret)[a-zA-Z_]*[[:space:]]*=[[:space:]]*['\"][^'\"]{3,}['\"]"
    "CRITICAL|HARDCODED|Password en parametro URL|[?&](pass(word)?|pwd|auth)=[^&'\"[:space:]]{3,}"

    # API Keys y tokens
    "CRITICAL|API_KEY|API key generica|['\"]?(api[_-]?key|apikey|api[_-]?secret)['\"]?[[:space:]]*[:=][[:space:]]*['\"]?[a-zA-Z0-9_\-]{16,}['\"]?"
    "CRITICAL|API_KEY|Token de acceso|['\"]?(access[_-]?token|auth[_-]?token|bearer[_-]?token)['\"]?[[:space:]]*[:=][[:space:]]*['\"]?[a-zA-Z0-9_.\-]{20,}['\"]?"
    "CRITICAL|API_KEY|JWT hardcodeado|eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"
    "CRITICAL|API_KEY|Google API key|AIza[0-9A-Za-z_-]{35}"
    "CRITICAL|API_KEY|AWS Access Key ID|AKIA[0-9A-Z]{16}"
    "CRITICAL|API_KEY|AWS Secret Access Key|['\"]?aws[_-]?secret[_-]?(access[_-]?)?key['\"]?[[:space:]]*[:=][[:space:]]*['\"]?[a-zA-Z0-9/+]{40}['\"]?"
    "CRITICAL|API_KEY|Stripe API key|(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}"
    "CRITICAL|API_KEY|GitHub token|gh[oprstu]_[a-zA-Z0-9]{36}"
    "CRITICAL|API_KEY|Slack token|xox[baprs]-[0-9a-zA-Z]{10,}"
    "CRITICAL|API_KEY|SendGrid API key|SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"

    # Secretos de aplicacion
    "HIGH|APP_SECRET|Secret key de aplicacion|['\"]?(secret[_-]?key|app[_-]?secret|flask[_-]?secret|django[_-]?secret|laravel[_-]?key)['\"]?[[:space:]]*[:=][[:space:]]*['\"][^'\"]{8,}['\"]"
    "HIGH|APP_SECRET|Salt hardcodeado|['\"]?(salt|pepper|hmac[_-]?key)['\"]?[[:space:]]*[:=][[:space:]]*['\"][^'\"]{8,}['\"]"
    "HIGH|APP_SECRET|Clave de cifrado|['\"]?(encrypt(ion)?[_-]?key|aes[_-]?key|des[_-]?key|cipher[_-]?key)['\"]?[[:space:]]*[:=][[:space:]]*['\"][^'\"]{8,}['\"]"
    "HIGH|APP_SECRET|Private key PEM|-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"

    # Cadenas de conexion y BBDD
    "CRITICAL|DB_CONN|Cadena conexion MySQL/MariaDB|mysql://[^[:space:]'\"]{8,}"
    "CRITICAL|DB_CONN|Cadena conexion PostgreSQL|postgres(ql)?://[^[:space:]'\"]{8,}"
    "CRITICAL|DB_CONN|Cadena conexion MongoDB|mongodb(\+srv)?://[^[:space:]'\"]{8,}"
    "CRITICAL|DB_CONN|Cadena conexion Redis con auth|redis://:?[^@[:space:]]{3,}@[^[:space:]]{5,}"
    "CRITICAL|DB_CONN|Cadena conexion MSSQL|[Ss]erver=[^;]+;[Dd]atabase=[^;]+;[Uu]ser"
    "HIGH|DB_CONN|Host de base de datos|['\"]?(db[_-]?host|database[_-]?host|mysql[_-]?host)['\"]?[[:space:]]*[:=][[:space:]]*['\"][^'\"]{3,}['\"]"
    "CRITICAL|DB_CONN|Usuario de base de datos|['\"]?(db[_-]?user(name)?|database[_-]?user)['\"]?[[:space:]]*[:=][[:space:]]*['\"][^'\"]{3,}['\"]"
    "CRITICAL|DB_CONN|Password de base de datos|['\"]?(db[_-]?pass(word)?|database[_-]?pass(word)?)['\"]?[[:space:]]*[:=][[:space:]]*['\"][^'\"]{3,}['\"]"

    # Hashes
    "HIGH|HASH|Hash MD5 (32 hex)|['\"][0-9a-fA-F]{32}['\"]"
    "HIGH|HASH|Hash SHA1 (40 hex)|['\"][0-9a-fA-F]{40}['\"]"
    "HIGH|HASH|Hash SHA256 (64 hex)|['\"][0-9a-fA-F]{64}['\"]"
    "HIGH|HASH|Hash bcrypt|\\\$2[aby]\\\$[0-9]{2}\\\$[./A-Za-z0-9]{53}"
    "HIGH|HASH|Hash MD5 htpasswd|[a-zA-Z0-9_-]+:\\\$apr1\\\$"

    # SQL dump — credenciales en texto plano
    "CRITICAL|SQLDUMP|INSERT con campo password en SQL|INSERT[[:space:]]+INTO[^;]*(password|passwd|pwd|pass)[^;]*VALUES[^;]*['\"][^'\"]{4,}['\"]"
    "CRITICAL|SQLDUMP|CREATE USER con password en SQL|CREATE[[:space:]]+USER[^;]+IDENTIFIED[[:space:]]+BY[[:space:]]+['\"][^'\"]{4,}['\"]"
    "HIGH|SQLDUMP|Hash en columna SQL|['\"][0-9a-fA-F]{32,64}['\"]"
    "HIGH|SQLDUMP|Cadena conexion en comentario SQL|--[[:space:]]*(mysql|postgres|mongodb|redis|server).*://[^[:space:]]{8,}"

    # Infraestructura
    "HIGH|INFRA|IP privada clase A|(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
    "HIGH|INFRA|IP privada clase B|(172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3})"
    "HIGH|INFRA|IP privada clase C|(192\.168\.[0-9]{1,3}\.[0-9]{1,3})"
    "HIGH|INFRA|Localhost hardcodeado|(127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
    "MEDIUM|INFRA|Ruta del sistema de ficheros|['\"/](var|etc|home|root|usr|tmp|srv|opt)/[a-zA-Z0-9_./\-]{5,}"
    "MEDIUM|INFRA|Puerto interno en URL|https?://(localhost|127\.0\.0\.1|10\.[0-9.]+|192\.168\.[0-9.]+):[0-9]{2,5}"

    # PII y usuarios
    "MEDIUM|PII|Direccion de email|[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
    "HIGH|PII|Email en comentario|<!--[^>]*[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}[^>]*-->"
    "HIGH|HARDCODED|Username hardcodeado|['\"]?(username|user[_-]?name|login|uname)['\"]?[[:space:]]*[:=][[:space:]]*['\"][^'\"]{3,}['\"]"

    # Configuracion sensible
    "HIGH|CONFIG|Variable de entorno con secret|process\.env\.[A-Z_]*(SECRET|KEY|TOKEN|PASS|PWD|AUTH)[A-Z_]*"
    "HIGH|CONFIG|Fichero .env referenciado|require\(['\"]\.env['\"]|dotenv|\.env\."
    "MEDIUM|CONFIG|Modo debug activo|[Dd]ebug[a-z ]*[[:space:]]*[=:][[:space:]]*(true|1|on|yes|development)"
    "MEDIUM|CONFIG|phpinfo expuesto|phpinfo[[:space:]]*\(\)"
    "HIGH|CONFIG|Clave de SMTP|['\"]?(smtp[_-]?pass(word)?|mail[_-]?pass(word)?|email[_-]?pass)['\"]?[[:space:]]*[:=][[:space:]]*['\"][^'\"]{4,}['\"]"
    "MEDIUM|CONFIG|DSN con credenciales|[a-zA-Z]{3,}://[a-zA-Z0-9._-]+:[^/[:space:]]{3,}@[a-zA-Z0-9._-]+"
    "MEDIUM|CONFIG|TODO/FIXME con dato sensible|//[[:space:]]*(TODO|FIXME|HACK|XXX)[^:]*:[^/\n]*(pass|key|token|auth|secret|credential)"
)

# =============================================================================
# MOTOR DE ANALISIS DE TEXTO
# =============================================================================
analyze_source() {
    local url="$1"
    local content="$2"
    local findings=()
    local hit_count=0

    for pattern_entry in "${PATTERNS[@]}"; do
        IFS='|' read -r severity category description regex <<< "$pattern_entry"
        local matches
        matches=$(echo "$content" | grep -onE "$regex" 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            while IFS= read -r match; do
                [[ -z "$match" ]] && continue
                local linenum matched_text
                linenum=$(echo "$match" | cut -d: -f1)
                matched_text=$(echo "$match" | cut -d: -f2- | tr -d '\001-\010\013\014\016-\037' | sed 's/^[[:space:]]*//' | head -c 200)
                findings+=("${severity}"$'\x01'"${category}"$'\x01'"${description}"$'\x01'"${linenum}"$'\x01'"${matched_text}")
                (( hit_count++ )) || true
            done <<< "$matches"
        fi
    done

    echo "${hit_count}"
    printf '%s\n' "${findings[@]+"${findings[@]}"}"
}

# =============================================================================
# ESCRITURA DE HALLAZGOS
# =============================================================================
write_finding() {
    local url="$1" severity="$2" category="$3" description="$4"
    local linenum="$5" matched_text="$6"
    local source_type="${7:-text}"   # text | metadata | sqlite | exif

    local color="$NC"
    case "$severity" in
        CRITICAL) color="$RED"    ;;
        HIGH)     color="$ORANGE" ;;
        MEDIUM)   color="$YELLOW" ;;
        LOW)      color="$GREEN"  ;;
    esac

    if ! $QUIET; then
        echo -e "  ${color}${BOLD}[$severity]${NC} ${BOLD}$description${NC}" >&2
        echo -e "           ${CYAN}Linea/Campo $linenum${NC} => $matched_text" >&2
        echo "" >&2
    fi

    if [[ "$FORMAT" == "txt" ]]; then
        {
            echo "  [$severity] [$category] $description"
            echo "  Linea/Campo : $linenum"
            echo "  Match       : $matched_text"
            echo "  Fuente      : $source_type"
            echo "  URL         : $url"
            echo "  ──────────────────────────────────────────────────────"
        } >> "$OUTPUT_FILE"
    elif [[ "$FORMAT" == "json" ]]; then
        local safe_text safe_url
        safe_text=$(echo "$matched_text" | tr -d '\001-\010\013\014\016-\037' | sed 's/\\/\\\\/g; s/"/\\"/g')
        safe_url=$(printf '%s' "$url" | sed 's/"/\\"/g')
        {
            printf '  {\n'
            printf '    "severity": "%s",\n'     "$severity"
            printf '    "category": "%s",\n'     "$category"
            printf '    "description": "%s",\n'  "$description"
            printf '    "line_field": "%s",\n'   "$linenum"
            printf '    "match": "%s",\n'        "$safe_text"
            printf '    "source_type": "%s",\n'  "$source_type"
            printf '    "url": "%s"\n'           "$safe_url"
            printf '  },\n'
        } >> "$OUTPUT_FILE"
    fi

    (( TOTAL_FINDINGS++ )) || true
}

write_url_header() {
    local url="$1" num="$2" ftype="$3"
    if [[ "$FORMAT" == "txt" ]]; then
        {
            echo ""
            echo "┌──────────────────────────────────────────────────────────────"
            echo "│ Recurso  : $url"
            echo "│ Tipo     : $ftype"
            echo "│ Hallazgos: $num"
            echo "└──────────────────────────────────────────────────────────────"
            echo ""
        } >> "$OUTPUT_FILE"
    fi
}

# =============================================================================
# MODULO: EXTRAER LINKS DEL HTML
# =============================================================================
extract_links() {
    local html="$1"
    local base_domain="$2"

    echo "$html" \
        | grep -oE '(href|src|action|data-src)="[^"]*"' \
        | grep -oE '"[^"]*"' \
        | tr -d '"' \
        | grep -vE '^(#|mailto:|tel:|javascript:)' \
        | while read -r link; do
            if echo "$link" | grep -qE '^https?://'; then
                echo "$link" | grep -q "$base_domain" && echo "$link"
            elif echo "$link" | grep -qE '^//'; then
                local proto
                proto=$(echo "$base_domain" | grep -oE '^https?')
                echo "${proto}:${link}"
            elif echo "$link" | grep -qE '^/'; then
                echo "${base_domain}${link}"
            elif [[ -n "$link" ]]; then
                echo "${base_domain}/${link}"
            fi
        done | sort -u
}

# =============================================================================
# MODULO: PDF
# =============================================================================
analyze_pdf() {
    local url="$1"
    local filepath="$2"
    local hit_count=0

    log_doc "Analizando PDF: $url"

    # ── Texto del PDF con pdftotext ───────────────────────────────────────────
    if command -v pdftotext &>/dev/null; then
        local text_file="${filepath}.txt"
        pdftotext "$filepath" "$text_file" 2>/dev/null || true

        if [[ -s "$text_file" ]]; then
            local analysis
            analysis=$(analyze_source "$url" "$(cat "$text_file")")
            local count
            count=$(echo "$analysis" | head -1)

            if (( count > 0 )); then
                write_url_header "$url" "$count" "PDF (texto)"
                local idx=0
                while IFS=$'\x01' read -r sev cat desc lnum mtxt; do
                    (( idx++ )) || true
                    [[ $idx -eq 1 ]] && continue
                    [[ -z "$sev" ]] && continue
                    write_finding "$url" "$sev" "$cat" "$desc" "$lnum" "$mtxt" "pdf-text"
                    (( hit_count++ )) || true
                done <<< "$analysis"
            fi
        fi
    else
        log_warn "pdftotext no disponible — omitiendo extraccion de texto PDF"
    fi

    # ── Metadatos PDF con exiftool ────────────────────────────────────────────
    if command -v exiftool &>/dev/null; then
        local meta
        meta=$(exiftool -s "$filepath" 2>/dev/null || true)

        if [[ -n "$meta" ]]; then
            local findings_meta=()
            local meta_hit=0

            # Campos de metadatos especificos a extraer
            # Extraer campos de metadatos sin arrays asociativos (compatibilidad subshell)
            local _pdf_fields="Author:MEDIUM:METADATA:Autor del documento
Creator:MEDIUM:METADATA:Aplicacion creadora
Producer:MEDIUM:METADATA:Productor PDF
Company:MEDIUM:METADATA:Empresa del autor
LastModifiedBy:MEDIUM:METADATA:Ultimo editor
CreateDate:LOW:METADATA:Fecha de creacion
ModifyDate:LOW:METADATA:Fecha de modificacion"

            while IFS=: read -r _field _sev _cat _desc; do
                local value
                value=$(echo "$meta" | grep -E "^${_field}[[:space:]]*:" | cut -d: -f2- | sed 's/^[[:space:]]*//' | head -c 200 || true)
                if [[ -n "$value" && "$value" != "-" ]]; then
                    findings_meta+=("${_sev}${_cat}${_desc}: ${value}meta${value}")
                    (( meta_hit++ )) || true
                fi
            done <<< "$_pdf_fields"

            # Buscar rutas de ficheros embebidas en metadatos
            local embedded_paths
            embedded_paths=$(echo "$meta" | grep -oE '[A-Za-z]:\\[A-Za-z0-9_\\. \-]+|/[a-z]+/[a-zA-Z0-9_./\-]{5,}' 2>/dev/null || true)
            if [[ -n "$embedded_paths" ]]; then
                while IFS= read -r path; do
                    [[ -z "$path" ]] && continue
                    findings_meta+=("HIGHMETADATARuta interna en metadatos PDFmeta${path}")
                    (( meta_hit++ )) || true
                done <<< "$embedded_paths"
            fi

            # Buscar emails en metadatos
            local meta_emails
            meta_emails=$(echo "$meta" | grep -oE '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}' 2>/dev/null || true)
            if [[ -n "$meta_emails" ]]; then
                while IFS= read -r email; do
                    [[ -z "$email" ]] && continue
                    findings_meta+=("MEDIUMMETADATAEmail en metadatos PDFmeta${email}")
                    (( meta_hit++ )) || true
                done <<< "$meta_emails"
            fi

            if (( meta_hit > 0 )); then
                write_url_header "$url" "$meta_hit" "PDF (metadatos)"
                for entry in "${findings_meta[@]}"; do
                    IFS='|' read -r sev cat desc lnum mtxt <<< "$entry"
                    write_finding "$url" "$sev" "$cat" "$desc" "$lnum" "$mtxt" "pdf-metadata"
                    (( hit_count++ )) || true
                done
            fi
        fi
    else
        log_warn "exiftool no disponible — omitiendo metadatos PDF"
    fi

    echo "$hit_count"
}

# =============================================================================
# MODULO: WORD (.docx)
# =============================================================================
analyze_word_docx() {
    local url="$1"
    local filepath="$2"
    local hit_count=0

    log_doc "Analizando Word DOCX: $url"

    if ! python3 -c "import docx" &>/dev/null 2>&1; then
        log_warn "python3-docx no disponible. Instala: pip install python-docx"
        echo "0"; return
    fi

    # Extraer texto y metadatos con python-docx
    local py_output
    py_output=$(python3 - "$filepath" << 'PYEOF' 2>/dev/null || true
import sys, docx, json

try:
    doc = docx.Document(sys.argv[1])

    # Texto completo
    text_lines = []
    for i, para in enumerate(doc.paragraphs, 1):
        if para.text.strip():
            text_lines.append(f"{i}: {para.text}")
    # Texto en tablas
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                if cell.text.strip():
                    text_lines.append(f"table: {cell.text}")
    # Comentarios embebidos (si los hay)
    # Metadatos del nucleo
    core = doc.core_properties
    meta = {
        "author":         str(core.author or ""),
        "last_modified_by": str(core.last_modified_by or ""),
        "company":        str(getattr(core, "company", "") or ""),
        "created":        str(core.created or ""),
        "modified":       str(core.modified or ""),
        "revision":       str(core.revision or ""),
        "keywords":       str(core.keywords or ""),
        "description":    str(core.description or ""),
        "subject":        str(core.subject or ""),
    }
    print("TEXT_START")
    print("\n".join(text_lines))
    print("META_START")
    print(json.dumps(meta))
except Exception as e:
    print(f"ERROR:{e}", file=sys.stderr)
PYEOF
    )

    if [[ -z "$py_output" ]]; then
        log_warn "No se pudo leer $url (DOCX)"
        echo "0"; return
    fi

    # Analizar texto extraido
    local text_section
    text_section=$(echo "$py_output" | sed -n '/^TEXT_START$/,/^META_START$/p' | grep -v "TEXT_START\|META_START" || true)

    if [[ -n "$text_section" ]]; then
        local analysis
        analysis=$(analyze_source "$url" "$text_section")
        local count
        count=$(echo "$analysis" | head -1)
        if (( count > 0 )); then
            write_url_header "$url" "$count" "Word DOCX (texto)"
            local idx=0
            while IFS=$'\x01' read -r sev cat desc lnum mtxt; do
                (( idx++ )) || true
                [[ $idx -eq 1 ]] && continue
                [[ -z "$sev" ]] && continue
                write_finding "$url" "$sev" "$cat" "$desc" "$lnum" "$mtxt" "docx-text"
                (( hit_count++ )) || true
            done <<< "$analysis"
        fi
    fi

    # Analizar metadatos
    local meta_json
    meta_json=$(echo "$py_output" | sed -n '/^META_START$/,$p' | tail -n +2 || true)

    # Procesar metadatos DOCX — bloque Python único y limpio
    local meta_hits
    meta_hits=$(python3 - "$meta_json" 2>/dev/null << 'PYEOF_META' || true
import sys, json
try:
    meta = json.loads(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].strip() else {}
except Exception:
    meta = {}
sev_map = {
    "author":           ("MEDIUM", "METADATA", "Autor del documento Word"),
    "last_modified_by": ("MEDIUM", "METADATA", "Ultimo editor del documento"),
    "company":          ("MEDIUM", "METADATA", "Empresa en metadatos Word"),
    "revision":         ("LOW",    "METADATA", "Numero de revision"),
    "keywords":         ("MEDIUM", "METADATA", "Palabras clave del documento"),
    "description":      ("MEDIUM", "METADATA", "Descripcion del documento"),
}
for field, (sev, cat, desc) in sev_map.items():
    val = meta.get(field, "").strip()
    if val and val not in ("None", "0", ""):
        print(f"{sev}|{cat}|{desc}|meta|{val}")
PYEOF_META
    )

    if [[ -n "$meta_hits" ]]; then
        local mcount
        mcount=$(echo "$meta_hits" | grep -c '|' || true)
        write_url_header "$url" "$mcount" "Word DOCX (metadatos)"
        while IFS=$'\x01' read -r sev cat desc lnum mtxt; do
            [[ -z "$sev" ]] && continue
            write_finding "$url" "$sev" "$cat" "$desc" "$lnum" "$mtxt" "docx-metadata"
            (( hit_count++ )) || true
        done <<< "$meta_hits"
    fi

    echo "$hit_count"
}

# =============================================================================
# MODULO: WORD legacy (.doc) via antiword
# =============================================================================
analyze_word_doc() {
    local url="$1"
    local filepath="$2"
    local hit_count=0

    log_doc "Analizando Word DOC (legacy): $url"

    if ! command -v antiword &>/dev/null; then
        log_warn "antiword no disponible. Instala: apt install antiword"
        echo "0"; return
    fi

    local text
    text=$(antiword "$filepath" 2>/dev/null || true)

    if [[ -n "$text" ]]; then
        local analysis
        analysis=$(analyze_source "$url" "$text")
        local count
        count=$(echo "$analysis" | head -1)
        if (( count > 0 )); then
            write_url_header "$url" "$count" "Word DOC legacy"
            local idx=0
            while IFS=$'\x01' read -r sev cat desc lnum mtxt; do
                (( idx++ )) || true
                [[ $idx -eq 1 ]] && continue
                [[ -z "$sev" ]] && continue
                write_finding "$url" "$sev" "$cat" "$desc" "$lnum" "$mtxt" "doc-text"
                (( hit_count++ )) || true
            done <<< "$analysis"
        fi
    fi

    # Metadatos con exiftool
    if command -v exiftool &>/dev/null; then
        local meta_hits
        meta_hits=$(exiftool -s "$filepath" 2>/dev/null \
            | grep -iE '^(Author|LastSavedBy|Company|CreateDate|ModifyDate|RevisionNumber)' \
            | while IFS=: read -r field value; do
                value="${value#"${value%%[![:space:]]*}"}"
                [[ -z "$value" || "$value" == "-" ]] && continue
                echo "MEDIUM|METADATA|${field} en metadatos DOC|meta|${value}"
            done || true)
        if [[ -n "$meta_hits" ]]; then
            local mcount
            mcount=$(echo "$meta_hits" | wc -l)
            write_url_header "$url" "$mcount" "Word DOC (metadatos)"
            while IFS=$'\x01' read -r sev cat desc lnum mtxt; do
                [[ -z "$sev" ]] && continue
                write_finding "$url" "$sev" "$cat" "$desc" "$lnum" "$mtxt" "doc-metadata"
                (( hit_count++ )) || true
            done <<< "$meta_hits"
        fi
    fi

    echo "$hit_count"
}

# =============================================================================
# MODULO: EXCEL (.xlsx)
# =============================================================================
analyze_excel() {
    local url="$1"
    local filepath="$2"
    local hit_count=0

    log_doc "Analizando Excel XLSX: $url"

    if ! python3 -c "import openpyxl" &>/dev/null 2>&1; then
        log_warn "openpyxl no disponible. Instala: pip install openpyxl"
        echo "0"; return
    fi

    local py_output
    py_output=$(python3 - "$filepath" << 'PYEOF' 2>/dev/null || true
import sys, json

filepath = sys.argv[1]
try:
    # Intentar openpyxl primero (.xlsx nativo)
    import openpyxl
    wb = openpyxl.load_workbook(filepath, read_only=True, data_only=True)
except Exception:
    # Fallback para .xls legacy con xlrd si está disponible
    try:
        import xlrd
        book = xlrd.open_workbook(filepath)
        # Convertir a formato compatible
        class FakeWB:
            pass
        # Procesado básico con xlrd
        text_lines = []
        for si in range(book.nsheets):
            sh = book.sheet_by_index(si)
            for rx in range(sh.nrows):
                for val in sh.row_values(rx):
                    v = str(val).strip()
                    if v:
                        text_lines.append(f"{sh.name}!{rx+1}: {v}")
        print("TEXT_START")
        print("\n".join(text_lines))
        print("HIDDEN_START")
        print("[]")
        print("META_START")
        print("{}")
        sys.exit(0)
    except Exception as e2:
        print(f"ERROR_XLS:{e2}", file=sys.stderr)
        sys.exit(1)

try:
    text_lines = []
    hidden_sheets = []

    for sheetname in wb.sheetnames:
        ws = wb[sheetname]
        # Detectar hojas ocultas
        if ws.sheet_state != "visible":
            hidden_sheets.append(sheetname)
        for i, row in enumerate(ws.iter_rows(values_only=True), 1):
            for cell_val in row:
                if cell_val is not None:
                    val = str(cell_val).strip()
                    if val:
                        text_lines.append(f"{sheetname}!{i}: {val}")

    meta = {}
    props = wb.properties
    if props:
        meta = {
            "creator":      str(props.creator or ""),
            "lastModifiedBy": str(props.lastModifiedBy or ""),
            "company":      str(props.company or "") if hasattr(props, "company") else "",
            "created":      str(props.created or ""),
            "modified":     str(props.modified or ""),
            "keywords":     str(props.keywords or ""),
            "description":  str(props.description or ""),
        }

    print("TEXT_START")
    print("\n".join(text_lines))
    print("HIDDEN_START")
    print(json.dumps(hidden_sheets))
    print("META_START")
    print(json.dumps(meta))
except Exception as e:
    print(f"ERROR:{e}", file=sys.stderr)
PYEOF
    )

    if [[ -z "$py_output" ]]; then
        log_warn "No se pudo leer $url (XLSX)"
        echo "0"; return
    fi

    # Texto de celdas
    local text_section
    text_section=$(echo "$py_output" | sed -n '/^TEXT_START$/,/^HIDDEN_START$/p' | grep -v "TEXT_START\|HIDDEN_START" || true)

    if [[ -n "$text_section" ]]; then
        local analysis
        analysis=$(analyze_source "$url" "$text_section")
        local count
        count=$(echo "$analysis" | head -1)
        if (( count > 0 )); then
            write_url_header "$url" "$count" "Excel XLSX (celdas)"
            local idx=0
            while IFS=$'\x01' read -r sev cat desc lnum mtxt; do
                (( idx++ )) || true
                [[ $idx -eq 1 ]] && continue
                [[ -z "$sev" ]] && continue
                write_finding "$url" "$sev" "$cat" "$desc" "$lnum" "$mtxt" "xlsx-cell"
                (( hit_count++ )) || true
            done <<< "$analysis"
        fi
    fi

    # Hojas ocultas
    local hidden_json
    hidden_json=$(echo "$py_output" | sed -n '/^HIDDEN_START$/,/^META_START$/p' | grep -v "HIDDEN_START\|META_START" || true)
    local hidden_count
    hidden_count=$(python3 -c "import json,sys; d=json.loads(sys.argv[1]); print(len(d))" "$hidden_json" 2>/dev/null || echo "0")
    if (( hidden_count > 0 )); then
        local hidden_names
        hidden_names=$(python3 -c "import json,sys; print(', '.join(json.loads(sys.argv[1])))" "$hidden_json" 2>/dev/null || true)
        write_url_header "$url" "1" "Excel XLSX (hojas ocultas)"
        write_finding "$url" "HIGH" "EXCEL" "Hojas ocultas en el documento" "meta" "$hidden_count hoja(s): $hidden_names" "xlsx-hidden"
        (( hit_count++ )) || true
    fi

    # Metadatos
    local meta_json
    meta_json=$(echo "$py_output" | sed -n '/^META_START$/,$p' | tail -n +2 || true)
    if [[ -n "$meta_json" ]]; then
        local meta_hits
        meta_hits=$(python3 - "$meta_json" << 'PYEOF_XLSX_META' 2>/dev/null || true
import sys, json
try:
    meta = json.loads(sys.argv[1])
except Exception:
    sys.exit(0)
fields = {
    "creator":        ("MEDIUM", "METADATA", "Autor del Excel"),
    "lastModifiedBy": ("MEDIUM", "METADATA", "Ultimo editor del Excel"),
    "company":        ("MEDIUM", "METADATA", "Empresa en metadatos Excel"),
    "keywords":       ("MEDIUM", "METADATA", "Palabras clave"),
    "description":    ("MEDIUM", "METADATA", "Descripcion del Excel"),
}
for field, (sev, cat, desc) in fields.items():
    val = meta.get(field, "").strip()
    if val and val not in ("None", "0", ""):
        print(f"{sev}{cat}{desc}meta{val}")
PYEOF_XLSX_META
        )
        if [[ -n "$meta_hits" ]]; then
            local mcount
            mcount=$(echo "$meta_hits" | grep -c '|' || true)
            write_url_header "$url" "$mcount" "Excel XLSX (metadatos)"
            while IFS=$'\x01' read -r sev cat desc lnum mtxt; do
                [[ -z "$sev" ]] && continue
                write_finding "$url" "$sev" "$cat" "$desc" "$lnum" "$mtxt" "xlsx-metadata"
                (( hit_count++ )) || true
            done <<< "$meta_hits"
        fi
    fi

    echo "$hit_count"
}

# =============================================================================
# MODULO: IMAGENES (solo metadatos EXIF via exiftool)
# =============================================================================
analyze_image() {
    local url="$1"
    local filepath="$2"
    local hit_count=0

    log_doc "Analizando imagen: $url"

    if ! command -v exiftool &>/dev/null; then
        log_warn "exiftool no disponible. Instala: apt install libimage-exiftool-perl"
        echo "0"; return
    fi

    local meta
    meta=$(exiftool -s "$filepath" 2>/dev/null || true)
    [[ -z "$meta" ]] && { echo "0"; return; }

    local findings=()
    local fcount=0

    # GPS — coordenadas revelan ubicacion fisica
    local gps_lat gps_lon
    gps_lat=$(echo "$meta" | grep -iE '^GPSLatitude[[:space:]]*:' | cut -d: -f2- | sed 's/^[[:space:]]*//' | head -1 || true)
    gps_lon=$(echo "$meta" | grep -iE '^GPSLongitude[[:space:]]*:' | cut -d: -f2- | sed 's/^[[:space:]]*//' | head -1 || true)
    if [[ -n "$gps_lat" && -n "$gps_lon" ]]; then
        findings+=("HIGHEXIFCoordenadas GPS embebidas en imagenGPSLat: $gps_lat | Lon: $gps_lon")
        (( fcount++ )) || true
    fi

    # Autor y software
    local exif_fields=(
        "Artist:MEDIUM|EXIF|Autor de la imagen"
        "Author:MEDIUM|EXIF|Autor en metadatos"
        "Creator:MEDIUM|EXIF|Creador de la imagen"
        "Copyright:MEDIUM|EXIF|Copyright en metadatos"
        "Software:LOW|EXIF|Software usado para editar"
        "Make:LOW|EXIF|Fabricante de la camara"
        "Model:LOW|EXIF|Modelo de la camara"
        "HostComputer:MEDIUM|EXIF|Nombre del equipo de origen"
        "UserComment:HIGH|EXIF|Comentario de usuario en EXIF"
        "ImageDescription:MEDIUM|EXIF|Descripcion de imagen"
        "DocumentName:MEDIUM|EXIF|Nombre del documento"
        "XPComment:HIGH|EXIF|Comentario Windows en EXIF"
        "XPAuthor:MEDIUM|EXIF|Autor Windows en EXIF"
        "XPKeywords:MEDIUM|EXIF|Palabras clave Windows"
    )

    for entry in "${exif_fields[@]}"; do
        local field="${entry%%:*}"
        local meta_rest="${entry#*:}"
        IFS='|' read -r sev cat desc <<< "$meta_rest"
        local value
        value=$(echo "$meta" | grep -iE "^${field}[[:space:]]*:" | cut -d: -f2- | sed 's/^[[:space:]]*//' | head -c 200 || true)
        if [[ -n "$value" && "$value" != "-" && "$value" != "0" ]]; then
            findings+=("${sev}${cat}${desc}${field}${value}")
            (( fcount++ )) || true
        fi
    done

    # Emails en metadatos de imagen
    local img_emails
    img_emails=$(echo "$meta" | grep -oE '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}' 2>/dev/null || true)
    if [[ -n "$img_emails" ]]; then
        while IFS= read -r email; do
            [[ -z "$email" ]] && continue
            findings+=("MEDIUMEXIFEmail en metadatos de imagenmeta$email")
            (( fcount++ )) || true
        done <<< "$img_emails"
    fi

    # Rutas del sistema en metadatos
    local img_paths
    img_paths=$(echo "$meta" | grep -oE '[A-Za-z]:\\[A-Za-z0-9_\\. \-]+|/[a-z]+/[a-zA-Z0-9_./\-]{5,}' 2>/dev/null || true)
    if [[ -n "$img_paths" ]]; then
        while IFS= read -r path; do
            [[ -z "$path" ]] && continue
            findings+=("HIGHEXIFRuta del sistema en metadatos de imagenmeta$path")
            (( fcount++ )) || true
        done <<< "$img_paths"
    fi

    if (( fcount > 0 )); then
        write_url_header "$url" "$fcount" "Imagen (metadatos EXIF)"
        for entry in "${findings[@]}"; do
            IFS=$'\x01' read -r sev cat desc lnum mtxt <<< "$entry"
            write_finding "$url" "$sev" "$cat" "$desc" "$lnum" "$mtxt" "image-exif"
            (( hit_count++ )) || true
        done
    else
        log_info "  => Sin metadatos sensibles en imagen"
    fi

    echo "$hit_count"
}

# =============================================================================
# MODULO: SQLite
# =============================================================================
analyze_sqlite() {
    local url="$1"
    local filepath="$2"
    local hit_count=0

    log_doc "Analizando SQLite: $url"

    if ! command -v sqlite3 &>/dev/null; then
        log_warn "sqlite3 no disponible. Instala: apt install sqlite3"
        echo "0"; return
    fi

    # Verificar que es un fichero SQLite valido
    local magic
    magic=$(head -c 16 "$filepath" 2>/dev/null | strings | head -1 || true)
    if ! echo "$magic" | grep -q "SQLite"; then
        log_warn "El fichero no parece un SQLite valido: $url"
        echo "0"; return
    fi

    local findings=()
    local fcount=0

    # Esquema completo
    local schema
    schema=$(sqlite3 "$filepath" ".schema" 2>/dev/null || true)

    # Tablas con nombres sensibles
    local sensitive_tables
    sensitive_tables=$(echo "$schema" | grep -iE 'CREATE TABLE[^(]*(user|pass|auth|credential|secret|token|key|admin|account|login)' | grep -oE '[a-zA-Z_][a-zA-Z0-9_]+' | grep -ivE '^(CREATE|TABLE|IF|NOT|EXISTS|INTEGER|TEXT|REAL|BLOB|NULL|PRIMARY|KEY|DEFAULT|UNIQUE)$' | head -20 || true)

    if [[ -n "$sensitive_tables" ]]; then
        findings+=("HIGHSQLITETablas con nombres sensibles detectadasschema$(echo "$sensitive_tables" | tr '\n' ' ')")
        (( fcount++ )) || true
    fi

    # Columnas con campos sensibles
    local sensitive_cols
    sensitive_cols=$(echo "$schema" | grep -iE '(password|passwd|pwd|pass|secret|token|api_key|auth|salt|hash|credit|ssn|pin)[[:space:]]' | head -c 500 || true)
    if [[ -n "$sensitive_cols" ]]; then
        while IFS= read -r col; do
            [[ -z "$col" ]] && continue
            findings+=("CRITICALSQLITEColumna sensible en esquemaschema${col}")
            (( fcount++ )) || true
        done <<< "$sensitive_cols"
    fi

    # Intentar volcar datos de tablas sensibles (max 5 filas por tabla)
    local tables
    tables=$(sqlite3 "$filepath" ".tables" 2>/dev/null || true)
    for table in $tables; do
        local tlower
        tlower=$(echo "$table" | tr '[:upper:]' '[:lower:]')
        if echo "$tlower" | grep -qiE 'user|pass|auth|credential|secret|token|key|admin|account|login|config|setting'; then
            local dump
            dump=$(sqlite3 "$filepath" "SELECT * FROM \"${table}\" LIMIT 5;" 2>/dev/null | head -20 || true)
            if [[ -n "$dump" ]]; then
                local analysis
                analysis=$(analyze_source "$url" "$dump")
                local count
                count=$(echo "$analysis" | head -1)
                if (( count > 0 )); then
                    local idx=0
                    while IFS=$'\x01' read -r sev cat desc lnum mtxt; do
                        (( idx++ )) || true
                        [[ $idx -eq 1 ]] && continue
                        [[ -z "$sev" ]] && continue
                        findings+=("${sev}${cat}[tabla: ${table}] ${desc}${lnum}${mtxt}")
                        (( fcount++ )) || true
                    done <<< "$analysis"
                else
                    # Aunque no matchee patrones, volcar primeras filas como MEDIUM
                    findings+=("MEDIUMSQLITEDatos en tabla sensible '${table}'data$(echo "$dump" | head -3 | tr '\n' ' ' | head -c 200)")
                    (( fcount++ )) || true
                fi
            fi
        fi
    done

    if (( fcount > 0 )); then
        write_url_header "$url" "$fcount" "SQLite (BBDD)"
        for entry in "${findings[@]}"; do
            IFS=$'\x01' read -r sev cat desc lnum mtxt <<< "$entry"
            write_finding "$url" "$sev" "$cat" "$desc" "$lnum" "$mtxt" "sqlite"
            (( hit_count++ )) || true
        done
    else
        log_info "  => Sin datos sensibles en SQLite"
    fi

    echo "$hit_count"
}

# =============================================================================
# MODULO: SQL dumps (.sql / .dump)
# =============================================================================
analyze_sqldump() {
    local url="$1"
    local content="$2"
    local hit_count=0

    log_doc "Analizando SQL dump: $url"

    local analysis
    analysis=$(analyze_source "$url" "$content")
    local count
    count=$(echo "$analysis" | head -1)

    if (( count > 0 )); then
        write_url_header "$url" "$count" "SQL dump"
        local idx=0
        while IFS=$'\x01' read -r sev cat desc lnum mtxt; do
            (( idx++ )) || true
            [[ $idx -eq 1 ]] && continue
            [[ -z "$sev" ]] && continue
            write_finding "$url" "$sev" "$cat" "$desc" "$lnum" "$mtxt" "sqldump"
            (( hit_count++ )) || true
        done <<< "$analysis"
    else
        log_info "  => Sin hallazgos en SQL dump"
    fi

    echo "$hit_count"
}

# =============================================================================
# REPORTE
# =============================================================================
init_report() {
    local ts_full ts_iso
    ts_full=$(date '+%Y-%m-%d %H:%M:%S')
    ts_iso=$(date '+%Y-%m-%dT%H:%M:%S')
    if [[ "$FORMAT" == "txt" ]]; then
        {
            printf '=============================================================================\n'
            printf '  GHOSTTAG v2.0 -- Source Code + Document + Binary Credential Hunter\n'
            printf '  Fecha    : %s\n' "$ts_full"
            printf '  Target   : %s\n' "$TARGET_URL"
            printf '  Depth    : %s\n' "$DEPTH"
            printf '=============================================================================\n\n'
        } > "$OUTPUT_FILE"
    elif [[ "$FORMAT" == "json" ]]; then
        {
            printf '{\n'
            printf '  "tool": "ghosttag",\n'
            printf '  "version": "2.0",\n'
            printf '  "date": "%s",\n' "$ts_iso"
            printf '  "target": "%s",\n' "$TARGET_URL"
            printf '  "depth": %s,\n' "$DEPTH"
            printf '  "findings": [\n'
        } > "$OUTPUT_FILE"
    fi
}

close_report() {
    if [[ "$FORMAT" == "txt" ]]; then
        {
            echo ""
            echo "============================================================="
            echo "  RESUMEN FINAL"
            echo "  URLs/recursos analizados : $TOTAL_URLS"
            echo "  Documentos/binarios      : $TOTAL_DOCS"
            echo "  Hallazgos totales        : $TOTAL_FINDINGS"
            echo "  Reporte                  : $OUTPUT_FILE"
            echo "============================================================="
        } >> "$OUTPUT_FILE"
    elif [[ "$FORMAT" == "json" ]]; then
        python3 - "$OUTPUT_FILE" "$TOTAL_URLS" "$TOTAL_DOCS" "$TOTAL_FINDINGS" << 'PYEOF'
import sys, re, json
path, total_urls, total_docs, total_findings = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
with open(path, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()
# Eliminar trailing comma antes del cierre del array de findings
# Cubre casos: "  },\n  ]" o "  },\n\n  ]"
content = re.sub(r',(\s*\]\s*)$', r'\1', content.rstrip(), flags=re.DOTALL)
# Eliminar el cierre parcial si existe
content = re.sub(r'\s*\]\s*$', '', content, flags=re.DOTALL)
summary = (
    '\n  ],\n'
    '  "summary": {\n'
    '    "urls_analyzed": '    + total_urls     + ',\n'
    '    "docs_analyzed": '    + total_docs     + ',\n'
    '    "total_findings": '   + total_findings + '\n'
    '  }\n'
    '}'
)
content = content.rstrip() + summary
# Validar JSON antes de escribir
try:
    json.loads(content)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
except json.JSONDecodeError as e:
    # Último recurso: estructura mínima válida
    fallback = (
        '{\n'
        '  "tool": "ghosttag",\n'
        '  "findings": [],\n'
        '  "summary": {\n'
        '    "urls_analyzed": ' + total_urls + ',\n'
        '    "docs_analyzed": ' + total_docs + ',\n'
        '    "total_findings": ' + total_findings + '\n'
        '  }\n'
        '}'
    )
    with open(path, 'w', encoding='utf-8') as f:
        f.write(fallback)
PYEOF
        local py_exit=$?
        (( py_exit != 0 )) && echo "]}" >> "$OUTPUT_FILE" || true
    fi
}

# =============================================================================
# PROCESADO DE UNA URL — enrutador principal
# =============================================================================
process_url() {
    local url="$1"
    local current_depth="${2:-0}"

    # Evitar loops
    if [[ -v VISITED_URLS["$url"] ]]; then
        return 0
    fi
    VISITED_URLS["$url"]=1
    (( TOTAL_URLS++ )) || true

    # Clasificar el recurso
    local rtype
    rtype=$(classify_resource "$url")

    # ── Recursos de texto (HTML, JS, CSS, JSON, PHP...) ──────────────────────
    if [[ "$rtype" == "html" || "$rtype" == "sqldump" ]]; then
        log_info "Analizando [${rtype}/${current_depth}]: ${BOLD}$url${NC}"

        local content
        content=$(fetch_url "$url")
        [[ -z "$content" ]] && { log_warn "Sin contenido: $url"; return 0; }

        local line_count
        line_count=$(echo "$content" | wc -l)
        log_info "  => ${line_count} lineas"

        if [[ "$rtype" == "sqldump" ]]; then
            analyze_sqldump "$url" "$content" >/dev/null 2>&1 || true
            # hits del sqldump ya se acumulan via write_finding -> TOTAL_FINDINGS
        else
            local analysis
            analysis=$(analyze_source "$url" "$content")
            local hit_count
            hit_count=$(echo "$analysis" | head -1)

            if (( hit_count > 0 )); then
                log_section "  [!] $hit_count hallazgo(s) en $url"
                write_url_header "$url" "$hit_count" "HTML/JS/CSS"
                local idx=0
                while IFS=$'\x01' read -r sev cat desc lnum mtxt; do
                    (( idx++ )) || true
                    [[ $idx -eq 1 ]] && continue
                    [[ -z "$sev" ]] && continue
                    write_finding "$url" "$sev" "$cat" "$desc" "$lnum" "$mtxt" "text"
                done <<< "$analysis"
            else
                log_info "  => Sin hallazgos"
            fi
        fi

        # Spider — seguir enlaces si no hemos llegado al limite
        if (( current_depth < DEPTH )); then
            local base_domain
            base_domain=$(get_base_domain)
            local links
            links=$(extract_links "$content" "$base_domain" || true)

            if [[ -n "$links" ]]; then
                local lcount
                lcount=$(echo "$links" | wc -l)
                log_info "  => ${lcount} enlace(s) a explorar"
                while IFS= read -r link; do
                    [[ -z "$link" ]] && continue
                    process_url "$link" $(( current_depth + 1 ))
                done <<< "$links"
            fi
        fi

    # ── Recursos binarios / documentos ───────────────────────────────────────
    else
        (( TOTAL_DOCS++ )) || true
        local tmpfile
        tmpfile="${WORK_DIR}/doc_$(date +%s%N).bin"

        log_info "Descargando [${rtype}]: ${BOLD}$url${NC}"
        fetch_binary "$url" "$tmpfile"

        if [[ ! -s "$tmpfile" ]]; then
            log_warn "Sin contenido o error al descargar: $url"
            rm -f "$tmpfile"
            return 0
        fi

        local hits=0
        local _mod_output
        # Los logs (log_doc, log_warn, write_finding) van a stderr directamente.
        # stdout del módulo contiene únicamente el número de hits (última línea echo).
        case "$rtype" in
            pdf)               _mod_output=$(analyze_pdf        "$url" "$tmpfile") ;;
            word)              _mod_output=$(analyze_word_docx  "$url" "$tmpfile") ;;
            word_legacy)       _mod_output=$(analyze_word_doc   "$url" "$tmpfile") ;;
            excel|excel_legacy)_mod_output=$(analyze_excel      "$url" "$tmpfile") ;;
            image)             _mod_output=$(analyze_image      "$url" "$tmpfile") ;;
            sqlite)            _mod_output=$(analyze_sqlite     "$url" "$tmpfile") ;;
        esac
        # stdout solo contiene el entero de hits
        hits=$(echo "$_mod_output" | grep -oE '^[0-9]+$' | tail -1 || echo "0")

        rm -f "$tmpfile"

        if (( hits > 0 )); then
            log_section "  [!] $hits hallazgo(s) en documento: $url"
        else
            log_info "  => Sin hallazgos en documento"
        fi
    fi
}

# =============================================================================
# RESUMEN TERMINAL
# =============================================================================
print_summary() {
    echo "" >&2
    echo -e "${CYAN}${BOLD}======================================================${NC}" >&2
    echo -e "${BOLD}  GHOSTTAG v2.0 — Resumen${NC}" >&2
    echo -e "${CYAN}${BOLD}======================================================${NC}" >&2
    echo -e "  URLs/recursos analizados : ${BOLD}$TOTAL_URLS${NC}" >&2
    echo -e "  Documentos/binarios      : ${BOLD}$TOTAL_DOCS${NC}" >&2
    echo -e "  Hallazgos totales        : ${BOLD}${RED}$TOTAL_FINDINGS${NC}" >&2
    echo -e "  Reporte                  : ${BOLD}$OUTPUT_FILE${NC}" >&2
    echo -e "${CYAN}${BOLD}======================================================${NC}" >&2
    echo "" >&2
    if (( TOTAL_FINDINGS > 0 )); then
        echo -e "${RED}${BOLD}  [!] Se encontraron credenciales o datos sensibles.${NC}" >&2
        echo -e "${YELLOW}  Revisa el reporte: $OUTPUT_FILE${NC}" >&2
    else
        echo -e "${GREEN}  [OK] No se detectaron patrones sensibles conocidos.${NC}" >&2
    fi
    echo "" >&2
}

# =============================================================================
# LIMPIEZA
# =============================================================================
cleanup() {
    [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]] && rm -rf "$WORK_DIR" || true
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    banner
    check_and_install_deps
    parse_args "$@"
    validate
    build_curl_flags

    # Directorio temporal para ficheros binarios
    WORK_DIR=$(mktemp -d /tmp/ghosttag_XXXXXX)
    trap cleanup EXIT INT TERM

    init_report
    log_section "Iniciando analisis"
    echo "" >&2

    process_url "$TARGET_URL" 0

    close_report
    print_summary
}

# Solo ejecutar main si el script se lanza directamente (no si se hace source)
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
