#!/usr/bin/env bash
# ============================================================
#  FASFO - Forensics Analysis Suite For Operations
#  Usage : fasfo <namafile|textdecode|url> --Forensics [OPTIONS]
#  CTF Edition | Kali Linux / Parrot OS
# ============================================================

VERSION="5.0.0"
FASFO_DIR="$HOME/.fasfo"
REPORT_DIR="$FASFO_DIR/reports"
mkdir -p "$REPORT_DIR"

# ─────────────────────────────────────────
#  PATH DETECTION — tools non-standar
# ─────────────────────────────────────────
# stegsolve: cari .jar di lokasi umum
STEGSOLVE_JAR=""
for _p in "$HOME/bin/stegsolve.jar" "$HOME/tools/stegsolve.jar" \
           "/opt/stegsolve.jar" "/usr/local/bin/stegsolve.jar" \
           "$(pwd)/stegsolve.jar"; do
  [[ -f "$_p" ]] && { STEGSOLVE_JAR="$_p"; break; }
done

# volatility3: cek command vol3 / volatility3, atau python module
VOL3_CMD=""
if   command -v volatility3 &>/dev/null; then VOL3_CMD="volatility3"
elif command -v vol3        &>/dev/null; then VOL3_CMD="vol3"
elif python3 -c "import volatility3" &>/dev/null 2>&1; then VOL3_CMD="python3 -m volatility3"
fi

# outguess: cek juga outguess-0.2
OUTGUESS_CMD=""
if   command -v outguess     &>/dev/null; then OUTGUESS_CMD="outguess"
elif command -v outguess-0.2 &>/dev/null; then OUTGUESS_CMD="outguess-0.2"
fi

# stegcrack: brute-force password steghide
STEGCRACK_CMD=""
if   command -v stegcrack    &>/dev/null; then STEGCRACK_CMD="stegcrack"
elif command -v stegCrack    &>/dev/null; then STEGCRACK_CMD="stegCrack"
elif python3 -c "import stegcrack" &>/dev/null 2>&1; then STEGCRACK_CMD="python3 -m stegcrack"
fi

# wordlist: cari rockyou.txt di lokasi umum
WORDLIST=""
for _w in "/usr/share/wordlists/rockyou.txt" \
           "/usr/share/wordlists/rockyou.txt.gz" \
           "$HOME/wordlists/rockyou.txt" \
           "/opt/wordlists/rockyou.txt"; do
  [[ -f "$_w" ]] && { WORDLIST="$_w"; break; }
done
# jika .gz, ekstrak dulu (lazy extract ke /tmp)
if [[ "$WORDLIST" == *.gz ]]; then
  info "Mengekstrak rockyou.txt.gz ke /tmp/rockyou.txt ..."
  gunzip -c "$WORDLIST" > /tmp/rockyou.txt 2>/dev/null
  WORDLIST="/tmp/rockyou.txt"
fi

# ─────────────────────────────────────────
#  COLORS & STYLES
# ─────────────────────────────────────────
R='\033[0;31m'   # red
G='\033[0;32m'   # green
Y='\033[0;33m'   # yellow
B='\033[0;34m'   # blue
M='\033[0;35m'   # magenta
C='\033[0;36m'   # cyan
W='\033[1;37m'   # white bold
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'     # reset

# ─────────────────────────────────────────
#  DECODE ENGINE — All Encoding Models
# ─────────────────────────────────────────

# Array global untuk menampung semua hasil decode
DECODE_HITS=()

# ── Helper: cetak hasil decode ────────────
_decode_hit() {
  local method="$1"
  local original="$2"
  local decoded="$3"
  # simpan ke array global
  DECODE_HITS+=("[$method] $decoded")
  echo -e "  ${M}[DECODE]${NC} ${BOLD}${method}${NC}: ${DIM}${original:0:40}${NC} → ${G}${BOLD}${decoded}${NC}"
  log_report "DECODED[$method]: $decoded"
}

# ── Cek apakah hasil decode terlihat seperti flag ─────
_looks_like_flag() {
  local s="$1"
  echo "$s" | grep -qiE '^[A-Za-z0-9_!@#$%^&*-]{3,}\{[^}]+\}$|^\{[A-Za-z0-9_!@#$%^&*-]+\}$'
}

# ── Cek apakah string printable (hasil decode valid) ──
_is_printable() {
  local s="$1"
  [[ -z "$s" ]] && return 1
  # cek minimal 4 karakter printable berurutan
  echo "$s" | grep -qP '[\x20-\x7e]{4,}'
}

# ────────────────────────────────────────────────────
#  MASTER DECODE: coba semua encoding pada satu string
# ────────────────────────────────────────────────────
decode_string() {
  local raw="$1"
  local silent="${2:-false}"   # jika true, tidak print header
  local found_any=false

  [[ "$silent" != "true" ]] && \
    echo -e "\n  ${C}[*]${NC} ${BOLD}Mencoba decode:${NC} ${DIM}${raw:0:80}${NC}"

  # ── 1. REVERSED (balik string) ──────────────────
  local rev
  rev=$(echo "$raw" | rev 2>/dev/null)
  if [[ "$rev" != "$raw" ]] && _is_printable "$rev"; then
    if _looks_like_flag "$rev"; then
      _decode_hit "REVERSED" "$raw" "$rev"
      found_any=true
    fi
    # juga cek reversed tanpa prefix/suffix brace mismatch
    local rev_inner
    rev_inner=$(echo "$raw" | tr -d '{}' | rev)
    if _looks_like_flag "{$rev_inner}"; then
      _decode_hit "REVERSED+FIX" "$raw" "{$rev_inner}"
      found_any=true
    fi
  fi

  # ── 2. BASE64 ────────────────────────────────────
  # Bersihkan whitespace & padding
  local b64clean
  b64clean=$(echo "$raw" | tr -d ' \n\r' | sed 's/[^A-Za-z0-9+/=]//g')
  # tambah padding jika perlu
  local padlen=$(( ${#b64clean} % 4 ))
  [[ "$padlen" -eq 2 ]] && b64clean="${b64clean}=="
  [[ "$padlen" -eq 3 ]] && b64clean="${b64clean}="
  local b64dec
  b64dec=$(echo "$b64clean" | base64 -d 2>/dev/null | tr -d '\0')
  if _is_printable "$b64dec"; then
    _decode_hit "BASE64" "$raw" "$b64dec"
    found_any=true
    # rekursi 1 level dalam: decode hasil base64 juga
    decode_string "$b64dec" true
  fi

  # ── 3. BASE64 URL-safe (- dan _) ─────────────────
  local b64url
  b64url=$(echo "$raw" | tr -- '-_' '+/' | tr -d ' \n\r')
  padlen=$(( ${#b64url} % 4 ))
  [[ "$padlen" -eq 2 ]] && b64url="${b64url}=="
  [[ "$padlen" -eq 3 ]] && b64url="${b64url}="
  local b64urldec
  b64urldec=$(echo "$b64url" | base64 -d 2>/dev/null | tr -d '\0')
  if _is_printable "$b64urldec" && [[ "$b64urldec" != "$b64dec" ]]; then
    _decode_hit "BASE64URL" "$raw" "$b64urldec"
    found_any=true
  fi

  # ── 4. HEX (0x... atau pure hex) ─────────────────
  local hexclean
  hexclean=$(echo "$raw" | sed 's/^0x//;s/ //g;s/\\x//g' | tr -d '[:space:]')
  if [[ ${#hexclean} -ge 8 ]] && echo "$hexclean" | grep -qE '^[0-9a-fA-F]+$'; then
    local hexdec
    hexdec=$(echo "$hexclean" | xxd -r -p 2>/dev/null | tr -d '\0')
    if _is_printable "$hexdec"; then
      _decode_hit "HEX" "$raw" "$hexdec"
      found_any=true
    fi
  fi

  # ── 5. HEX dengan spasi (misal: 46 54 43 7b ...) ─
  if echo "$raw" | grep -qE '^([0-9a-fA-F]{2} ?)+$'; then
    local hexsp
    hexsp=$(echo "$raw" | tr -d ' ' | xxd -r -p 2>/dev/null | tr -d '\0')
    if _is_printable "$hexsp" && [[ "$hexsp" != "$hexdec" ]]; then
      _decode_hit "HEX_SPACED" "$raw" "$hexsp"
      found_any=true
    fi
  fi

  # ── 6. ROT13 ─────────────────────────────────────
  local rot13
  rot13=$(echo "$raw" | tr 'A-Za-z' 'N-ZA-Mn-za-m')
  if [[ "$rot13" != "$raw" ]] && (_looks_like_flag "$rot13" || _is_printable "$rot13"); then
    _decode_hit "ROT13" "$raw" "$rot13"
    found_any=true
  fi

  # ── 7. CAESAR BRUTE FORCE (ROT 1-25) ─────────────
  local best_rot="" best_score=0
  for shift in {1..25}; do
    [[ "$shift" -eq 13 ]] && continue  # skip ROT13 sudah di atas
    local rotN
    rotN=$(echo "$raw" | python3 -c "
import sys
s=sys.stdin.read().rstrip()
n=$shift
r=''
for c in s:
    if c.isalpha():
        base=ord('A') if c.isupper() else ord('a')
        r+=chr((ord(c)-base+n)%26+base)
    else:
        r+=c
print(r)" 2>/dev/null)
    if _looks_like_flag "$rotN"; then
      _decode_hit "ROT${shift}" "$raw" "$rotN"
      found_any=true
    fi
  done

  # ── 8. URL DECODE (%xx) ──────────────────────────
  if echo "$raw" | grep -qE '%[0-9a-fA-F]{2}'; then
    local urldec
    urldec=$(python3 -c "import sys,urllib.parse; print(urllib.parse.unquote(sys.argv[1]))" "$raw" 2>/dev/null)
    if [[ -n "$urldec" && "$urldec" != "$raw" ]] && _is_printable "$urldec"; then
      _decode_hit "URL_DECODE" "$raw" "$urldec"
      found_any=true
    fi
  fi

  # ── 9. BINARY (01010011...) ──────────────────────
  if echo "$raw" | grep -qE '^[01 ]{8,}$'; then
    local bindec
    bindec=$(echo "$raw" | tr -d ' ' | python3 -c "
import sys
b=sys.stdin.read().strip()
r=''
for i in range(0,len(b),8):
    chunk=b[i:i+8]
    if len(chunk)==8:
        r+=chr(int(chunk,2))
print(r)" 2>/dev/null | tr -d '\0')
    if _is_printable "$bindec"; then
      _decode_hit "BINARY" "$raw" "$bindec"
      found_any=true
    fi
  fi

  # ── 10. MORSE CODE (. - / space) ─────────────────
  if echo "$raw" | grep -qE '^[.\- /]+$'; then
    local morsedec
    morsedec=$(python3 -c "
morse={'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F',
'-- .':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L',
'--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R',
'...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X',
'-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2',
'...--':'3','....-':'4','.....':'5','-....':'6','--...':'7',
'---..':'8','----.':'9'}
import sys
words=sys.stdin.read().strip().split('/')
r=' '.join(''.join(morse.get(c,'?') for c in w.strip().split()) for w in words)
print(r)" <<< "$raw" 2>/dev/null)
    if _is_printable "$morsedec" && echo "$morsedec" | grep -qv '?'; then
      _decode_hit "MORSE" "$raw" "$morsedec"
      found_any=true
    fi
  fi

  # ── 11. ATBASH (A=Z, B=Y, ...) ───────────────────
  local atbash
  atbash=$(echo "$raw" | python3 -c "
import sys
s=sys.stdin.read().rstrip()
r=''
for c in s:
    if c.isalpha():
        base=ord('A') if c.isupper() else ord('a')
        r+=chr(base+25-(ord(c)-base))
    else:
        r+=c
print(r)" 2>/dev/null)
  if [[ "$atbash" != "$raw" ]] && _looks_like_flag "$atbash"; then
    _decode_hit "ATBASH" "$raw" "$atbash"
    found_any=true
  fi

  # ── 12. OCTAL (misal: 106 124 103 ...) ───────────
  if echo "$raw" | grep -qE '^([0-7]{3} ?)+$'; then
    local octdec
    octdec=$(echo "$raw" | python3 -c "
import sys
tokens=sys.stdin.read().strip().split()
print(''.join(chr(int(t,8)) for t in tokens if t))" 2>/dev/null | tr -d '\0')
    if _is_printable "$octdec"; then
      _decode_hit "OCTAL" "$raw" "$octdec"
      found_any=true
    fi
  fi

  # ── 13. HTML ENTITIES (&amp; &#65; dll) ──────────
  if echo "$raw" | grep -qE '&[a-z]+;|&#[0-9]+;'; then
    local htmldec
    htmldec=$(python3 -c "
import sys,html
print(html.unescape(sys.argv[1]))" "$raw" 2>/dev/null)
    if [[ "$htmldec" != "$raw" ]] && _is_printable "$htmldec"; then
      _decode_hit "HTML_ENTITY" "$raw" "$htmldec"
      found_any=true
    fi
  fi

  # ── 14. REVERSED BASE64 ───────────────────────────
  local revb64
  revb64=$(echo "$raw" | rev | base64 -d 2>/dev/null | tr -d '\0')
  if _is_printable "$revb64" && [[ "$revb64" != "$b64dec" ]]; then
    _decode_hit "REV+BASE64" "$raw" "$revb64"
    found_any=true
  fi

  # ── 15. XOR brute force (single byte, 0x01-0xFF) ─
  # hanya jika string terlihat seperti hex atau raw bytes
  if echo "$raw" | grep -qE '^[0-9a-fA-F]{8,}$'; then
    local xor_found=false
    for xk in $(seq 1 255); do
      local xordec
      xordec=$(echo "$raw" | xxd -r -p 2>/dev/null | python3 -c "
import sys
data=sys.stdin.buffer.read()
k=$xk
print(''.join(chr(b^k) for b in data))" 2>/dev/null | tr -d '\0')
      if _looks_like_flag "$xordec"; then
        _decode_hit "XOR(0x$(printf '%02x' $xk))" "$raw" "$xordec"
        found_any=true
        xor_found=true
        break
      fi
    done
  fi

  # ── 16. L33TSPEAK normalisasi ─────────────────────
  local leet
  leet=$(echo "$raw" | python3 -c "
import sys
leet_map={'4':'a','@':'a','3':'e','1':'i','!':'i','0':'o','5':'s','\$':'s','7':'t','8':'b','6':'g','9':'g'}
s=sys.stdin.read().rstrip()
r=''.join(leet_map.get(c,c) for c in s.lower())
print(r)" 2>/dev/null)
  if [[ "$leet" != "${raw,,}" ]] && _is_printable "$leet"; then
    _decode_hit "L33T" "$raw" "$leet"
    found_any=true
  fi

  # ── 17. REVERSED BRACKET FLAG (}...{XTC → CTF{...}) ─
  # Khusus untuk format seperti }...{FTC atau }...{CTF
  if echo "$raw" | grep -qE '^\}[^{]+\{[A-Za-z0-9]{2,8}$'; then
    # ekstrak prefix terbalik dan isi
    local prefix_rev
    local content_rev
    prefix_rev=$(echo "$raw" | grep -oE '\{[A-Za-z0-9]{2,8}$' | tr -d '{' | rev)
    content_rev=$(echo "$raw" | grep -oE '^\}[^{]+' | tr -d '}' | rev)
    local reconstructed="${prefix_rev}{${content_rev}}"
    if _is_printable "$reconstructed"; then
      _decode_hit "REVERSED_FLAG" "$raw" "$reconstructed"
      found_any=true
    fi
  fi

  $found_any || echo -e "  ${DIM}  → Tidak ada encoding yang cocok ditemukan${NC}"
}

# ────────────────────────────────────────────────────
#  DECODE SEMUA FLAG CANDIDATES (dipanggil di summary)
# ────────────────────────────────────────────────────
decode_flag_candidates() {
  local report="$REPORT_FILE"
  section "Auto Decode — Flag Candidates"

  local candidates=()
  local seen_cands=()

  _add_candidate() {
    local c="$1"
    c=$(echo "$c" | xargs 2>/dev/null)
    [[ -z "$c" || ${#c} -lt 4 ]] && return
    for prev in "${seen_cands[@]}"; do [[ "$prev" == "$c" ]] && return; done
    seen_cands+=("$c")
    candidates+=("$c")
  }

  # ── 1. Dari REPORT_FILE ───────────────────────────
  if [[ -f "$report" ]]; then
    while IFS= read -r line; do
      local val
      val=$(echo "$line" | sed 's/^[^:]*://' | xargs 2>/dev/null)
      [[ -n "$val" ]] && _add_candidate "$val"
    done < <(grep -iE \
      '^(STRINGS_FLAGS|STRINGS_FLAGS_REV|STRINGS_ENCODED|ZSTEG|STEGHIDE|B64_FLAG|LOG_FLAG|HTTP_FLAG|CRACKED_FLAG|EXTRACTED_FLAG|MEM_FLAG|DECODED|FLAG|PCAP_DNS):' \
      "$report" 2>/dev/null)

    # Juga scan raw sample strings dari report
    while IFS= read -r line; do
      local rawval
      rawval=$(echo "$line" | sed 's/^STRINGS_RAW_SAMPLE://')
      # Pecah dengan separator |
      IFS='|' read -ra raw_tokens <<< "$rawval"
      for tok in "${raw_tokens[@]}"; do
        tok=$(echo "$tok" | xargs 2>/dev/null)
        [[ ${#tok} -lt 6 ]] && continue
        # Hanya ambil token yang terlihat seperti encoded/reversed/flag
        echo "$tok" | grep -qiE \
          '(\}[A-Za-z0-9_]{3,}\{[A-Za-z0-9]{2,10}|[A-Za-z0-9+/]{20,}={0,2}|[0-9a-fA-F]{32,64}|0x[0-9a-fA-F]{8,}|%[0-9a-fA-F]{2}|[A-Za-z0-9]{2,10}\{[^}]{3,}\})' \
          && _add_candidate "$tok"
      done
    done < <(grep '^STRINGS_RAW_SAMPLE:' "$report" 2>/dev/null)

    # Dari baris STRINGS_FLAGS_REV: ekstrak token bersih saja
    while IFS= read -r revline; do
      local revval
      revval=$(echo "$revline" | sed 's/^STRINGS_FLAGS_REV://')
      # Ekstrak token }...{PREFIX murni tanpa noise teks komentar
      local rev_token
      rev_token=$(echo "$revval" | grep -oE '\}[A-Za-z0-9_!@#$%^&*-]{3,}\{[A-Za-z0-9]{2,10}' | head -1)
      [[ -n "$rev_token" ]] && _add_candidate "$rev_token"
    done < <(grep '^STRINGS_FLAGS_REV:' "$report" 2>/dev/null)
  fi

  # ── 2. Scan langsung dari TARGET file ─────────────
  if [[ -n "$TARGET" && -f "$TARGET" ]]; then
    while IFS= read -r fline; do
      fline=$(echo "$fline" | xargs 2>/dev/null)
      [[ ${#fline} -lt 4 ]] && continue
      _add_candidate "$fline"
    done < <(strings "$TARGET" 2>/dev/null | grep -iE \
      '(\}[A-Za-z0-9_!@#$%^&*-]{3,}\{[A-Za-z0-9]{2,10}|[A-Za-z0-9]{2,10}\{[^}]{3,}\}|[A-Za-z0-9+/]{24,}={0,2}|[0-9a-fA-F]{32,64}|0x[0-9a-fA-F]{8,}|%[0-9a-fA-F]{2}(%[0-9a-fA-F]{2}){3,}|[01 ]{32,})' \
      2>/dev/null | sort -u | head -60)
  fi

  if [[ ${#candidates[@]} -eq 0 ]]; then
    info "Tidak ada kandidat yang perlu di-decode"
    return
  fi

  info "Ditemukan ${#candidates[@]} kandidat — mencoba semua model decode..."
  divider

  for cand in "${candidates[@]}"; do
    decode_string "$cand"
  done

  # Tampilkan ringkasan DECODE_HITS
  if [[ ${#DECODE_HITS[@]} -gt 0 ]]; then
    divider
    echo -e "  ${M}${BOLD}[DECODE HITS — RINGKASAN]${NC}"
    for hit in "${DECODE_HITS[@]}"; do
      echo -e "    ${G}✔${NC} $hit"
      log_report "DECODE_HIT: $hit"
    done
  fi
}

# ────────────────────────────────────────────────────
#  STANDALONE DECODE MODE (fasfo "string" --decode)
# ────────────────────────────────────────────────────
run_decode_mode() {
  local input="$1"
  banner
  section "FASFO Decode Mode"
  info "Input: ${BOLD}${input}${NC}"
  divider

  DECODE_HITS=()
  # jika tidak ada REPORT_FILE, set dummy
  [[ -z "$REPORT_FILE" ]] && REPORT_FILE="/dev/null"

  decode_string "$input"

  # Laporan
  echo ""
  echo -e "${BOLD}${C}╔══════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}${C}║         FASFO DECODE REPORT              ║${NC}"
  echo -e "${BOLD}${C}╚══════════════════════════════════════════╝${NC}"
  echo -e "  ${W}Input   :${NC} ${input:0:60}"
  echo -e "  ${W}Hasil   :${NC} ${#DECODE_HITS[@]} encoding berhasil di-decode"
  echo ""

  if [[ ${#DECODE_HITS[@]} -gt 0 ]]; then
    echo -e "  ${M}${BOLD}[DECODE RESULTS]${NC}"
    for hit in "${DECODE_HITS[@]}"; do
      echo -e "    ${G}✔${NC} $hit"
    done
  else
    echo -e "  ${Y}[!]${NC} Tidak ada encoding yang berhasil di-decode untuk input ini."
    echo -e "  ${DIM}Tips: pastikan input adalah string encoded yang valid.${NC}"
  fi
  echo ""

  # ── Laporan disimpan ──
  local dec_report="$REPORT_DIR/decode_$(date +%Y%m%d_%H%M%S).txt"
  {
    echo "FASFO Decode Report — $(date)"
    echo "Input: $input"
    echo "---"
    for hit in "${DECODE_HITS[@]}"; do
      echo "DECODED: $hit"
    done
  } > "$dec_report"
  echo -e "  ${W}Report  :${NC} $dec_report"
  echo ""
}

# ─────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────
banner() {
  echo -e "${C}"
  echo "  ███████╗ █████╗ ███████╗███████╗ ██████╗ "
  echo "  ██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗"
  echo "  █████╗  ███████║███████╗███████╗██║   ██║"
  echo "  ██╔══╝  ██╔══██║╚════██║╚════██║██║   ██║"
  echo "  ██║     ██║  ██║███████║███████║╚██████╔╝"
  echo "  ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ "
  echo -e "${DIM}${W}  Forensics Analysis Suite For Operations  v${VERSION}${NC}"
  echo -e "${DIM}  CTF Edition · Kali Linux${NC}"
  echo ""
}

# ─────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────
section() { echo -e "\n${BOLD}${B}╔══[ ${W}$1${B} ]${NC}"; }
ok()      { echo -e "  ${G}[+]${NC} $1"; }
info()    { echo -e "  ${C}[*]${NC} $1"; }
warn()    { echo -e "  ${Y}[!]${NC} $1"; }
fail()    { echo -e "  ${R}[-]${NC} $1"; }
found()   { echo -e "  ${M}[FLAG?]${NC} ${BOLD}$1${NC}"; }
divider() { echo -e "  ${DIM}────────────────────────────────────────${NC}"; }

# cek apakah tool tersedia
has() { command -v "$1" &>/dev/null; }

# run tool, tampilkan output dengan indent
run_tool() {
  local label="$1"; shift
  echo -e "  ${DIM}→ $label${NC}"
  "$@" 2>/dev/null | sed 's/^/    /' | head -40
}

# simpan ke report
log_report() { echo "$1" >> "$REPORT_FILE"; }

# ─────────────────────────────────────────
#  DEPENDENCY CHECK
# ─────────────────────────────────────────
check_deps() {
  section "Dependency Check"

  # Tools apt biasa — cek nama binary-nya, bukan nama package
  local apt_tools=(file strings xxd binwalk exiftool foremost steghide zsteg tshark pngcheck identify ffmpeg whois dig unzip p7zip-full john zipdetails)
  local miss_apt=()
  for t in "${apt_tools[@]}"; do
    if has "$t"; then ok "$t"
    else
      case "$t" in
        dig)        warn "dig ${DIM}(tidak ditemukan — package: bind9-dnsutils)${NC}"; miss_apt+=("bind9-dnsutils") ;;
        p7zip-full) warn "7z ${DIM}(tidak ditemukan — package: p7zip-full)${NC}";      miss_apt+=("p7zip-full") ;;
        zipdetails)
          # zipdetails bagian dari perl, cek alternatif
          has perl && ok "zipdetails ${DIM}(via perl)${NC}" || { warn "zipdetails ${DIM}(tidak ditemukan)${NC}"; miss_apt+=("perl"); } ;;
        *)          warn "$t ${DIM}(tidak ditemukan)${NC}"; miss_apt+=("$t") ;;
      esac
    fi
  done

  # cek rar/unrar
  if has unrar; then ok "unrar"
  elif has rar; then ok "rar"
  else warn "unrar ${DIM}(tidak ditemukan)${NC}"; miss_apt+=("unrar"); fi

  # cek john the ripper
  if has john; then ok "john"
  else warn "john ${DIM}(tidak ditemukan — untuk bruteforce archive)${NC}"; miss_apt+=("john"); fi

  # cek fcrackzip
  if has fcrackzip; then ok "fcrackzip"
  else warn "fcrackzip ${DIM}(tidak ditemukan — zip bruteforce)${NC}"; miss_apt+=("fcrackzip"); fi

  # wordlist
  divider
  if [[ -n "$WORDLIST" ]]; then
    ok "wordlist ${DIM}→ $WORDLIST${NC}"
  else
    warn "rockyou.txt ${DIM}(tidak ditemukan)${NC}"
    echo -e "    ${DIM}Fix: sudo gunzip /usr/share/wordlists/rockyou.txt.gz${NC}"
    echo -e "    ${DIM}     atau: sudo apt install wordlists${NC}"
  fi

  # stegsolve (jar)
  divider
  if [[ -n "$STEGSOLVE_JAR" ]]; then
    ok "stegsolve ${DIM}→ $STEGSOLVE_JAR${NC}"
  else
    warn "stegsolve.jar ${DIM}(tidak ditemukan di lokasi umum)${NC}"
    echo -e "    ${DIM}Fix: wget http://www.caesum.com/handbook/Stegsolve.jar -O ~/bin/stegsolve.jar${NC}"
  fi

  # volatility3
  if [[ -n "$VOL3_CMD" ]]; then
    ok "volatility3 ${DIM}→ $VOL3_CMD${NC}"
  else
    warn "volatility3 ${DIM}(tidak ditemukan)${NC}"
    echo -e "    ${DIM}Fix: pip3 install volatility3${NC}"
    echo -e "    ${DIM}     atau: git clone https://github.com/volatilityfoundation/volatility3${NC}"
  fi

  # outguess
  if [[ -n "$OUTGUESS_CMD" ]]; then
    ok "outguess ${DIM}→ $OUTGUESS_CMD${NC}"
  else
    warn "outguess ${DIM}(tidak ditemukan — tidak ada di repo Kali)${NC}"
    echo -e "    ${DIM}Build dari source:${NC}"
    echo -e "    ${DIM}  git clone https://github.com/crorvick/outguess${NC}"
    echo -e "    ${DIM}  cd outguess && ./configure && make && sudo make install${NC}"
    echo -e "    ${DIM}Alternatif: steghide / zsteg sudah cover sebagian besar kasus${NC}"
  fi

  # stegcrack
  if [[ -n "$STEGCRACK_CMD" ]]; then
    ok "stegcrack ${DIM}→ $STEGCRACK_CMD${NC}"
  else
    warn "stegcrack ${DIM}(tidak ditemukan)${NC}"
    echo -e "    ${DIM}Fix: pip3 install stegcrack${NC}"
    echo -e "    ${DIM}     atau: sudo pip3 install stegcrack --break-system-packages${NC}"
    echo -e "    ${DIM}Fungsi: brute-force password steghide dengan wordlist (rockyou)${NC}"
  fi

  # WSL display warning
  divider
  if grep -qi "microsoft\|wsl" /proc/version 2>/dev/null; then
    warn "${Y}WSL terdeteksi${NC} — tool GUI (stegsolve, stegsolve-GUI) tidak bisa dibuka langsung"
    echo -e "    ${DIM}Gunakan: fasfo image.png --Forensics --stego  (CLI mode, tanpa GUI)${NC}"
    echo -e "    ${DIM}Atau install VcXsrv/X410 di Windows lalu: export DISPLAY=:0${NC}"
  fi

  # Advanced tools (v4.0.0)
  divider
  echo -e "  ${BOLD}${W}Advanced Tools (v4.0.0):${NC}"

  # scalpel
  if has scalpel; then ok "scalpel ${DIM}(advanced file carving)${NC}"
  else warn "scalpel ${DIM}(opsional — sudo apt install scalpel)${NC}"; fi

  # objdump (untuk malware triage)
  if has objdump; then ok "objdump ${DIM}(ELF/PE analysis — binutils)${NC}"
  else warn "objdump ${DIM}(sudo apt install binutils)${NC}"; miss_apt+=("binutils"); fi

  # hexdump
  if has hexdump; then ok "hexdump ${DIM}(annotated hex view)${NC}"
  else warn "hexdump ${DIM}(sudo apt install bsdmainutils)${NC}"; miss_apt+=("bsdmainutils"); fi

  # sleuthkit (fls, mactime, tsk_recover)
  if has fls; then ok "sleuthkit/fls ${DIM}(NTFS/EXT4 forensics)${NC}"
  else warn "sleuthkit ${DIM}(sudo apt install sleuthkit)${NC}"; miss_apt+=("sleuthkit"); fi

  if has mactime; then ok "mactime ${DIM}(timeline reconstruction)${NC}"
  else warn "mactime ${DIM}(sudo apt install sleuthkit)${NC}"; fi

  # Python PIL/Pillow (stego analysis)
  if python3 -c "from PIL import Image" &>/dev/null 2>&1; then
    ok "Pillow ${DIM}(Python image analysis)${NC}"
  else
    warn "Pillow ${DIM}(pip3 install Pillow — dibutuhkan untuk advanced stego)${NC}"
    echo -e "    ${DIM}Fix: pip3 install Pillow numpy${NC}"
  fi

  # numpy
  if python3 -c "import numpy" &>/dev/null 2>&1; then
    ok "numpy ${DIM}(Python numerical analysis)${NC}"
  else
    warn "numpy ${DIM}(pip3 install numpy — untuk frequency domain analysis)${NC}"
  fi

  # zeek
  if has zeek; then ok "zeek ${DIM}(advanced network analysis)${NC}"
  else warn "zeek ${DIM}(opsional — sudo apt install zeek)${NC}"; fi

  # sonic-visualiser
  if has sonic-visualiser; then ok "sonic-visualiser ${DIM}(audio spectrogram)${NC}"
  else warn "sonic-visualiser ${DIM}(sudo apt install sonic-visualiser)${NC}"; fi

  # ffmpeg (audio/video)
  if has ffmpeg; then ok "ffmpeg ${DIM}(audio/video processing)${NC}"
  else warn "ffmpeg ${DIM}(sudo apt install ffmpeg)${NC}"; miss_apt+=("ffmpeg"); fi

  # ── Crypto Tools (v5.0.0) ──────────────────────────────────
  divider
  echo -e "  ${BOLD}${W}Crypto Tools (v5.0.0):${NC}"

  # openssl
  if has openssl; then ok "openssl ${DIM}(RSA/cert analysis, AES encrypt/decrypt)${NC}"
  else warn "openssl ${DIM}(sudo apt install openssl)${NC}"; miss_apt+=("openssl"); fi

  # hashcat
  if has hashcat; then ok "hashcat ${DIM}(GPU hash cracking — MD5/SHA/bcrypt)${NC}"
  else warn "hashcat ${DIM}(opsional — sudo apt install hashcat)${NC}"; fi

  # pycryptodome
  if python3 -c "from Crypto.Cipher import AES" &>/dev/null 2>&1; then
    ok "pycryptodome ${DIM}(Python crypto: AES, RSA, DES, ChaCha20)${NC}"
  else
    warn "pycryptodome ${DIM}(pip3 install pycryptodome — dibutuhkan untuk crypto analysis)${NC}"
    echo -e "    ${DIM}Fix: pip3 install pycryptodome${NC}"
  fi

  # hashpumpy (length extension)
  if python3 -c "import hashpumpy" &>/dev/null 2>&1; then
    ok "hashpumpy ${DIM}(length extension attack)${NC}"
  else
    warn "hashpumpy ${DIM}(pip3 install hashpumpy — hash length extension attack)${NC}"
  fi

  # z3-solver (SMT for crypto)
  if python3 -c "import z3" &>/dev/null 2>&1; then
    ok "z3-solver ${DIM}(SMT solver untuk reverse crypto / symbolic execution)${NC}"
  else
    warn "z3-solver ${DIM}(opsional — pip3 install z3-solver)${NC}"
  fi

  # SageMath
  if has sage; then ok "sage/SageMath ${DIM}(RSA factoring, elliptic curves, DLP)${NC}"
  else warn "sage ${DIM}(opsional — sudo apt install sagemath — berat ~2GB)${NC}"; fi

  # RsaCtfTool
  if has RsaCtfTool || [[ -f "$HOME/tools/RsaCtfTool/RsaCtfTool.py" ]]; then
    ok "RsaCtfTool ${DIM}(RSA multi-attack auto-solver)${NC}"
  else
    warn "RsaCtfTool ${DIM}(opsional — pip3 install requests && git clone https://github.com/RsaCtfTool/RsaCtfTool)${NC}"
  fi

  # Summary
  if [[ ${#miss_apt[@]} -gt 0 ]]; then
    echo ""
    echo -e "  ${Y}Install apt tools yang kurang:${NC}"
    echo -e "  ${DIM}sudo apt install ${miss_apt[*]}${NC}"
  fi
}

# ─────────────────────────────────────────
#  MODULE 1 — FILE ANALYSIS
# ─────────────────────────────────────────
mod_file_analysis() {
  section "File Analysis"
  local target="$1"

  # Magic bytes
  divider
  info "Magic Bytes & File Type"
  if has file; then
    local ftype
    ftype=$(file "$target")
    ok "$ftype"
    log_report "FILE_TYPE: $ftype"

    # deteksi anomali: extension vs magic mismatch
    local ext="${target##*.}"
    local magic_short
    magic_short=$(file --brief "$target" | tr '[:upper:]' '[:lower:]')
    case "$ext" in
      jpg|jpeg) [[ "$magic_short" != *"jpeg"* ]] && found "Extension mismatch: .$ext tapi magic=$magic_short" ;;
      png)      [[ "$magic_short" != *"png"* ]]  && found "Extension mismatch: .$ext tapi magic=$magic_short" ;;
      pdf)      [[ "$magic_short" != *"pdf"* ]]  && found "Extension mismatch: .$ext tapi magic=$magic_short" ;;
    esac
  fi

  # Strings analysis
  divider
  info "Strings Extraction (printable ≥6 char)"
  if has strings; then
    local str_out
    str_out=$(strings -n 6 "$target" 2>/dev/null)
    echo "$str_out" | head -30 | sed 's/^/    /'

    # ── Deteksi flag CTF (format normal) ──
    local flags
    flags=$(echo "$str_out" | grep -iE \
      '(flag|CTF|picoCTF|DUCTF|HTB|THM|REDLIMIT|FTC|XGH|pico)\{[^}]+\}' 2>/dev/null)
    if [[ -n "$flags" ]]; then
      found "Possible flag (normal): $flags"
      log_report "STRINGS_FLAGS: $flags"
    fi

    # ── Deteksi REVERSED flag: }...{PREFIX ──
    # Format: }isi_flag{PREFIX  (kurung kurawal terbalik)
    local rev_flags
    rev_flags=$(echo "$str_out" | grep -iE \
      '\}[A-Za-z0-9_!@#$%^&*-]{3,}\{[A-Za-z0-9]{2,10}' \
      2>/dev/null)
    if [[ -n "$rev_flags" ]]; then
      found "Possible REVERSED flag ditemukan — akan di-decode otomatis:"
      echo "$rev_flags" | sed 's/^/    /'
      log_report "STRINGS_FLAGS_REV: $rev_flags"
      # Ekstrak token bersih lalu decode
      while IFS= read -r rfline; do
        local rf_clean
        rf_clean=$(echo "$rfline" | grep -oE '\}[A-Za-z0-9_!@#$%^&*-]{3,}\{[A-Za-z0-9]{2,10}' | head -1)
        if [[ -n "$rf_clean" ]]; then
          decode_string "$rf_clean"
        fi
      done <<< "$rev_flags"
    fi

    # ── Deteksi pola mencurigakan lain: checksum, hash, encoded ──
    local sus_strings
    sus_strings=$(echo "$str_out" | grep -iE \
      '([A-Za-z0-9+/]{24,}={0,2}|[0-9a-fA-F]{32,64}|0x[0-9a-fA-F]{8,}|%[0-9a-fA-F]{2}(%[0-9a-fA-F]{2}){3,})' \
      2>/dev/null | head -10)
    if [[ -n "$sus_strings" ]]; then
      info "String mencurigakan (possible encoded) — dicoba decode:"
      echo "$sus_strings" | sed 's/^/    /'
      log_report "STRINGS_ENCODED: $sus_strings"
      # decode tiap kandidat
      while IFS= read -r sline; do
        [[ ${#sline} -lt 8 ]] && continue
        decode_string "$sline"
      done <<< "$sus_strings"
    fi

    # ── Kumpulkan SEMUA strings ke REPORT untuk decode_flag_candidates ──
    log_report "STRINGS_RAW_SAMPLE: $(echo "$str_out" | grep -v '^$' | head -100 | tr '\n' '|')"
  fi

  # Hex dump header (16 bytes pertama)
  divider
  info "Hex Dump (header 32 bytes)"
  if has xxd; then
    xxd "$target" 2>/dev/null | head -4 | sed 's/^/    /'
  fi

  # Binwalk
  divider
  info "Binwalk — Embedded File/Signature Scan"
  if has binwalk; then
    local bw_out
    bw_out=$(binwalk "$target" 2>/dev/null)
    echo "$bw_out" | sed 's/^/    /' | head -30
    # deteksi embedded files
    local embedded
    embedded=$(echo "$bw_out" | grep -vE "^DECIMAL|^---" | grep -v "^$" | wc -l)
    [[ "$embedded" -gt 1 ]] && found "Binwalk menemukan $embedded embedded signature — coba: binwalk -e $target"
    log_report "BINWALK: $bw_out"
  fi

  # File carving dengan foremost
  divider
  info "File Carving (foremost)"
  if has foremost; then
    local carve_dir="$REPORT_DIR/carved_$(basename "$target")"
    mkdir -p "$carve_dir"
    foremost -i "$target" -o "$carve_dir" -q 2>/dev/null
    local carved_count
    carved_count=$(find "$carve_dir" -type f ! -name "audit.txt" 2>/dev/null | wc -l)
    [[ "$carved_count" -gt 0 ]] && found "Foremost berhasil carve $carved_count file → $carve_dir"
    ok "Carving selesai. Output: $carve_dir"
  fi

  # Metadata
  divider
  info "Metadata (exiftool)"
  if has exiftool; then
    local meta
    meta=$(exiftool "$target" 2>/dev/null)
    echo "$meta" | head -25 | sed 's/^/    /'
    # cari metadata mencurigakan
    local sus_meta
    sus_meta=$(echo "$meta" | grep -iE '(comment|author|creator|producer|subject|description|flag|secret|password|key)' 2>/dev/null)
    [[ -n "$sus_meta" ]] && found "Metadata mencurigakan:\n$sus_meta"
    log_report "METADATA: $sus_meta"
  fi
}

# ─────────────────────────────────────────
#  MODULE 2 — STEGANOGRAPHY
# ─────────────────────────────────────────
mod_steganography() {
  section "Steganography Analysis"
  local target="$1"
  local ftype
  ftype=$(file --brief "$target" 2>/dev/null | tr '[:upper:]' '[:lower:]')

  # PNG analysis
  if [[ "$ftype" == *"png"* ]]; then
    divider
    info "PNG Check (pngcheck)"
    has pngcheck && run_tool "pngcheck" pngcheck -v "$target"

    divider
    info "zsteg — LSB & Channel Analysis"
    if has zsteg; then
      local zsteg_out
      zsteg_out=$(zsteg "$target" 2>/dev/null)
      echo "$zsteg_out" | head -20 | sed 's/^/    /'
      local zflag
      zflag=$(echo "$zsteg_out" | grep -iE '(flag|CTF|{[^}]+})' 2>/dev/null)
      [[ -n "$zflag" ]] && found "zsteg hit: $zflag"
      log_report "ZSTEG: $zflag"
    fi
  fi

  # JPEG analysis
  if [[ "$ftype" == *"jpeg"* || "$ftype" == *"jpg"* ]]; then
    divider
    info "Steghide — Hidden Data (no passphrase)"
    if has steghide; then
      local sh_out
      sh_out=$(steghide extract -sf "$target" -p "" 2>&1)
      ok "$sh_out"
      [[ "$sh_out" == *"wrote"* ]] && found "Steghide berhasil extract tanpa passphrase!"
      log_report "STEGHIDE: $sh_out"
    fi

    divider
    info "StegCrack — Brute-force Password Steghide"
    if [[ -n "$STEGCRACK_CMD" ]]; then
      if [[ -n "$WORDLIST" ]]; then
        info "Menjalankan StegCrack dengan wordlist: ${DIM}$WORDLIST${NC}"
        info "${Y}[!]${NC} Proses ini bisa memakan waktu — tekan Ctrl+C untuk skip"
        local sc_out sc_pass
        sc_out=$($STEGCRACK_CMD "$target" "$WORDLIST" 2>&1)
        echo "$sc_out" | tail -5 | sed 's/^/    /'
        sc_pass=$(echo "$sc_out" | grep -iE "password|found|cracked" | head -3)
        if [[ -n "$sc_pass" ]]; then
          found "StegCrack berhasil! $sc_pass"
          log_report "STEGCRACK_HIT: $sc_pass"
          # Coba langsung extract dengan password yang ditemukan
          local cracked_pw
          cracked_pw=$(echo "$sc_out" | grep -oP '(?<=password: |Password: |found: )\S+' | head -1)
          if [[ -n "$cracked_pw" ]]; then
            info "Mencoba extract dengan password: ${W}$cracked_pw${NC}"
            steghide extract -sf "$target" -p "$cracked_pw" -f 2>&1 | sed 's/^/    /'
          fi
        else
          warn "StegCrack: password tidak ditemukan di wordlist"
          log_report "STEGCRACK: tidak ditemukan"
        fi
      else
        warn "StegCrack tersedia tapi wordlist (rockyou.txt) tidak ditemukan"
        warn "Install wordlist: sudo apt install wordlists && sudo gunzip /usr/share/wordlists/rockyou.txt.gz"
        warn "Manual: stegcrack $target /path/to/wordlist.txt"
      fi
    else
      warn "stegcrack tidak ditemukan — install: pip3 install stegcrack"
      warn "Manual brute-force: while read p; do steghide extract -sf $target -p \"\$p\" 2>/dev/null && echo \"PASS: \$p\" && break; done < $WORDLIST"
    fi

    divider
    info "Outguess Check"
    if [[ -n "$OUTGUESS_CMD" ]]; then
      $OUTGUESS_CMD -r "$target" /tmp/fasfo_outguess_out 2>/dev/null
      [[ -f /tmp/fasfo_outguess_out ]] && {
        found "Outguess extract berhasil!"
        strings /tmp/fasfo_outguess_out | head -10 | sed 's/^/    /'
        rm -f /tmp/fasfo_outguess_out
      }
    else
      warn "outguess tidak ditemukan — sudo apt install outguess"
    fi
  fi

  # Audio analysis
  if [[ "$ftype" == *"audio"* || "$ftype" == *"wave"* || "$ftype" == *"mp3"* ]]; then
    divider
    info "Audio Steganography (spectogram hint)"
    warn "Untuk spectrogram: buka di Audacity atau Sonic Visualiser"
    warn "Cek juga: steghide extract -sf $target -p \"\""
    if has ffmpeg; then
      info "ffmpeg audio info:"
      ffmpeg -i "$target" 2>&1 | grep -E "(Duration|Audio|Stream)" | sed 's/^/    /'
    fi

    # StegCrack untuk WAV (steghide support WAV)
    if [[ "$ftype" == *"wave"* || "$ftype" == *"wav"* ]]; then
      divider
      info "StegCrack — Brute-force Password Steghide (WAV)"
      if [[ -n "$STEGCRACK_CMD" ]] && [[ -n "$WORDLIST" ]]; then
        info "Menjalankan StegCrack pada file WAV..."
        local sc_wav_out sc_wav_pass
        sc_wav_out=$($STEGCRACK_CMD "$target" "$WORDLIST" 2>&1)
        sc_wav_pass=$(echo "$sc_wav_out" | grep -iE "password|found|cracked" | head -3)
        if [[ -n "$sc_wav_pass" ]]; then
          found "StegCrack WAV berhasil! $sc_wav_pass"
          log_report "STEGCRACK_WAV_HIT: $sc_wav_pass"
        else
          warn "StegCrack WAV: password tidak ditemukan di wordlist"
        fi
      elif [[ -z "$STEGCRACK_CMD" ]]; then
        warn "stegcrack tidak ditemukan — install: pip3 install stegcrack"
      else
        warn "Wordlist tidak ditemukan untuk StegCrack"
      fi
    fi
  fi

  # stegsolve hint (WSL-safe: tidak launch GUI, tapi tampilkan cara pakai)
  divider
  info "Stegsolve"
  if [[ -n "$STEGSOLVE_JAR" ]]; then
    # WSL check
    if grep -qi "microsoft\|wsl" /proc/version 2>/dev/null; then
      warn "WSL: stegsolve GUI tidak bisa dibuka otomatis"
      warn "Jalankan manual di terminal baru: ${W}java -jar $STEGSOLVE_JAR${NC}"
      warn "Atau di Windows PowerShell buka file gambar dengan stegsolve"
    else
      info "Membuka stegsolve (background)..."
      java -jar "$STEGSOLVE_JAR" "$target" &>/dev/null &
      ok "Stegsolve dibuka: $STEGSOLVE_JAR"
    fi
  else
    warn "stegsolve.jar tidak ditemukan"
    warn "Download: wget http://www.caesum.com/handbook/Stegsolve.jar -O ~/bin/stegsolve.jar"
  fi

  # strings pass terhadap image untuk flag sederhana
  local raw_flag
  raw_flag=$(strings "$target" 2>/dev/null | grep -iE '\{[a-zA-Z0-9_!@#$%^&*-]{3,}\}' 2>/dev/null)
  [[ -n "$raw_flag" ]] && found "Raw flag pattern ditemukan di strings: $raw_flag"
}

# ─────────────────────────────────────────
#  MODULE 3 — NETWORK FORENSICS
# ─────────────────────────────────────────
mod_network_forensics() {
  section "Network Forensics (PCAP)"
  local target="$1"

  if ! has tshark; then
    warn "tshark tidak ditemukan. Install: sudo apt install tshark"
    return
  fi

  # ── Ringkasan PCAP ────────────────────
  divider
  info "Ringkasan PCAP"
  if has capinfos; then
    run_tool "capinfos" capinfos "$target" 2>/dev/null
  else
    tshark -r "$target" -q -z io,phs 2>/dev/null | head -20 | sed 's/^/    /'
  fi

  divider
  info "Protokol yang digunakan"
  tshark -r "$target" -q -z ptype,tree 2>/dev/null | head -25 | sed 's/^/    /'

  divider
  info "Top 10 IP Conversations"
  tshark -r "$target" -q -z conv,ip 2>/dev/null | head -15 | sed 's/^/    /'

  # ── HTTP Analysis ─────────────────────
  divider
  info "HTTP Requests (host + URI)"
  tshark -r "$target" -Y "http.request" -T fields \
    -e ip.src -e http.host -e http.request.uri 2>/dev/null | head -20 | sed 's/^/    /'

  divider
  info "Credentials / Cleartext (FTP, Telnet, HTTP Basic Auth)"
  local creds
  creds=$(tshark -r "$target" -Y "ftp || telnet || http.authbasic" \
    -T fields -e ftp.request.command -e ftp.request.arg \
    -e http.authbasic 2>/dev/null | grep -v "^$" | head -10)
  [[ -n "$creds" ]] && found "Possible credentials: $creds" || ok "Tidak ada cleartext credential"

  divider
  info "Flag pattern di payload (data.text)"
  local net_flag
  net_flag=$(tshark -r "$target" -T fields -e data.text 2>/dev/null | \
    grep -iE '(flag|CTF|picoCTF|HTB|THM)\{[^}]+\}' | head -5)
  [[ -n "$net_flag" ]] && found "Flag di network payload: $net_flag"

  # ══════════════════════════════════════════════════════
  #  DNS ANALYSIS ENGINE
  #  Deteksi DNS tunneling, data exfiltration via subdomain
  # ══════════════════════════════════════════════════════
  divider
  info "═══ DNS Analysis Engine ═══"

  # ── Step 1: Ekstrak semua DNS queries (request only) ──
  divider
  info "[Step 1] Ekstrak Semua DNS Queries"
  echo -e "  ${DIM}tshark -r <pcap> -Y \"dns.flags.response == 0\" -T fields -e dns.qry.name${NC}"
  echo ""

  local dns_all
  dns_all=$(tshark -r "$target" -Y "dns.flags.response == 0" \
    -T fields -e dns.qry.name 2>/dev/null | grep -v '^$')

  local dns_unique
  dns_unique=$(echo "$dns_all" | sort -u)

  if [[ -z "$dns_all" ]]; then
    # fallback: semua DNS termasuk response
    dns_all=$(tshark -r "$target" -Y "dns" -T fields -e dns.qry.name 2>/dev/null | grep -v '^$')
    dns_unique=$(echo "$dns_all" | sort -u)
  fi

  local dns_total dns_unique_count
  dns_total=$(echo "$dns_all" | wc -l)
  dns_unique_count=$(echo "$dns_unique" | wc -l)
  ok "Total DNS query   : $dns_total"
  ok "Domain unik       : $dns_unique_count"
  echo ""
  echo "$dns_unique" | head -30 | sed 's/^/    /'
  [[ "$dns_unique_count" -gt 30 ]] && echo "    ... (dan $((dns_unique_count - 30)) domain lainnya)"

  log_report "PCAP_DNS_TOTAL: $dns_total queries | $dns_unique_count unique"

  # ── Step 2: Deteksi DNS Tunneling ─────────────────────
  divider
  info "[Step 2] Deteksi DNS Tunneling & Anomali"
  echo -e "  ${DIM}Mencari pola: subdomain berurutan, entropi tinggi, domain C2${NC}"
  echo ""

  local tunnel_found=false

  # Cari subdomain dengan pola nomor urut: NN-<data>.<domain>
  local seq_domains
  seq_domains=$(echo "$dns_all" | grep -E '^[0-9]{2,3}-[A-Za-z0-9+/=_-]+\.' 2>/dev/null)

  # Cari subdomain sangat panjang (>30 char sebelum dot pertama)
  local long_sub
  long_sub=$(echo "$dns_unique" | awk -F'.' '{if(length($1)>30) print $0}' | head -10)

  # Cari subdomain dengan entropi tinggi (campuran huruf+angka acak >=8 char)
  local high_entropy
  high_entropy=$(echo "$dns_unique" | awk -F'.' '
    {
      s=$1; l=length(s)
      if(l>=8) {
        # hitung unique char
        delete seen; u=0
        for(i=1;i<=l;i++){c=substr(s,i,1); if(!seen[c]){seen[c]=1;u++}}
        ratio=u/l
        if(ratio>=0.6 && l>=8) print $0
      }
    }' | head -20)

  # Deteksi: query ke domain yang sama berulang dengan subdomain berbeda
  local repeat_domains
  repeat_domains=$(echo "$dns_all" | \
    awk -F'.' 'NF>=3{
      # ambil parent domain: 2 field terakhir
      n=NF; parent=$(n-1)"."$n
      count[parent]++
    }
    END{for(d in count) if(count[d]>=4) print count[d], d}' | \
    sort -rn | head -10)

  if [[ -n "$seq_domains" ]]; then
    tunnel_found=true
    found "POLA DNS TUNNELING — Subdomain berurutan ditemukan!"
    echo "$seq_domains" | sort -u | head -15 | awk '{printf "    %s\n", $0}'
    log_report "DNS_TUNNEL_SEQ: $(echo "$seq_domains" | sort -u | wc -l) sequential subdomains"
  fi

  if [[ -n "$long_sub" ]]; then
    tunnel_found=true
    found "Subdomain panjang tidak wajar (>30 char):"
    echo "$long_sub" | sed 's/^/    /'
    log_report "DNS_LONG_SUB: $long_sub"
  fi

  if [[ -n "$high_entropy" ]]; then
    tunnel_found=true
    found "Subdomain entropi tinggi (kemungkinan data encoded):"
    echo "$high_entropy" | sed 's/^/    /'
    log_report "DNS_HIGH_ENTROPY: $(echo "$high_entropy" | wc -l) domains"
  fi

  if [[ -n "$repeat_domains" ]]; then
    found "Domain induk dengan banyak subdomain unik (≥4 query):"
    echo "$repeat_domains" | awk '{printf "    %-6s query → %s\n", $1, $2}' | sed 's/^/  /'
    log_report "DNS_REPEAT_PARENT: $repeat_domains"
  fi

  [[ "$tunnel_found" == false ]] && ok "Tidak ada indikasi DNS tunneling yang ditemukan"

  # ── Step 3: Ekstrak & Kelompokkan Data dari Subdomain ─
  divider
  info "[Step 3] Ekstrak Data Chunk dari Subdomain"
  echo -e "  ${DIM}Mengidentifikasi parent domain C2 dan mengurutkan chunk data${NC}"
  echo ""

  # Temukan parent domain yang paling sering menjadi target tunneling
  local c2_candidates
  c2_candidates=$(echo "$dns_all" | \
    awk -F'.' 'NF>=3{
      n=NF; parent=$(n-1)"."$n
      # hanya hitung jika subdomain (field 1) mirip data encoded
      if(length($1)>=4 && $1~/^[A-Za-z0-9+/=_-]+$/)
        count[parent]++
    }
    END{for(d in count) if(count[d]>=3) print count[d], d}' | \
    sort -rn | head -5)

  if [[ -n "$c2_candidates" ]]; then
    echo -e "  ${C}[*]${NC} Kandidat domain C2 (berdasarkan frekuensi query):"
    echo "$c2_candidates" | awk '{printf "    %-6s query → %s\n", $1, $2}' | sed 's/^/  /'
    echo ""

    # Proses setiap kandidat C2
    echo "$c2_candidates" | awk '{print $2}' | while IFS= read -r c2dom; do
      echo -e "  ${B}┌─── Analisis domain: ${BOLD}${c2dom}${NC}${B} ───${NC}"

      # Kumpulkan semua query ke domain ini
      local c2_queries
      c2_queries=$(echo "$dns_all" | grep -E "\.${c2dom//./\\.}$|\.${c2dom//./\\.}\." 2>/dev/null | \
        grep -v "^${c2dom}$" | sort -u)

      # Fallback: cari subdomain langsung
      [[ -z "$c2_queries" ]] && \
        c2_queries=$(echo "$dns_all" | grep "${c2dom}" | grep -v "^${c2dom}$" | sort -u)

      local q_count
      q_count=$(echo "$c2_queries" | grep -c . 2>/dev/null || echo 0)
      echo -e "  ${B}│${NC}  Total query unik: ${q_count}"
      echo ""

      # Ekstrak subdomain (semua level sebelum parent domain)
      echo -e "  ${B}│${NC}  ${C}Query list (urut):${NC}"
      echo "$c2_queries" | sort | head -20 | while IFS= read -r qline; do
        # Ekstrak bagian sebelum parent domain
        local sub
        sub=$(echo "$qline" | sed "s/\.${c2dom//./\\.}$//" | sed "s/${c2dom//./\\.}$//")
        printf "  │    %s\n" "$qline"
      done

      # Deteksi format: NN-<chunk>.<c2dom>
      local seq_chunks
      seq_chunks=$(echo "$c2_queries" | grep -E '^[0-9]{2,3}-' | sort -t'-' -k1,1n)

      if [[ -n "$seq_chunks" ]]; then
        echo ""
        echo -e "  ${B}│${NC}  ${M}Pola chunk berurutan terdeteksi!${NC}"
        echo -e "  ${B}│${NC}"
        # Tampilkan tabel chunk
        printf "  │  %-8s %-45s %-15s\n" "Urutan" "Full Domain" "Data Chunk"
        echo "  │  $(printf '─%.0s' {1..65})"
        echo "$seq_chunks" | while IFS= read -r sq; do
          local seq_num chunk_data
          seq_num=$(echo "$sq" | cut -d'-' -f1)
          # ambil bagian antara '-' pertama dan domain c2
          chunk_data=$(echo "$sq" | sed "s/^[0-9]*-//" | sed "s/\.${c2dom//./\\.}$//" | \
            awk -F'.' '{print $1}')
          printf "  │  %-8s %-45s ${M}%-15s${NC}\n" "$seq_num" "${sq:0:43}" "$chunk_data"
        done
        echo "  │"
        log_report "DNS_CHUNKS: $(echo "$seq_chunks" | wc -l) ordered chunks from $c2dom"
      fi

      echo -e "  ${B}└──────────────────────────────────────────────${NC}"
      echo ""
    done
  else
    ok "Tidak ada domain C2 yang teridentifikasi"
  fi

  # ── Step 4: Decode Data Exfiltration ──────────────────
  divider
  info "[Step 4] Decode Data Exfiltration dari DNS Subdomain"
  echo -e "  ${DIM}Mencoba Base32, Base64, Hex decode pada data chunk yang ditemukan${NC}"
  echo ""

  # Cari semua domain dengan pola NN-<data>.<parent>
  local all_seq_q
  all_seq_q=$(echo "$dns_all" | grep -E '^[0-9]{2,3}-[A-Za-z0-9+/=_-]+\.' | sort -u)

  if [[ -n "$all_seq_q" ]]; then
    # Temukan parent domain dari query ini
    local seq_parent
    seq_parent=$(echo "$all_seq_q" | awk -F'.' 'NF>=3{n=NF; print $(n-1)"."$n}' | \
      sort | uniq -c | sort -rn | head -1 | awk '{print $2}')

    # Kumpulkan chunk urut
    local ordered_chunks
    ordered_chunks=$(echo "$all_seq_q" | \
      grep -E "\.${seq_parent//./\\.}" | \
      sort -t'-' -k1,1n | \
      sed "s/^[0-9]*-//" | \
      sed "s/\.${seq_parent//./\\.}$//" | \
      awk -F'.' '{print $1}')

    if [[ -n "$ordered_chunks" ]]; then
      local combined
      combined=$(echo "$ordered_chunks" | tr -d '\n')

      echo -e "  ${C}[*]${NC} Data chunk terkumpul (${seq_parent}):"
      echo "$ordered_chunks" | nl -ba | awk '{printf "    chunk[%02d] = %s\n", $1-1, $2}'
      echo ""
      echo -e "  ${C}[*]${NC} Gabungan raw : ${BOLD}${combined}${NC}"
      echo ""

      # ── Coba Base32 decode ─────────────────
      echo -e "  ${C}[*]${NC} Mencoba BASE32 decode..."
      local b32upper
      b32upper=$(echo "$combined" | tr '[:lower:]' '[:upper:]')
      # tambah padding
      local b32pad
      local padlen=$(( (8 - ${#b32upper} % 8) % 8 ))
      b32pad="${b32upper}$(printf '=%.0s' $(seq 1 $padlen 2>/dev/null))"
      local b32dec
      b32dec=$(echo "$b32pad" | base64 --decode -i 2>/dev/null | tr -d '\0' | strings 2>/dev/null | head -3)
      if [[ -z "$b32dec" ]]; then
        b32dec=$(python3 -c "
import base64, sys
s='${b32upper}'
pad=(8-len(s)%8)%8
try:
  result=base64.b32decode(s+'='*pad)
  print(result.decode('utf-8','ignore'))
except Exception as e:
  pass
" 2>/dev/null)
      fi
      if [[ -n "$b32dec" ]]; then
        found "BASE32 decode berhasil: ${BOLD}${b32dec}${NC}"
        echo "$b32dec" | grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF)\{[^}]+\}' | \
          while IFS= read -r fl; do
            found "FLAG dari DNS tunnel: ${BOLD}${fl}${NC}"
            log_report "DNS_TUNNEL_FLAG: $fl"
          done
        log_report "DNS_B32_DECODED: $b32dec"
      else
        ok "BASE32: tidak berhasil di-decode"
      fi

      # ── Coba Base64 decode ─────────────────
      echo -e "  ${C}[*]${NC} Mencoba BASE64 decode..."
      local b64dec
      b64dec=$(echo "$combined" | base64 -d 2>/dev/null | tr -d '\0' | strings 2>/dev/null | head -3)
      if [[ -n "$b64dec" ]] && echo "$b64dec" | grep -qP '[\x20-\x7e]{4,}'; then
        found "BASE64 decode berhasil: ${BOLD}${b64dec}${NC}"
        echo "$b64dec" | grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF)\{[^}]+\}' | \
          while IFS= read -r fl; do
            found "FLAG dari DNS tunnel (b64): ${BOLD}${fl}${NC}"
            log_report "DNS_TUNNEL_FLAG_B64: $fl"
          done
        log_report "DNS_B64_DECODED: $b64dec"
      else
        ok "BASE64: tidak berhasil di-decode"
      fi

      # ── Coba Hex decode ────────────────────
      echo -e "  ${C}[*]${NC} Mencoba HEX decode..."
      if echo "$combined" | grep -qE '^[0-9a-fA-F]+$'; then
        local hexdec
        hexdec=$(echo "$combined" | xxd -r -p 2>/dev/null | tr -d '\0' | strings 2>/dev/null | head -3)
        if [[ -n "$hexdec" ]]; then
          found "HEX decode berhasil: ${BOLD}${hexdec}${NC}"
          log_report "DNS_HEX_DECODED: $hexdec"
        else
          ok "HEX: tidak berhasil di-decode"
        fi
      else
        ok "HEX: bukan string hex valid"
      fi

      # ── Coba decode via FASFO decode engine ──
      echo ""
      echo -e "  ${C}[*]${NC} Mencoba semua metode decode engine FASFO..."
      decode_string "$combined"
    fi

  else
    # Fallback: coba decode semua subdomain panjang langsung
    if [[ -n "$high_entropy" ]]; then
      echo -e "  ${C}[*]${NC} Mencoba decode subdomain high-entropy secara individual:"
      echo "$high_entropy" | head -10 | while IFS= read -r hd; do
        local sub_only
        sub_only=$(echo "$hd" | cut -d'.' -f1)
        decode_string "$sub_only" true
      done
    else
      ok "Tidak ada data chunk yang bisa di-decode"
    fi
  fi

  # ── Analisis tambahan: DNS response types ─────────────
  divider
  info "DNS Record Types yang Digunakan"
  tshark -r "$target" -Y "dns" -T fields -e dns.qry.type 2>/dev/null | \
    sort | uniq -c | sort -rn | head -10 | \
    awk '{
      type=$2+0
      name="?"
      if(type==1)  name="A"
      else if(type==2)  name="NS"
      else if(type==5)  name="CNAME"
      else if(type==6)  name="SOA"
      else if(type==12) name="PTR"
      else if(type==15) name="MX"
      else if(type==16) name="TXT"
      else if(type==28) name="AAAA"
      else if(type==255) name="ANY"
      printf "    %-6s × type %-4s (%s)\n", $1, $2, name
    }' | sed 's/^/  /'

  # TXT records sering dipakai untuk DNS tunneling (data response)
  local dns_txt
  dns_txt=$(tshark -r "$target" -Y "dns.qry.type == 16" \
    -T fields -e dns.qry.name -e dns.txt 2>/dev/null | grep -v '^$' | head -15)
  if [[ -n "$dns_txt" ]]; then
    found "DNS TXT records ditemukan (sering dipakai C2 response):"
    echo "$dns_txt" | sed 's/^/    /'
    # Coba decode TXT content
    echo "$dns_txt" | awk '{print $2}' | while IFS= read -r txt; do
      [[ ${#txt} -ge 8 ]] && decode_string "$txt" true
    done
    log_report "DNS_TXT: $dns_txt"
  fi

  # ── IOC Summary ───────────────────────────────────────
  divider
  info "Indicators of Compromise (IOC) — DNS"
  echo ""

  # Kumpulkan semua domain eksternal (non-internal)
  local ext_domains
  ext_domains=$(echo "$dns_unique" | \
    grep -vE '\.(local|internal|corp|lan|home|arpa)$' | \
    grep -vE '^(www\.(google|microsoft|youtube|github|apple|amazon|cloudflare)\.(com|net))$')

  local sus_score=0
  [[ -n "$seq_domains"   ]] && (( sus_score += 3 ))
  [[ -n "$long_sub"      ]] && (( sus_score += 2 ))
  [[ -n "$high_entropy"  ]] && (( sus_score += 2 ))
  [[ -n "$dns_txt"       ]] && (( sus_score += 1 ))

  if [[ "$sus_score" -ge 3 ]]; then
    found "Skor kecurigaan DNS Tunneling: ${BOLD}${sus_score}/8${NC} — ${R}TINGGI${NC}"
  elif [[ "$sus_score" -ge 1 ]]; then
    warn "Skor kecurigaan DNS Tunneling: ${sus_score}/8 — SEDANG"
  else
    ok "Skor kecurigaan DNS Tunneling: 0/8 — rendah"
  fi

  echo ""
  echo -e "  ${C}[*]${NC} Semua domain eksternal yang di-query:"
  echo "$ext_domains" | head -20 | sed 's/^/    /'
  [[ $(echo "$ext_domains" | wc -l) -gt 20 ]] && \
    echo "    ... ($(( $(echo "$ext_domains" | wc -l) - 20 )) domain lainnya)"

  divider
  info "Export HTTP objects — jalankan manual:"
  warn "tshark -r $target --export-objects http,/tmp/pcap_http_export"
  warn "tshark -r $target -Y 'dns' -T fields -e dns.qry.name -e dns.resp.name > dns_full.txt"

  log_report "PCAP_DNS_UNIQUE: $dns_unique_count domains"
  log_report "PCAP_IOC_SCORE: $sus_score/8"
}

# ─────────────────────────────────────────
#  MODULE 4 — MEMORY FORENSICS
# ─────────────────────────────────────────
mod_memory_forensics() {
  section "Memory & Disk Forensics"
  local target="$1"

  if [[ -z "$VOL3_CMD" ]]; then
    warn "volatility3 tidak ditemukan."
    warn "Install: pip3 install volatility3"
    warn "Atau: git clone https://github.com/volatilityfoundation/volatility3 && cd volatility3 && pip3 install -e ."
    divider
    info "Fallback: Quick strings pass (flag pattern)"
    local mem_flag
    mem_flag=$(strings "$target" 2>/dev/null | grep -iE '(flag|CTF|picoCTF|HTB|THM)\{[^}]+\}' | head -5)
    [[ -n "$mem_flag" ]] && found "Flag ditemukan via strings: $mem_flag"
    return
  fi

  divider
  info "OS Profile Detection"
  $VOL3_CMD -f "$target" windows.info 2>/dev/null | sed 's/^/    /' | head -20 || \
  $VOL3_CMD -f "$target" linux.info   2>/dev/null | sed 's/^/    /' | head -20

  divider
  info "Running Processes"
  $VOL3_CMD -f "$target" windows.pslist 2>/dev/null | sed 's/^/    /' | head -30

  divider
  info "Network Connections (dari memory)"
  $VOL3_CMD -f "$target" windows.netstat 2>/dev/null | sed 's/^/    /' | head -20

  divider
  info "Command History"
  $VOL3_CMD -f "$target" windows.cmdline 2>/dev/null | sed 's/^/    /' | head -20

  divider
  info "Clipboard Content"
  $VOL3_CMD -f "$target" windows.clipboard 2>/dev/null | sed 's/^/    /'

  divider
  info "Dump Suggestion"
  warn "Untuk dump proses: $VOL3_CMD -f $target windows.dumpfiles --pid <PID>"
  warn "Untuk strings di memory: strings $target | grep -iE '(flag|CTF|password)'"

  # strings langsung di file memory
  divider
  info "Quick strings pass (flag pattern)"
  local mem_flag
  mem_flag=$(strings "$target" 2>/dev/null | grep -iE '(flag|CTF|picoCTF|HTB|THM)\{[^}]+\}' | head -5)
  [[ -n "$mem_flag" ]] && found "Flag ditemukan via strings: $mem_flag"
  log_report "MEM_FLAG: $mem_flag"
}

# ══════════════════════════════════════════════════════════════════
#  MODULE 4B — ADVANCED FILE ANALYSIS (Deep Inspection + Malware)
# ══════════════════════════════════════════════════════════════════
mod_advanced_file() {
  section "Advanced File Analysis — Deep Inspection"
  local target="$1"

  # ── 1. Analisis struktur internal file (header, chunk) ──────────
  divider
  info "[1] Struktur Internal File — Header & Chunk Parsing"
  if has xxd; then
    echo -e "  ${DIM}Full hex dump (256 bytes pertama):${NC}"
    xxd "$target" 2>/dev/null | head -16 | sed 's/^/    /'

    echo ""
    echo -e "  ${DIM}256 bytes terakhir:${NC}"
    local fsize_bytes
    fsize_bytes=$(stat -c%s "$target" 2>/dev/null || wc -c < "$target")
    if [[ "$fsize_bytes" -gt 256 ]]; then
      local tail_offset=$(( fsize_bytes - 256 ))
      xxd "$target" 2>/dev/null | tail -16 | sed 's/^/    /'
    fi

    # Deteksi magic bytes → tipe file nyata
    local magic_hex
    magic_hex=$(xxd -l 8 "$target" 2>/dev/null | head -1 | awk '{print $2$3}' | tr -d ' ')
    info "Magic hex (8 bytes pertama): ${W}${magic_hex}${NC}"
    log_report "ADV_MAGIC_HEX: $magic_hex"

    # Parsing format populer berdasarkan magic
    case "${magic_hex:0:8}" in
      89504e47) found "PNG detected — Parsing chunks..."
                # PNG chunk parser
                python3 - "$target" << 'PYEOF' 2>/dev/null | sed 's/^/    /'
import struct, sys
try:
    with open(sys.argv[1],'rb') as f:
        sig = f.read(8)
        print(f"Signature: {sig.hex()}")
        chunk_num = 0
        while True:
            hdr = f.read(8)
            if len(hdr) < 8: break
            length, ctype = struct.unpack('>I4s', hdr)
            ctype_s = ctype.decode('latin1','replace')
            data = f.read(length)
            crc = f.read(4)
            chunk_num += 1
            flag_hint = ''
            if any(kw in data.decode('latin1','replace').lower() for kw in ['flag','ctf','htb','picoctf']):
                flag_hint = ' ◀ POSSIBLE FLAG DATA!'
            print(f"  Chunk {chunk_num:3d}: {ctype_s:6s} length={length:8d}{flag_hint}")
            if ctype_s == 'IEND': break
except Exception as e:
    print(f"Error: {e}")
PYEOF
                ;;
      ffd8ffe*) found "JPEG detected — Parsing segments..."
                python3 - "$target" << 'PYEOF' 2>/dev/null | sed 's/^/    /'
import struct, sys
try:
    with open(sys.argv[1],'rb') as f:
        data = f.read()
    i = 0
    seg_num = 0
    while i < len(data)-1:
        if data[i] != 0xFF: i+=1; continue
        marker = data[i+1]
        if marker in (0xD8,0xD9):
            name = 'SOI' if marker==0xD8 else 'EOI'
            print(f"  Seg {seg_num:3d}: FF{marker:02X} ({name}) at 0x{i:06X}")
            i += 2; seg_num += 1; continue
        if i+3 >= len(data): break
        length = struct.unpack('>H', data[i+2:i+4])[0]
        seg_data = data[i+4:i+2+length]
        name = {0xE0:'APP0',0xE1:'APP1(EXIF/XMP)',0xE2:'APP2',0xFE:'COM',
                0xC0:'SOF0',0xDA:'SOS',0xDB:'DQT',0xC4:'DHT'}.get(marker,f'FF{marker:02X}')
        flag_hint = ''
        try:
            txt = seg_data.decode('latin1','replace').lower()
            if any(k in txt for k in ['flag','ctf','htb','picoctf']): flag_hint = ' ◀ FLAG DATA!'
        except: pass
        print(f"  Seg {seg_num:3d}: {name:20s} length={length:6d} at 0x{i:06X}{flag_hint}")
        i += 2 + length; seg_num += 1
        if seg_num > 60: print("  ... (truncated)"); break
except Exception as e:
    print(f"Error: {e}")
PYEOF
                ;;
      25504446) found "PDF detected — Parsing objects..."
                python3 - "$target" << 'PYEOF' 2>/dev/null | sed 's/^/    /'
import re, sys
try:
    with open(sys.argv[1],'rb') as f:
        raw = f.read().decode('latin1','replace')
    header = raw[:20].split('\n')[0]
    print(f"  Header  : {header}")
    objects = re.findall(r'(\d+ \d+ obj)', raw)
    print(f"  Objects : {len(objects)}")
    streams = len(re.findall(r'stream\b', raw))
    print(f"  Streams : {streams}")
    js      = len(re.findall(r'/JavaScript|/JS\b', raw))
    if js: print(f"  ⚠ JavaScript : {js} (suspicious!)")
    uris    = re.findall(r'/URI\s*\(([^)]+)\)', raw)
    if uris: print(f"  URIs    : {uris[:5]}")
    # flag scan
    flags = re.findall(r'[A-Za-z0-9_]{2,10}\{[^}]{3,}\}', raw)
    if flags: print(f"  ◀ FLAG PATTERN: {flags[:3]}")
except Exception as e:
    print(f"Error: {e}")
PYEOF
                ;;
      504b0304) found "ZIP/Office detected — parsing via zipfile..."
                python3 - "$target" << 'PYEOF' 2>/dev/null | sed 's/^/    /'
import zipfile, sys
try:
    with zipfile.ZipFile(sys.argv[1]) as z:
        for info in z.infolist()[:40]:
            flag = ''
            try:
                inner = z.read(info.filename).decode('latin1','replace').lower()
                if any(k in inner for k in ['flag','ctf','htb']): flag = ' ◀ FLAG!'
            except: pass
            print(f"  {info.filename:40s} {info.file_size:8d} bytes{flag}")
except Exception as e:
    print(f"Error: {e}")
PYEOF
                ;;
    esac
  fi

  # ── 2. Polyglot file detection ──────────────────────────────────
  divider
  info "[2] Polyglot File Detection (1 file → banyak format)"
  local poly_hits=0
  local fdata_head
  fdata_head=$(xxd -l 512 "$target" 2>/dev/null | xxd -r -p 2>/dev/null | cat -v 2>/dev/null)

  # Cek multiple magic bytes dalam satu file
  local magic_checks=(
    "89504e47:PNG"
    "ffd8ff:JPEG"
    "25504446:PDF"
    "504b0304:ZIP/DOCX/JAR"
    "1f8b:GZIP"
    "7f454c46:ELF"
    "4d5a:PE/EXE"
    "52494646:RIFF(WAV/AVI)"
    "cafebabe:Java CLASS"
    "377abcaf:7-Zip"
  )

  local file_hex
  file_hex=$(xxd -p "$target" 2>/dev/null | tr -d '\n')

  for entry in "${magic_checks[@]}"; do
    local sig="${entry%%:*}"
    local name="${entry##*:}"
    if echo "$file_hex" | grep -q "^${sig}"; then
      ok "  Header: ${G}${name}${NC} (posisi 0)"
    elif echo "$file_hex" | grep -qP "${sig}"; then
      found "  Polyglot hit: ${G}${name}${NC} signature ditemukan di TENGAH file!"
      log_report "ADV_POLYGLOT: $name"
      (( poly_hits++ ))
    fi
  done
  [[ "$poly_hits" -eq 0 ]] && ok "Tidak ada polyglot indicator ditemukan"

  # ── 3. Binwalk entropy analysis ─────────────────────────────────
  divider
  info "[3] Binwalk — Entropy Analysis (deteksi enkripsi/kompresi)"
  if has binwalk; then
    binwalk -E "$target" 2>/dev/null | head -20 | sed 's/^/    /'
    local bw_ent
    bw_ent=$(binwalk -E "$target" 2>/dev/null | grep -E "^[0-9]" | awk '{if($3+0 > 0.95) print $0}')
    [[ -n "$bw_ent" ]] && found "Entropy TINGGI terdeteksi — kemungkinan encrypted/compressed data:"
    [[ -n "$bw_ent" ]] && echo "$bw_ent" | sed 's/^/    /'
    log_report "ADV_ENTROPY: ${bw_ent:0:200}"

    # Deep extraction
    echo ""
    info "Binwalk deep extraction (--dd semua signature):"
    local bw_extract_dir="$REPORT_DIR/binwalk_deep_$(basename "$target")_$$"
    mkdir -p "$bw_extract_dir"
    binwalk --dd='.*' -C "$bw_extract_dir" "$target" 2>/dev/null | head -15 | sed 's/^/    /'
    local extracted
    extracted=$(find "$bw_extract_dir" -type f 2>/dev/null | wc -l)
    [[ "$extracted" -gt 0 ]] && found "Binwalk deep extract: $extracted file → $bw_extract_dir"
    ok "Extraction dir: $bw_extract_dir"
  else
    warn "binwalk tidak ditemukan — sudo apt install binwalk"
  fi

  # ── 4. Manual file carving tanpa signature ───────────────────────
  divider
  info "[4] File Carving — foremost & scalpel"
  if has foremost; then
    local carve_dir="$REPORT_DIR/carve_adv_$(basename "$target")_$$"
    mkdir -p "$carve_dir"
    foremost -t all -i "$target" -o "$carve_dir" 2>/dev/null
    local n
    n=$(find "$carve_dir" -type f ! -name "audit.txt" 2>/dev/null | wc -l)
    [[ "$n" -gt 0 ]] && found "Foremost berhasil carve ${n} file → $carve_dir"
    # tampilkan audit.txt
    [[ -f "$carve_dir/audit.txt" ]] && head -20 "$carve_dir/audit.txt" | sed 's/^/    /'
  else
    warn "foremost tidak tersedia"
  fi

  if has scalpel; then
    local scalpel_dir="$REPORT_DIR/scalpel_$(basename "$target")_$$"
    mkdir -p "$scalpel_dir"
    scalpel "$target" -o "$scalpel_dir" 2>/dev/null | tail -10 | sed 's/^/    /'
    local ns
    ns=$(find "$scalpel_dir" -type f 2>/dev/null | wc -l)
    [[ "$ns" -gt 0 ]] && found "Scalpel berhasil carve ${ns} file → $scalpel_dir"
  else
    info "scalpel tidak tersedia (opsional): sudo apt install scalpel"
  fi

  # ── 5. Embedded data detection ──────────────────────────────────
  divider
  info "[5] Embedded Data Detection — Nested Files"
  # Deteksi file dalam file (nested)
  if has binwalk; then
    local nested
    nested=$(binwalk "$target" 2>/dev/null | grep -vE "^DECIMAL|^---" | grep -v "^$")
    local nest_count
    nest_count=$(echo "$nested" | wc -l)
    [[ "$nest_count" -gt 1 ]] && found "$nest_count embedded signature ditemukan:"
    echo "$nested" | head -20 | sed 's/^/    /'
  fi

  # cari string "PK\x03\x04" atau signature ZIP di tengah file
  local zip_offsets
  zip_offsets=$(grep -c "PK" "$target" 2>/dev/null || true)
  [[ "$zip_offsets" -gt 1 ]] && found "Multiple ZIP signature ditemukan — kemungkinan nested archive"

  # ── 6. XOR obfuscation detection & brute force ──────────────────
  divider
  info "[6] XOR Obfuscation Detection & Brute Force"
  info "Mencoba XOR brute force pada seluruh file (key 0x01-0xFF)..."
  python3 - "$target" << 'PYEOF' 2>/dev/null
import sys
flag_patterns = [b'flag{', b'ctf{', b'picoctf{', b'htb{', b'thm{', b'FLAG{', b'CTF{']
try:
    with open(sys.argv[1], 'rb') as f:
        data = f.read(65536)  # max 64KB
    for key in range(1, 256):
        xored = bytes(b ^ key for b in data)
        for pat in flag_patterns:
            idx = xored.find(pat)
            if idx != -1:
                snippet = xored[idx:idx+60].decode('latin1','replace')
                print(f"  ◀ XOR key=0x{key:02X} ({key:3d}): FLAG ditemukan! → {snippet}")
                break
except Exception as e:
    print(f"  Error: {e}")
PYEOF
  ok "XOR scan selesai"
  log_report "ADV_XOR_SCAN: done"

  # ── 7. Malware static triage ────────────────────────────────────
  divider
  info "[7] Basic Malware Static Triage"

  # Cek apakah ELF atau PE
  local file_magic
  file_magic=$(file --brief "$target" 2>/dev/null | tr '[:upper:]' '[:lower:]')

  if echo "$file_magic" | grep -qiE "elf|executable|pe32|mz|dll"; then
    found "Binary executable terdeteksi — melakukan triage..."

    # Strings yang mencurigakan (IOC)
    echo -e "  ${Y}[!]${NC} Suspicious strings (network IOC, API calls):"
    strings "$target" 2>/dev/null | grep -iE \
      '(http[s]?://|ftp://|\.onion|/etc/passwd|/etc/shadow|cmd\.exe|powershell|shellcode|/bin/sh|wget|curl|nc -e|/dev/tcp|base64 -d|exec\(|eval\(|system\(|popen\()' \
      2>/dev/null | sort -u | head -20 | sed 's/^/    /'

    echo ""
    echo -e "  ${Y}[!]${NC} Import/Export functions (jika ELF/PE):"
    if has objdump; then
      objdump -d "$target" 2>/dev/null | grep -iE "<(socket|connect|send|recv|execve|system|popen|fork|ptrace|dlopen)@" | \
        head -15 | sed 's/^/    /'
    fi

    echo ""
    echo -e "  ${Y}[!]${NC} Packer/obfuscation indicators:"
    strings "$target" 2>/dev/null | grep -iE \
      '(upx|packed|packer|themida|vmprotect|aspack|mpress|petite)' \
      2>/dev/null | head -5 | sed 's/^/    /'

    # Entropy per section (high entropy = packed/encrypted)
    echo ""
    info "Entropy per bagian file:"
    if has binwalk; then
      binwalk -E "$target" 2>/dev/null | grep -E "^[0-9]" | \
        awk '{printf "    offset=0x%08X  entropy=%.3f\n", $1, $3}' | head -20
    fi
    log_report "ADV_MALWARE_TRIAGE: ELF/PE binary analyzed"
  else
    ok "Bukan binary executable — skipping malware triage"
    info "Untuk analisis script/macro: cek strings output di atas"
  fi

  # ── 8. hexdump full view dengan annotasi ─────────────────────────
  divider
  info "[8] Annotated Hexdump (hexdump -C)"
  if has hexdump; then
    hexdump -C "$target" 2>/dev/null | head -32 | sed 's/^/    /'
    echo -e "  ${DIM}(hanya 32 baris pertama — gunakan: hexdump -C $target | less)${NC}"
  fi
}

# ══════════════════════════════════════════════════════════════════
#  MODULE 4C — ADVANCED MEMORY & DISK FORENSICS (DFIR)
# ══════════════════════════════════════════════════════════════════
mod_advanced_memory() {
  section "Advanced Memory & Disk Forensics (DFIR)"
  local target="$1"

  if [[ -z "$VOL3_CMD" ]]; then
    warn "volatility3 tidak ditemukan — beberapa fitur tidak tersedia"
    warn "Install: pip3 install volatility3"
  fi

  # ── 1. Process analysis: hidden & injected processes ────────────
  divider
  info "[1] Process Analysis — Hidden & Injected Process Detection"
  if [[ -n "$VOL3_CMD" ]]; then
    echo -e "  ${DIM}pstree:${NC}"
    $VOL3_CMD -f "$target" windows.pstree 2>/dev/null | head -40 | sed 's/^/    /'

    echo ""
    echo -e "  ${DIM}pslist vs psscan (cari proses tersembunyi):${NC}"
    local pslist_pids psscan_pids
    pslist_pids=$($VOL3_CMD -f "$target" windows.pslist 2>/dev/null | awk 'NR>2{print $2}' | sort)
    psscan_pids=$($VOL3_CMD -f "$target" windows.psscan 2>/dev/null | awk 'NR>2{print $2}' | sort)

    local hidden_procs
    hidden_procs=$(comm -13 <(echo "$pslist_pids") <(echo "$psscan_pids") 2>/dev/null)
    if [[ -n "$hidden_procs" ]]; then
      found "HIDDEN PROCESS terdeteksi (ada di psscan tapi tidak di pslist):"
      echo "$hidden_procs" | sed 's/^/    PID: /'
      log_report "ADV_MEM_HIDDEN_PROC: $hidden_procs"
    else
      ok "Tidak ada proses tersembunyi ditemukan"
    fi

    # ── 2. DLL injection detection ─────────────────────────────────
    divider
    info "[2] DLL Injection Detection"
    echo -e "  ${DIM}Menjalankan windows.malfind (injected code detection):${NC}"
    local malfind_out
    malfind_out=$($VOL3_CMD -f "$target" windows.malfind 2>/dev/null)
    if [[ -n "$malfind_out" ]]; then
      found "Malfind menemukan anomali (potential injection):"
      echo "$malfind_out" | head -30 | sed 's/^/    /'
      local malfind_count
      malfind_count=$(echo "$malfind_out" | grep -c "^[0-9]" 2>/dev/null || echo "?")
      log_report "ADV_MEM_MALFIND: $malfind_count entries"
    else
      ok "Malfind: tidak ada injeksi terdeteksi"
    fi

    # Suspicious process names
    echo ""
    info "Proses mencurigakan (nama umum malware):"
    $VOL3_CMD -f "$target" windows.pslist 2>/dev/null | \
      grep -iE '(mimikatz|meterpreter|nc\.exe|ncat|psexec|cobalt|beacon|payload|rat\.|trojan|inject|shell\.exe)' | \
      sed 's/^/    /' | head -10
    [[ $? -ne 0 ]] && ok "Tidak ada proses mencurigakan ditemukan"

    # ── 3. Credential dumping — LSASS analysis ─────────────────────
    divider
    info "[3] Credential Dumping — LSASS Analysis"
    echo -e "  ${DIM}Mencari proses lsass.exe:${NC}"
    local lsass_pid
    lsass_pid=$($VOL3_CMD -f "$target" windows.pslist 2>/dev/null | \
      grep -i lsass | awk '{print $2}' | head -1)

    if [[ -n "$lsass_pid" ]]; then
      ok "lsass.exe ditemukan — PID: $lsass_pid"
      echo -e "  ${Y}[!]${NC} Untuk dump credentials:"
      echo -e "  ${DIM}  $VOL3_CMD -f $target windows.hashdump${NC}"
      echo -e "  ${DIM}  $VOL3_CMD -f $target windows.lsadump${NC}"
      echo -e "  ${DIM}  $VOL3_CMD -f $target windows.cachedump${NC}"

      # Jalankan hashdump
      echo ""
      info "Menjalankan windows.hashdump..."
      $VOL3_CMD -f "$target" windows.hashdump 2>/dev/null | head -20 | sed 's/^/    /'
      log_report "ADV_MEM_LSASS_PID: $lsass_pid"
    else
      ok "lsass.exe tidak ditemukan (kemungkinan bukan Windows memory)"
    fi

    # ── 4. Network connections dari memory ─────────────────────────
    divider
    info "[4] Network Connections dari Memory"
    $VOL3_CMD -f "$target" windows.netstat 2>/dev/null | head -25 | sed 's/^/    /'

    echo ""
    info "Suspicious outbound connections:"
    $VOL3_CMD -f "$target" windows.netstat 2>/dev/null | \
      grep -vE "(127\.0\.0\.1|0\.0\.0\.0|CLOSED|::1)" | \
      grep -iE "ESTABLISHED|LISTEN|CLOSE_WAIT" | \
      head -15 | sed 's/^/    /'

    # ── 5. Command history ─────────────────────────────────────────
    divider
    info "[5] Command History (cmdline, conhost, PowerShell)"
    echo -e "  ${DIM}CMD command lines:${NC}"
    $VOL3_CMD -f "$target" windows.cmdline 2>/dev/null | head -25 | sed 's/^/    /'

    echo ""
    echo -e "  ${DIM}PowerShell commands (via strings):${NC}"
    strings "$target" 2>/dev/null | \
      grep -iE '(powershell|invoke-expression|invoke-mimikatz|downloadstring|iex |encodedcommand|-enc |bypass|hidden|base64)' | \
      sort -u | head -15 | sed 's/^/    /'

    # ── 6. Loaded modules & rootkit hooks ──────────────────────────
    divider
    info "[6] Loaded Modules & Rootkit Detection"
    echo -e "  ${DIM}Kernel modules (drivers):${NC}"
    $VOL3_CMD -f "$target" windows.driverscan 2>/dev/null | head -20 | sed 's/^/    /'

    echo ""
    echo -e "  ${DIM}SSDT hooks (rootkit indicator):${NC}"
    $VOL3_CMD -f "$target" windows.ssdt 2>/dev/null | head -20 | sed 's/^/    /'
    local ssdt_hooks
    ssdt_hooks=$($VOL3_CMD -f "$target" windows.ssdt 2>/dev/null | grep -v "ntoskrnl\|win32k" | grep -v "^$" | wc -l)
    [[ "$ssdt_hooks" -gt 0 ]] && found "SSDT hook terdeteksi! $ssdt_hooks non-standard entries — kemungkinan rootkit"

    log_report "ADV_MEM_SSDT_HOOKS: $ssdt_hooks"
  fi

  # ── 7. Disk forensics: NTFS artifacts ──────────────────────────
  divider
  info "[7] Disk Forensics — NTFS / EXT4 Artifacts"

  # Cek Alternate Data Streams (ADS)
  info "Alternate Data Streams (ADS) detection:"
  if has tsk_recover; then
    echo -e "  ${DIM}Menggunakan Sleuth Kit untuk ADS scan:${NC}"
    if has fls; then
      fls -r -l "$target" 2>/dev/null | grep ":.*:" | head -20 | sed 's/^/    /'
      local ads_count
      ads_count=$(fls -r -l "$target" 2>/dev/null | grep -c ":.*:" 2>/dev/null || echo 0)
      ads_count=$(echo "$ads_count" | tr -d '[:space:]')
      [[ "$ads_count" =~ ^[0-9]+$ ]] || ads_count=0
      [[ "$ads_count" -gt 0 ]] && found "ADS ditemukan: $ads_count entries"
      log_report "ADV_DISK_ADS: $ads_count"
    fi
  else
    info "Sleuth Kit (fls/tsk_recover) tidak tersedia — sudo apt install sleuthkit"
    # fallback: strings untuk mendeteksi ADS pattern
    strings "$target" 2>/dev/null | grep -iE ':\$DATA|:Zone\.Identifier|:AFP_AfpInfo' | \
      head -5 | sed 's/^/    /'
  fi

  # ── 8. Timeline reconstruction ─────────────────────────────────
  divider
  info "[8] Timeline Reconstruction"
  if has fls && has mactime; then
    echo -e "  ${DIM}Membuat timeline dengan fls + mactime:${NC}"
    local timeline_file="$REPORT_DIR/timeline_$(basename "$target")_$$.csv"
    fls -r -m "/" "$target" 2>/dev/null > /tmp/fasfo_bodyfile_$$.txt
    mactime -b /tmp/fasfo_bodyfile_$$.txt 2>/dev/null | tail -30 | sed 's/^/    /'
    mactime -b /tmp/fasfo_bodyfile_$$.txt 2>/dev/null > "$timeline_file"
    ok "Timeline tersimpan: $timeline_file"
    rm -f /tmp/fasfo_bodyfile_$$.txt
    log_report "ADV_DISK_TIMELINE: $timeline_file"
  else
    info "mactime/fls tidak tersedia — sudo apt install sleuthkit"
    # Tampilkan stat dari file target sebagai pseudo-timeline
    echo -e "  ${DIM}File timestamps (stat):${NC}"
    stat "$target" 2>/dev/null | grep -E "(Access|Modify|Change|Birth)" | sed 's/^/    /'
  fi

  # ── 9. Slack space detection ────────────────────────────────────
  divider
  info "[9] Slack Space & Anti-Forensics Detection"
  info "Cek slack space (data di luar EOF):"
  python3 - "$target" << 'PYEOF' 2>/dev/null
import os, sys
try:
    path = sys.argv[1]
    size = os.path.getsize(path)
    # Cek apakah file size tidak align ke block size (512)
    block_size = 512
    slack = block_size - (size % block_size)
    if slack != block_size:
        print(f"  File size: {size} bytes — Slack space: {slack} bytes")
        with open(path, 'rb') as f:
            f.seek(size)
            # Baca sampai block boundary
            slack_data = f.read(slack)
            if slack_data and any(b != 0 for b in slack_data):
                print(f"  ◀ DATA di slack space: {slack_data[:64].hex()}")
            else:
                print(f"  Slack space kosong (zeroed)")
    else:
        print(f"  File size tepat pada block boundary")
except Exception as e:
    print(f"  Error: {e}")
PYEOF

  # Anti-forensics indicators
  info "Anti-forensics indicators:"
  if has strings; then
    strings "$target" 2>/dev/null | \
      grep -iE '(timestomp|shred|secure.delete|wipe|sdelete|eraser|bcwipe|evidence.eliminator|anti.forensic)' | \
      head -5 | sed 's/^/    /'
  fi

  # ── 10. Autopsy hint ───────────────────────────────────────────
  divider
  info "[10] Tool Suggestions untuk Analisis Lanjutan"
  echo -e "  ${Y}[!]${NC} Autopsy GUI:"
  echo -e "  ${DIM}    autopsy (buka browser ke http://localhost:9999/autopsy)${NC}"
  echo -e "  ${Y}[!]${NC} Sleuth Kit CLI:"
  echo -e "  ${DIM}    fls -r $target | grep -i flag${NC}"
  echo -e "  ${DIM}    icat $target <inode>    # ekstrak file dari inode${NC}"
  echo -e "  ${DIM}    tsk_recover -e $target /tmp/recovery/${NC}"
  echo -e "  ${Y}[!]${NC} Volatility3 plugins lanjutan:"
  echo -e "  ${DIM}    $VOL3_CMD -f $target windows.dumpfiles --virtaddr <addr>${NC}"
  echo -e "  ${DIM}    $VOL3_CMD -f $target windows.vadinfo --pid <pid>${NC}"
}

# ══════════════════════════════════════════════════════════════════
#  MODULE 3B — ADVANCED NETWORK FORENSICS
# ══════════════════════════════════════════════════════════════════
mod_advanced_network() {
  section "Advanced Network Forensics"
  local target="$1"

  if ! has tshark; then
    warn "tshark tidak ditemukan — sudo apt install tshark"
    return
  fi

  # ── 1. File reconstruction dari PCAP ────────────────────────────
  divider
  info "[1] Rekonstruksi File dari PCAP (HTTP, FTP, SMB)"

  local http_export_dir="$REPORT_DIR/pcap_http_$(basename "$target")_$$"
  mkdir -p "$http_export_dir"

  info "HTTP object extraction:"
  tshark -r "$target" --export-objects "http,$http_export_dir" 2>/dev/null
  local http_files
  http_files=$(find "$http_export_dir" -type f 2>/dev/null | wc -l)
  if [[ "$http_files" -gt 0 ]]; then
    found "HTTP objects extracted: $http_files file → $http_export_dir"
    find "$http_export_dir" -type f 2>/dev/null | while read -r hf; do
      local hf_flag
      hf_flag=$(strings "$hf" 2>/dev/null | grep -iE '(flag|CTF|HTB|picoCTF)\{[^}]+\}' | head -1)
      [[ -n "$hf_flag" ]] && found "FLAG di HTTP object $(basename "$hf"): $hf_flag"
    done
    log_report "ADV_NET_HTTP_FILES: $http_files"
  else
    ok "Tidak ada HTTP object untuk di-extract"
  fi

  # FTP data extraction
  divider
  info "FTP data reconstruction:"
  tshark -r "$target" -Y "ftp-data" -T fields -e ftp-data.command \
    -e ftp-data.setup-frame 2>/dev/null | head -10 | sed 's/^/    /'

  # SMB file extraction hint
  info "SMB/CIFS files (export manual):"
  local smb_count
  smb_count=$(tshark -r "$target" -Y "smb || smb2" -q -z io,phs 2>/dev/null | grep -c "smb" || echo 0)
  [[ "$smb_count" -gt 0 ]] && warn "SMB traffic terdeteksi — extract manual: tshark -r $target --export-objects smb,/tmp/smb_export"

  # ── 2. Manual protocol decoding ─────────────────────────────────
  divider
  info "[2] Manual Protocol Decoding (non-standard ports)"

  # Cek koneksi ke port tidak lazim
  echo -e "  ${DIM}Koneksi ke port tidak standar (bukan 80,443,53,22,21,25):${NC}"
  tshark -r "$target" -T fields -e ip.dst -e tcp.dstport -e udp.dstport 2>/dev/null | \
    awk '{
      port = ($2 != "") ? $2 : $3
      if (port != "" && port+0 != 80 && port+0 != 443 && port+0 != 53 &&
          port+0 != 22 && port+0 != 21 && port+0 != 25 && port+0 != 0)
        print $1, port
    }' | sort | uniq -c | sort -rn | head -15 | sed 's/^/    /'

  # Raw TCP stream extraction
  info "TCP stream extraction (stream 0-5):"
  for stream_id in 0 1 2 3 4 5; do
    local stream_data
    stream_data=$(tshark -r "$target" -q -z follow,tcp,ascii,$stream_id 2>/dev/null | \
      head -20 | grep -v "^=\|^$\|Follow\|Filter\|Node\|bytes")
    if [[ -n "$stream_data" ]]; then
      echo -e "  ${C}[Stream $stream_id]${NC}"
      echo "$stream_data" | head -8 | sed 's/^/    /'
      # flag scan in stream
      local stream_flag
      stream_flag=$(tshark -r "$target" -q -z follow,tcp,ascii,$stream_id 2>/dev/null | \
        grep -iE '(flag|CTF|HTB)\{[^}]+\}' | head -2)
      [[ -n "$stream_flag" ]] && found "FLAG di TCP stream $stream_id: $stream_flag"
    fi
  done

  # ── 3. Encrypted traffic analysis (TLS patterns, SNI) ──────────
  divider
  info "[3] TLS / Encrypted Traffic Analysis"

  echo -e "  ${DIM}TLS version distribution:${NC}"
  tshark -r "$target" -Y "tls" -T fields -e tls.record.version 2>/dev/null | \
    sort | uniq -c | sort -rn | \
    awk '{
      ver=$2+0
      name="unknown"
      if(ver==769) name="TLS 1.0 (DEPRECATED!)"
      else if(ver==770) name="TLS 1.1 (DEPRECATED!)"
      else if(ver==771) name="TLS 1.2"
      else if(ver==772) name="TLS 1.3"
      printf "    %-6s × 0x%04X (%s)\n", $1, ver, name
    }' | head -10

  echo ""
  info "SNI (Server Name Indication) — domain yang dikunjungi:"
  tshark -r "$target" -Y "tls.handshake.type == 1" \
    -T fields -e tls.handshake.extensions_server_name 2>/dev/null | \
    sort | uniq -c | sort -rn | head -20 | sed 's/^/    /'

  # Certificate info
  info "Certificate Subject CN:"
  tshark -r "$target" -Y "tls.handshake.certificate" \
    -T fields -e tls.handshake.certificate 2>/dev/null | head -5 | sed 's/^/    /'

  # ── 4. C2 traffic detection ─────────────────────────────────────
  divider
  info "[4] C2 (Command & Control) Traffic Detection"

  # Beacon interval detection (periodic connections)
  echo -e "  ${DIM}Koneksi paling sering (potential beacon/C2):${NC}"
  tshark -r "$target" -T fields -e ip.dst -e frame.time_relative 2>/dev/null | \
    awk '
    {
      ip=$1; t=$2+0
      if(ip && t>0) {
        if(last[ip]) {
          diff = t - last[ip]
          if(diff > 0 && diff < 3600) {
            sum[ip] += diff; cnt[ip]++
          }
        }
        last[ip] = t
      }
    }
    END {
      for(ip in cnt) {
        if(cnt[ip] >= 5) {
          avg = sum[ip]/cnt[ip]
          printf "  %-18s  %3d connections  avg_interval=%.1fs\n", ip, cnt[ip], avg
        }
      }
    }' | sort -k4 -n | head -10 | sed 's/^/  /'

  # Known C2 indicators in payload
  echo ""
  info "C2 keywords di payload:"
  tshark -r "$target" -T fields -e data.text 2>/dev/null | \
    grep -iE '(cmd=|command=|task=|exec=|upload|download|shell|whoami|ipconfig|systeminfo|getuid|getsystem|migrate|hashdump|rev_shell|meterpreter)' | \
    head -10 | sed 's/^/    /'

  # ── 5. DNS tunneling (enhanced) ─────────────────────────────────
  divider
  info "[5] DNS Tunneling Detection (Enhanced)"
  info "Mencari tool-spesifik DNS tunnel patterns:"

  local dns_queries
  dns_queries=$(tshark -r "$target" -Y "dns.flags.response == 0" \
    -T fields -e dns.qry.name 2>/dev/null | grep -v '^$')

  # iodine pattern: hex strings sebagai subdomain
  local iodine_pat
  iodine_pat=$(echo "$dns_queries" | grep -E '^[0-9a-fA-F]{20,}\.' | head -5)
  [[ -n "$iodine_pat" ]] && found "Possible iodine DNS tunnel (hex subdomains):"
  [[ -n "$iodine_pat" ]] && echo "$iodine_pat" | sed 's/^/    /'

  # dnscat2 pattern
  local dnscat_pat
  dnscat_pat=$(echo "$dns_queries" | grep -E '^\d+\.' | head -5)
  [[ -n "$dnscat_pat" ]] && found "Possible dnscat2 pattern (numeric subdomain prefix):"
  [[ -n "$dnscat_pat" ]] && echo "$dnscat_pat" | sed 's/^/    /'

  # Covert channel via large DNS responses
  info "DNS response sizes (covert channel indicator):"
  tshark -r "$target" -Y "dns.flags.response == 1" \
    -T fields -e frame.len -e dns.qry.name 2>/dev/null | \
    awk '{if($1+0 > 512) print "    LARGE("$1"bytes): "$2}' | head -10

  # ── 6. Data exfiltration via covert channels ────────────────────
  divider
  info "[6] Covert Channel Detection"

  # ICMP data exfiltration
  echo -e "  ${DIM}ICMP payload (potential exfiltration):${NC}"
  tshark -r "$target" -Y "icmp" -T fields -e data.text -e frame.len 2>/dev/null | \
    awk '{if($2+0 > 28) print "  ICMP payload_size="$2": "$1}' | head -10 | sed 's/^/  /'

  # DNS exfiltration reconstruction (data di subdomain)
  info "DNS exfil data reconstruction:"
  local b32_chunks
  b32_chunks=$(echo "$dns_queries" | \
    grep -oE '^[A-Z2-7]{8,}\.' | tr -d '.' | tr -d '\n' | head -c 500)
  if [[ -n "$b32_chunks" ]]; then
    local b32dec
    b32dec=$(python3 -c "
import base64, sys
try:
    data = sys.argv[1]
    # pad to multiple of 8
    pad = (8 - len(data)%8)%8
    decoded = base64.b32decode(data + '='*pad, casefold=True)
    print(decoded.decode('latin1','replace'))
except Exception as e:
    print('decode failed:', e)" "$b32_chunks" 2>/dev/null)
    [[ -n "$b32dec" ]] && found "DNS Base32 exfil decoded: ${b32dec:0:200}"
  fi

  # HTTP exfiltration in headers / cookies
  info "HTTP headers suspicious (data in cookie/header):"
  tshark -r "$target" -Y "http.request" -T fields \
    -e http.cookie -e http.user_agent -e http.x_forwarded_for 2>/dev/null | \
    grep -v "^$" | head -10 | sed 's/^/    /'

  # ── 7. Zeek/Bro hint & NetworkMiner ────────────────────────────
  divider
  info "[7] Tool Lanjutan — Zeek & NetworkMiner"
  if has zeek; then
    local zeek_dir="$REPORT_DIR/zeek_$(basename "$target")_$$"
    mkdir -p "$zeek_dir"
    zeek -r "$target" -C LogAscii::output_dir="$zeek_dir" 2>/dev/null &
    ok "Zeek berjalan di background → output: $zeek_dir"
  else
    warn "Zeek tidak tersedia — sudo apt install zeek"
    echo -e "  ${DIM}Alternatif: zeek -r $target${NC}"
  fi

  info "NetworkMiner (GUI):"
  echo -e "  ${DIM}sudo mono /opt/NetworkMiner/NetworkMiner.exe $target${NC}"
  echo -e "  ${DIM}Atau download: https://www.netresec.com/?page=NetworkMiner${NC}"

  log_report "ADV_NET_DONE: advanced network analysis completed"
}

# ══════════════════════════════════════════════════════════════════
#  MODULE 2B — ADVANCED STEGANOGRAPHY
# ══════════════════════════════════════════════════════════════════
mod_advanced_stego() {
  section "Advanced Steganography Analysis"
  local target="$1"
  local ftype
  ftype=$(file --brief "$target" 2>/dev/null | tr '[:upper:]' '[:lower:]')

  # ── 1. Multi-layer stego detection ──────────────────────────────
  divider
  info "[1] Multi-Layer Steganography Detection"
  info "Menjalankan zsteg deep scan (--all):"
  if has zsteg; then
    zsteg --all "$target" 2>/dev/null | head -40 | sed 's/^/    /'
    local zsteg_hits
    zsteg_hits=$(zsteg --all "$target" 2>/dev/null | grep -iE '(flag|CTF|HTB|picoCTF|{[^}]+})' | head -5)
    [[ -n "$zsteg_hits" ]] && found "zsteg deep scan hit: $zsteg_hits"
    log_report "ADV_STEGO_ZSTEG: ${zsteg_hits:0:200}"
  else
    warn "zsteg tidak tersedia — gem install zsteg"
  fi

  # ── 2. Statistical analysis (chi-square, entropy) ───────────────
  divider
  info "[2] Statistical Analysis — Chi-Square & Entropy"
  python3 - "$target" << 'PYEOF' 2>/dev/null
import sys, math, collections
try:
    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    # Entropy calculation
    if len(data) == 0:
        print("  Empty file"); sys.exit()
    freq = collections.Counter(data)
    total = len(data)
    entropy = -sum((c/total) * math.log2(c/total) for c in freq.values() if c > 0)
    print(f"  Entropy       : {entropy:.4f} bits/byte (max=8.0)")
    if entropy > 7.5:
        print("  ⚠ Entropy SANGAT TINGGI → kemungkinan enkripsi atau kompresi")
    elif entropy > 7.0:
        print("  ⚠ Entropy tinggi → mungkin ada data tersembunyi atau compressed")
    else:
        print("  Entropy normal")

    # LSB analysis (untuk image)
    # Cek distribusi LSB
    lsb_counts = [0, 0]
    for b in data[:8192]:  # sample 8KB
        lsb_counts[b & 1] += 1
    lsb_ratio = lsb_counts[1] / (lsb_counts[0] + lsb_counts[1] + 1e-9)
    print(f"  LSB ratio     : {lsb_ratio:.4f} (0.5 = random/hidden data)")
    if abs(lsb_ratio - 0.5) < 0.02:
        print("  ⚠ LSB ratio mendekati 0.5 → strong indicator steganography!")
    else:
        print("  LSB ratio normal")

    # Chi-square test (simplified)
    expected = total / 256
    chi_sq = sum((freq.get(i,0) - expected)**2 / expected for i in range(256))
    chi_norm = chi_sq / 255  # normalized
    print(f"  Chi-square    : {chi_sq:.2f} (normalized: {chi_norm:.3f})")
    if chi_norm < 1.5:
        print("  ⚠ Chi-square RENDAH → distribusi terlalu uniform → kemungkinan steganografi!")
    else:
        print("  Chi-square normal")

    # Byte frequency visualization (mini histogram)
    print("\n  Byte frequency histogram (ASCII range 32-126):")
    max_count = max(freq.get(i,0) for i in range(32,127))
    for i in range(32, 127, 8):
        avg = sum(freq.get(j,0) for j in range(i,min(i+8,127))) // 8
        bar = '█' * int(avg * 30 / (max_count+1))
        print(f"    {i:3d}-{i+7:3d}: {bar}")

except Exception as e:
    print(f"  Error: {e}")
PYEOF
  log_report "ADV_STEGO_STATS: done"

  # ── 3. stegsolve channel analysis (CLI simulation) ───────────────
  divider
  info "[3] Stegsolve Channel Analysis (CLI via Python)"
  if echo "$ftype" | grep -qiE "png|jpeg|bmp|gif|tiff"; then
    python3 - "$target" << 'PYEOF' 2>/dev/null
import sys
try:
    from PIL import Image
    img = Image.open(sys.argv[1]).convert('RGBA')
    w, h = img.size
    pixels = list(img.getdata())

    print(f"  Image size: {w}x{h} — {w*h} pixels")

    # Ekstrak data dari setiap channel dengan berbagai bit plane
    for channel_idx, channel_name in enumerate(['R','G','B','A']):
        for bit_plane in [0, 1, 2]:  # LSB, bit1, bit2
            bits = []
            for px in pixels[:8000]:  # sample
                bits.append((px[channel_idx] >> bit_plane) & 1)
            # Konversi bit ke bytes
            data = bytearray()
            for i in range(0, len(bits)-7, 8):
                byte = 0
                for b in range(8): byte |= bits[i+b] << b
                data.append(byte)
            try:
                text = data.decode('ascii','replace').replace('\x00','')
                # Cek apakah ada teks printable atau flag pattern
                printable = sum(1 for c in text if 32<=ord(c)<127)
                if printable > len(text)*0.7 and len(text) > 10:
                    flag = [i for i in range(len(text)-3)
                            if text[i:i+4].lower() in ('flag','ctf{','htb{','pico')]
                    marker = ' ◀ POSSIBLE FLAG!' if flag else ''
                    print(f"  [{channel_name} bit{bit_plane}]: {text[:60]!r}{marker}")
            except: pass

    # Alpha channel check
    if img.mode == 'RGBA':
        alpha_vals = [px[3] for px in pixels[:1000]]
        alpha_set = set(alpha_vals)
        if len(alpha_set) > 2:
            print(f"  Alpha channel: {len(alpha_set)} unique values — kemungkinan data tersembunyi!")

except ImportError:
    print("  PIL tidak tersedia — pip3 install Pillow")
except Exception as e:
    print(f"  Error: {e}")
PYEOF
  else
    info "File bukan gambar — skipping channel analysis"
  fi

  # ── 4. Audio steganography ──────────────────────────────────────
  divider
  info "[4] Audio Steganography Analysis"
  if echo "$ftype" | grep -qiE "audio|wave|mp3|flac|ogg|aiff"; then
    # Spectrogram hint
    info "File audio terdeteksi!"
    warn "Analisis spectrogram di Sonic Visualiser atau Audacity:"
    echo -e "  ${DIM}  sonic-visualiser $target${NC}"
    echo -e "  ${DIM}  audacity $target${NC}"

    # Ekstrak dengan ffmpeg
    if has ffmpeg; then
      info "ffmpeg audio metadata:"
      ffmpeg -i "$target" 2>&1 | grep -E "(Duration|Audio|Stream|bitrate|Hz|channel)" | sed 's/^/    /'

      # Frame extraction untuk video
      if echo "$ftype" | grep -qiE "video|mp4|avi|mkv|mov"; then
        info "Video frame extraction (untuk frame-based stego):"
        local frame_dir="$REPORT_DIR/frames_$(basename "$target")_$$"
        mkdir -p "$frame_dir"
        ffmpeg -i "$target" -vf "fps=1" "$frame_dir/frame_%04d.png" -hide_banner 2>/dev/null
        local nframes
        nframes=$(find "$frame_dir" -name "*.png" 2>/dev/null | wc -l)
        [[ "$nframes" -gt 0 ]] && ok "$nframes frames diekstrak → $frame_dir"
        log_report "ADV_STEGO_FRAMES: $nframes"
      fi

      # WAV LSB stego extraction
      if echo "$ftype" | grep -qiE "wave|wav"; then
        info "WAV LSB steganography extraction:"
        python3 - "$target" << 'PYEOF' 2>/dev/null
import sys, struct, wave
try:
    with wave.open(sys.argv[1], 'rb') as wf:
        frames = wf.readframes(wf.getnframes())
        n_channels = wf.getnchannels()
        sampwidth = wf.getsampwidth()
        framerate = wf.getframerate()
        print(f"  Channels: {n_channels}, Sample width: {sampwidth}, Rate: {framerate}Hz")
        print(f"  Total frames: {wf.getnframes()}")

        # LSB extraction (16-bit samples)
        if sampwidth == 2:
            samples = struct.unpack(f'<{len(frames)//2}h', frames)
            bits = [s & 1 for s in samples[:8192*8]]
            data = bytearray()
            for i in range(0, len(bits)-7, 8):
                byte = sum(bits[i+j] << j for j in range(8))
                data.append(byte)
            text = data.decode('ascii','replace').replace('\x00','')
            printable = sum(1 for c in text if 32<=ord(c)<127)
            if printable > len(text)*0.6 and len(text) > 8:
                flag = any(kw in text.lower() for kw in ['flag','ctf{','htb{'])
                print(f"  LSB data: {text[:80]!r}")
                if flag: print("  ◀ POSSIBLE FLAG IN WAV LSB!")
except Exception as e:
    print(f"  Error: {e}")
PYEOF
      fi
    fi

    # Steghide on audio
    if has steghide; then
      local sh_audio
      sh_audio=$(steghide extract -sf "$target" -p "" 2>&1)
      [[ "$sh_audio" == *"wrote"* ]] && found "Steghide audio extract berhasil!"
    fi
  else
    info "File bukan audio — skipping audio stego analysis"
    info "Jika file audio: fasfo audio.wav --Forensics --adv-stego"
  fi

  # ── 5. Frequency domain hiding ──────────────────────────────────
  divider
  info "[5] Frequency Domain Steganography (DCT/DWT hints)"
  if echo "$ftype" | grep -qiE "jpeg|jpg"; then
    python3 - "$target" << 'PYEOF' 2>/dev/null
import sys
try:
    from PIL import Image
    import numpy as np
    img = Image.open(sys.argv[1]).convert('L')
    arr = np.array(img, dtype=float)

    # Simple DCT analysis via numpy (no scipy needed)
    # Check for unusual quantization artifacts
    h, w = arr.shape
    block_diffs = []
    for y in range(0, h-8, 8):
        for x in range(0, w-8, 8):
            block = arr[y:y+8, x:x+8]
            block_diffs.append(float(np.std(block)))

    if block_diffs:
        avg_std = sum(block_diffs)/len(block_diffs)
        print(f"  Average block std deviation: {avg_std:.3f}")
        low_var = sum(1 for d in block_diffs if d < 2.0)
        ratio = low_var / len(block_diffs)
        print(f"  Low variance 8x8 blocks: {low_var}/{len(block_diffs)} ({ratio:.1%})")
        if ratio > 0.3:
            print("  ⚠ Banyak block dengan variance rendah → kemungkinan DCT steganography (jsteg/outguess)")
except ImportError:
    print("  numpy/PIL tidak tersedia — pip3 install numpy Pillow")
except Exception as e:
    print(f"  Error: {e}")
PYEOF
  fi

  # ── 6. Noise pattern analysis ──────────────────────────────────
  divider
  info "[6] Noise Pattern Analysis"
  python3 - "$target" << 'PYEOF' 2>/dev/null
import sys, collections
try:
    from PIL import Image
    img = Image.open(sys.argv[1]).convert('RGB')
    w, h = img.size
    if w < 4 or h < 4:
        print("  Image too small"); sys.exit()

    pixels = list(img.getdata())
    # Analisis noise pada LSB per channel
    for ch_idx, ch_name in enumerate(['R','G','B']):
        lsbs = [px[ch_idx] & 1 for px in pixels]
        # Count transitions (0→1 atau 1→0)
        transitions = sum(1 for i in range(1,len(lsbs)) if lsbs[i] != lsbs[i-1])
        total = len(lsbs)
        ratio = transitions / total
        expected = 0.5  # random noise
        deviation = abs(ratio - expected)
        indicator = ''
        if deviation < 0.05:
            indicator = ' ← LSB tampak ACAK (steganography indicator!)'
        elif deviation > 0.3:
            indicator = ' ← pattern tidak acak (natural image)'
        print(f"  {ch_name} LSB transition ratio: {ratio:.4f}{indicator}")

    # Cek visual artifact (banding)
    row_means = []
    for y in range(h):
        row = [pixels[y*w+x][0] for x in range(w)]
        row_means.append(sum(row)/w)
    mean_var = sum(abs(row_means[i]-row_means[i-1]) for i in range(1,len(row_means))) / len(row_means)
    print(f"  Row mean variation: {mean_var:.3f} ({'banding artifact terdeteksi!' if mean_var < 0.5 else 'normal'})")

except ImportError:
    print("  PIL tidak tersedia — pip3 install Pillow")
except Exception as e:
    print(f"  Error: {e}")
PYEOF

  # ── 7. Tool hints advanced ─────────────────────────────────────
  divider
  info "[7] Tool Advanced — Referensi Lanjutan"
  echo -e "  ${Y}[!]${NC} openstego  : java -jar openstego.jar"
  echo -e "  ${Y}[!]${NC} silenteye  : silenteye (GUI)"
  echo -e "  ${Y}[!]${NC} snow       : snow -C -m -p password $target"
  echo -e "  ${Y}[!]${NC} stegoveritas: stegoveritas $target"
  echo -e "  ${Y}[!]${NC} exiftool extended: exiftool -all= -tagsfromfile @ -all:all $target"
  echo -e "  ${DIM}  (Pillow/numpy analysis tersedia jika: pip3 install Pillow numpy)${NC}"

  log_report "ADV_STEGO_DONE: advanced stego analysis completed"
}

# ─────────────────────────────────────────
#  MODULE 6 — ARCHIVE ANALYSIS
# ─────────────────────────────────────────
mod_archive() {
  section "Archive Analysis"
  local target="$1"
  local arc_type=""
  local extract_dir="$REPORT_DIR/extracted_$(basename "$target")_$$"

  # ── Deteksi tipe archive ──────────────────
  divider
  info "Deteksi Format Archive"
  local magic
  magic=$(file --brief "$target" 2>/dev/null | tr '[:upper:]' '[:lower:]')
  local ext="${target##*.}"
  ext="${ext,,}"

  case "$magic" in
    *"zip"*)                  arc_type="zip"  ;;
    *"rar"*)                  arc_type="rar"  ;;
    *"7-zip"*)                arc_type="7z"   ;;
    *"gzip"*)                 arc_type="gz"   ;;
    *"bzip2"*)                arc_type="bz2"  ;;
    *"xz"*)                   arc_type="xz"   ;;
    *"posix tar"*|*"tar"*)    arc_type="tar"  ;;
    *)
      case "$ext" in
        zip)           arc_type="zip" ;;
        rar)           arc_type="rar" ;;
        7z)            arc_type="7z"  ;;
        gz|tgz)        arc_type="gz"  ;;
        bz2|tbz2)      arc_type="bz2" ;;
        xz)            arc_type="xz"  ;;
        tar)           arc_type="tar" ;;
        *)             arc_type="unknown" ;;
      esac
      ;;
  esac

  ok "Format terdeteksi: ${BOLD}${arc_type^^}${NC} ${DIM}($magic)${NC}"
  log_report "ARCHIVE_TYPE: $arc_type"

  if [[ "$arc_type" == "unknown" ]]; then
    warn "Format tidak dikenali sebagai archive"
    warn "Coba: fasfo $target --Forensics --file  untuk analisis file biasa"
    return
  fi

  # ── Metadata & Listing ─────────────────────
  divider
  info "Metadata & Isi Archive"

  local is_encrypted=false

  case "$arc_type" in
    zip)
      # listing detail
      if has unzip; then
        local zip_list
        zip_list=$(unzip -v "$target" 2>/dev/null)
        echo "$zip_list" | head -40 | sed 's/^/    /'

        # cek enkripsi
        if echo "$zip_list" | grep -qE "^\s+[0-9]+.*[Bb]"; then
          local enc_check
          enc_check=$(unzip -l "$target" 2>&1 | grep -i "unsupported\|encrypted\|password")
          [[ -n "$enc_check" ]] && is_encrypted=true
        fi
        # cara lain cek enkripsi zip
        if unzip -t "$target" 2>&1 | grep -qi "password\|encrypted\|incorrect"; then
          is_encrypted=true
        fi

        # ZIP comment (sering ada hint/flag di sini!)
        local zip_comment
        zip_comment=$(unzip -z "$target" 2>/dev/null | grep -v "^Archive:")
        if [[ -n "$zip_comment" ]]; then
          found "ZIP Comment ditemukan: $zip_comment"
          log_report "ZIP_COMMENT: $zip_comment"
        fi

        # Timestamp file-file di dalam zip
        divider
        info "Timestamp File dalam ZIP"
        unzip -v "$target" 2>/dev/null | awk 'NR>3 && NF>5 {printf "    %-12s %-8s %s\n", $5, $6, $NF}' | head -20

        # Extra field / anomali
        if has zipdetails; then
          divider
          info "ZIP Internal Detail (zipdetails)"
          zipdetails "$target" 2>/dev/null | grep -iE "(comment|extra|flag|method|encrypt)" | head -20 | sed 's/^/    /'
        fi
      fi
      ;;

    rar)
      if has unrar; then
        local rar_list
        rar_list=$(unrar l "$target" 2>/dev/null)
        echo "$rar_list" | head -40 | sed 's/^/    /'
        echo "$rar_list" | grep -qi "encrypted\|\*" && is_encrypted=true
      elif has rar; then
        rar l "$target" 2>/dev/null | head -40 | sed 's/^/    /'
      else
        warn "unrar tidak ditemukan — sudo apt install unrar"
      fi

      # RAR comment
      if has unrar; then
        local rar_comment
        rar_comment=$(unrar c "$target" 2>/dev/null | grep -v "^$\|^UNRAR\|^Copyright\|^Encrypted\|^Archive\|^--")
        [[ -n "$rar_comment" ]] && found "RAR Comment: $rar_comment" && log_report "RAR_COMMENT: $rar_comment"
      fi
      ;;

    7z)
      if has 7z; then
        local z7_list
        z7_list=$(7z l "$target" 2>/dev/null)
        echo "$z7_list" | head -40 | sed 's/^/    /'
        echo "$z7_list" | grep -qi "encrypted\|+" && is_encrypted=true
      else
        warn "7z tidak ditemukan — sudo apt install p7zip-full"
      fi
      ;;

    gz)
      if has tar; then
        tar -tzvf "$target" 2>/dev/null | head -30 | sed 's/^/    /' || \
        { info "Bukan tar.gz, mencoba gzip info..."; file "$target" | sed 's/^/    /'; }
      fi
      ;;

    bz2)
      has tar && tar -tjvf "$target" 2>/dev/null | head -30 | sed 's/^/    /'
      ;;

    xz)
      has tar && tar -tJvf "$target" 2>/dev/null | head -30 | sed 's/^/    /'
      ;;

    tar)
      has tar && tar -tvf "$target" 2>/dev/null | head -30 | sed 's/^/    /'
      ;;
  esac

  # ── ZIP Bomb Detection ─────────────────────
  divider
  info "Zip Bomb / Nested Archive Detection"
  if [[ "$arc_type" == "zip" ]] && has unzip; then
    local compressed_size ratio
    compressed_size=$(unzip -v "$target" 2>/dev/null | awk 'NR>3 && /[0-9]/{sum+=$1} END{print sum+0}')
    local actual_size
    actual_size=$(stat -c%s "$target" 2>/dev/null || echo 0)

    if [[ "$compressed_size" -gt 0 && "$actual_size" -gt 0 ]]; then
      ratio=$(( compressed_size / actual_size ))
      ok "Compressed: ${actual_size} bytes → Uncompressed: ${compressed_size} bytes (rasio ~${ratio}x)"
      if [[ "$ratio" -gt 100 ]]; then
        found "⚠️  PERINGATAN ZIP BOMB! Rasio kompresi sangat tinggi: ${ratio}x"
        log_report "ZIP_BOMB_RATIO: ${ratio}x"
      fi
    fi

    # deteksi nested zip (zip dalam zip)
    local nested
    nested=$(unzip -l "$target" 2>/dev/null | grep -iE "\.(zip|rar|7z|gz|tar)$")
    if [[ -n "$nested" ]]; then
      found "Nested archive terdeteksi di dalam:"
      echo "$nested" | sed 's/^/    /'
      log_report "NESTED_ARCHIVE: $nested"
    fi
  fi

  # ── String scan pada file archive ─────────
  divider
  info "String Scan (flag pattern di dalam archive)"
  if has strings; then
    local arc_strings
    arc_strings=$(strings "$target" 2>/dev/null | grep -iE '(flag|CTF|picoCTF|HTB|THM|DUCTF)\{[^}]+\}' | head -5)
    [[ -n "$arc_strings" ]] && found "Flag ditemukan di body archive: $arc_strings" && log_report "ARC_FLAG: $arc_strings"
    # juga cari filename yang mencurigakan di body
    local sus_names
    sus_names=$(strings "$target" 2>/dev/null | grep -iE '(password|passwd|secret|flag|key|hint|note)\.(txt|md|py|sh|png|jpg)' | head -5)
    [[ -n "$sus_names" ]] && found "Filename mencurigakan: $sus_names"
  fi

  # ── Extract (jika tidak terenkripsi) ───────
  divider
  if [[ "$is_encrypted" == true ]]; then
    warn "Archive ${BOLD}terenkripsi / password protected${NC} — melewati ekstraksi biasa"
    info "Melanjutkan ke bruteforce..."
    mod_archive_bruteforce "$target" "$arc_type"
  else
    info "Ekstraksi ke: $extract_dir"
    mkdir -p "$extract_dir"
    local extract_ok=false

    case "$arc_type" in
      zip) has unzip && unzip -q "$target" -d "$extract_dir" 2>/dev/null && extract_ok=true ;;
      rar) has unrar && unrar x -y "$target" "$extract_dir/" 2>/dev/null && extract_ok=true ;;
      7z)  has 7z    && 7z x "$target" -o"$extract_dir" -y 2>/dev/null   && extract_ok=true ;;
      gz)  has tar   && tar -xzf "$target" -C "$extract_dir" 2>/dev/null  && extract_ok=true ;;
      bz2) has tar   && tar -xjf "$target" -C "$extract_dir" 2>/dev/null  && extract_ok=true ;;
      xz)  has tar   && tar -xJf "$target" -C "$extract_dir" 2>/dev/null  && extract_ok=true ;;
      tar) has tar   && tar -xf  "$target" -C "$extract_dir" 2>/dev/null  && extract_ok=true ;;
    esac

    if [[ "$extract_ok" == true ]]; then
      ok "Ekstraksi berhasil → $extract_dir"

      # scan isi hasil ekstraksi
      divider
      info "Scan Isi Hasil Ekstraksi"
      local extracted_files
      extracted_files=$(find "$extract_dir" -type f 2>/dev/null)
      local file_count
      file_count=$(echo "$extracted_files" | grep -c . 2>/dev/null || echo 0)
      ok "Total file: $file_count"

      echo "$extracted_files" | head -30 | while read -r f; do
        local finfo
        finfo=$(file --brief "$f" 2>/dev/null)
        echo -e "    ${DIM}$(basename "$f")${NC} — $finfo"

        # scan flag di tiap file
        local inner_flag
        inner_flag=$(strings "$f" 2>/dev/null | grep -iE '(flag|CTF|picoCTF|HTB|THM)\{[^}]+\}' | head -2)
        [[ -n "$inner_flag" ]] && found "FLAG di $(basename "$f"): $inner_flag"

        # rekursi: jika ada nested archive, scan juga
        if echo "$finfo" | grep -qiE "zip|rar|7-zip|gzip|bzip|tar"; then
          warn "Nested archive: $(basename "$f") — gunakan: fasfo $f --Forensics --archive"
        fi
      done

      # cari file teks, baca isinya
      divider
      info "Isi File Teks (txt, md, flag, note, hint)"
      find "$extract_dir" -type f \( -name "*.txt" -o -name "*.md" \
        -o -name "*flag*" -o -name "*note*" -o -name "*hint*" \
        -o -name "*secret*" -o -name "*password*" \) 2>/dev/null | \
      while read -r tf; do
        echo -e "  ${W}>>> $(basename "$tf")${NC}"
        cat "$tf" 2>/dev/null | head -20 | sed 's/^/    /'
        # cek flag
        local tf_flag
        tf_flag=$(cat "$tf" 2>/dev/null | grep -iE '(flag|CTF)\{[^}]+\}')
        [[ -n "$tf_flag" ]] && found "$tf_flag" && log_report "EXTRACTED_FLAG: $tf_flag"
      done

    else
      warn "Ekstraksi gagal — cek apakah file corrupt atau butuh password"
    fi
  fi
}

# ── Bruteforce sub-function ────────────────
mod_archive_bruteforce() {
  local target="$1"
  local arc_type="$2"
  local found_pass=""

  section "Archive Crack — Smart Attack"

  # ── FASE 1: SMART PASSWORDS (selesai dalam detik) ──────────
  divider
  info "Fase 1: Smart Password Attack ${DIM}(CTF common passwords)${NC}"

  # Nama file tanpa ekstensi — sering jadi password di CTF
  local basename_noext
  basename_noext=$(basename "$target" | sed 's/\.[^.]*$//')

  # Daftar password CTF yang paling sering muncul
  local smart_list=(
    # kosong / trivial
    "" "password" "123456" "admin" "root" "toor" "1234" "12345"
    "123456789" "qwerty" "abc123" "letmein" "welcome"
    # nama file itu sendiri (CTF trick)
    "$basename_noext" "${basename_noext}123" "${basename_noext}!"
    "${basename_noext^^}" "${basename_noext,,}"
    # CTF classic
    "ctf" "flag" "secret" "hacker" "hackme" "h4ck3r"
    "password123" "p@ssw0rd" "pass123" "passw0rd"
    "redlimit" "REDLIMIT" "lks" "LKS" "lks2026" "LKS2026"
    "cyber" "security" "forensics" "stego" "crypto"
    "openme" "open" "unlock" "extract" "zip" "archive"
    "infected" "malware" "analysis" "reverse" "challenge"
    # tahun umum
    "2024" "2025" "2026" "2023"
    # keyboard walks
    "qwerty123" "asdf" "asdfgh" "zxcvbn" "1q2w3e"
  )

  local total=${#smart_list[@]}
  local tested=0

  for pw in "${smart_list[@]}"; do
    (( tested++ ))
    printf "\r  ${C}[*]${NC} Testing smart passwords... ${DIM}%d/%d${NC}" "$tested" "$total"

    case "$arc_type" in
      zip)
        if unzip -P "$pw" -t "$target" &>/dev/null 2>&1; then
          found_pass="$pw"; break
        fi ;;
      rar)
        if has unrar && unrar t -p"$pw" "$target" &>/dev/null 2>&1; then
          found_pass="$pw"; break
        fi ;;
      7z)
        if has 7z && 7z t -p"$pw" "$target" &>/dev/null 2>&1; then
          found_pass="$pw"; break
        fi ;;
    esac
  done
  echo "" # newline setelah progress

  if [[ -n "$found_pass" ]]; then
    found "Password ditemukan (Fase 1 — Smart): '${BOLD}${found_pass}${NC}'"
    log_report "PASSWORD_FOUND: $found_pass (smart attack)"
    _do_extract "$target" "$arc_type" "$found_pass"
    return
  fi
  warn "Fase 1 selesai — tidak ditemukan, lanjut ke Fase 2..."

  # ── FASE 2: ZIP2JOHN + JOHN (GPU-accelerated, jauh lebih cepat dari fcrackzip) ──
  divider
  info "Fase 2: john the ripper ${DIM}(zip2john → john --wordlist)${NC}"

  local wl="$WORDLIST"
  # cek env var custom
  [[ -z "$wl" && -n "$FASFO_WORDLIST" && -f "$FASFO_WORDLIST" ]] && wl="$FASFO_WORDLIST"

  if has john; then
    local hash_file="/tmp/fasfo_hash_$$"
    local john_ok=false

    case "$arc_type" in
      zip)
        if has zip2john; then
          zip2john "$target" > "$hash_file" 2>/dev/null && john_ok=true
        fi ;;
      rar)
        if has rar2john; then
          rar2john "$target" > "$hash_file" 2>/dev/null && john_ok=true
        fi ;;
      7z)
        # 7z2john biasanya ada di /usr/share/john/
        local z2j
        z2j=$(find /usr/share/john /usr/lib/john "$HOME/.local" -name "7z2john*" 2>/dev/null | head -1)
        [[ -z "$z2j" ]] && has 7z2john && z2j="7z2john"
        if [[ -n "$z2j" ]]; then
          "$z2j" "$target" > "$hash_file" 2>/dev/null && john_ok=true
        fi ;;
    esac

    if [[ "$john_ok" == true && -s "$hash_file" ]]; then
      ok "Hash diekstrak: $hash_file"

      if [[ -n "$wl" ]]; then
        info "Wordlist: $wl"
        info "Menjalankan john... ${DIM}(Ctrl+C untuk skip ke mode lain)${NC}"
        # jalankan john dengan progress, bisa di-Ctrl+C tanpa kill script
        john --wordlist="$wl" --fork=2 "$hash_file" 2>/dev/null &
        local john_pid=$!
        # tampilkan progress tiap 5 detik, max 5 menit
        local elapsed=0
        while kill -0 $john_pid 2>/dev/null && [[ $elapsed -lt 300 ]]; do
          sleep 5
          elapsed=$(( elapsed + 5 ))
          local cracked
          cracked=$(john --show "$hash_file" 2>/dev/null | grep -c ":")
          printf "\r  ${C}[*]${NC} John running... ${DIM}%ds elapsed, %d cracked${NC}" "$elapsed" "$cracked"
          [[ "$cracked" -gt 0 ]] && { kill $john_pid 2>/dev/null; break; }
        done
        echo ""
        kill $john_pid 2>/dev/null; wait $john_pid 2>/dev/null

        found_pass=$(john --show "$hash_file" 2>/dev/null | grep -oP "(?<=:)[^:]+(?=:)" | head -1)
      else
        # tanpa wordlist, coba john built-in incremental + single mode (cepat)
        info "rockyou tidak ada, pakai john single + incremental mode..."
        john --single "$hash_file" 2>/dev/null &
        local jp=$!; sleep 10; kill $jp 2>/dev/null; wait $jp 2>/dev/null
        found_pass=$(john --show "$hash_file" 2>/dev/null | grep -oP "(?<=:)[^:]+(?=:)" | head -1)
      fi

      rm -f "$hash_file"

      if [[ -n "$found_pass" ]]; then
        echo ""
        found "Password ditemukan (Fase 2 — John): '${BOLD}${found_pass}${NC}'"
        log_report "PASSWORD_FOUND: $found_pass (john)"
        _do_extract "$target" "$arc_type" "$found_pass"
        return
      fi
      warn "Fase 2 selesai — tidak ditemukan"
    else
      warn "Gagal ekstrak hash — john skip"
      rm -f "$hash_file"
    fi
  else
    warn "john tidak ditemukan — sudo apt install john"
  fi

  # ── FASE 3: fcrackzip dengan batas waktu (ZIP only) ────────
  if [[ "$arc_type" == "zip" ]] && has fcrackzip && [[ -n "$wl" ]]; then
    divider
    info "Fase 3: fcrackzip ${DIM}(timeout 60 detik)${NC}"
    warn "Hanya 60 detik — jika tidak ditemukan, password mungkin tidak ada di rockyou"

    local fcr_out
    # jalankan fcrackzip dengan timeout 60 detik
    fcr_out=$(timeout 60 fcrackzip -u -D -p "$wl" "$target" 2>/dev/null)
    found_pass=$(echo "$fcr_out" | grep -oP "(?<=PASSWORD FOUND\!\!\!\!: pw == ).*" | tr -d '[:space:]')

    if [[ -n "$found_pass" ]]; then
      found "Password ditemukan (Fase 3 — fcrackzip): '${BOLD}${found_pass}${NC}'"
      log_report "PASSWORD_FOUND: $found_pass (fcrackzip)"
      _do_extract "$target" "$arc_type" "$found_pass"
      return
    fi
    warn "Fase 3 timeout/tidak ditemukan"
  fi

  # ── TIDAK DITEMUKAN ─────────────────────────────────────────
  divider
  fail "Password tidak ditemukan di semua fase"
  echo ""
  echo -e "  ${Y}Saran selanjutnya:${NC}"
  echo -e "  ${DIM}1. Cek deskripsi soal — hint password sering tersembunyi di sana${NC}"
  echo -e "  ${DIM}2. Coba password dari filename: '${basename_noext}'${NC}"
  echo -e "  ${DIM}3. Coba wordlist custom: export FASFO_WORDLIST=/path/wordlist.txt${NC}"
  echo -e "  ${DIM}4. Gunakan hashcat (GPU): zip2john flag.zip > h.txt && hashcat -m 17200 h.txt rockyou.txt${NC}"
  echo -e "  ${DIM}5. Cek metadata file lain di soal yang sama — password sering hidden di sana${NC}"
}

# ── Helper: ekstrak setelah password ditemukan ─────────────
_do_extract() {
  local target="$1" arc_type="$2" pw="$3"
  local out_dir="$REPORT_DIR/cracked_$(basename "$target")_$$"
  mkdir -p "$out_dir"

  divider
  info "Mengekstrak dengan password yang ditemukan..."

  local ok_flag=false
  case "$arc_type" in
    zip) unzip -P "$pw" -q "$target" -d "$out_dir" 2>/dev/null && ok_flag=true ;;
    rar) unrar x -y -p"$pw" "$target" "$out_dir/" 2>/dev/null && ok_flag=true ;;
    7z)  7z x "$target" -o"$out_dir" -p"$pw" -y 2>/dev/null   && ok_flag=true ;;
  esac

  if [[ "$ok_flag" == true ]]; then
    ok "Ekstraksi berhasil → $out_dir"
    echo ""
    # tampilkan & scan semua file hasil ekstrak
    find "$out_dir" -type f | while read -r f; do
      local ftype
      ftype=$(file --brief "$f" 2>/dev/null)
      echo -e "  ${W}>>> $(basename "$f")${NC} ${DIM}($ftype)${NC}"
      # baca file teks langsung
      if echo "$ftype" | grep -qiE "text|ascii"; then
        cat "$f" 2>/dev/null | head -30 | sed 's/^/    /'
      fi
      # cari flag
      local ff
      ff=$(strings "$f" 2>/dev/null | grep -iE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT)\{[^}]+\}' | head -3)
      [[ -n "$ff" ]] && found "FLAG: $ff" && log_report "CRACKED_FLAG: $ff"
    done
  else
    warn "Ekstraksi gagal meski password benar — coba manual: unzip -P '$pw' $target"
  fi
}

# ─────────────────────────────────────────
#  MODULE 5 — OSINT
# ─────────────────────────────────────────
mod_osint() {
  section "OSINT & Metadata Recon"
  local target="$1"

  # Cek apakah input adalah URL atau domain
  if [[ "$target" =~ ^https?:// || "$target" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    divider
    info "Whois Lookup"
    has whois && run_tool "whois" whois "$target"

    divider
    info "DNS Lookup"
    has dig && run_tool "dig" dig ANY "$target" +noall +answer

    divider
    info "Wayback Machine Hint"
    warn "Cek: https://web.archive.org/web/*/$target"
    warn "Atau: curl 'http://archive.org/wayback/available?url=$target'"
  fi

  # Metadata dari file
  if [[ -f "$target" ]]; then
    divider
    info "Exiftool Full Metadata Dump"
    has exiftool && exiftool -a -u "$target" 2>/dev/null | sed 's/^/    /' | head -50

    divider
    info "GPS Koordinat (jika ada)"
    if has exiftool; then
      local gps
      gps=$(exiftool "$target" 2>/dev/null | grep -iE '(GPS|latitude|longitude|location)' )
      if [[ -n "$gps" ]]; then
        found "GPS data ditemukan:"
        echo "$gps" | sed 's/^/    /'
        log_report "GPS: $gps"
      else
        info "Tidak ada data GPS"
      fi
    fi

    divider
    info "Hidden/Unusual Metadata Fields"
    if has exiftool; then
      local hidden_meta
      hidden_meta=$(exiftool -a -u -G1 "$target" 2>/dev/null | \
        grep -iE '(comment|user comment|description|subject|tags|keywords|author|creator|flag|secret|note|hint)')
      [[ -n "$hidden_meta" ]] && found "Field tersembunyi:\n$hidden_meta"
    fi
  fi
}

# ─────────────────────────────────────────
#  MODULE 7 — LOG ANALYSIS
# ─────────────────────────────────────────
mod_log_analysis() {
  section "Log Analysis"
  local target="$1"
  local log_type="unknown"

  # ── Deteksi jenis log ──────────────────
  divider
  info "Deteksi Jenis Log"
  local fname
  fname=$(basename "$target" | tr '[:upper:]' '[:lower:]')
  local ftype
  ftype=$(file --brief "$target" 2>/dev/null | tr '[:upper:]' '[:lower:]')

  if [[ "$ftype" == *"data"* ]] && [[ "$fname" =~ ^(wtmp|btmp|lastlog|faillog)$ ]]; then
    log_type="binary_login"
  elif [[ "$fname" =~ auth\.log$|secure$ ]]; then
    log_type="auth"
  elif [[ "$fname" =~ access\.log$|access_log$ ]]; then
    log_type="http"
  elif [[ "$fname" =~ error\.log$|error_log$ ]]; then
    log_type="http_error"
  elif [[ "$fname" =~ syslog$|messages$|kern\.log$ ]]; then
    log_type="syslog"
  elif [[ "$fname" =~ \.journal$ ]] || [[ "$ftype" == *"journal"* ]]; then
    log_type="journal"
  else
    log_type="generic"
  fi

  ok "Jenis log terdeteksi: ${BOLD}${log_type^^}${NC}"
  log_report "LOG_TYPE: $log_type"

  # ── Binary login logs ──────────────────
  if [[ "$log_type" == "binary_login" ]]; then
    divider
    info "Login History (last/lastb/lastlog)"
    if [[ "$fname" == "wtmp" ]]; then
      has last    && run_tool "last"    last    -f "$target" | head -30
    elif [[ "$fname" == "btmp" ]]; then
      has lastb   && run_tool "lastb"   lastb   -f "$target" | head -30
    elif [[ "$fname" == "lastlog" ]]; then
      has lastlog && run_tool "lastlog" lastlog -f "$target" | head -30
    fi
    divider
    info "String scan (fallback)"
    strings "$target" 2>/dev/null | grep -vE '^(.{1,3}|.{200,})$' | head -20 | sed 's/^/    /'
    return
  fi

  # ── Systemd journal ────────────────────
  if [[ "$log_type" == "journal" ]]; then
    divider
    info "Systemd Journal"
    if has journalctl; then
      run_tool "journalctl" journalctl --file "$target" --no-pager -n 50
    else
      warn "journalctl tidak tersedia — fallback ke strings"
      strings "$target" 2>/dev/null | grep -E '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -30 | sed 's/^/    /'
    fi
    # tetap lanjut ke universal checks di bawah
  fi

  # ── Auth / SSH log ─────────────────────
  if [[ "$log_type" == "auth" ]]; then
    divider
    info "SSH Failed Logins"
    local failed_ssh
    failed_ssh=$(grep -iE "failed password|invalid user|authentication failure" "$target" 2>/dev/null)
    echo "$failed_ssh" | head -20 | sed 's/^/    /'
    local fail_count
    fail_count=$(echo "$failed_ssh" | grep -c . 2>/dev/null || echo 0)
    [[ "$fail_count" -gt 10 ]] && found "Brute force terdeteksi: $fail_count failed login attempts!" && \
      log_report "BRUTE_FORCE: $fail_count attempts"

    divider
    info "Top IP Penyerang"
    echo "$failed_ssh" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
      sort | uniq -c | sort -rn | head -10 | sed 's/^/    /'

    divider
    info "Successful SSH Logins"
    grep -iE "accepted (password|publickey)" "$target" 2>/dev/null | \
      head -15 | sed 's/^/    /'

    divider
    info "Sudo / Privilege Escalation"
    local sudo_log
    sudo_log=$(grep -iE "sudo|su\[|COMMAND=" "$target" 2>/dev/null)
    echo "$sudo_log" | head -15 | sed 's/^/    /'
    local sus_sudo
    sus_sudo=$(echo "$sudo_log" | grep -iE "(bash|sh|python|nc|wget|curl|chmod|passwd|/bin/)" 2>/dev/null)
    [[ -n "$sus_sudo" ]] && found "Sudo mencurigakan ditemukan:\n$sus_sudo" && \
      log_report "SUS_SUDO: $sus_sudo"

    divider
    info "User Baru / Akun Dibuat"
    grep -iE "useradd|adduser|new user|new group" "$target" 2>/dev/null | head -10 | sed 's/^/    /'

    divider
    info "PAM / Session Events"
    grep -iE "session opened|session closed|pam_unix" "$target" 2>/dev/null | head -15 | sed 's/^/    /'
  fi

  # ── HTTP access log ────────────────────
  if [[ "$log_type" == "http" || "$log_type" == "http_error" ]]; then
    divider
    info "HTTP Status Code Summary"
    awk '{print $9}' "$target" 2>/dev/null | grep -E '^[0-9]{3}$' | \
      sort | uniq -c | sort -rn | head -10 | \
      awk '{printf "    %-6s requests → HTTP %s\n", $1, $2}'

    divider
    info "Top 10 IP Address"
    awk '{print $1}' "$target" 2>/dev/null | sort | uniq -c | sort -rn | head -10 | sed 's/^/    /'

    divider
    info "Request Mencurigakan (SQLi, LFI, RCE, XSS, Path Traversal)"
    local sus_req
    sus_req=$(grep -iE "(union.*select|'.*'--|<script|onerror=|../|etc/passwd|/proc/self|\
cmd=|exec\(|system\(|base64_decode|eval\(|%2e%2e|%00|%0a|/wp-admin|/phpmyadmin|\
\.php\?.*=http|shell_exec|passthru|wget |curl )" "$target" 2>/dev/null)
    if [[ -n "$sus_req" ]]; then
      found "Request mencurigakan ditemukan ($(echo "$sus_req" | wc -l) baris):"
      echo "$sus_req" | head -20 | sed 's/^/    /'
      log_report "SUS_HTTP: $(echo "$sus_req" | wc -l) suspicious requests"
    else
      ok "Tidak ada request mencurigakan yang ditemukan"
    fi

    divider
    info "User-Agent Mencurigakan / Scanner"
    awk -F'"' 'NF>=6{print $6}' "$target" 2>/dev/null | sort | uniq -c | sort -rn | head -15 | sed 's/^/    /'
    local sus_ua
    sus_ua=$(awk -F'"' 'NF>=6{print $6}' "$target" 2>/dev/null | \
      grep -iE "(nikto|sqlmap|nmap|masscan|zgrab|python-requests|go-http|curl|wget|nuclei|dirbuster|gobuster|hydra)" 2>/dev/null | sort -u)
    [[ -n "$sus_ua" ]] && found "Scanner/tool terdeteksi di User-Agent:\n$sus_ua"

    divider
    info "POST / Upload Requests"
    grep -iE "\"POST|\"PUT" "$target" 2>/dev/null | head -15 | sed 's/^/    /'

    divider
    info "404 / 403 Enumeration (path bruteforce)"
    local enum_count
    enum_count=$(awk '$9=="404"||$9=="403"{print $7}' "$target" 2>/dev/null | wc -l)
    ok "Total 404/403: $enum_count request"
    if [[ "$enum_count" -gt 50 ]]; then
      found "Kemungkinan directory/path enumeration terdeteksi ($enum_count requests)"
      awk '$9=="404"{print $7}' "$target" 2>/dev/null | sort | uniq -c | sort -rn | head -10 | sed 's/^/    /'
    fi

    divider
    info "Flag Pattern di URL / Request"
    local url_flag
    url_flag=$(grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT)\{[^}]+\}' "$target" 2>/dev/null)
    [[ -n "$url_flag" ]] && found "FLAG ditemukan di HTTP log: $url_flag" && \
      log_report "HTTP_FLAG: $url_flag"
  fi

  # ── Syslog ─────────────────────────────
  if [[ "$log_type" == "syslog" ]]; then
    divider
    info "Service Crashes / Errors Kritis"
    grep -iE "(error|failed|crash|killed|segfault|out of memory|oom-killer|panic)" "$target" 2>/dev/null | \
      head -20 | sed 's/^/    /'

    divider
    info "Cron Jobs yang Dijalankan"
    grep -iE "CRON|crontab" "$target" 2>/dev/null | head -15 | sed 's/^/    /'

    divider
    info "Kernel / Hardware Events"
    grep -iE "kernel:|kerne|usb|device|mount|umount|iptables|firewall" "$target" 2>/dev/null | \
      head -15 | sed 's/^/    /'

    divider
    info "Network / Firewall Events"
    grep -iE "iptables|firewall|blocked|dropped|UFW|nftables|conntrack" "$target" 2>/dev/null | \
      head -15 | sed 's/^/    /'
  fi

  # ══════════════════════════════════════════════════════
  #  AWK / GREP / SORT|UNIQ-C ENGINE
  #  Sub-modul khusus per log type — parsing kolom presisi
  # ══════════════════════════════════════════════════════

  # ── AWK+GREP+SORT Engine: AUTH log ────────────────────
  if [[ "$log_type" == "auth" ]]; then
    divider
    info "═══ AWK/GREP/SORT Engine — AUTH ═══"

    # [awk] Ekstrak kolom: tanggal jam host service user
    divider
    info "[awk] Distribusi Service yang Log (kolom 5)"
    awk '{print $5}' "$target" 2>/dev/null | \
      grep -v '^$' | \
      sed 's/\[.*\]//' | \
      sort | uniq -c | sort -rn | head -15 | \
      awk '{printf "    %-6s × %s\n", $1, $2}' | sed 's/^/  /'
    log_report "AWK_AUTH_SERVICES: $(awk '{print $5}' "$target" 2>/dev/null | sed 's/\[.*\]//' | sort | uniq -c | sort -rn | head -5 | tr '\n' '|')"

    divider
    info "[grep|sort|uniq -c] Frekuensi Username di Failed Login"
    grep -iE "invalid user|failed password" "$target" 2>/dev/null | \
      grep -oP "(?<=user |invalid user )\S+" | \
      sort | uniq -c | sort -rn | head -15 | \
      awk '{printf "    %-6s × user: %s\n", $1, $2}' | sed 's/^/  /'
    log_report "AWK_AUTH_USERS: $(grep -iE 'invalid user|failed password' "$target" 2>/dev/null | grep -oP '(?<=user |invalid user )\S+' | sort | uniq -c | sort -rn | head -5 | tr '\n' '|')"

    divider
    info "[grep|sort|uniq -c] Top IP Sumber Koneksi (semua, termasuk sukses)"
    grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' "$target" 2>/dev/null | \
      sort | uniq -c | sort -rn | head -15 | \
      awk '{printf "    %-6s × %s\n", $1, $2}' | sed 's/^/  /'

    divider
    info "[awk] Distribusi Event per Jam (kolom 3 = timestamp HH:MM:SS)"
    awk '{print $3}' "$target" 2>/dev/null | \
      grep -oE '^[0-9]{2}' | \
      sort | uniq -c | sort -rn | head -10 | \
      awk '{printf "    Jam %02d:00-%02d:59 → %4d events\n", $2, $2, $1}' | sed 's/^/  /'
    log_report "AWK_AUTH_HOURLY: done"

    divider
    info "[awk] Distribusi Event per Tanggal (kolom 1-2)"
    awk '{print $1, $2}' "$target" 2>/dev/null | \
      grep -v '^$' | \
      sort | uniq -c | sort -rn | head -10 | \
      awk '{printf "    %-6s × %s %s\n", $1, $2, $3}' | sed 's/^/  /'

    divider
    info "[grep] Filter: Baris dengan Port yang Berbeda-beda (port scanning?)"
    local port_scan
    port_scan=$(grep -oP "port \K[0-9]+" "$target" 2>/dev/null | \
      sort -n | uniq -c | sort -rn | head -10)
    if [[ -n "$port_scan" ]]; then
      echo "$port_scan" | awk '{printf "    %-6s × port %s\n", $1, $2}' | sed 's/^/  /'
      local uniq_ports
      uniq_ports=$(grep -oP "port \K[0-9]+" "$target" 2>/dev/null | sort -u | wc -l)
      [[ "$uniq_ports" -gt 5 ]] && \
        found "Port scanning terdeteksi: $uniq_ports port unik dalam log auth" && \
        log_report "AWK_PORT_SCAN: $uniq_ports unique ports"
    fi

    divider
    info "[awk] Ringkasan Aksi: Accepted vs Failed vs Invalid"
    grep -oiE "(Accepted|Failed|Invalid|Disconnected|Connection closed|session opened|session closed)" \
      "$target" 2>/dev/null | \
      sort | uniq -c | sort -rn | \
      awk '{printf "    %-6s × %s\n", $1, $2}' | sed 's/^/  /'
  fi

  # ── AWK+GREP+SORT Engine: HTTP access log ─────────────
  if [[ "$log_type" == "http" ]]; then
    divider
    info "═══ AWK/GREP/SORT Engine — HTTP ═══"

    # Format Combined Log: IP - - [timestamp] "METHOD URI HTTP/x.x" STATUS BYTES "referer" "ua"
    divider
    info "[awk col 7] Top URI yang Paling Banyak Diakses"
    awk '{print $7}' "$target" 2>/dev/null | \
      grep -v '^$' | \
      sort | uniq -c | sort -rn | head -20 | \
      awk '{printf "    %-6s × %s\n", $1, $2}' | sed 's/^/  /'
    log_report "AWK_HTTP_TOP_URI: $(awk '{print $7}' "$target" 2>/dev/null | sort | uniq -c | sort -rn | head -5 | tr '\n' '|')"

    divider
    info "[awk col 6] Top HTTP Method (GET/POST/PUT/DELETE dll)"
    awk '{gsub(/"/, "", $6); print $6}' "$target" 2>/dev/null | \
      grep -E '^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)$' | \
      sort | uniq -c | sort -rn | \
      awk '{printf "    %-6s × %s\n", $1, $2}' | sed 's/^/  /'
    log_report "AWK_HTTP_METHODS: $(awk '{gsub(/"/, "", $6); print $6}' "$target" 2>/dev/null | grep -E '^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)$' | sort | uniq -c | sort -rn | tr '\n' '|')"

    divider
    info "[awk col 9] Distribusi HTTP Status Code"
    awk '{print $9}' "$target" 2>/dev/null | \
      grep -E '^[0-9]{3}$' | \
      sort | uniq -c | sort -rn | \
      awk '{
        code=$2+0
        if(code>=500) label="[SERVER ERROR]"
        else if(code>=400) label="[CLIENT ERROR]"
        else if(code>=300) label="[REDIRECT]"
        else if(code>=200) label="[SUCCESS]"
        else label=""
        printf "    %-6s × HTTP %s %s\n", $1, $2, label
      }' | sed 's/^/  /'

    divider
    info "[awk col 10] Distribusi Response Size (bytes)"
    awk '$10~/^[0-9]+$/{print $10+0}' "$target" 2>/dev/null | \
      sort -n | \
      awk '
        BEGIN{min=999999999; max=0; sum=0; cnt=0}
        {
          if($1<min) min=$1
          if($1>max) max=$1
          sum+=$1; cnt++
        }
        END{
          if(cnt>0)
            printf "    Min: %d B  |  Max: %d B  |  Avg: %d B  |  Total: %d req\n",
              min, max, sum/cnt, cnt
        }' | sed 's/^/  /'

    divider
    info "[grep|awk] Request 5xx — Server Error (perlu dicermati)"
    grep -E '" 5[0-9]{2} ' "$target" 2>/dev/null | \
      awk '{print $9, $7}' | \
      sort | uniq -c | sort -rn | head -10 | \
      awk '{printf "    %-6s × HTTP %s → %s\n", $1, $2, $3}' | sed 's/^/  /'

    divider
    info "[grep|sort|uniq -c] Top Referer (sumber traffic)"
    awk -F'"' 'NF>=8{print $8}' "$target" 2>/dev/null | \
      grep -v '^-$' | grep -v '^$' | \
      sort | uniq -c | sort -rn | head -10 | \
      awk '{printf "    %-6s × %s\n", $1, $2}' | sed 's/^/  /'

    divider
    info "[awk] Request per Jam (traffic timeline)"
    awk -F'[/: ]' '{
      # kolom timestamp: [11/Apr/2024:08:12:34
      for(i=1;i<=NF;i++){
        if($i~/^[0-9]{2}$/ && $(i+1)~/^[0-9]{2}$/ && $(i+2)~/^[0-9]{2}$/){
          print $i; break
        }
      }
    }' "$target" 2>/dev/null | \
      grep -E '^[0-9]{2}$' | \
      sort | uniq -c | sort -k2 -n | \
      awk '{
        bar=""
        n=int($1/5)
        for(i=0;i<n && i<40;i++) bar=bar"█"
        printf "    %02d:xx  [%-40s] %d\n", $2, bar, $1
      }' | sed 's/^/  /'

    divider
    info "[grep|sort|uniq -c] URI dengan Query String Mencurigakan"
    awk '{print $7}' "$target" 2>/dev/null | \
      grep -iE '(\?.*=|%27|%3c|%3e|\.\.\/|%2e%2e|union|select|exec|eval|base64|cmd=|shell)' | \
      sort | uniq -c | sort -rn | head -15 | \
      awk '{printf "    %-6s × %s\n", $1, $2}' | sed 's/^/  /'
    log_report "AWK_HTTP_SUS_URI: $(awk '{print $7}' "$target" 2>/dev/null | grep -iE '(\?.*=|%27|%3c|union|select|exec|eval|base64|cmd=)' | wc -l) suspicious URIs"
  fi

  # ── AWK+GREP+SORT Engine: SYSLOG ──────────────────────
  if [[ "$log_type" == "syslog" ]]; then
    divider
    info "═══ AWK/GREP/SORT Engine — SYSLOG ═══"

    divider
    info "[awk col 5] Top Process/Service yang Paling Banyak Log"
    awk '{print $5}' "$target" 2>/dev/null | \
      sed 's/\[.*\]//; s/:$//' | \
      grep -v '^$' | \
      sort | uniq -c | sort -rn | head -15 | \
      awk '{printf "    %-6s × %s\n", $1, $2}' | sed 's/^/  /'
    log_report "AWK_SYSLOG_PROCS: $(awk '{print $5}' "$target" 2>/dev/null | sed 's/\[.*\]//' | sort | uniq -c | sort -rn | head -5 | tr '\n' '|')"

    divider
    info "[grep|sort|uniq -c] Level Severity (error/warn/info/debug/crit)"
    grep -oiE '\b(emergency|alert|critical|crit|error|err|warning|warn|notice|info|debug)\b' \
      "$target" 2>/dev/null | \
      tr '[:upper:]' '[:lower:]' | \
      sort | uniq -c | sort -rn | \
      awk '{printf "    %-6s × %-10s\n", $1, $2}' | sed 's/^/  /'

    divider
    info "[awk] Event Timeline per Jam"
    awk '{print $3}' "$target" 2>/dev/null | \
      grep -oE '^[0-9]{2}' | \
      sort | uniq -c | sort -k2 -n | \
      awk '{
        bar=""
        n=int($1/3)
        for(i=0;i<n && i<40;i++) bar=bar"▪"
        printf "    %02d:xx  [%-40s] %d\n", $2, bar, $1
      }' | sed 's/^/  /'

    divider
    info "[grep|sort|uniq -c] Hostname/Node yang Muncul"
    awk '{print $4}' "$target" 2>/dev/null | \
      grep -v '^$' | grep -vE '^[0-9]{2}:[0-9]{2}' | \
      sort | uniq -c | sort -rn | head -10 | \
      awk '{printf "    %-6s × %s\n", $1, $2}' | sed 's/^/  /'

    divider
    info "[grep] Anomali: Baris dengan PID tidak normal (>99999)"
    grep -oP '\[\K[0-9]{6,}\]' "$target" 2>/dev/null | \
      sort -u | head -10 | \
      while read -r pid; do
        cnt=$(grep -c "\[$pid\]" "$target" 2>/dev/null || echo 0)
        echo "    PID $pid → $cnt baris"
      done | sed 's/^/  /'
  fi

  # ── AWK+GREP+SORT Engine: GENERIC log ─────────────────
  if [[ "$log_type" == "generic" ]]; then
    divider
    info "═══ AWK/GREP/SORT Engine — GENERIC ═══"

    divider
    info "[awk col 1] Frekuensi Token Pertama (field 1)"
    awk '{print $1}' "$target" 2>/dev/null | \
      grep -v '^$' | sort | uniq -c | sort -rn | head -15 | \
      awk '{printf "    %-6s × %s\n", $1, $2}' | sed 's/^/  /'

    divider
    info "[grep|sort|uniq -c] Kata Kunci Error/Warning/Info"
    grep -oiE '\b(ERROR|WARN|WARNING|FAIL|FAILED|CRITICAL|FATAL|INFO|DEBUG|EXCEPTION|TRACEBACK|DENIED|BLOCKED|ATTACK)\b' \
      "$target" 2>/dev/null | \
      tr '[:upper:]' '[:lower:]' | \
      sort | uniq -c | sort -rn | \
      awk '{printf "    %-6s × %-12s\n", $1, $2}' | sed 's/^/  /'
    log_report "AWK_GENERIC_LEVELS: $(grep -oiE '\b(ERROR|WARN|FAIL|CRITICAL|FATAL|INFO|DEBUG)\b' "$target" 2>/dev/null | tr '[:upper:]' '[:lower:]' | sort | uniq -c | sort -rn | head -5 | tr '\n' '|')"

    divider
    info "[awk] Panjang Baris — distribusi (deteksi baris anomali panjang)"
    awk '{print length($0)}' "$target" 2>/dev/null | \
      sort -n | \
      awk '
        BEGIN{min=99999;max=0;sum=0;cnt=0;over=0}
        {
          if($1<min) min=$1; if($1>max) max=$1
          sum+=$1; cnt++
          if($1>500) over++
        }
        END{
          if(cnt>0)
            printf "    Min: %d  |  Max: %d  |  Avg: %d  |  >500 chars: %d baris\n",
              min, max, sum/cnt, over
        }' | sed 's/^/  /'
  fi

  # ─────────────────────────────────────────
  # UNIVERSAL CHECKS (berlaku untuk semua jenis log)
  # ─────────────────────────────────────────

  divider
  info "═══ Universal Checks ═══"

  # ── AWK+GREP+SORT Universal: semua log type ───────────
  divider
  info "[grep|sort|uniq -c] Flag Pattern Scan (semua format CTF)"

  local log_flag log_flag_bracket any_flag_found=false

  # ── Format 1: PREFIX{...} — kurung kurawal standar ──────
  log_flag=$(grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC)\{[^}]+\}' "$target" 2>/dev/null)
  if [[ -n "$log_flag" ]]; then
    found "FLAG DITEMUKAN (format kurung kurawal):"
    echo "$log_flag" | sort | uniq -c | sort -rn | \
      awk '{printf "    %-6s × %s\n", $1, $2}' | sed 's/^/  /'
    log_report "LOG_FLAG: $log_flag"
    any_flag_found=true
  fi

  # ── Format 2: PREFIX[...] — kurung siku (CTF log challenge) ──
  # Contoh: /CTF[l0g/4n4lys1s/t1m3l1n3]  atau  CTF[flag_value]
  log_flag_bracket=$(grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC)\[[^\]]+\]' "$target" 2>/dev/null)
  if [[ -n "$log_flag_bracket" ]]; then
    found "FLAG DITEMUKAN (format kurung siku [ ]):"
    echo "$log_flag_bracket" | sort | uniq -c | sort -rn | \
      awk '{printf "    %-6s × %s\n", $1, $2}' | sed 's/^/  /'
    log_report "LOG_FLAG_BRACKET: $log_flag_bracket"
    any_flag_found=true
    # Ekstrak isi dalam bracket dan coba decode
    local bracket_inner
    bracket_inner=$(echo "$log_flag_bracket" | grep -oP '(?<=\[)[^\]]+' | sort -u)
    if [[ -n "$bracket_inner" ]]; then
      echo -e "\n  ${C}[*]${NC} Mencoba decode isi flag bracket:"
      echo "$bracket_inner" | while IFS= read -r bi; do
        decode_string "$bi" true
      done
    fi
  fi

  # ── Format 3: PREFIX[...] di dalam URI/path HTTP log ─────
  # Menangkap pola: /path/CTF[value] atau GET /CTF[...] di access log
  local uri_bracket_flag
  uri_bracket_flag=$(grep -oiE '/[A-Za-z0-9/_-]*[Cc][Tt][Ff]\[[^\] "]+\]' "$target" 2>/dev/null | \
    grep -oiE '[Cc][Tt][Ff]\[[^\]]+\]')
  if [[ -n "$uri_bracket_flag" ]]; then
    found "FLAG di URI/path HTTP (bracket siku):"
    echo "$uri_bracket_flag" | sort | uniq -c | sort -rn | \
      awk '{printf "    %-6s × %s\n", $1, $2}' | sed 's/^/  /'
    log_report "LOG_FLAG_URI_BRACKET: $uri_bracket_flag"
    any_flag_found=true
  fi

  # ── Format 4: Reversed flag }...{PREFIX ─────────────────
  if [[ "$any_flag_found" == false ]]; then
    local rev_log_flag
    rev_log_flag=$(grep -oiE '\}[A-Za-z0-9_!@#$%^&*-]{3,}\{[A-Za-z0-9]{2,10}' "$target" 2>/dev/null)
    if [[ -n "$rev_log_flag" ]]; then
      found "REVERSED FLAG ditemukan — decode:"
      echo "$rev_log_flag" | sort -u | while IFS= read -r rf; do
        decode_string "$rf"
      done
      log_report "LOG_FLAG_REV: $rev_log_flag"
      any_flag_found=true
    fi
  fi

  if [[ "$any_flag_found" == false ]]; then
    ok "Tidak ada flag pattern eksplisit yang ditemukan"
  fi

  divider
  info "[grep|sort|uniq -c] Keyword Sensitif (password/secret/token/key/hint)"
  local keywords
  keywords=$(grep -iE '\b(password|passwd|secret|token|apikey|api_key|flag|hint|credential|auth_token|private_key)\s*[=:]\s*\S+' \
    "$target" 2>/dev/null)
  if [[ -n "$keywords" ]]; then
    found "Keyword sensitif ditemukan:"
    echo "$keywords" | \
      grep -oiE '\b(password|passwd|secret|token|apikey|api_key|flag|hint|credential|auth_token|private_key)\s*[=:]\s*\S+' | \
      sort | uniq -c | sort -rn | head -15 | \
      awk '{printf "    %-6s × %s\n", $1, $2}' | sed 's/^/  /'
    log_report "SENSITIVE_KEYWORDS: $(echo "$keywords" | wc -l) hits"
  fi

  divider
  info "[grep|sort|uniq -c] IP Address — Frekuensi Kemunculan"
  local all_ips
  all_ips=$(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$target" 2>/dev/null)
  if [[ -n "$all_ips" ]]; then
    # Tabel: semua IP dengan frekuensi, tandai internal vs publik
    echo "$all_ips" | sort | uniq -c | sort -rn | head -20 | \
      awk '{
        tag=""
        if($2~/^(127\.|0\.0\.|255\.)/) tag="[LOOPBACK]"
        else if($2~/^(10\.|192\.168\.)/) tag="[PRIVATE]"
        else if($2~/^172\.(1[6-9]|2[0-9]|3[01])\./) tag="[PRIVATE]"
        else tag="[PUBLIC]"
        printf "    %-6s × %-18s %s\n", $1, $2, tag
      }' | sed 's/^/  /'
    local pub_ip_count
    pub_ip_count=$(echo "$all_ips" | \
      grep -vE '^(127\.|0\.0\.|255\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' | \
      sort -u | wc -l)
    ok "Total IP publik unik: $pub_ip_count"
    log_report "AWK_IP_FREQ: $(echo "$all_ips" | sort | uniq -c | sort -rn | head -5 | tr '\n' '|')"
  else
    ok "Tidak ada IP address yang ditemukan"
  fi

  divider
  info "[grep|sort|uniq -c] Domain / Hostname yang Muncul"
  grep -oiE '([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}' "$target" 2>/dev/null | \
    grep -vE '^[0-9.]+$' | \
    grep -vE '\.(log|txt|conf|sh|py|php|html|jpg|png|css|js)$' | \
    sort | uniq -c | sort -rn | head -15 | \
    awk '{printf "    %-6s × %s\n", $1, $2}' | sed 's/^/  /'

  divider
  info "[grep|sort|uniq -c] URL / Endpoint"
  grep -oiE 'https?://[a-zA-Z0-9./_?=&%+-]+' "$target" 2>/dev/null | \
    sort | uniq -c | sort -rn | head -15 | \
    awk '{printf "    %-6s × %s\n", $1, $2}' | sed 's/^/  /'

  divider
  info "[grep|sort|uniq -c] Email Address yang Ditemukan"
  grep -oiE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$target" 2>/dev/null | \
    sort | uniq -c | sort -rn | head -10 | \
    awk '{printf "    %-6s × %s\n", $1, $2}' | sed 's/^/  /'

  # Base64 detection & decode
  divider
  info "[grep|sort|uniq -c] Base64 Strings (possible encoded data)"
  local b64_result=""
  while IFS= read -r b64str; do
    [[ ${#b64str} -lt 20 ]] && continue
    local decoded
    decoded=$(echo "$b64str" | base64 -d 2>/dev/null | strings 2>/dev/null | head -3 | tr '\n' ' ')
    if [[ -n "$decoded" ]]; then
      b64_result+="    B64: ${b64str:0:40}... → $decoded\n"
      local b64flag
      b64flag=$(echo "$decoded" | grep -oiE '(flag|CTF|picoCTF|HTB|THM|FTC)\{[^}]+\}')
      [[ -n "$b64flag" ]] && found "FLAG dari base64 decode: $b64flag" && \
        log_report "B64_FLAG: $b64flag"
    fi
  done < <(grep -oE '[A-Za-z0-9+/]{20,}={0,2}' "$target" 2>/dev/null | \
    sort | uniq -c | sort -rn | awk '{print $2}' | head -30)
  if [[ -n "$b64_result" ]]; then
    found "Base64 berhasil di-decode:"
    printf "%b" "$b64_result" | head -15 | sed 's/^/  /'
  fi

  # Hex encoded strings
  divider
  info "[grep|sort|uniq -c] Hex Encoded Strings (0x... / pure hex 32+ char)"
  grep -oE '(0x[0-9a-fA-F]{8,}|[0-9a-fA-F]{32,64})' "$target" 2>/dev/null | \
    sort | uniq -c | sort -rn | head -10 | \
    while read -r cnt h; do
      h_clean="${h#0x}"
      local hd
      hd=$(echo "$h_clean" | xxd -r -p 2>/dev/null | strings 2>/dev/null | head -1)
      if [[ -n "$hd" ]]; then
        printf "    %-6s × %s → %s\n" "$cnt" "${h:0:40}" "$hd"
      else
        printf "    %-6s × %s\n" "$cnt" "${h:0:64}"
      fi
    done | sed 's/^/  /'

  # ── AWK Timeline universal ─────────────────────────────
  divider
  info "[awk|sort|uniq -c] Timeline — Aktivitas per Jam"
  grep -oE '[0-9]{2}:[0-9]{2}:[0-9]{2}' "$target" 2>/dev/null | \
    cut -d: -f1 | sort | uniq -c | sort -k2 -n | \
    awk '{
      bar=""
      n=int($1/2)
      for(i=0;i<n && i<40;i++) bar=bar"▌"
      printf "    %02d:xx  [%-40s] %d events\n", $2, bar, $1
    }' | sed 's/^/  /'
  log_report "AWK_TIMELINE: done"

  divider
  info "[awk] Statistik File Log"
  local line_count word_count
  line_count=$(wc -l < "$target" 2>/dev/null)
  word_count=$(wc -w < "$target" 2>/dev/null)
  local file_size
  file_size=$(du -sh "$target" 2>/dev/null | cut -f1)
  ok "Total baris : $line_count"
  ok "Total kata  : $word_count"
  ok "Ukuran file : $file_size"

  # Periode log
  local ts_pattern='[0-9]{4}-[0-9]{2}-[0-9]{2}|[A-Z][a-z]{2}\s+[0-9]{1,2}\s+[0-9]{2}:[0-9]{2}'
  local first_ts last_ts
  first_ts=$(head -5 "$target" 2>/dev/null | grep -oE "$ts_pattern" | head -1)
  last_ts=$(tail -5  "$target" 2>/dev/null | grep -oE "$ts_pattern" | tail -1)
  [[ -n "$first_ts" || -n "$last_ts" ]] && ok "Periode     : ${first_ts:-?} → ${last_ts:-?}"

  # ── AWK: Deteksi format kolom otomatis ────────────────
  divider
  info "[awk] Auto-Detect Format Kolom Log"
  local sample_line
  sample_line=$(grep -v '^#\|^$' "$target" 2>/dev/null | head -1)
  local col_count
  col_count=$(echo "$sample_line" | awk '{print NF}')
  ok "Sample baris: ${sample_line:0:80}"
  ok "Jumlah kolom (NF): $col_count"
  # tampilkan tiap kolom
  if [[ "$col_count" -ge 2 && "$col_count" -le 20 ]]; then
    echo "$sample_line" | awk '{for(i=1;i<=NF;i++) printf "    kolom[%d] = %s\n", i, $i}' | sed 's/^/  /'
  fi

  log_report "LOG_LINES: $line_count"

  # ══════════════════════════════════════════════════════
  #  CTF INVESTIGATIVE SCAN — Step-by-step attack analysis
  #  Khusus HTTP access log: IP aktif → attack pattern → timeline
  # ══════════════════════════════════════════════════════
  if [[ "$log_type" == "http" ]]; then

    divider
    info "═══ CTF Investigative Scan ═══"
    echo -e "  ${DIM}Analisis sistematis untuk identifikasi penyerang di HTTP log${NC}"

    # ── STEP 1: Identifikasi IP Paling Aktif ──────────────
    divider
    info "${BOLD}[Step 1]${NC} Identifikasi IP Paling Aktif"
    echo -e "  ${DIM}awk '{print \$1}' <log> | sort | uniq -c | sort -rn${NC}"
    echo ""

    local top_ips
    top_ips=$(awk '{print $1}' "$target" 2>/dev/null | sort | uniq -c | sort -rn | head -20)

    # Tampilkan dengan label publik/private
    echo "$top_ips" | awk '{
      tag=""
      if($2~/^(127\.|0\.0\.|255\.)/) tag="[LOOPBACK]"
      else if($2~/^(10\.|192\.168\.)/) tag="[PRIVATE]"
      else if($2~/^172\.(1[6-9]|2[0-9]|3[01])\./) tag="[PRIVATE]"
      else tag="[PUBLIC]"
      printf "    %-8s %s  %s\n", $1, $2, tag
    }' | sed 's/^/  /'

    # Deteksi IP mencurigakan: publik dengan request tinggi
    local sus_ips
    sus_ips=$(echo "$top_ips" | awk '{
      if($2!~/^(127\.|0\.0\.|255\.|10\.|192\.168\.)/ &&
         $2!~/^172\.(1[6-9]|2[0-9]|3[01])\./ &&
         $1+0 >= 3)
        print $2, $1
    }' | head -10)

    if [[ -n "$sus_ips" ]]; then
      echo ""
      found "IP publik dengan aktivitas tinggi:"
      echo "$sus_ips" | while read -r ip cnt; do
        echo -e "    ${M}→${NC} ${BOLD}${ip}${NC}  (${cnt} requests)"
      done | sed 's/^/  /'
      log_report "CTF_SUS_IPS: $sus_ips"
    fi

    # ── STEP 2: Konfirmasi dengan Attack Pattern Matching ──
    divider
    info "${BOLD}[Step 2]${NC} Konfirmasi Attack Pattern (Path Traversal, SQLi, RCE, XSS, dll)"
    echo -e "  ${DIM}grep -E '(\\.\\./|etc/passwd|cmd=|exec|union|select|<script|wget|curl)' <log>${NC}"
    echo ""

    local attack_patterns='(\.\.\/|\.\.%2[Ff]|%2[Ee]%2[Ee]\/|etc\/passwd|etc\/shadow|\/proc\/self|cmd=|exec\(|system\(|union.*select|select.*from|<script|onerror=|onload=|wget |curl |nc -|\/bin\/bash|\/bin\/sh|base64_decode|eval\(|shell_exec|passthru|phpinfo|%00|%0[aAdD]|\/wp-admin|\/phpmyadmin|\.git\/|\.env|\.htaccess)'

    local attack_lines
    attack_lines=$(grep -iE "$attack_patterns" "$target" 2>/dev/null)

    if [[ -n "$attack_lines" ]]; then
      local attack_count
      attack_count=$(echo "$attack_lines" | wc -l)
      found "Request berbahaya ditemukan: ${BOLD}${attack_count} baris${NC}"
      echo ""

      # Breakdown per jenis serangan
      echo -e "  ${C}[*]${NC} Breakdown tipe serangan:"
      local pt_count sqli_count xss_count rce_count lfi_count misc_count
      pt_count=$(echo  "$attack_lines" | grep -icE '(\.\.\/|%2e%2e|%2[Ff]%2[Ee]|\/etc\/)' || echo 0)
      sqli_count=$(echo "$attack_lines" | grep -icE '(union.*select|select.*from|or.*1=1|--|%27|%3d)' || echo 0)
      xss_count=$(echo  "$attack_lines" | grep -icE '(<script|onerror=|onload=|javascript:)' || echo 0)
      rce_count=$(echo  "$attack_lines" | grep -icE '(cmd=|exec\(|system\(|wget |curl |nc -|\/bin\/bash|shell_exec|passthru)' || echo 0)
      lfi_count=$(echo  "$attack_lines" | grep -icE '(etc\/passwd|etc\/shadow|\/proc\/self|\.env|\.git\/)' || echo 0)
      misc_count=$(echo "$attack_lines" | grep -icE '(phpinfo|base64_decode|eval\(|%00)' || echo 0)

      [[ "$pt_count"   -gt 0 ]] && echo -e "    ${Y}▸${NC} Path Traversal    : ${BOLD}${pt_count}${NC} request"
      [[ "$sqli_count" -gt 0 ]] && echo -e "    ${Y}▸${NC} SQL Injection      : ${BOLD}${sqli_count}${NC} request"
      [[ "$xss_count"  -gt 0 ]] && echo -e "    ${Y}▸${NC} XSS               : ${BOLD}${xss_count}${NC} request"
      [[ "$rce_count"  -gt 0 ]] && echo -e "    ${Y}▸${NC} RCE / Command Inj : ${BOLD}${rce_count}${NC} request"
      [[ "$lfi_count"  -gt 0 ]] && echo -e "    ${Y}▸${NC} LFI / File Access : ${BOLD}${lfi_count}${NC} request"
      [[ "$misc_count" -gt 0 ]] && echo -e "    ${Y}▸${NC} Misc (eval/phpinfo): ${BOLD}${misc_count}${NC} request"

      echo ""
      echo -e "  ${C}[*]${NC} Sample request berbahaya (maks 10):"
      echo "$attack_lines" | head -10 | sed 's/^/    /'

      # Identifikasi IP yang melakukan serangan
      local attacker_ips
      attacker_ips=$(echo "$attack_lines" | awk '{print $1}' | sort | uniq -c | sort -rn | head -10)
      echo ""
      echo -e "  ${C}[*]${NC} IP sumber serangan:"
      echo "$attacker_ips" | awk '{printf "    %-8s %s\n", $1, $2}' | sed 's/^/  /'

      log_report "CTF_ATTACK_PATTERNS: $attack_count requests | PT:$pt_count SQLi:$sqli_count XSS:$xss_count RCE:$rce_count LFI:$lfi_count"
    else
      ok "Tidak ada request berbahaya yang ditemukan"
    fi

    # ── STEP 3: Analisis Seluruh Aktivitas IP Penyerang ───
    divider
    info "${BOLD}[Step 3]${NC} Analisis Mendalam per IP Penyerang"
    echo -e "  ${DIM}grep '<IP>' <log> | analisis status, URI, method${NC}"
    echo ""

    # Ambil top 3 IP penyerang (publik, request >= 2)
    local inv_ips
    inv_ips=$(awk '{print $1}' "$target" 2>/dev/null | \
      grep -vE '^(127\.|0\.0\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' | \
      sort | uniq -c | sort -rn | head -3 | awk '{print $2}')

    if [[ -z "$inv_ips" ]]; then
      # fallback: ambil IP manapun yang paling aktif
      inv_ips=$(awk '{print $1}' "$target" 2>/dev/null | sort | uniq -c | sort -rn | head -3 | awk '{print $2}')
    fi

    if [[ -n "$inv_ips" ]]; then
      echo "$inv_ips" | while IFS= read -r inv_ip; do
        [[ -z "$inv_ip" ]] && continue
        local ip_lines
        ip_lines=$(grep "^$inv_ip " "$target" 2>/dev/null)
        [[ -z "$ip_lines" ]] && ip_lines=$(grep "$inv_ip" "$target" 2>/dev/null)
        [[ -z "$ip_lines" ]] && continue

        local ip_total
        ip_total=$(echo "$ip_lines" | wc -l)
        echo -e "  ${B}┌─── IP: ${BOLD}${inv_ip}${NC}${B} (${ip_total} total request) ───${NC}"

        # Status code breakdown
        local ip_200 ip_301 ip_400 ip_403 ip_404 ip_500
        ip_200=$(echo "$ip_lines" | awk '$9~/^200/' | wc -l)
        ip_301=$(echo "$ip_lines" | awk '$9~/^30[0-9]/' | wc -l)
        ip_403=$(echo "$ip_lines" | awk '$9~/^403/' | wc -l)
        ip_404=$(echo "$ip_lines" | awk '$9~/^404/' | wc -l)
        ip_400=$(echo "$ip_lines" | awk '$9~/^4[^03][0-9]/' | wc -l)
        ip_500=$(echo "$ip_lines" | awk '$9~/^5/' | wc -l)
        echo -e "  ${B}│${NC}  Status: 200=${ip_200}  3xx=${ip_301}  403=${ip_403}  404=${ip_404}  4xx=${ip_400}  5xx=${ip_500}"

        # URI yang berhasil diakses (200)
        local success_uris
        success_uris=$(echo "$ip_lines" | awk '$9~/^200/{print $7}' | sort | uniq -c | sort -rn | head -5)
        if [[ -n "$success_uris" ]]; then
          echo -e "  ${B}│${NC}  ${G}✓ URI berhasil diakses (200):${NC}"
          echo "$success_uris" | awk '{printf "  │    %-6s × %s\n", $1, $2}'

          # Deteksi flag di URI yang berhasil diakses — kurung kurawal {  }
          local uri_flag_200
          uri_flag_200=$(echo "$ip_lines" | awk '$9~/^200/{print $7}' | \
            grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC)\{[^}]+\}')
          if [[ -n "$uri_flag_200" ]]; then
            echo -e "  ${B}│${NC}  ${M}🚩 FLAG di URI (200): ${BOLD}${uri_flag_200}${NC}"
            log_report "CTF_URI_FLAG_200: $inv_ip → $uri_flag_200"
          fi

          # Deteksi flag di URI yang berhasil diakses — kurung siku [  ]
          # Contoh: /CTF[l0g/4n4lys1s/t1m3l1n3]
          local uri_bracket_200
          uri_bracket_200=$(echo "$ip_lines" | awk '$9~/^200/{print $7}' | \
            grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC)\[[^\]]+\]')
          if [[ -n "$uri_bracket_200" ]]; then
            local ub_inner
            ub_inner=$(echo "$uri_bracket_200" | grep -oP '(?<=\[)[^\]]+' | sort -u | head -3)
            echo -e "  ${B}│${NC}  ${M}🚩 FLAG (bracket siku) di URI (200): ${BOLD}${uri_bracket_200}${NC}"
            echo -e "  ${B}│${NC}     ${DIM}isi: ${ub_inner}${NC}"
            log_report "CTF_URI_BRACKET_FLAG_200: $inv_ip → $uri_bracket_200"
          fi
        fi

        # Request berbahaya dari IP ini
        local ip_attacks
        ip_attacks=$(echo "$ip_lines" | grep -iE "$attack_patterns" 2>/dev/null)
        if [[ -n "$ip_attacks" ]]; then
          local ia_count
          ia_count=$(echo "$ip_attacks" | wc -l)
          echo -e "  ${B}│${NC}  ${R}⚠ Request berbahaya: ${ia_count} ditemukan${NC}"
          echo "$ip_attacks" | head -5 | awk '{printf "  │    [%s] %s → HTTP %s\n", $4, $7, $9}' | \
            sed 's/\[//;s/\]//'
          found "IP ${BOLD}${inv_ip}${NC} melakukan serangan (${ia_count} requests berbahaya)"
          log_report "CTF_ATTACKER: $inv_ip | $ia_count attack requests"
        fi

        echo -e "  ${B}└──────────────────────────────────────────────${NC}"
        echo ""
      done
    fi

    # ── STEP 4: Timeline Serangan ──────────────────────────
    divider
    info "${BOLD}[Step 4]${NC} Timeline Serangan — Rekonstruksi Kronologi"
    echo -e "  ${DIM}Mengurutkan seluruh request mencurigakan berdasarkan waktu${NC}"
    echo ""

    if [[ -n "$attack_lines" ]]; then
      # Header tabel
      printf "  %-20s %-40s %-12s %s\n" "Waktu" "URI / Request" "HTTP Status" "IP"
      echo "  $(printf '─%.0s' {1..85})"

      echo "$attack_lines" | head -25 | while IFS= read -r aline; do
        local tl_ip tl_ts tl_method tl_uri tl_status tl_label
        tl_ip=$(echo "$aline" | awk '{print $1}')
        tl_ts=$(echo "$aline" | grep -oE '\[[^]]+\]' | head -1 | tr -d '[]' | cut -d: -f2-4)
        tl_uri=$(echo "$aline" | awk '{print $7}')
        tl_status=$(echo "$aline" | awk '{print $9}')

        # Warna status
        case "${tl_status:0:1}" in
          2) tl_label="${G}${tl_status} ✓${NC}" ;;
          3) tl_label="${C}${tl_status} →${NC}" ;;
          4) tl_label="${Y}${tl_status} ✗${NC}" ;;
          5) tl_label="${R}${tl_status} !!${NC}" ;;
          *) tl_label="${tl_status}" ;;
        esac

        # Deteksi tipe serangan untuk keterangan
        local tl_note=""
        echo "$tl_uri" | grep -qiE '(\.\.\/|%2e%2e)' && tl_note="[Path Traversal]"
        echo "$tl_uri" | grep -qiE '(union|select|--|%27)' && tl_note="[SQLi]"
        echo "$tl_uri" | grep -qiE '(<script|onerror)' && tl_note="[XSS]"
        echo "$tl_uri" | grep -qiE '(cmd=|exec|wget|curl|nc -)' && tl_note="[RCE]"
        echo "$tl_uri" | grep -qiE '(etc/passwd|etc/shadow|\.env)' && tl_note="[LFI]"
        echo "$tl_uri" | grep -qiE '(backup|admin|phpmyadmin|\.git)' && tl_note="[Enum]"
        # Deteksi flag bracket siku di URI timeline
        echo "$tl_uri" | grep -qiE '(flag|CTF|picoCTF|HTB|THM)\[[^\]]+\]' && tl_note="${M}[FLAG!]${NC}"

        printf "  %-20s %-40s " "${tl_ts:-?}" "${tl_uri:0:38}"
        echo -e "${tl_label}  ${DIM}${tl_note}${NC}  ${DIM}${tl_ip}${NC}"
      done

      echo ""
      local succ_attack
      succ_attack=$(echo "$attack_lines" | awk '$9~/^200/' | head -5)
      if [[ -n "$succ_attack" ]]; then
        found "Request berbahaya yang BERHASIL (HTTP 200):"
        echo "$succ_attack" | awk '{printf "    [%s] %s → HTTP %s\n", $4, $7, $9}' | sed 's/\[//;s/\]//' | sed 's/^/  /'
        log_report "CTF_ATTACK_SUCCESS: $(echo "$succ_attack" | wc -l) requests returned 200"
      else
        ok "Tidak ada request berbahaya yang mengembalikan HTTP 200"
      fi

      # ── Cek flag bracket siku di seluruh URI HTTP 200 log ─
      divider
      info "[grep] FLAG dengan Format Bracket Siku di Seluruh Log"
      echo -e "  ${DIM}grep -oiE 'CTF\[[^\]]+\]' <log>${NC}"
      echo ""
      local all_bracket_flags
      all_bracket_flags=$(grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC)\[[^\]]+\]' "$target" 2>/dev/null)
      if [[ -n "$all_bracket_flags" ]]; then
        found "FLAG (bracket siku) ditemukan di log:"
        echo "$all_bracket_flags" | sort | uniq -c | sort -rn | \
          awk '{printf "    %-6s × %s\n", $1, $2}' | sed 's/^/  /'
        # Tampilkan context baris — HTTP status aksesnya
        echo ""
        echo -e "  ${C}[*]${NC} Context baris (beserta HTTP status):"
        echo "$all_bracket_flags" | sort -u | while IFS= read -r bf; do
          local bf_escaped bf_status bf_context
          bf_escaped=$(echo "$bf" | sed 's/\[/\\[/g; s/\]/\\]/g')
          bf_context=$(grep -iE "$bf_escaped" "$target" 2>/dev/null | head -3)
          echo "$bf_context" | while IFS= read -r cline; do
            local c_status c_ts c_ip
            c_ip=$(echo "$cline" | awk '{print $1}')
            c_ts=$(echo "$cline" | grep -oE '\[[^]]+\]' | head -1 | tr -d '[]' | cut -d: -f2-4)
            c_status=$(echo "$cline" | awk '{print $9}')
            # Warna berdasarkan status
            local c_label
            case "${c_status:0:1}" in
              2) c_label="${G}HTTP ${c_status} ✓ BERHASIL${NC}" ;;
              4) c_label="${Y}HTTP ${c_status} ✗${NC}" ;;
              5) c_label="${R}HTTP ${c_status} !!${NC}" ;;
              *) c_label="HTTP ${c_status}" ;;
            esac
            echo -e "    ${DIM}[${c_ts}]${NC} ${BOLD}${bf}${NC} → ${c_label}  ${DIM}dari ${c_ip}${NC}"
          done
        done
        log_report "CTF_BRACKET_FLAG: $all_bracket_flags"
      else
        ok "Tidak ada flag format bracket siku yang ditemukan"
      fi

      log_report "CTF_TIMELINE: $(echo "$attack_lines" | wc -l) attack events reconstructed"
    else
      ok "Tidak ada data timeline serangan (tidak ada request berbahaya)"
    fi

  fi  # end if log_type == http

  log_report "LOG_LINES: $line_count"
}

# ═══════════════════════════════════════════════════════════════
#  MODULE 10 — CRYPTOGRAPHY ANALYSIS
#  Sub-kategori: Classical, Symmetric, Asymmetric, Hashing, Flaws
# ═══════════════════════════════════════════════════════════════
mod_cryptography() {
  local target="$1"
  section "🔐 Cryptography Analysis"
  log_report "MODULE: Cryptography"
  echo -e "  ${DIM}Target: $target${NC}"
  echo ""

  # ── Baca konten target ──────────────────────────────────────
  local content=""
  if [[ -f "$target" ]]; then
    content=$(strings "$target" 2>/dev/null)
  elif [[ "$target" =~ ^https?:// ]]; then
    warn "Target URL — mode terbatas (gunakan file lokal untuk analisis penuh)"
    content="$target"
  else
    content="$target"
  fi

  # ════════════════════════════════════════════════════════════
  #  BAGIAN 1 — CLASSICAL CIPHERS
  # ════════════════════════════════════════════════════════════
  divider
  info "${BOLD}[1/5] Classical Ciphers${NC} — Caesar, Vigenere, Substitution, Transposition"
  echo ""

  # ── 1a. Caesar / ROT Brute Force ──────────────────────────
  info "${BOLD}[Caesar / ROT Brute Force]${NC}"
  echo -e "  ${DIM}Mencoba semua ROT1–ROT25 dan mencari flag pattern...${NC}"
  echo ""

  # Ambil string candidate (panjang 8-200 karakter, hanya alfabet)
  local caesar_candidates
  caesar_candidates=$(echo "$content" | grep -oE '[A-Za-z ]{8,}' | sort -u | head -20)

  if [[ -z "$caesar_candidates" ]]; then
    # Coba baca file mentah jika strings kosong
    [[ -f "$target" ]] && caesar_candidates=$(cat "$target" 2>/dev/null | grep -oE '[A-Za-z ]{8,}' | sort -u | head -20)
  fi

  local caesar_hit=false
  if [[ -n "$caesar_candidates" ]]; then
    while IFS= read -r cline; do
      [[ -z "$cline" ]] && continue
      for rot in {1..25}; do
        local rotted
        rotted=$(echo "$cline" | tr 'A-Za-z' \
          "$(echo {A..Z} | tr -d ' ' | cut -c$((rot+1))- | cat - <(echo {A..Z} | tr -d ' ' | cut -c1-$rot))$(echo {a..z} | tr -d ' ' | cut -c$((rot+1))- | cat - <(echo {a..z} | tr -d ' ' | cut -c1-$rot))" 2>/dev/null)
        # Cara sederhana: gunakan python3
        rotted=$(python3 -c "
s='$cline'
r=$rot
res=''
for c in s:
    if c.isalpha():
        base=ord('A') if c.isupper() else ord('a')
        res+=chr((ord(c)-base+r)%26+base)
    else:
        res+=c
print(res)
" 2>/dev/null)
        if echo "$rotted" | grep -qiE '(flag|ctf|key|secret|password|answer)\{?[^}]{3,}\}?'; then
          found "ROT${rot}: ${BOLD}$rotted${NC}"
          log_report "FLAG_CAESAR_ROT${rot}: $rotted"
          caesar_hit=true
        fi
        # Cek flag pattern standar
        if echo "$rotted" | grep -qiE '^[A-Za-z0-9_]{2,10}\{[^}]{3,}\}$'; then
          found "ROT${rot} flag format: ${BOLD}$rotted${NC}"
          log_report "FLAG_CAESAR_ROT${rot}: $rotted"
          caesar_hit=true
        fi
      done
    done
  fi
  [[ "$caesar_hit" == false ]] && ok "Tidak ada Caesar/ROT flag ditemukan secara otomatis"

  # ── 1b. Frequency Analysis ──────────────────────────────────
  divider
  info "${BOLD}[Frequency Analysis]${NC}"
  echo -e "  ${DIM}Analisis frekuensi karakter untuk mendeteksi substitution cipher${NC}"
  echo ""

  if [[ -n "$content" ]]; then
    local letters
    letters=$(echo "$content" | tr -cd 'A-Za-z' | tr '[:upper:]' '[:lower:]')
    if [[ ${#letters} -gt 20 ]]; then
      echo -e "  ${C}[*]${NC} Distribusi frekuensi huruf (top 10):"
      echo "$letters" | fold -w1 | sort | uniq -c | sort -rn | head -10 | \
        while read -r cnt ch; do
          local pct=$(( cnt * 100 / ${#letters} ))
          local bar; bar=$(printf '█%.0s' $(seq 1 $((pct / 2 + 1))))
          printf "    ${W}%s${NC} : %3d%% %s\n" "$ch" "$pct" "$bar"
        done
      echo ""

      # Cek Index of Coincidence (IC) via python3
      local ic
      ic=$(python3 -c "
s='$(echo "$letters" | head -c 2000)'
n=len(s)
if n < 2:
    print('0.000')
    exit()
from collections import Counter
freq=Counter(s)
ic=sum(v*(v-1) for v in freq.values())/(n*(n-1))
print(f'{ic:.4f}')
" 2>/dev/null)

      if [[ -n "$ic" ]]; then
        echo -e "  ${C}[*]${NC} Index of Coincidence (IC): ${BOLD}${ic}${NC}"
        # IC ~0.065 = English plaintext, ~0.038 = random/polyalphabetic
        local ic_int
        ic_int=$(echo "$ic" | tr -d '.' | sed 's/^0*//')
        # Komparasi sederhana via python3
        python3 -c "
ic=$ic
if ic > 0.060:
    print('  \033[0;32m[+]\033[0m IC tinggi (~0.065) → kemungkinan monoalphabetic/Caesar cipher')
elif ic > 0.045:
    print('  \033[0;33m[!]\033[0m IC sedang → kemungkinan Vigenere dengan kunci pendek')
else:
    print('  \033[0;31m[-]\033[0m IC rendah (~0.038) → kemungkinan transposisi atau random')
" 2>/dev/null
        log_report "CRYPTO_IC: $ic"
      fi

      # Bigram/Trigram analysis sederhana
      echo ""
      echo -e "  ${C}[*]${NC} Bigram paling umum:"
      echo "$letters" | fold -w2 | sort | uniq -c | sort -rn | head -5 | \
        awk '{printf "    %s × %s\n", $1, $2}'
    else
      warn "Teks alfabetik terlalu pendek untuk frequency analysis (< 20 karakter)"
    fi
  fi

  # ── 1c. Atbash / ROT13 / Vigenere hints ────────────────────
  divider
  info "${BOLD}[Atbash + ROT13 + Vigenere Kasiski Hint]${NC}"
  echo ""

  # Atbash
  if [[ -n "$content" ]]; then
    local atbash_results
    atbash_results=$(echo "$content" | grep -oE '[A-Za-z]{6,}' | head -10 | while read -r w; do
      python3 -c "
w='$w'
r=''.join(chr(ord('Z')-ord(c)+ord('A')) if c.isupper() else chr(ord('z')-ord(c)+ord('a')) for c in w)
print(r)
" 2>/dev/null
    done)
    local atbash_flag
    atbash_flag=$(echo "$atbash_results" | grep -iE '(flag|ctf|key|secret)')
    if [[ -n "$atbash_flag" ]]; then
      found "Atbash decode: ${BOLD}$atbash_flag${NC}"
      log_report "FLAG_ATBASH: $atbash_flag"
    else
      ok "Tidak ada flag Atbash yang terdeteksi"
    fi

    # ROT13 (sudah ada di decode engine, tapi kita check ulang)
    local rot13_check
    rot13_check=$(echo "$content" | tr 'A-Za-z' 'N-ZA-Mn-za-m' | grep -iE '(flag|ctf|key|secret)\{?[^}]*\}?' | head -3)
    if [[ -n "$rot13_check" ]]; then
      found "ROT13 decode: ${BOLD}$rot13_check${NC}"
      log_report "FLAG_ROT13: $rot13_check"
    fi

    # Kasiski test hint untuk Vigenere
    echo ""
    info "${BOLD}[Kasiski Test — Panjang Kunci Vigenere]${NC}"
    echo -e "  ${DIM}Mencari repeated trigrams untuk estimasi panjang kunci...${NC}"
    python3 -c "
import re
text = '''$(echo "$letters" | head -c 500 | tr "'" ' ')'''
text = re.sub(r'[^a-z]','',text.lower())
if len(text) < 30:
    print('  Teks terlalu pendek untuk Kasiski test')
    exit()
spacings = []
for n in [3,4]:
    for i in range(len(text)-n):
        tri = text[i:i+n]
        for j in range(i+n,len(text)-n+1):
            if text[j:j+n]==tri:
                spacings.append(j-i)
if not spacings:
    print('  Tidak ada repeated ngram ditemukan (mungkin bukan Vigenere)')
else:
    from math import gcd
    from functools import reduce
    g = reduce(gcd, spacings)
    print(f'  GCD spacings: {g}  → estimasi panjang kunci: {g}')
    print(f'  Spacings sample: {spacings[:8]}')
" 2>/dev/null
  fi

  # ── 1d. Transposition Cipher detection ─────────────────────
  divider
  info "${BOLD}[Transposition Cipher Detection]${NC}"
  echo -e "  ${DIM}Cek apakah teks adalah anagram / columnar transposition${NC}"
  echo ""
  if [[ -n "$content" ]]; then
    python3 -c "
from collections import Counter
text = '$(echo "$content" | tr -cd 'A-Za-z' | head -c 300)'
if len(text) < 10:
    print('  Teks terlalu pendek')
    exit()
# Check IC sama dengan English? (transposisi tidak ubah IC)
n = len(text)
freq = Counter(text.lower())
ic = sum(v*(v-1) for v in freq.values())/(n*(n-1)) if n>1 else 0
if ic > 0.060:
    print(f'  IC={ic:.4f} → Frekuensi huruf mirip English plaintext')
    print('  Kemungkinan TRANSPOSITION cipher (huruf tidak disubstitusi)')
    print('  Coba: columnar, rail fence, atau route transposition')
else:
    print(f'  IC={ic:.4f} → Bukan transposisi sederhana')
" 2>/dev/null
  fi

  # ════════════════════════════════════════════════════════════
  #  BAGIAN 2 — MODERN SYMMETRIC CRYPTO
  # ════════════════════════════════════════════════════════════
  divider
  info "${BOLD}[2/5] Modern Symmetric Crypto${NC} — AES/DES/Block Cipher Attacks"
  echo ""

  # ── 2a. Detect AES/DES magic bytes & patterns ──────────────
  info "${BOLD}[AES / DES Pattern Detection]${NC}"
  echo ""

  if [[ -f "$target" ]]; then
    # Cek ukuran file (AES block = 16 bytes, DES = 8 bytes)
    local fsize_bytes
    fsize_bytes=$(stat -c%s "$target" 2>/dev/null || echo 0)
    echo -e "  ${C}[*]${NC} Ukuran file: ${BOLD}${fsize_bytes}${NC} bytes"

    if [[ "$fsize_bytes" -gt 0 ]]; then
      local mod16=$(( fsize_bytes % 16 ))
      local mod8=$(( fsize_bytes % 8 ))
      [[ "$mod16" -eq 0 ]] && echo -e "  ${Y}[!]${NC} Ukuran file = kelipatan 16 → ${BOLD}kemungkinan AES-encrypted (ECB/CBC)${NC}"
      [[ "$mod16" -ne 0 && "$mod8" -eq 0 ]] && echo -e "  ${Y}[!]${NC} Ukuran file = kelipatan 8 (bukan 16) → ${BOLD}kemungkinan DES/3DES-encrypted${NC}"
      [[ "$mod16" -ne 0 && "$mod8" -ne 0 ]] && echo -e "  ${G}[+]${NC} Ukuran tidak kelipatan block → mungkin ada padding scheme atau bukan block cipher"
      log_report "CRYPTO_FILESIZE_BYTES: $fsize_bytes (mod16=$mod16, mod8=$mod8)"
    fi

    # ── 2b. ECB Mode Detection (pengulangan block 16 bytes) ────
    divider
    info "${BOLD}[ECB Mode Detection — Duplicate Blocks]${NC}"
    echo -e "  ${DIM}Mencari block 16-byte yang identik (ciri khas ECB mode)${NC}"
    echo ""

    python3 -c "
import sys
try:
    with open('$target','rb') as f:
        data=f.read()
    blocks=[data[i:i+16].hex() for i in range(0,len(data)-15,16)]
    from collections import Counter
    cnt=Counter(blocks)
    dupes=[(b,c) for b,c in cnt.items() if c>1]
    if dupes:
        print(f'  \033[0;35m[FLAG?]\033[0m \033[1mECB mode terdeteksi! {len(dupes)} block duplikat ditemukan:\033[0m')
        for b,c in sorted(dupes,key=lambda x:-x[1])[:5]:
            print(f'    Block: {b}  ×{c}')
    else:
        if len(blocks)>1:
            print(f'  \033[0;32m[+]\033[0m Tidak ada block duplikat dari {len(blocks)} blocks — bukan ECB atau data terenkripsi baik')
        else:
            print('  \033[0;33m[!]\033[0m File terlalu kecil untuk analisis ECB')
except Exception as e:
    print(f'  Error: {e}')
" 2>/dev/null

    # ── 2c. CBC IV Detection ────────────────────────────────────
    divider
    info "${BOLD}[CBC IV / Padding Oracle Hints]${NC}"
    echo -e "  ${DIM}Cek struktur awal file untuk IV dan PKCS#7 padding${NC}"
    echo ""

    python3 -c "
try:
    with open('$target','rb') as f:
        data=f.read()
    if len(data) < 32:
        print('  File terlalu kecil untuk analisis CBC')
        exit()
    iv_candidate=data[:16].hex()
    last_block=data[-16:] if len(data)>=16 else b''
    # Cek PKCS#7 padding
    if last_block:
        pad_byte=last_block[-1]
        if 1 <= pad_byte <= 16:
            padding=last_block[-pad_byte:]
            if all(b==pad_byte for b in padding):
                print(f'  \033[0;33m[!]\033[0m PKCS#7 padding valid ditemukan: 0x{pad_byte:02x} × {pad_byte}')
                print(f'  → Padding oracle attack mungkin applicable jika ada oracle (decryption service)')
            else:
                print('  \033[0;32m[+]\033[0m Padding tidak valid atau bukan PKCS#7')
        else:
            print('  \033[0;32m[+]\033[0m Tidak ada PKCS#7 padding standar')
    print(f'  IV candidate (16 bytes pertama): {iv_candidate}')
    # Cek apakah IV adalah null bytes (zero IV — kelemahan implementasi)
    if data[:16] == b'\x00'*16:
        print('  \033[0;35m[FLAG?]\033[0m \033[1mNULL IV terdeteksi! Kelemahan CBC — bisa XOR plaintext langsung\033[0m')
except Exception as e:
    print(f'  Error: {e}')
" 2>/dev/null
  else
    info "Target bukan file — lewati analisis binary CBC/ECB"
  fi

  # ── 2d. Cari string cipher terkait di konten ───────────────
  divider
  info "${BOLD}[Crypto String Patterns]${NC}"
  echo -e "  ${DIM}Mencari pola AES key, IV, dan mode dalam strings file${NC}"
  echo ""
  echo "$content" | grep -iE '(aes|des|3des|blowfish|chacha|rc4|key|iv|nonce|cipher|encrypt|decrypt|mode=|ecb|cbc|ctr|gcm)' | \
    head -15 | sed 's/^/    /' | sed "s/\(aes\|des\|key\|iv\|nonce\|ecb\|cbc\|ctr\|gcm\)/$(printf '\033[1;33m')&$(printf '\033[0m')/gi" 2>/dev/null
  echo ""

  # ════════════════════════════════════════════════════════════
  #  BAGIAN 3 — ASYMMETRIC CRYPTOGRAPHY
  # ════════════════════════════════════════════════════════════
  divider
  info "${BOLD}[3/5] Asymmetric Cryptography${NC} — RSA, DH, ECC"
  echo ""

  # ── 3a. Deteksi PEM/DER/RSA ────────────────────────────────
  info "${BOLD}[RSA Key / Certificate Detection]${NC}"
  echo ""

  # Cek file PEM
  if [[ -f "$target" ]]; then
    if grep -q "BEGIN" "$target" 2>/dev/null; then
      local pem_types
      pem_types=$(grep "-----BEGIN" "$target" 2>/dev/null | sed 's/-----BEGIN //;s/-----//')
      echo -e "  ${Y}[!]${NC} PEM headers ditemukan:"
      echo "$pem_types" | while read -r pt; do
        echo -e "    → ${BOLD}$pt${NC}"
      done

      # Ekstrak info RSA key dengan openssl
      if has openssl; then
        echo ""
        info "[openssl] Analisis RSA key/certificate:"
        # Coba sebagai RSA private key
        openssl rsa -in "$target" -text -noout 2>/dev/null | \
          grep -E '(Public-Key|modulus|publicExponent|privateExponent)' | \
          head -10 | sed 's/^/    /'
        # Coba sebagai public key
        openssl rsa -pubin -in "$target" -text -noout 2>/dev/null | \
          grep -E '(Public-Key|Exponent|Modulus)' | head -10 | sed 's/^/    /'
        # Coba sebagai X.509 certificate
        openssl x509 -in "$target" -text -noout 2>/dev/null | \
          grep -E '(Subject:|Issuer:|Public Key|RSA Public Key|Exponent:|Serial Number)' | \
          head -10 | sed 's/^/    /'
      else
        warn "openssl tidak tersedia — install: sudo apt install openssl"
      fi
    fi
  fi

  # Scan konten untuk parameter RSA
  echo ""
  info "${BOLD}[RSA Parameter Scan]${NC}"
  echo -e "  ${DIM}Mencari n, e, d, p, q, c dalam strings file...${NC}"
  echo ""
  echo "$content" | grep -iE '^[ne][ =:]+[0-9]{10,}|^(n|e|d|p|q|c)[ =:]+0x[0-9a-f]+|modulus|exponent|prime[12]' | \
    head -15 | sed 's/^/    /'

  # ── 3b. RSA Attack Identification ──────────────────────────
  divider
  info "${BOLD}[RSA Attack Identification]${NC}"
  echo ""

  # Ekstrak e dan n dari konten
  local rsa_e rsa_n
  rsa_e=$(echo "$content" | grep -ioE 'e[ =:]+([0-9]+)' | head -1 | grep -oE '[0-9]+$')
  rsa_n=$(echo "$content" | grep -ioE 'n[ =:]+([0-9]{20,})' | head -1 | grep -oE '[0-9]{20,}$')

  if [[ -z "$rsa_e" ]]; then
    # Coba cari pola lain
    rsa_e=$(echo "$content" | grep -oE '\b(3|17|65537|65539)\b' | head -1)
  fi

  python3 -c "
import sys, math

# Nilai dari konten
e_val = '$rsa_e'
n_val = '$rsa_n'

print('  Analisis parameter RSA yang ditemukan:')

if e_val:
    try:
        e = int(e_val)
        print(f'  e = {e}')
        if e == 3:
            print('  \033[0;35m[FLAG?]\033[0m \033[1mSmall e=3 terdeteksi!\033[0m')
            print('         → Cube Root Attack: jika m^3 < n, maka m = c^(1/3)')
            print('         → Hastad Broadcast Attack jika c dikirim ke 3 penerima')
        elif e == 17:
            print('  \033[0;33m[!]\033[0m e=17 (kecil) → coba small e attack')
        elif e == 65537:
            print('  \033[0;32m[+]\033[0m e=65537 (standar) — serangan small-e kurang efektif')
        else:
            print(f'  \033[0;33m[!]\033[0m e={e} — cek apakah termasuk Wiener attack range')
    except:
        pass
else:
    print('  e tidak ditemukan dalam konten')

if n_val:
    try:
        n = int(n_val)
        bit_len = n.bit_length()
        print(f'  n = {str(n)[:40]}...')
        print(f'  Panjang modulus: {bit_len} bit')
        if bit_len < 512:
            print('  \033[0;35m[FLAG?]\033[0m \033[1mModulus sangat kecil (<512 bit) — bisa difaktorkan!\033[0m')
            print('         → Coba: factordb.com atau SageMath factor(n)')
        elif bit_len < 1024:
            print('  \033[0;33m[!]\033[0m Modulus kecil (<1024 bit) — berpotensi rentan')
        else:
            print(f'  \033[0;32m[+]\033[0m Modulus {bit_len} bit (aman dari faktorisasi brute force)')
        # Cek apakah n bisa difaktorkan trivial
        for p in [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47]:
            if n % p == 0:
                q = n // p
                print(f'  \033[0;35m[FLAG?]\033[0m \033[1mFaktor trivial ditemukan! n = {p} × {q}\033[0m')
                break
    except:
        pass
else:
    print('  n tidak ditemukan dalam konten')

# Wiener attack hint
print()
print('  Panduan serangan RSA CTF:')
print('  ┌─ Small e (e=3)   → Cube Root / Hastad Broadcast')
print('  ├─ Large d (Wiener) → e/n ratio besar → d kecil')
print('  ├─ Common factor   → 2 ciphertext share faktor p')
print('  ├─ Same n diff e   → CRT / Extended Euclidean')
print('  └─ n kecil (<512)  → FactorDB / YAFU / msieve')
" 2>/dev/null

  # ── 3c. Diffie-Hellman Hints ────────────────────────────────
  divider
  info "${BOLD}[Diffie-Hellman / ECC Detection]${NC}"
  echo ""

  echo "$content" | grep -iE '(diffie|hellman|dh|ecdh|ecdsa|elliptic|curve25519|p256|p384|secp|generator|prime|modulus|private.?key|public.?key)' | \
    head -10 | sed 's/^/    /'

  # Cek DH parameter file
  if [[ -f "$target" ]] && has openssl; then
    openssl dhparam -in "$target" -text -noout 2>/dev/null | \
      grep -E '(prime|generator|DH Parameters)' | head -5 | sed 's/^/    /'
  fi

  python3 -c "
print('  Panduan serangan DH/ECC CTF:')
print('  ┌─ Small subgroup   → order p kecil → discrete log trivial')
print('  ├─ g=1 atau g=0    → trivial shared secret')
print('  ├─ Weak prime       → pohlig-hellman / pohlig-silver attack')
print('  ├─ ECC invalid curve → low-order point attack')
print('  └─ ECDSA k reuse   → k bisa dihitung, private key bocor')
" 2>/dev/null

  # ════════════════════════════════════════════════════════════
  #  BAGIAN 4 — HASHING
  # ════════════════════════════════════════════════════════════
  divider
  info "${BOLD}[4/5] Hashing${NC} — MD5/SHA detection, cracking, length extension"
  echo ""

  # ── 4a. Hash detection dari strings ────────────────────────
  info "${BOLD}[Hash String Detection]${NC}"
  echo -e "  ${DIM}Mencari pola hash MD5, SHA1, SHA256, SHA512, bcrypt, NTLM...${NC}"
  echo ""

  local hashes_found=false

  # MD5 (32 hex)
  local md5_hits
  md5_hits=$(echo "$content" | grep -oE '\b[0-9a-fA-F]{32}\b' | grep -v '00000000' | sort -u | head -5)
  if [[ -n "$md5_hits" ]]; then
    echo -e "  ${Y}[!]${NC} ${BOLD}MD5 hashes (32 hex) ditemukan:${NC}"
    echo "$md5_hits" | while read -r h; do
      echo -e "    ${M}$h${NC}"
      log_report "HASH_MD5: $h"
    done
    hashes_found=true
  fi

  # SHA1 (40 hex)
  local sha1_hits
  sha1_hits=$(echo "$content" | grep -oE '\b[0-9a-fA-F]{40}\b' | sort -u | head -5)
  if [[ -n "$sha1_hits" ]]; then
    echo -e "  ${Y}[!]${NC} ${BOLD}SHA1 hashes (40 hex) ditemukan:${NC}"
    echo "$sha1_hits" | while read -r h; do
      echo -e "    ${M}$h${NC}"
      log_report "HASH_SHA1: $h"
    done
    hashes_found=true
  fi

  # SHA256 (64 hex)
  local sha256_hits
  sha256_hits=$(echo "$content" | grep -oE '\b[0-9a-fA-F]{64}\b' | sort -u | head -5)
  if [[ -n "$sha256_hits" ]]; then
    echo -e "  ${Y}[!]${NC} ${BOLD}SHA256 hashes (64 hex) ditemukan:${NC}"
    echo "$sha256_hits" | while read -r h; do
      echo -e "    ${M}$h${NC}"
      log_report "HASH_SHA256: $h"
    done
    hashes_found=true
  fi

  # SHA512 (128 hex)
  local sha512_hits
  sha512_hits=$(echo "$content" | grep -oE '\b[0-9a-fA-F]{128}\b' | sort -u | head -3)
  if [[ -n "$sha512_hits" ]]; then
    echo -e "  ${Y}[!]${NC} ${BOLD}SHA512 hashes (128 hex) ditemukan:${NC}"
    echo "$sha512_hits" | while read -r h; do
      echo -e "    ${M}${h:0:64}...${NC}"
      log_report "HASH_SHA512: $h"
    done
    hashes_found=true
  fi

  # bcrypt ($2a$, $2b$)
  local bcrypt_hits
  bcrypt_hits=$(echo "$content" | grep -oE '\$2[ab]\$[0-9]{2}\$[./A-Za-z0-9]{53}' | head -3)
  if [[ -n "$bcrypt_hits" ]]; then
    echo -e "  ${Y}[!]${NC} ${BOLD}bcrypt hash ditemukan:${NC}"
    echo "$bcrypt_hits" | while read -r h; do
      echo -e "    ${M}$h${NC}"
      log_report "HASH_BCRYPT: $h"
    done
    hashes_found=true
  fi

  # NTLM (LM:NTLM format)
  local ntlm_hits
  ntlm_hits=$(echo "$content" | grep -oE '[A-Za-z0-9_-]+:[0-9]+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}' | head -3)
  if [[ -n "$ntlm_hits" ]]; then
    echo -e "  ${Y}[!]${NC} ${BOLD}NTLM/LM hash ditemukan:${NC}"
    echo "$ntlm_hits" | while read -r h; do
      echo -e "    ${M}$h${NC}"
      log_report "HASH_NTLM: $h"
    done
    hashes_found=true
  fi

  [[ "$hashes_found" == false ]] && ok "Tidak ada hash yang terdeteksi dalam strings file"

  # ── 4b. Hash cracking via john / hashcat ───────────────────
  divider
  info "${BOLD}[Hash Cracking — John / Hashcat]${NC}"
  echo ""

  if [[ "$hashes_found" == true ]]; then
    local hash_file="/tmp/fasfo_hashes_$(date +%s).txt"
    {
      [[ -n "$md5_hits" ]] && echo "$md5_hits"
      [[ -n "$sha1_hits" ]] && echo "$sha1_hits"
      [[ -n "$sha256_hits" ]] && echo "$sha256_hits"
    } > "$hash_file"

    if has john && [[ -f "$hash_file" ]] && [[ -n "$WORDLIST" ]]; then
      echo -e "  ${C}[*]${NC} Menjalankan john dengan wordlist: ${DIM}$WORDLIST${NC}"
      timeout 30 john --wordlist="$WORDLIST" --format=raw-md5 "$hash_file" 2>/dev/null | \
        grep -v "^Using\|^Loaded\|^Warning\|^Session\|^Proceeding\|^No password" | \
        head -10 | sed 's/^/    /'
      timeout 15 john --show "$hash_file" 2>/dev/null | head -5 | sed 's/^/    /'
      local john_cracked
      john_cracked=$(john --show "$hash_file" 2>/dev/null | grep -v "^0 " | head -5)
      if [[ -n "$john_cracked" ]]; then
        found "John cracked: ${BOLD}$john_cracked${NC}"
        log_report "FLAG_HASH_CRACKED: $john_cracked"
      fi
    elif has john; then
      warn "John tersedia tapi wordlist tidak ditemukan — set FASFO_WORDLIST=/path/to/wordlist"
    else
      warn "john tidak tersedia — install: sudo apt install john"
    fi

    if has hashcat; then
      echo -e "  ${C}[*]${NC} Contoh perintah hashcat:"
      [[ -n "$md5_hits" ]] && echo -e "    ${DIM}hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt${NC}"
      [[ -n "$sha256_hits" ]] && echo -e "    ${DIM}hashcat -m 1400 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt${NC}"
      [[ -n "$bcrypt_hits" ]] && echo -e "    ${DIM}hashcat -m 3200 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt${NC}"
    fi
    rm -f "$hash_file"
  else
    info "Tidak ada hash untuk di-crack"
  fi

  # ── 4c. Length Extension Attack ────────────────────────────
  divider
  info "${BOLD}[Hash Length Extension Attack]${NC}"
  echo ""
  echo -e "  ${DIM}MD5 dan SHA1 rentan terhadap length extension attack${NC}"
  echo ""

  echo "$content" | grep -iE '(signature|mac|hmac|token|auth|verify|hash)' | head -5 | sed 's/^/    /'

  python3 -c "
print('  Panduan Length Extension Attack:')
print('  ┌─ Tool: hash_extender (https://github.com/iagox86/hash_extender)')
print('  ├─ hashpump (pip install hashpumpy)')
print('  ├─ Rentan: MD5, SHA1, SHA256 (tanpa HMAC)')
print('  ├─ Tidak rentan: SHA3, bcrypt, HMAC-SHA256')
print('  └─ Contoh: hashpump -s <sig> -d <data> -a \"&admin=1\" -k <keylen>')
" 2>/dev/null

  if has hashpump 2>/dev/null || python3 -c "import hashpumpy" 2>/dev/null; then
    ok "hashpumpy tersedia — bisa digunakan untuk length extension"
  else
    warn "hashpump tidak tersedia — install: pip3 install hashpumpy"
  fi

  # ── 4d. Rainbow Table hints ────────────────────────────────
  divider
  info "${BOLD}[Rainbow Table / Online Crack]${NC}"
  echo ""
  if [[ "$hashes_found" == true ]]; then
    echo -e "  ${C}[*]${NC} Coba crack hash secara online:"
    echo -e "    → ${W}https://crackstation.net${NC}   (MD5, SHA1, SHA256, NTLM)"
    echo -e "    → ${W}https://hashes.com/en/decrypt/hash${NC}"
    echo -e "    → ${W}https://www.md5online.org${NC}"
    echo -e "    → ${W}https://sha256.online${NC}"
    echo ""
    # Tampilkan hash terpendek untuk mudah dicopy
    [[ -n "$md5_hits" ]] && echo -e "  ${M}[MD5 untuk crack]${NC} $(echo "$md5_hits" | head -1)"
    [[ -n "$sha1_hits" ]] && echo -e "  ${M}[SHA1 untuk crack]${NC} $(echo "$sha1_hits" | head -1)"
    [[ -n "$sha256_hits" ]] && echo -e "  ${M}[SHA256 untuk crack]${NC} $(echo "$sha256_hits" | head -1)"
  fi

  # ════════════════════════════════════════════════════════════
  #  BAGIAN 5 — CRYPTO IMPLEMENTATION FLAWS
  # ════════════════════════════════════════════════════════════
  divider
  info "${BOLD}[5/5] Crypto Implementation Flaws${NC} — RNG, Timing, Nonce Reuse, Custom Crypto"
  echo ""

  # ── 5a. Weak RNG Detection ─────────────────────────────────
  info "${BOLD}[Weak RNG / Predictable Randomness]${NC}"
  echo ""

  echo "$content" | grep -iE '(random\.seed|srand|rand\(\)|mt_rand|time\(\)|gettime|timestamp|urandom|os\.random|secrets)' | \
    head -10 | sed 's/^/    /'

  python3 -c "
import re
content = '''$(echo "$content" | head -c 3000 | tr "'" ' ')'''
# Cari seed berbasis waktu
time_seeds = re.findall(r'(seed\s*\(.*?time|srand\s*\(.*?time)', content, re.IGNORECASE)
if time_seeds:
    print('  \033[0;35m[FLAG?]\033[0m \033[1mTime-based seed terdeteksi! RNG predictable!\033[0m')
    for ts in time_seeds[:3]:
        print(f'    → {ts}')
else:
    # Cek angka yang mungkin hardcoded seed
    hardcoded = re.findall(r'seed\s*\(\s*([0-9]+)\s*\)', content, re.IGNORECASE)
    if hardcoded:
        print(f'  \033[0;35m[FLAG?]\033[0m \033[1mHardcoded seed ditemukan: {hardcoded}\033[0m')
    else:
        print('  \033[0;32m[+]\033[0m Tidak ada weak RNG pattern yang terdeteksi secara eksplisit')
" 2>/dev/null

  # ── 5b. Nonce / IV Reuse ───────────────────────────────────
  divider
  info "${BOLD}[Nonce / IV Reuse Detection]${NC}"
  echo -e "  ${DIM}Nonce reuse pada AES-CTR atau ChaCha20 = XOR plaintext langsung${NC}"
  echo ""

  if [[ -f "$target" ]]; then
    python3 -c "
try:
    with open('$target','rb') as f:
        data=f.read()
    # Analisis entropy per-blok untuk mendeteksi pola reuse
    import math, collections
    block_size=16
    blocks=[data[i:i+block_size] for i in range(0,len(data)-block_size+1,block_size)]
    if len(blocks) < 4:
        print('  File terlalu kecil untuk analisis nonce reuse')
    else:
        # Hitung entropy setiap block
        entropies=[]
        for b in blocks:
            cnt=collections.Counter(b)
            ent=-sum((c/len(b))*math.log2(c/len(b)) for c in cnt.values() if c>0)
            entropies.append(ent)
        avg_ent=sum(entropies)/len(entropies)
        low_ent=[i for i,e in enumerate(entropies) if e < 2.0]
        print(f'  Rata-rata entropy blok: {avg_ent:.3f} bit/byte')
        if low_ent:
            print(f'  \033[0;35m[FLAG?]\033[0m \033[1mBlok entropy rendah ditemukan di index: {low_ent[:8]}\033[0m')
            print('         → Kemungkinan: nonce reuse, zero-key, atau pola berulang')
        else:
            print('  \033[0;32m[+]\033[0m Entropy blok homogen — tidak ada indikasi nonce reuse jelas')

        # Cek apakah ada 2 blok identik pada posisi berbeda (CTR nonce reuse)
        block_map={}
        for i,b in enumerate(blocks):
            bh=b.hex()
            if bh in block_map:
                print(f'  \033[0;35m[FLAG?]\033[0m \033[1mBlok identik di posisi {block_map[bh]} dan {i} — nonce/key reuse!\033[0m')
                break
            block_map[bh]=i
except Exception as e:
    print(f'  Error: {e}')
" 2>/dev/null
  fi

  # ── 5c. Custom / Homebrew Crypto Detection ─────────────────
  divider
  info "${BOLD}[Custom Crypto / XOR Cipher Analysis]${NC}"
  echo -e "  ${DIM}Mencari pola XOR, shift, home-made cipher, dan operasi bitwise${NC}"
  echo ""

  echo "$content" | grep -iE '(\bxor\b|^\^|bitwise|rotate|ror|rol|\bshift\b|custom.*encrypt|encrypt.*custom|homebrew|hand.?made|my.*cipher)' | \
    head -10 | sed 's/^/    /'

  # XOR key brute force jika file kecil
  if [[ -f "$target" ]]; then
    local fsize_xor
    fsize_xor=$(stat -c%s "$target" 2>/dev/null || echo 99999)
    if [[ "$fsize_xor" -le 10000 ]]; then
      echo ""
      info "[XOR Single-Byte Brute Force]"
      echo -e "  ${DIM}Mencoba XOR 0x01–0xFF pada seluruh file, cari flag pattern...${NC}"
      echo ""
      python3 -c "
import sys
try:
    with open('$target','rb') as f:
        data=f.read()
    if len(data) > 5000:
        data=data[:5000]
    found_any=False
    for key in range(1,256):
        dec=bytes(b^key for b in data)
        try:
            text=dec.decode('ascii','ignore')
        except:
            continue
        import re
        # Cari flag pattern
        flags=re.findall(r'[A-Za-z0-9_]{2,10}\{[^}]{3,}\}', text)
        for fl in flags:
            print(f'  \033[0;35m[FLAG?]\033[0m \033[1mXOR key=0x{key:02x} ({key}): {fl}\033[0m')
            found_any=True
        # Cari kata kunci kripto umum
        if re.search(r'(flag|key|secret|ctf|password|admin)', text, re.IGNORECASE):
            snippet=re.search(r'.{0,20}(flag|key|secret|ctf|password|admin).{0,20}', text, re.IGNORECASE)
            if snippet:
                print(f'  \033[0;33m[!]\033[0m XOR key=0x{key:02x}: ...{snippet.group().strip()[:50]}...')
                found_any=True
    if not found_any:
        print('  \033[0;32m[+]\033[0m Tidak ada flag ditemukan dengan XOR single-byte brute force')
        print('  \033[2m→ Coba XOR multi-byte atau analisis manual\033[0m')
except Exception as e:
    print(f'  Error: {e}')
" 2>/dev/null
    else
      warn "File terlalu besar (${fsize_xor} bytes) untuk XOR brute force — batasan 10KB"
      info "Gunakan: python3 -c \"d=open('$target','rb').read(); [print(hex(k),bytes(b^k for b in d)[:50]) for k in range(256)]\""
    fi
  fi

  # ── 5d. Timing Attack hints ────────────────────────────────
  divider
  info "${BOLD}[Timing Attack / Side Channel Hints]${NC}"
  echo ""
  echo "$content" | grep -iE '(strcmp|memcmp|time\.sleep|timing|side.?channel|oracle|compare|verify)' | head -5 | sed 's/^/    /'
  python3 -c "
print('  Panduan Timing Attack CTF:')
print('  ┌─ strcmp() → tidak constant-time → timing oracle untuk brute force')
print('  ├─ sleep() berbasis nilai → bisa probe karakter per karakter')
print('  ├─ Tool: timing-attack (pip install timing-attack)')
print('  └─ Teknik: kirim banyak request, ukur response time, plot distribusi')
" 2>/dev/null

  # ── 5e. Entropy Analysis keseluruhan ───────────────────────
  divider
  info "${BOLD}[Entropy Analysis — Deteksi Encrypted/Compressed Data]${NC}"
  echo ""

  if [[ -f "$target" ]]; then
    python3 -c "
import math, collections
try:
    with open('$target','rb') as f:
        data=f.read()
    if not data:
        print('  File kosong')
        exit()
    cnt=collections.Counter(data)
    n=len(data)
    ent=-sum((c/n)*math.log2(c/n) for c in cnt.values() if c>0)
    print(f'  Entropy keseluruhan: \033[1m{ent:.4f}\033[0m bit/byte (max=8.0)')
    print()
    if ent > 7.8:
        print('  \033[0;35m[FLAG?]\033[0m \033[1mEntropy sangat tinggi (>7.8) → kemungkinan ENCRYPTED atau compressed\033[0m')
        print('         → AES/ChaCha20 ciphertext, ZIP, GZIP, atau binary acak')
    elif ent > 7.0:
        print('  \033[0;33m[!]\033[0m Entropy tinggi (7.0-7.8) → mungkin enkripsi lemah atau kompresi')
    elif ent > 5.5:
        print('  \033[0;32m[+]\033[0m Entropy sedang — kemungkinan file teks atau enkripsi parsial')
    else:
        print('  \033[0;32m[+]\033[0m Entropy rendah → data plaintext, structured binary, atau belum terenkripsi')
    # Byte frequency visualization
    unique_bytes=len(cnt)
    print(f'  Byte unik: {unique_bytes}/256')
    print(f'  Byte paling umum: {sorted(cnt.items(), key=lambda x:-x[1])[:3]}')
except Exception as e:
    print(f'  Error: {e}')
" 2>/dev/null
  fi

  # ── 5f. Tool Reference ──────────────────────────────────────
  divider
  info "${BOLD}[Referensi Tools Crypto CTF]${NC}"
  echo ""
  python3 -c "
tools = [
    ('RsaCtfTool',    'pip3 install requests pycryptodome',     'RSA multi-attack auto-solver'),
    ('pycryptodome',  'pip3 install pycryptodome',              'Python crypto library (AES, RSA, DES)'),
    ('SageMath',      'apt install sagemath',                   'Math engine: factor, elliptic, DLP'),
    ('hashcat',       'apt install hashcat',                    'GPU hash cracking'),
    ('john',          'apt install john',                       'CPU hash cracking + zip/rar/pdf'),
    ('openssl',       'apt install openssl',                    'Key/cert analysis, encryption'),
    ('hashpumpy',     'pip3 install hashpumpy',                 'Length extension attack'),
    ('z3-solver',     'pip3 install z3-solver',                 'SMT solver untuk reverse crypto'),
    ('CyberChef',     'https://gchq.github.io/CyberChef/',     'Browser-based crypto Swiss knife'),
    ('dcode.fr',      'https://www.dcode.fr/',                  'Classical cipher solver online'),
]
print('  {:<18} {:<40} {}'.format('Tool', 'Install', 'Kegunaan'))
print('  ' + '─'*80)
for name,install,desc in tools:
    print(f'  \033[1m{name:<18}\033[0m {install:<40} \033[2m{desc}\033[0m')
" 2>/dev/null

  echo ""
  log_report "CRYPTO_MODULE: Selesai — semua sub-analisis crypto dijalankan"
  ok "Modul Cryptography selesai."
}

# ─────────────────────────────────────────
#  REPORT SUMMARY
# ─────────────────────────────────────────
print_summary() {
  echo ""

  # ── AUTO DECODE semua kandidat yang ditemukan (sebelum SUMMARY) ──
  DECODE_HITS=()
  decode_flag_candidates

  echo ""
  echo -e "${BOLD}${C}╔══════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}${C}║         FASFO SCAN SUMMARY               ║${NC}"
  echo -e "${BOLD}${C}╚══════════════════════════════════════════╝${NC}"
  echo -e "  ${W}Target  :${NC} $TARGET"
  echo -e "  ${W}Waktu   :${NC} $(date '+%Y-%m-%d %H:%M:%S')"
  echo -e "  ${W}Report  :${NC} $REPORT_FILE"

  echo ""
  if [[ -f "$REPORT_FILE" ]] && grep -q "FLAG\|FOUND\|HIT" "$REPORT_FILE" 2>/dev/null; then
    echo -e "  ${M}${BOLD}[FLAG CANDIDATES]${NC}"
    grep -E "(FLAG|FOUND|HIT)" "$REPORT_FILE" | sed 's/^/  /' | head -10
  fi

  echo ""
  echo -e "  ${DIM}Scan selesai. Good luck on your CTF! 🚩${NC}"
  echo ""
}

# ─────────────────────────────────────────
#  MODULE 8 — WINDOWS REGISTRY ANALYSIS
# ─────────────────────────────────────────

# ── ROT13 decoder khusus UserAssist ──
_rot13() { echo "$1" | tr 'A-Za-z' 'N-ZA-Mn-za-m'; }

# ── Parse registry hive dengan reglookup ──
_reglookup_scan() {
  local hive="$1"
  local label="$2"
  if has reglookup; then
    local rl_out
    rl_out=$(reglookup "$hive" 2>/dev/null)
    if [[ -n "$rl_out" ]]; then
      ok "$label: reglookup berhasil membaca hive"
      log_report "REGLOOKUP_${label}: hive readable"
    else
      warn "$label: reglookup tidak bisa membaca hive (mungkin corrupt atau bukan registry hive)"
    fi
  else
    warn "reglookup tidak ditemukan — sudo apt install reglookup"
  fi
}

# ── Extract registry key values dengan reglookup ──
_reglookup_key() {
  local hive="$1"
  local key_path="$2"
  local label="$3"
  if has reglookup; then
    local kout
    kout=$(reglookup -r -p "$key_path" "$hive" 2>/dev/null)
    if [[ -n "$kout" ]]; then
      echo -e "  ${W}── $label ──${NC}"
      echo "$kout" | head -50 | sed 's/^/    /'
      # Cek flag di value
      local kflag
      kflag=$(echo "$kout" | grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC|XGH)\{[^}]+\}' 2>/dev/null)
      [[ -n "$kflag" ]] && found "FLAG di registry $label: $kflag" && log_report "REG_FLAG_${label}: $kflag"
      # Cek reversed flag
      local krev
      krev=$(echo "$kout" | grep -oE '\}[A-Za-z0-9_]{3,}\{[A-Za-z0-9]{2,10}' 2>/dev/null)
      if [[ -n "$krev" ]]; then
        found "REVERSED flag di registry $label — decode:"
        echo "$krev" | sort -u | head -10 | while IFS= read -r rf; do
          decode_string "$rf"
        done
      fi
    else
      info "$label: key tidak ditemukan atau kosong"
    fi
  fi
}

# ── Parse registry dengan RegRipper (rip.pl) ──
_regripper_scan() {
  local hive="$1"
  local hive_name="$2"
  local rip_cmd=""

  # Cek lokasi rip.pl
  for _rp in "rip.pl" "/usr/share/regripper/rip.pl" "/opt/regripper/rip.pl" \
             "$(find /usr -name 'rip.pl' 2>/dev/null | head -1)" \
             "$(find /opt -name 'rip.pl' 2>/dev/null | head -1)"; do
    [[ -x "$_rp" || -f "$_rp" ]] && { rip_cmd="$_p"; break; }
  done

  # Alternatif: cek regripper command
  if [[ -z "$rip_cmd" ]] && has regripper; then
    rip_cmd="regripper"
  fi

  if [[ -n "$rip_cmd" ]]; then
    info "Menjalankan RegRipper pada $hive_name ..."
    local rp_out
    rp_out=$("$rip_cmd" -r "$hive" -f "$hive_name" 2>/dev/null)
    if [[ -n "$rp_out" ]]; then
      echo "$rp_out" | head -80 | sed 's/^/    /'
      # Cek flag di output
      local rp_flag
      rp_flag=$(echo "$rp_out" | grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC|XGH)\{[^}]+\}' 2>/dev/null)
      [[ -n "$rp_flag" ]] && found "FLAG di RegRipper $hive_name: $rp_flag" && log_report "REG_RIPPER_FLAG_${hive_name}: $rp_flag"
      log_report "REG_RIPPER_${hive_name}: done"
    else
      warn "RegRipper tidak menghasilkan output untuk $hive_name"
    fi
  else
    warn "RegRipper (rip.pl) tidak ditemukan — install dari: https://github.com/keydet89/RegRipper3.0"
  fi
}

# ── Volatility3 registry extraction (dari memory dump) ──
_vol3_registry() {
  local target="$1"
  if [[ -z "$VOL3_CMD" ]]; then
    warn "volatility3 tidak ditemukan — skip registry memory extraction"
    return
  fi

  divider
  info "═══ Memory Registry Extraction (Volatility3) ═══"

  # List registry hives in memory
  divider
  info "Registry Hives in Memory"
  local hivelist
  hivelist=$($VOL3_CMD -f "$target" windows.registry.hivelist 2>/dev/null)
  if [[ -n "$hivelist" ]]; then
    echo "$hivelist" | head -30 | sed 's/^/    /'
    # Extract hive names untuk processing
    echo "$hivelist" | grep -oE '\b(SAM|SYSTEM|SOFTWARE|SECURITY|NTUSER\.DAT|UsrClass\.dat)\b' | \
      sort -u | while IFS= read -r hive; do
      ok "Hive ditemukan: $hive"
    done
  else
    warn "Tidak ada registry hive ditemukan di memory dump"
  fi

  # Extract key registry keys via printkey
  local printkey_keys=(
    "Microsoft\\Windows\\CurrentVersion\\Run"
    "Microsoft\\Windows\\CurrentVersion\\RunOnce"
    "Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
    "Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
    "CurrentControlSet\\Enum\\USB"
    "CurrentControlSet\\Control\\ComputerName\\ComputerName"
    "CurrentControlSet\\Control\\TimeZoneInformation"
  )

  for pk in "${printkey_keys[@]}"; do
    divider
    info "Registry Key: $pk"
    local pk_out
    pk_out=$($VOL3_CMD -f "$target" windows.registry.printkey --key "$pk" 2>/dev/null)
    if [[ -n "$pk_out" ]]; then
      echo "$pk_out" | head -40 | sed 's/^/    /'
      # Cek flag
      local pk_flag
      pk_flag=$(echo "$pk_out" | grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC|XGH)\{[^}]+\}' 2>/dev/null)
      [[ -n "$pk_flag" ]] && found "FLAG di memory registry ($pk): $pk_flag" && log_report "VOL3_REG_FLAG_${pk//\\/}: $pk_flag"
      # Cek reversed flag
      local pk_rev
      pk_rev=$(echo "$pk_out" | grep -oE '\}[A-Za-z0-9_]{3,}\{[A-Za-z0-9]{2,10}' 2>/dev/null)
      if [[ -n "$pk_rev" ]]; then
        found "REVERSED flag di memory registry ($pk) — decode:"
        echo "$pk_rev" | sort -u | head -5 | while IFS= read -r rf; do
          decode_string "$rf"
        done
      fi
    fi
  done

  # UserAssist — decode ROT13
  divider
  info "UserAssist Keys (ROT13 Decoded)"
  local ua_out
  ua_out=$($VOL3_CMD -f "$target" windows.registry.userassist 2>/dev/null)
  if [[ -n "$ua_out" ]]; then
    echo "$ua_out" | head -50 | sed 's/^/    /'
    # Decode ROT13 entries
    echo "$ua_out" | grep -v '^Volatility' | grep -v '^---' | \
      while IFS= read -r line; do
        local rot
        rot=$(_rot13 "$line")
        local ua_flag
        ua_flag=$(echo "$rot" | grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC|XGH)\{[^}]+\}' 2>/dev/null)
        [[ -n "$ua_flag" ]] && found "FLAG di UserAssist (ROT13 decoded): $ua_flag" && log_report "USERASSIST_FLAG: $ua_flag"
      done
    log_report "VOL3_USERASSIST: done"
  else
    info "Tidak ada UserAssist keys ditemukan"
  fi
}

# ── Parse Registry Export (.reg) text file ──
_parse_reg_export() {
  local target="$1"
  section "Registry Export File Analysis (.reg)"

  divider
  info "═══ Membaca Isi File .reg ═══"
  # Tampilkan isi file
  cat "$target" | head -100 | sed 's/^/    /'
  local total_lines
  total_lines=$(wc -l < "$target" 2>/dev/null || echo 0)
  ok "Total baris: $total_lines"
  log_report "REG_EXPORT_LINES: $total_lines"

  # ── Step 1: Identifikasi semua key path ──
  divider
  info "[Step 1] Registry Keys yang Ditemukan"
  local keys
  keys=$(grep -E '^\[HKEY_' "$target" 2>/dev/null)
  if [[ -n "$keys" ]]; then
    echo "$keys" | sed 's/^/    /'
    log_report "REG_EXPORT_KEYS: $(echo "$keys" | wc -l) keys"
  fi

  # ── Step 2: Identifikasi nilai mencurigakan ──
  divider
  info "[Step 2] Identifikasi Nilai Mencurigakan"

  # Cek key Run/RunOnce/RunServices (persistence)
  local run_keys
  run_keys=$(grep -iE 'RunOnce|RunServices|CurrentVersion\\Run|Winlogon\\Userinit' "$target" 2>/dev/null)
  if [[ -n "$run_keys" ]]; then
    found "Key startup/persistence ditemukan:"
    echo "$run_keys" | sed 's/^/    /'
    log_report "REG_EXPORT_PERSISTENCE: found"
  fi

  # ── Step 3: Extract & Decode Hex Values ──
  divider
  info "[Step 3] Extract & Decode Hex Data"

  # Pola: "KeyName"=hex:XX,XX,XX,...
  local hex_values
  hex_values=$(grep -E '"[^"]+"=hex:' "$target" 2>/dev/null)

  if [[ -n "$hex_values" ]]; then
    found "Hex-encoded values ditemukan:"

    # Proses multi-line hex values (continuation lines dengan \)
    # Gabungkan continuation lines dulu
    local merged_hex
    merged_hex=$(awk '
      /"[^"]+"=hex:/ {
        # Hapus prefix "key"=hex: dan kumpulkan hex bytes
        sub(/.*=hex:/, "")
        gsub(/\\/, "")
        gsub(/^[ \t]+/, "")
        printf "%s", $0
        next
      }
      /^[ \t]+[0-9a-fA-F]/ {
        gsub(/\\/, "")
        gsub(/^[ \t]+/, "")
        printf "%s", $0
        next
      }
      {
        # baris bukan continuation, reset
      }
    ' "$target" 2>/dev/null)

    # Juga coba pola single-line hex
    local single_line_hex
    single_line_hex=$(grep -E '"[^"]+"=hex:[0-9a-fA-F]' "$target" 2>/dev/null | sed 's/.*=hex://')

    # Gabungkan semua hex data
    local all_hex
    all_hex="${merged_hex}${single_line_hex}"
    all_hex=$(echo "$all_hex" | tr -d ' \\,' | tr -d '\n')

    if [[ -n "$all_hex" && ${#all_hex} -ge 4 ]]; then
      # Validasi: pastikan hanya hex chars
      if echo "$all_hex" | grep -qE '^[0-9a-fA-F]+$'; then
        info "Hex data terkumpul (${#all_hex} chars): ${all_hex:0:80}..."

        # Decode hex ke ASCII
        local decoded
        decoded=$(echo "$all_hex" | xxd -r -p 2>/dev/null | tr -d '\0')

        if [[ -n "$decoded" ]]; then
          found "HEX decode berhasil:"
          echo -e "    ${G}${BOLD}${decoded}${NC}"
          log_report "REG_EXPORT_HEX_DECODED: $decoded"

          # Cek flag di decoded
          local hex_flag
          hex_flag=$(echo "$decoded" | grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC|XGH)\{[^}]+\}' 2>/dev/null)
          if [[ -n "$hex_flag" ]]; then
            found "🚩 FLAG DITEMUKAN DI HEX DATA: ${BOLD}${hex_flag}${NC}"
            log_report "REG_EXPORT_FLAG: $hex_flag"
          fi
        else
          warn "Hex decode gagal (mungkin bukan ASCII)"
        fi

        # Tampilkan tabel hex → ASCII breakdown
        divider
        info "Hex → ASCII Breakdown"
        echo -e "    ${DIM}Hex\t\t\tASCII\tKeterangan${NC}"
        # Proses per 4-8 byte untuk readability
        echo "$all_hex" | fold -w 8 | while IFS= read -r chunk; do
          [[ -z "$chunk" ]] && continue
          local ascii_chunk
          ascii_chunk=$(echo "$chunk" | xxd -r -p 2>/dev/null | tr -d '\0' | cat -v)
          # Format comma-separated untuk display
          local comma_hex
          comma_hex=$(echo "$chunk" | sed 's/../&,/g' | sed 's/,$//')
          printf "    ${DIM}%s\t${NC}%s\n" "$comma_hex" "$ascii_chunk"
        done | head -20
      else
        warn "Data hex tidak valid (berisi karakter non-hex)"
      fi
    fi

    # Tampilkan hex values asli
    echo ""
    info "Raw hex values dari file:"
    echo "$hex_values" | head -30 | sed 's/^/    /'
    log_report "REG_EXPORT_HEX_RAW: $(echo "$hex_values" | wc -l) entries"
  else
    info "Tidak ada hex-encoded values ditemukan"
  fi

  # ── Step 4: String values ──
  divider
  info "[Step 4] String Values"
  local str_values
  str_values=$(grep -E '"[^"]+"="[^"]*"' "$target" 2>/dev/null | grep -v 'Windows Registry Editor' | grep -v '^;')
  if [[ -n "$str_values" ]]; then
    echo "$str_values" | head -40 | sed 's/^/    /'
    # Cek flag di string values
    local str_flag
    str_flag=$(echo "$str_values" | grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC|XGH)\{[^}]+\}' 2>/dev/null)
    if [[ -n "$str_flag" ]]; then
      found "FLAG di string value: ${BOLD}${str_flag}${NC}"
      log_report "REG_EXPORT_STR_FLAG: $str_flag"
    fi
    # Cek reversed flag
    local str_rev
    str_rev=$(echo "$str_values" | grep -oE '\}[A-Za-z0-9_]{3,}\{[A-Za-z0-9]{2,10}' 2>/dev/null)
    if [[ -n "$str_rev" ]]; then
      found "REVERSED flag di string value — decode:"
      echo "$str_rev" | sort -u | head -5 | while IFS= read -r rf; do
        decode_string "$rf"
      done
    fi
    log_report "REG_EXPORT_STR_VALUES: $(echo "$str_values" | wc -l) entries"
  fi

  # ── Step 5: Dword values ──
  divider
  info "[Step 5] Dword Values"
  local dword_values
  dword_values=$(grep -E '"[^"]+"=dword:' "$target" 2>/dev/null)
  if [[ -n "$dword_values" ]]; then
    echo "$dword_values" | sed 's/^/    /'
    log_report "REG_EXPORT_DWORD: $(echo "$dword_values" | wc -l) entries"
  fi

  # ── Step 6: Full file flag scan ──
  divider
  info "[Step 6] Full File Flag Pattern Scan"
  local file_flag
  file_flag=$(grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC|XGH)\{[^}]+\}' "$target" 2>/dev/null)
  if [[ -n "$file_flag" ]]; then
    found "FLAG ditemukan di file .reg:"
    echo "$file_flag" | sort -u | sed 's/^/    /'
    log_report "REG_EXPORT_FULL_FLAG: $file_flag"
  else
    ok "Tidak ada flag pattern eksplisit di file .reg"
  fi

  # Reversed flag scan di seluruh file
  local file_rev
  file_rev=$(grep -oE '\}[A-Za-z0-9_]{3,}\{[A-Za-z0-9]{2,10}' "$target" 2>/dev/null | sort -u)
  if [[ -n "$file_rev" ]]; then
    found "REVERSED flag di file .reg — decode:"
    echo "$file_rev" | head -10 | while IFS= read -r rf; do
      decode_string "$rf"
    done
    log_report "REG_EXPORT_FULL_REV: $file_rev"
  fi

  log_report "REG_EXPORT_ANALYSIS: completed"
}

# ── MAIN Registry Module ──
mod_registry() {
  section "Windows Registry Analysis"
  local target="$1"

  divider
  info "Deteksi Jenis Registry File"
  local fname
  fname=$(basename "$target" | tr '[:upper:]' '[:lower:]')
  local ftype
  ftype=$(file --brief "$target" 2>/dev/null | tr '[:upper:]' '[:lower:]')

  local hive_type="unknown"
  local hive_name="unknown"

  # ── Deteksi .reg export file (text-based) ──
  if [[ "$fname" == *.reg ]] || [[ "$ftype" == *"registry"* && "$ftype" != *"regf"* ]] || \
     head -1 "$target" 2>/dev/null | grep -qi "Windows Registry Editor\|REGEDIT4"; then
    hive_type="reg_export"
    hive_name="Registry Export (.reg)"
  fi

  # Deteksi registry hive file (binary)
  if [[ "$hive_type" == "unknown" ]]; then
    case "$fname" in
      sam*)            hive_type="sam";        hive_name="SAM" ;;
      system*)         hive_type="system";     hive_name="SYSTEM" ;;
      software*)       hive_type="software";   hive_name="SOFTWARE" ;;
      security*)       hive_type="security";   hive_name="SECURITY" ;;
      ntuser*)         hive_type="ntuser";     hive_name="NTUSER.DAT" ;;
      usrclass*)       hive_type="usrclass";   hive_name="UsrClass.dat" ;;
      *)
        # Cek magic bytes
        if [[ "$ftype" == *"registry"* ]] || [[ "$ftype" == *"regf"* ]]; then
          hive_type="auto"
          hive_name="Registry Hive (auto)"
        elif [[ "$ftype" == *"memory"* ]] || [[ "$ftype" == *"data"* ]] || [[ "$fname" == *".raw" ]]; then
          hive_type="memory"
          hive_name="Memory Dump"
        else
          # Cek apakah ini memory dump
          if file "$target" 2>/dev/null | grep -qi "memory\|dump\|crash\|hiberfil"; then
            hive_type="memory"
            hive_name="Memory Dump"
          fi
        fi
        ;;
    esac
  fi

  if [[ "$hive_type" == "unknown" ]]; then
    warn "File tidak terdeteksi sebagai registry file"
    warn "Format yang didukung: .reg export, SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT, UsrClass.dat, memory dump"
    info "Coba: fasfo $target --Forensics --file  untuk analisis file biasa"
    return
  fi

  ok "Jenis terdeteksi: ${BOLD}${hive_name}${NC} ${DIM}($ftype)${NC}"
  log_report "REGISTRY_TYPE: $hive_type"

  # ── Scenario 0: .reg Export File ──
  if [[ "$hive_type" == "reg_export" ]]; then
    _parse_reg_export "$target"
    return
  fi

  # ── Scenario A: Memory Dump → gunakan volatility3 ──
  if [[ "$hive_type" == "memory" ]]; then
    _vol3_registry "$target"
    # Juga coba strings pass sebagai fallback
    divider
    info "Quick strings pass pada memory dump (registry-related)"
    local mem_reg
    mem_reg=$(strings "$target" 2>/dev/null | grep -iE '(CurrentVersion|Microsoft|Windows|Run|RunOnce|Software)' | head -30)
    if [[ -n "$mem_reg" ]]; then
      echo "$mem_reg" | sed 's/^/    /'
      local mem_flag
      mem_flag=$(echo "$mem_reg" | grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC|XGH)\{[^}]+\}' 2>/dev/null)
      [[ -n "$mem_flag" ]] && found "FLAG di memory strings: $mem_flag" && log_report "MEM_REG_FLAG: $mem_flag"
    fi
    return
  fi

  # ── Scenario B: Offline Registry Hive File ──
  divider
  info "═══ Offline Registry Hive Analysis ═══"

  # Step 1: reglookup scan
  divider
  info "[Step 1] Hive Structure Scan (reglookup)"
  _reglookup_scan "$target" "$hive_name"

  # Step 2: reglookup key extraction — CTF-relevant keys
  divider
  info "[Step 2] Registry Key Extraction"

  # Definisikan key paths per hive type
  local -a keys_to_check=()

  case "$hive_type" in
    sam)
      keys_to_check=(
        "SAM\\Domains\\Account\\Users"
        "SAM\\Domains\\Account\\Users\\Names"
      ) ;;
    system)
      keys_to_check=(
        "CurrentControlSet\\Control\\ComputerName\\ComputerName"
        "CurrentControlSet\\Control\\TimeZoneInformation"
        "CurrentControlSet\\Control\\Windows"
        "CurrentControlSet\\Enum\\USB"
        "CurrentControlSet\\Enum\\USBSTOR"
        "ControlSet001\\Control\\ComputerName\\ComputerName"
        "MountedDevices"
      ) ;;
    software)
      keys_to_check=(
        "Microsoft\\Windows\\CurrentVersion\\Uninstall"
        "Microsoft\\Windows\\CurrentVersion\\Run"
        "Microsoft\\Windows\\CurrentVersion\\RunOnce"
        "Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"
        "Microsoft\\Windows NT\\CurrentVersion"
        "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"
      ) ;;
    security)
      keys_to_check=(
        "Policy\\PolAdtEv"
        "Policy\\PolAudit"
      ) ;;
    ntuser)
      keys_to_check=(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedURLs"
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"
        "Software\\Microsoft\\Internet Explorer\\TypedURLs"
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
        "Software\\Microsoft\\Windows\\Shell\\Bags"
        "Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit"
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSaveMRU"
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedMRU"
      ) ;;
    usrclass)
      keys_to_check=(
        "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU"
        "Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags"
        "Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache"
      ) ;;
    auto)
      # Coba semua key umum
      keys_to_check=(
        "Microsoft\\Windows\\CurrentVersion\\Run"
        "Microsoft\\Windows\\CurrentVersion\\RunOnce"
        "Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
        "Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
        "CurrentControlSet\\Enum\\USB"
        "CurrentControlSet\\Control\\ComputerName\\ComputerName"
        "Microsoft\\Windows\\CurrentVersion\\Uninstall"
        "Microsoft\\Windows NT\\CurrentVersion"
        "SAM\\Domains\\Account\\Users"
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedURLs"
      ) ;;
  esac

  for key in "${keys_to_check[@]}"; do
    _reglookup_key "$target" "$key" "$hive_name → $key"
  done

  # Step 3: UserAssist ROT13 decoding
  divider
  info "[Step 3] UserAssist ROT13 Decoding"
  if [[ "$hive_type" == "ntuser" || "$hive_type" == "auto" ]]; then
    if has reglookup; then
      local ua_raw
      ua_raw=$(reglookup -r -p "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist" "$target" 2>/dev/null)
      if [[ -n "$ua_raw" ]]; then
        # Ekstrak value names dan decode ROT13
        echo "$ua_raw" | grep -v '^Path' | grep -v '^Last' | grep -v '^Size' | \
          grep '|' | while IFS='|' read -r path lastmod size value; do
          local decoded_name
          decoded_name=$(_rot13 "$path")
          if [[ -n "$decoded_name" && "$decoded_name" != "$path" ]]; then
            echo -e "    ${DIM}$path${NC} → ${G}${decoded_name}${NC}"
            # Cek flag di decoded name
            local ua_flag
            ua_flag=$(echo "$decoded_name" | grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC|XGH)\{[^}]+\}' 2>/dev/null)
            [[ -n "$ua_flag" ]] && found "FLAG di UserAssist (ROT13): $ua_flag" && log_report "USERASSIST_FLAG: $ua_flag"
          fi
        done
        log_report "USERASSIST_DECODED: done"
      else
        info "Tidak ada UserAssist entries ditemukan"
      fi
    fi
  else
    info "UserAssist hanya tersedia di hive NTUSER.DAT"
  fi

  # Step 4: Run Keys analysis
  divider
  info "[Step 4] Run Keys (Persistence Analysis)"
  local run_keys=(
    "Microsoft\\Windows\\CurrentVersion\\Run"
    "Microsoft\\Windows\\CurrentVersion\\RunOnce"
    "Microsoft\\Windows\\CurrentVersion\\RunServices"
    "Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"
    "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit"
  )
  for rk in "${run_keys[@]}"; do
    if has reglookup; then
      local rk_out
      rk_out=$(reglookup -r -p "$rk" "$target" 2>/dev/null)
      if [[ -n "$rk_out" ]]; then
        found "Run key ditemukan: $rk"
        echo "$rk_out" | sed 's/^/    /'
        # Cek flag
        local rk_flag
        rk_flag=$(echo "$rk_out" | grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC|XGH)\{[^}]+\}' 2>/dev/null)
        [[ -n "$rk_flag" ]] && found "FLAG di Run key ($rk): $rk_flag" && log_report "RUNKEY_FLAG_${rk//\\/}: $rk_flag"
        log_report "RUNKEY_${rk//\\/}: found"
      fi
    fi
  done

  # Step 5: USB Device History
  divider
  info "[Step 5] USB Device History"
  if [[ "$hive_type" == "system" || "$hive_type" == "auto" ]]; then
    if has reglookup; then
      local usb_out
      usb_out=$(reglookup -r -p "CurrentControlSet\\Enum\\USB" "$target" 2>/dev/null)
      if [[ -n "$usb_out" ]]; then
        echo "$usb_out" | head -40 | sed 's/^/    /'
        # Hitung unique USB devices
        local usb_count
        usb_count=$(echo "$usb_out" | grep -c '|' 2>/dev/null || echo 0)
        ok "Total USB device entries: $usb_count"
        log_report "USB_DEVICES: $usb_count entries"
        # Cek flag
        local usb_flag
        usb_flag=$(echo "$usb_out" | grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC|XGH)\{[^}]+\}' 2>/dev/null)
        [[ -n "$usb_flag" ]] && found "FLAG di USB history: $usb_flag" && log_report "USB_FLAG: $usb_flag"
      else
        info "Tidak ada USB device history ditemukan"
      fi

      # USBSTOR
      local usbstor_out
      usbstor_out=$(reglookup -r -p "CurrentControlSet\\Enum\\USBSTOR" "$target" 2>/dev/null)
      if [[ -n "$usbstor_out" ]]; then
        found "USBSTOR entries ditemukan:"
        echo "$usbstor_out" | head -30 | sed 's/^/    /'
        log_report "USBSTOR: found"
      fi
    fi
  else
    info "USB history hanya tersedia di hive SYSTEM"
  fi

  # Step 6: RecentDocs & MRU
  divider
  info "[Step 6] Recent Documents & MRU Lists"
  if [[ "$hive_type" == "ntuser" || "$hive_type" == "auto" ]]; then
    local mru_keys=(
      "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
      "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"
      "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSaveMRU"
      "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedMRU"
      "Software\\Microsoft\\Internet Explorer\\TypedURLs"
    )
    for mk in "${mru_keys[@]}"; do
      if has reglookup; then
        local mk_out
        mk_out=$(reglookup -r -p "$mk" "$target" 2>/dev/null)
        if [[ -n "$mk_out" ]]; then
          echo -e "  ${W}── $mk ──${NC}"
          echo "$mk_out" | head -25 | sed 's/^/    /'
          local mk_flag
          mk_flag=$(echo "$mk_out" | grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC|XGH)\{[^}]+\}' 2>/dev/null)
          [[ -n "$mk_flag" ]] && found "FLAG di MRU ($mk): $mk_flag" && log_report "MRU_FLAG_${mk//\\/}: $mk_flag"
          log_report "MRU_${mk//\\/}: found"
        fi
      fi
    done
  fi

  # Step 7: Installed Programs
  divider
  info "[Step 7] Installed Programs (Uninstall Keys)"
  if [[ "$hive_type" == "software" || "$hive_type" == "auto" ]]; then
    if has reglookup; then
      local uni_out
      uni_out=$(reglookup -r -p "Microsoft\\Windows\\CurrentVersion\\Uninstall" "$target" 2>/dev/null)
      if [[ -n "$uni_out" ]]; then
        echo "$uni_out" | grep -E '\|DisplayName\||\|DisplayVersion\|' | head -30 | sed 's/^/    /'
        local uni_count
        uni_count=$(echo "$uni_out" | grep -c 'DisplayName' 2>/dev/null || echo 0)
        ok "Total installed programs: $uni_count"
        log_report "INSTALLED_PROGRAMS: $uni_count"
        # Cek program mencurigakan
        local sus_prog
        sus_prog=$(echo "$uni_out" | grep -iE '(ncat|netcat|meterpreter|cobalt|sliver|mythic|psexec|mimikatz|lazagne|seatbelt|rubeus|sharphound|bloodhound|juicypotato|godpotato|printspoofer|spoolsample| PetitPotam|DFSCoerce)' 2>/dev/null)
        [[ -n "$sus_prog" ]] && found "Program mencurigakan ditemukan:\n$sus_prog" && log_report "SUS_PROGRAMS: $sus_prog"
      else
        info "Tidak ada installed programs ditemukan"
      fi
    fi
  else
    info "Installed programs hanya tersedia di hive SOFTWARE"
  fi

  # Step 8: System Info (ComputerName, TimeZone, Shutdown)
  divider
  info "[Step 8] System Information"
  local sys_keys=(
    "CurrentControlSet\\Control\\ComputerName\\ComputerName"
    "CurrentControlSet\\Control\\TimeZoneInformation"
    "CurrentControlSet\\Control\\Windows\\ShutdownTime"
  )
  for sk in "${sys_keys[@]}"; do
    if has reglookup; then
      local sk_out
      sk_out=$(reglookup -r -p "$sk" "$target" 2>/dev/null)
      if [[ -n "$sk_out" ]]; then
        echo -e "  ${W}── $sk ──${NC}"
        echo "$sk_out" | sed 's/^/    /'
      fi
    fi
  done

  # Step 9: SAM Users (jika hive SAM)
  if [[ "$hive_type" == "sam" || "$hive_type" == "auto" ]]; then
    divider
    info "[Step 9] SAM User Accounts"
    if has reglookup; then
      local sam_out
      sam_out=$(reglookup -r -p "SAM\\Domains\\Account\\Users\\Names" "$target" 2>/dev/null)
      if [[ -n "$sam_out" ]]; then
        found "SAM user accounts ditemukan:"
        echo "$sam_out" | sed 's/^/    /'
        log_report "SAM_USERS: $sam_out"
      else
        info "Tidak ada SAM user accounts ditemukan"
      fi
    fi
  fi

  # Step 10: RegRipper full analysis (jika tersedia)
  divider
  info "[Step 10] RegRipper Full Analysis"
  _regripper_scan "$target" "$hive_type"

  # Step 11: Flag Pattern Scan di seluruh hive
  divider
  info "[Step 11] Full Hive Flag Pattern Scan"
  if has reglookup; then
    local full_scan
    full_scan=$(reglookup "$target" 2>/dev/null)
    if [[ -n "$full_scan" ]]; then
      local all_flags
      all_flags=$(echo "$full_scan" | grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC|XGH)\{[^}]+\}' 2>/dev/null)
      if [[ -n "$all_flags" ]]; then
        found "FLAG ditemukan di full hive scan:"
        echo "$all_flags" | sort -u | sed 's/^/    /'
        log_report "REG_FULL_FLAG: $all_flags"
      else
        ok "Tidak ada flag pattern eksplisit di full hive scan"
      fi
      # Reversed flag scan
      local all_rev
      all_rev=$(echo "$full_scan" | grep -oE '\}[A-Za-z0-9_]{3,}\{[A-Za-z0-9]{2,10}' 2>/dev/null | sort -u)
      if [[ -n "$all_rev" ]]; then
        found "REVERSED flag ditemukan di full hive scan — decode:"
        echo "$all_rev" | head -10 | while IFS= read -r rf; do
          decode_string "$rf"
        done
        log_report "REG_FULL_REV: $all_rev"
      fi
      # Base64/hex scan
      local all_enc
      all_enc=$(echo "$full_scan" | grep -oE '([A-Za-z0-9+/]{24,}={0,2}|[0-9a-fA-F]{32,64})' 2>/dev/null | sort -u | head -10)
      if [[ -n "$all_enc" ]]; then
        info "Encoded strings di hive — coba decode:"
        echo "$all_enc" | while IFS= read -r es; do
          decode_string "$es"
        done
        log_report "REG_FULL_ENC: found"
      fi
    fi
  fi

  log_report "REGISTRY_ANALYSIS: $hive_name completed"
}

# ─────────────────────────────────────────
#  MODULE 9 — WINDOWS ARTIFACT ANALYSIS
# ─────────────────────────────────────────

# ── LNK File Analysis ──
_parse_lnk() {
  local target="$1"
  divider
  info "LNK File Analysis"
  local ftype
  ftype=$(file --brief "$target" 2>/dev/null | tr '[:upper:]' '[:lower:]')

  if [[ "$ftype" != *"shortcut"* ]] && [[ "$ftype" != *"lnk"* ]]; then
    warn "File bukan LNK shortcut — skip"
    return
  fi

  # Strings analysis pada LNK (target path, arguments, dll)
  divider
  info "LNK Target & Arguments (strings)"
  local lnk_strings
  lnk_strings=$(strings "$target" 2>/dev/null | grep -iE '(^[A-Z]:\\\\|\.exe|\.bat|\.ps1|\.vbs|\.cmd|\.msi)' | head -20)
  if [[ -n "$lnk_strings" ]]; then
    echo "$lnk_strings" | sed 's/^/    /'
    local lnk_flag
    lnk_flag=$(echo "$lnk_strings" | grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC|XGH)\{[^}]+\}' 2>/dev/null)
    [[ -n "$lnk_flag" ]] && found "FLAG di LNK file: $lnk_flag" && log_report "LNK_FLAG: $lnk_flag"
    log_report "LNK_TARGETS: $lnk_strings"
  fi

  # Cek flag di raw strings
  local raw_lnk_flag
  raw_lnk_flag=$(strings "$target" 2>/dev/null | grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC|XGH)\{[^}]+\}' 2>/dev/null)
  [[ -n "$raw_lnk_flag" ]] && found "FLAG di LNK raw strings: $raw_lnk_flag" && log_report "LNK_RAW_FLAG: $raw_lnk_flag"

  # Hex dump header
  divider
  info "LNK Header (hex)"
  if has xxd; then
    xxd "$target" 2>/dev/null | head -8 | sed 's/^/    /'
  fi

  # LNK file info via file command
  divider
  info "LNK File Info"
  file -v "$target" 2>/dev/null | sed 's/^/    /'
}

# ── Prefetch File Analysis ──
_parse_prefetch() {
  local target="$1"
  divider
  info "Prefetch File Analysis"
  local ftype
  ftype=$(file --brief "$target" 2>/dev/null | tr '[:upper:]' '[:lower:]')
  local fname
  fname=$(basename "$target" | tr '[:upper:]' '[:lower:]')

  if [[ "$ftype" != *"prefetch"* ]] && [[ "$fname" != *.pf ]]; then
    warn "File bukan Prefetch file — skip"
    return
  fi

  # Ekstrak executable name dari filename
  local exe_name
  exe_name=$(echo "$fname" | sed 's/\.pf$//' | sed 's/-[A-F0-9]*$//')
  ok "Executable: $exe_name"
  log_report "PREFETCH_EXE: $exe_name"

  # Strings analysis
  divider
  info "Prefetch Strings (DLLs, paths)"
  local pf_strings
  pf_strings=$(strings "$target" 2>/dev/null | grep -iE '(^[A-Z]:\\\\|\.dll|\.exe|\.sys|Program Files|Windows\\System32)' | head -30)
  if [[ -n "$pf_strings" ]]; then
    echo "$pf_strings" | sed 's/^/    /'
    log_report "PREFETCH_STRINGS: $pf_strings"
  fi

  # Cek flag
  local pf_flag
  pf_flag=$(strings "$target" 2>/dev/null | grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC|XGH)\{[^}]+\}' 2>/dev/null)
  [[ -n "$pf_flag" ]] && found "FLAG di Prefetch file: $pf_flag" && log_report "PREFETCH_FLAG: $pf_flag"

  # Reversed flag
  local pf_rev
  pf_rev=$(strings "$target" 2>/dev/null | grep -oE '\}[A-Za-z0-9_]{3,}\{[A-Za-z0-9]{2,10}' 2>/dev/null)
  if [[ -n "$pf_rev" ]]; then
    found "REVERSED flag di Prefetch — decode:"
    echo "$pf_rev" | sort -u | head -5 | while IFS= read -r rf; do
      decode_string "$rf"
    done
  fi

  # Hex dump
  divider
  info "Prefetch Header (hex)"
  if has xxd; then
    xxd "$target" 2>/dev/null | head -8 | sed 's/^/    /'
  fi
}

# ── Windows Event Log (.evtx) Analysis ──
_parse_evtx() {
  local target="$1"
  divider
  info "Windows Event Log (.evtx) Analysis"
  local ftype
  ftype=$(file --brief "$target" 2>/dev/null | tr '[:upper:]' '[:lower:]')

  if [[ "$ftype" != *"evt"* ]] && [[ "$(basename "$target")" != *.evtx ]]; then
    warn "File bukan Windows Event Log — skip"
    return
  fi

  # Cek apakah evtx_dump tersedia
  local evtx_tool=""
  for _et in "evtx_dump" "evtxinfo" "python-evtx"; do
    has "$_et" && { evtx_tool="$_et"; break; }
  done

  if [[ -n "$evtx_tool" ]]; then
    info "Parsing EVTX dengan $evtx_tool ..."
    local evtx_out
    evtx_out=$("$evtx_tool" "$target" 2>/dev/null | head -100)
    if [[ -n "$evtx_out" ]]; then
      echo "$evtx_out" | head -80 | sed 's/^/    /'
      # Cek flag
      local evtx_flag
      evtx_flag=$(echo "$evtx_out" | grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC|XGH)\{[^}]+\}' 2>/dev/null)
      [[ -n "$evtx_flag" ]] && found "FLAG di Event Log: $evtx_flag" && log_report "EVTX_FLAG: $evtx_flag"
      log_report "EVTX: parsed"
    fi
  else
    warn "evtx_dump tidak ditemukan — install: pip3 install python-evtx"
    warn "Atau: sudo apt install libevtx-utils"
    info "Fallback: strings analysis"
  fi

  # Fallback: strings analysis
  divider
  info "Event Log Strings (fallback)"
  local evtx_strings
  evtx_strings=$(strings "$target" 2>/dev/null | grep -iE '(Logon|Logoff|Error|Warning|Audit|4624|4625|4688|4698|4699)' | head -20)
  if [[ -n "$evtx_strings" ]]; then
    echo "$evtx_strings" | sed 's/^/    /'
    log_report "EVTX_STRINGS: $evtx_strings"
  fi

  # Cek flag di strings
  local evtx_sflag
  evtx_sflag=$(strings "$target" 2>/dev/null | grep -oiE '(flag|CTF|picoCTF|HTB|THM|DUCTF|REDLIMIT|FTC|XGH)\{[^}]+\}' 2>/dev/null)
  [[ -n "$evtx_sflag" ]] && found "FLAG di EVTX strings: $evtx_sflag" && log_report "EVTX_SFLAG: $evtx_sflag"
}

# ── MAIN Windows Artifact Module ──
mod_windows_artifacts() {
  section "Windows Artifact Analysis"
  local target="$1"

  divider
  info "Deteksi Jenis Artifact Windows"
  local fname
  fname=$(basename "$target" | tr '[:upper:]' '[:lower:]')
  local ftype
  ftype=$(file --brief "$target" 2>/dev/null | tr '[:upper:]' '[:lower:]')

  ok "File: ${BOLD}$fname${NC} ${DIM}($ftype)${NC}"

  # Deteksi dan parse berdasarkan tipe
  if [[ "$ftype" == *"shortcut"* ]] || [[ "$fname" == *.lnk ]]; then
    _parse_lnk "$target"
  elif [[ "$ftype" == *"prefetch"* ]] || [[ "$fname" == *.pf ]]; then
    _parse_prefetch "$target"
  elif [[ "$ftype" == *"evt"* ]] || [[ "$fname" == *.evtx ]]; then
    _parse_evtx "$target"
  else
    warn "Tipe file tidak dikenali sebagai Windows artifact standar"
    warn "Tipe yang didukung: LNK (.lnk), Prefetch (.pf), Event Log (.evtx)"
    info "Jalankan analisis file biasa sebagai fallback:"
    mod_file_analysis "$target"
  fi
}

# ─────────────────────────────────────────
#  HELP
# ─────────────────────────────────────────
show_help() {
  banner
  echo -e "${W}Usage:${NC}"
  echo -e "  fasfo <target> --Forensics [options]"
  echo ""
  echo -e "${W}Contoh:${NC}"
  echo -e "  fasfo image.png    --Forensics            ${DIM}# full scan${NC}"
  echo -e "  fasfo capture.pcap --Forensics --net      ${DIM}# network only${NC}"
  echo -e "  fasfo memory.raw   --Forensics --mem      ${DIM}# memory only${NC}"
  echo -e "  fasfo photo.jpg    --Forensics --stego    ${DIM}# stego only${NC}"
  echo -e "  fasfo domain.com   --Forensics --osint    ${DIM}# osint only${NC}"
  echo -e "  fasfo secret.zip   --Forensics --archive  ${DIM}# archive analysis + bruteforce${NC}"
  echo -e "  fasfo auth.log     --Forensics --log      ${DIM}# log analysis (auth/ssh)${NC}"
  echo -e "  fasfo SAM          --Forensics --registry  ${DIM}# registry hive${NC}"
  echo -e "  fasfo link.lnk     --Forensics --windows   ${DIM}# LNK/Prefetch/EVTX${NC}"
  echo -e "  fasfo binary.elf   --Forensics --adv-file  ${DIM}# deep file inspect + malware triage${NC}"
  echo -e "  fasfo memory.raw   --Forensics --adv-mem   ${DIM}# hidden proc, DLL inject, NTFS timeline${NC}"
  echo -e "  fasfo capture.pcap --Forensics --adv-net   ${DIM}# C2 detect, file recon, covert channel${NC}"
  echo -e "  fasfo photo.jpg    --Forensics --adv-stego ${DIM}# chi-square, LSB stats, audio, noise${NC}"
  echo -e "  fasfo cipher.txt   --Forensics --crypto    ${DIM}# crypto: Caesar, RSA, AES, hash, XOR${NC}"
  echo -e "  fasfo key.pem      --Forensics --crypto    ${DIM}# RSA key analysis + attack identification${NC}"
  echo -e "  fasfo --decode \"}tc4f1tr4_fn1_nur0tu4{FTC\"  ${DIM}# decode langsung${NC}"
  echo -e "  fasfo --decode \"RlRDe3R1cjBfMW5fNHJ0MTRmY3R9\"  ${DIM}# base64 decode${NC}"
  echo ""
  echo -e "${W}Core Options:${NC}"
  echo -e "  --Forensics     Wajib — aktifkan mode forensics"
  echo -e "  --decode        Decode string langsung (base64, hex, rot13, reversed, dll)"
  echo -e "  --file          Modul file analysis (magic bytes, strings, binwalk)"
  echo -e "  --stego         Modul steganography (zsteg, steghide, outguess)"
  echo -e "  --net           Modul network forensics + DNS tunneling"
  echo -e "  --mem           Modul memory forensics (volatility3)"
  echo -e "  --osint         Modul OSINT (whois, DNS, recon)"
  echo -e "  --archive       Modul archive (zip/rar/7z/tar + bruteforce)"
  echo -e "  --log           Modul log analysis (auth, http, syslog, wtmp)"
  echo -e "  --registry      Modul registry (SAM/SYSTEM/NTUSER/memory)"
  echo -e "  --windows       Modul Windows artifact (LNK/Prefetch/EVTX)"
  echo ""
  echo -e "${W}Advanced Options (v4.0.0):${NC}"
  echo -e "  --adv-file      Deep file inspect: chunk parsing, polyglot, XOR brute, malware triage"
  echo -e "  --adv-mem       Advanced DFIR: hidden proc, DLL inject, SSDT hooks, NTFS timeline"
  echo -e "  --adv-net       Advanced network: file recon PCAP, C2 detection, covert channels"
  echo -e "  --adv-stego     Advanced stego: chi-square, entropy, audio LSB, freq domain, noise"
  echo ""
  echo -e "${W}Crypto Options (v5.0.0 — NEW):${NC}"
  echo -e "  --crypto        ${M}🔐 NEW${NC} Full crypto suite:"
  echo -e "                  ${DIM}├─ Classical: Caesar/ROT brute, freq analysis, Vigenere Kasiski${NC}"
  echo -e "                  ${DIM}├─ Symmetric: AES ECB/CBC detect, padding oracle, XOR brute force${NC}"
  echo -e "                  ${DIM}├─ Asymmetric: RSA key parse, small-e/Wiener/common-factor hints${NC}"
  echo -e "                  ${DIM}├─ Hashing: MD5/SHA1/SHA256/bcrypt detect + john crack + online refs${NC}"
  echo -e "                  ${DIM}└─ Flaws: weak RNG, nonce reuse, entropy analysis, timing attack hints${NC}"
  echo ""
  echo -e "${W}Misc:${NC}"
  echo -e "  --deps          Cek semua dependency"
  echo -e "  --install       Install fasfo ke /usr/local/bin"
  echo -e "  --version       Tampilkan versi"
  echo -e "  --help, -h      Tampilkan bantuan ini"
  echo ""
  echo -e "${W}Env vars:${NC}"
  echo -e "  FASFO_WORDLIST=/path/to/wordlist.txt  ${DIM}# custom wordlist untuk bruteforce${NC}"
  echo ""
}

# ─────────────────────────────────────────
#  INSTALL (copy ke /usr/local/bin)
# ─────────────────────────────────────────
install_self() {
  local dest="/usr/local/bin/fasfo"
  echo -e "${C}[*]${NC} Menginstall fasfo ke $dest ..."
  sudo cp "$0" "$dest"
  sudo chmod +x "$dest"
  echo -e "${G}[+]${NC} Done! Jalankan: ${W}fasfo --help${NC}"
}

# ─────────────────────────────────────────
#  INTERACTIVE MENU HELPERS
# ─────────────────────────────────────────

# Tampilkan menu dengan nomor, kembalikan pilihan user
# Usage: menu_select "Judul" "opt1" "opt2" ...
# Return: pilihan di variabel MENU_CHOICE (string) dan MENU_IDX (angka 1-based)
menu_select() {
  local title="$1"; shift
  local opts=("$@")
  local total=${#opts[@]}

  echo ""
  echo -e "  ${BOLD}${C}┌─────────────────────────────────────────┐${NC}"
  printf  "  ${BOLD}${C}│${NC}  %-39s${BOLD}${C}│${NC}\n" "$title"
  echo -e "  ${BOLD}${C}├─────────────────────────────────────────┤${NC}"
  for i in "${!opts[@]}"; do
    printf  "  ${BOLD}${C}│${NC}  ${W}[%d]${NC} %-35s${BOLD}${C}│${NC}\n" "$((i+1))" "${opts[$i]}"
  done
  echo -e "  ${BOLD}${C}│${NC}  ${DIM}[0] Keluar / Batal${NC}$(printf '%*s' $((21)) '')${BOLD}${C}│${NC}"
  echo -e "  ${BOLD}${C}└─────────────────────────────────────────┘${NC}"
  echo ""

  while true; do
    printf "  ${Y}▶${NC} Pilih [0-${total}]: "
    read -r MENU_IDX
    if [[ "$MENU_IDX" == "0" ]]; then
      echo -e "  ${DIM}Keluar.${NC}"
      exit 0
    elif [[ "$MENU_IDX" =~ ^[0-9]+$ ]] && (( MENU_IDX >= 1 && MENU_IDX <= total )); then
      MENU_CHOICE="${opts[$((MENU_IDX-1))]}"
      echo ""
      return 0
    else
      echo -e "  ${R}[!]${NC} Pilihan tidak valid, masukkan angka 1-${total} atau 0 untuk keluar."
    fi
  done
}

# Menu multi-pilih (tekan nomor, Enter kosong = selesai)
# Usage: menu_multiselect "Judul" "opt1" "opt2" ...
# Return: array MENU_SELECTED berisi indeks (0-based) yang dipilih
menu_multiselect() {
  local title="$1"; shift
  local opts=("$@")
  local total=${#opts[@]}
  MENU_SELECTED=()

  echo ""
  echo -e "  ${BOLD}${C}┌─────────────────────────────────────────┐${NC}"
  printf  "  ${BOLD}${C}│${NC}  %-39s${BOLD}${C}│${NC}\n" "$title"
  printf  "  ${BOLD}${C}│${NC}  ${DIM}%-39s${NC}${BOLD}${C}│${NC}\n" "(pilih beberapa, pisah spasi)"
  echo -e "  ${BOLD}${C}├─────────────────────────────────────────┤${NC}"
  for i in "${!opts[@]}"; do
    printf  "  ${BOLD}${C}│${NC}  ${W}[%d]${NC} %-35s${BOLD}${C}│${NC}\n" "$((i+1))" "${opts[$i]}"
  done
  echo -e "  ${BOLD}${C}│${NC}  ${W}[a]${NC} %-35s${BOLD}${C}│${NC}" "Pilih SEMUA modul"
  echo -e "  ${BOLD}${C}│${NC}  ${DIM}[0] Keluar / Batal${NC}$(printf '%*s' $((21)) '')${BOLD}${C}│${NC}"
  echo -e "  ${BOLD}${C}└─────────────────────────────────────────┘${NC}"
  echo ""

  while true; do
    printf "  ${Y}▶${NC} Pilih modul [contoh: 1 3 5 atau a]: "
    read -r raw_input

    [[ "$raw_input" == "0" ]] && echo -e "  ${DIM}Keluar.${NC}" && exit 0

    if [[ "$raw_input" == "a" || "$raw_input" == "A" ]]; then
      for i in "${!opts[@]}"; do MENU_SELECTED+=("$i"); done
      echo -e "  ${G}[+]${NC} Semua modul dipilih."
      echo ""
      return 0
    fi

    local valid=true
    local selected_tmp=()
    for tok in $raw_input; do
      if [[ "$tok" =~ ^[0-9]+$ ]] && (( tok >= 1 && tok <= total )); then
        selected_tmp+=("$((tok-1))")
      else
        echo -e "  ${R}[!]${NC} Pilihan '$tok' tidak valid."
        valid=false
        break
      fi
    done

    if [[ "$valid" == true && ${#selected_tmp[@]} -gt 0 ]]; then
      # deduplicate
      local seen=()
      for idx in "${selected_tmp[@]}"; do
        local dup=false
        for s in "${seen[@]}"; do [[ "$s" == "$idx" ]] && dup=true; done
        [[ "$dup" == false ]] && seen+=("$idx")
      done
      MENU_SELECTED=("${seen[@]}")
      echo -e "  ${G}[+]${NC} Modul dipilih: $(for i in "${MENU_SELECTED[@]}"; do printf '[%s] ' "${opts[$i]}"; done)"
      echo ""
      return 0
    else
      echo -e "  ${R}[!]${NC} Pilih minimal satu modul yang valid."
    fi
  done
}

# ─────────────────────────────────────────
#  MENU UTAMA — MODE PILIH
# ─────────────────────────────────────────
menu_mode_utama() {
  local target="$1"

  # Info file singkat
  local ftype_info=""
  if [[ -f "$target" ]]; then
    ftype_info=$(file --brief "$target" 2>/dev/null | cut -c1-45)
  elif [[ "$target" =~ ^https?:// || "$target" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    ftype_info="URL / Domain"
  fi

  echo ""
  echo -e "  ${W}Target :${NC} ${BOLD}$target${NC}"
  [[ -n "$ftype_info" ]] && echo -e "  ${W}Tipe   :${NC} ${DIM}$ftype_info${NC}"
  [[ -f "$target" ]] && echo -e "  ${W}Ukuran :${NC} ${DIM}$(du -sh "$target" 2>/dev/null | cut -f1)${NC}"

  menu_select "Pilih Mode Analisis" \
    "🔍  Forensics — Analisis file / CTF" \
    "🔐  Crypto    — Analisis kriptografi & enkripsi" \
    "🔧  Dependency Check — Cek tools" \
    "ℹ️   Info & Help" \
    "🗑️   Lihat Laporan Tersimpan"

  case "$MENU_IDX" in
    1) menu_forensics "$target" ;;
    2) menu_crypto "$target" ;;
    3) banner; check_deps ;;
    4) show_help ;;
    5) menu_laporan ;;
  esac
}

# ─────────────────────────────────────────
#  MENU FORENSICS — PILIH MODUL
# ─────────────────────────────────────────
menu_forensics() {
  local target="$1"

  echo -e "\n  ${C}[*]${NC} Mode: ${BOLD}Forensics${NC} → Target: ${W}$target${NC}"

  # Susun daftar modul + auto-highlight modul yang relevan
  local modul_opts=(
    "📁  File Analysis       — magic bytes, strings, binwalk, exiftool"
    "🖼️   Steganography       — zsteg, steghide, outguess, stegsolve"
    "🌐  Network Forensics   — PCAP / tshark + DNS tunneling"
    "🧠  Memory Forensics    — volatility3 / strings"
    "📦  Archive Analysis    — ZIP/RAR/7Z + bruteforce"
    "🗒️   Log Analysis        — auth, http, syslog, wtmp, dll"
    "️   OSINT               — whois, DNS, metadata recon"
    "🪟  Registry Analysis   — SAM/SYSTEM/NTUSER/UserAssist/Run keys"
    "💻  Windows Artifacts   — LNK / Prefetch / Event Log (.evtx)"
    "🔬  Advanced File       — deep inspect, polyglot, XOR, malware triage"
    "🧬  Advanced Memory     — hidden proc, DLL inject, NTFS, timeline"
    "📡  Advanced Network    — file recon, C2 detect, covert channel"
    "🎭  Advanced Stego      — chi-square, audio, frequency, noise"
    "⚡  Full Scan           — Jalankan SEMUA modul sesuai tipe file"
  )

  # Auto-hint modul yang kemungkinan relevan berdasarkan tipe file
  if [[ -f "$target" ]]; then
    local _ft _bn
    _ft=$(file --brief "$target" 2>/dev/null | tr '[:upper:]' '[:lower:]')
    _bn=$(basename "$target" | tr '[:upper:]' '[:lower:]')
    echo ""
    echo -e "  ${Y}[!]${NC} ${BOLD}Saran modul berdasarkan tipe file:${NC}"
    echo "$_ft" | grep -qiE "png|jpeg|gif|bmp|tiff|image" && \
      echo -e "      ${G}→${NC} File Gambar terdeteksi — disarankan: ${W}[1] File Analysis${NC} + ${W}[2] Steganography${NC} ${DIM}(incl. StegCrack brute-force)${NC}"
    echo "$_ft" | grep -qiE "pcap|tcpdump|capture" && \
      echo -e "      ${G}→${NC} PCAP terdeteksi — disarankan: ${W}[3] Network Forensics${NC}"
    echo "$_ft" | grep -qiE "zip|rar|7-zip|gzip|bzip|tar" && \
      echo -e "      ${G}→${NC} Archive terdeteksi — disarankan: ${W}[5] Archive Analysis${NC}"
    echo "$_bn" | grep -qiE "auth\.log|secure|access\.log|syslog|messages|wtmp|btmp|\.log$" && \
      echo -e "      ${G}→${NC} Log file terdeteksi — disarankan: ${W}[6] Log Analysis${NC}"
    echo "$_ft" | grep -qiE "data|memory dump|raw" && \
      echo -e "      ${G}→${NC} Raw/memory file — disarankan: ${W}[4] Memory Forensics${NC}"
    # Registry hints
    echo "$_bn" | grep -qiE "^(sam|system|software|security|ntuser\.dat|usrclass\.dat)$" && \
      echo -e "      ${G}→${NC} Registry hive terdeteksi — disarankan: ${W}[8] Registry Analysis${NC}"
    echo "$_bn" | grep -qiE "\.reg$" && \
      echo -e "      ${G}→${NC} Registry export (.reg) terdeteksi — disarankan: ${W}[8] Registry Analysis${NC}"
    echo "$_ft" | grep -qiE "registry|regf" && \
      echo -e "      ${G}→${NC} Registry file terdeteksi — disarankan: ${W}[8] Registry Analysis${NC}"
    # Windows artifact hints
    echo "$_ft" | grep -qiE "shortcut" && echo "$_bn" | grep -qiE "\.lnk$" && \
      echo -e "      ${G}→${NC} LNK shortcut terdeteksi — disarankan: ${W}[9] Windows Artifacts${NC}"
    echo "$_ft" | grep -qiE "prefetch" && echo "$_bn" | grep -qiE "\.pf$" && \
      echo -e "      ${G}→${NC} Prefetch file terdeteksi — disarankan: ${W}[9] Windows Artifacts${NC}"
    echo "$_ft" | grep -qiE "evt" && echo "$_bn" | grep -qiE "\.evtx$" && \
      echo -e "      ${G}→${NC} Event Log terdeteksi — disarankan: ${W}[9] Windows Artifacts${NC}"
    # Crypto hints
    echo "$_bn" | grep -qiE '\.(pem|key|crt|cer|pub|enc|cry|asc|gpg|pgp)$' && \
      echo -e "      ${G}→${NC} File crypto/PEM terdeteksi — gunakan: ${W}Mode Crypto${NC}"
    echo "$_ft" | grep -qiE 'certificate|rsa|pgp|gpg|encrypted' && \
      echo -e "      ${G}→${NC} File terenkripsi/cert terdeteksi — gunakan: ${W}Mode Crypto${NC}"
    echo "$content" | grep -qiE '(BEGIN (RSA|EC|DSA|CERTIFICATE|PRIVATE|PUBLIC))' 2>/dev/null && \
      echo -e "      ${G}→${NC} PEM header ditemukan di file — gunakan: ${W}Mode Crypto${NC}"
  fi

  menu_multiselect "Pilih Modul Forensics" "${modul_opts[@]}"

  # Setup report
  REPORT_FILE="$REPORT_DIR/$(basename "$target")_$(date +%Y%m%d_%H%M%S).txt"
  echo "FASFO Report — $(date)"  > "$REPORT_FILE"
  echo "Target: $target"        >> "$REPORT_FILE"
  echo "---"                    >> "$REPORT_FILE"

  banner
  echo -e "  ${W}Target :${NC} $target"
  echo -e "  ${W}Mode   :${NC} Forensics (Interactive)"
  echo -e "  ${W}Report :${NC} $REPORT_FILE"

  local run_all=false
  # cek apakah Full Scan (idx 13) dipilih
  for idx in "${MENU_SELECTED[@]}"; do
    [[ "$idx" == "13" ]] && run_all=true
  done

  if [[ "$run_all" == true ]]; then
    _run_full_scan "$target"
  else
    for idx in "${MENU_SELECTED[@]}"; do
      case "$idx" in
        0) mod_file_analysis      "$target" ;;
        1) mod_steganography      "$target" ;;
        2) mod_network_forensics  "$target" ;;
        3) mod_memory_forensics   "$target" ;;
        4) mod_archive            "$target" ;;
        5) mod_log_analysis       "$target" ;;
        6) mod_osint              "$target" ;;
        7) mod_registry           "$target" ;;
        8) mod_windows_artifacts  "$target" ;;
        9) mod_advanced_file      "$target" ;;
        10) mod_advanced_memory   "$target" ;;
        11) mod_advanced_network  "$target" ;;
        12) mod_advanced_stego    "$target" ;;
      esac
    done
  fi

  print_summary

  # Tanya apakah mau scan lagi dengan modul lain
  echo ""
  printf "  ${Y}▶${NC} Jalankan modul lain untuk target yang sama? [y/N]: "
  read -r lagi
  if [[ "$lagi" =~ ^[yY]$ ]]; then
    menu_forensics "$target"
  fi
}

# ─────────────────────────────────────────
#  MENU CRYPTO — PILIH MODUL CRYPTO
# ─────────────────────────────────────────
menu_crypto() {
  local target="$1"

  echo -e "\n  ${C}[*]${NC} Mode: ${BOLD}Crypto${NC} → Target: ${W}$target${NC}"

  local crypto_opts=(
    "🔐  Full Cryptography  — Jalankan semua modul crypto"
    "🔑  Classic Cipher     — Caesar, ROT, Vigenere, Atbash, Rail-fence"
    "🧮  Modern Cipher      — AES, DES, RSA brute/known-plaintext"
    "🔒  Hash Cracking      — MD5, SHA1, SHA256 vs rockyou/hashcat"
    "⊕   XOR Analysis       — XOR brute, key recovery, visual XOR"
    "🔢  RSA Analysis       — factor N, small e, Wiener, common modulus"
    "🎲  Nonce / IV Reuse   — deteksi penggunaan ulang nonce/IV"
    "📜  Encoding Chains    — base64, hex, URL decode, morse, binary"
    "🔏  PKI / Cert Inspect — PEM, X.509, pubkey extraction"
  )

  # Auto-hint berdasarkan tipe file
  if [[ -f "$target" ]]; then
    local _ft _bn
    _ft=$(file --brief "$target" 2>/dev/null | tr '[:upper:]' '[:lower:]')
    _bn=$(basename "$target" | tr '[:upper:]' '[:lower:]')
    echo ""
    echo -e "  ${Y}[!]${NC} ${BOLD}Saran modul crypto berdasarkan tipe file:${NC}"
    echo "$_bn" | grep -qiE '\.(pem|key|crt|cer|pub)$' && \
      echo -e "      ${G}→${NC} File PKI/cert terdeteksi — disarankan: ${W}[9] PKI / Cert Inspect${NC}"
    echo "$_ft" | grep -qiE 'certificate|rsa|pgp|gpg|encrypted' && \
      echo -e "      ${G}→${NC} File terenkripsi terdeteksi — disarankan: ${W}[3] Hash Cracking${NC} + ${W}[5] RSA Analysis${NC}"
    echo "$_bn" | grep -qiE '\.(enc|cry|cipher|asc|gpg|pgp)$' && \
      echo -e "      ${G}→${NC} Ciphertext terdeteksi — disarankan: ${W}[2] Classic Cipher${NC} + ${W}[4] XOR Analysis${NC}"
    echo "$_ft" | grep -qiE 'text|ascii' && \
      echo -e "      ${G}→${NC} File teks terdeteksi — disarankan: ${W}[2] Classic Cipher${NC} + ${W}[8] Encoding Chains${NC}"
  fi

  menu_multiselect "Pilih Modul Crypto" "${crypto_opts[@]}"

  # Setup report
  REPORT_FILE="$REPORT_DIR/$(basename "$target")_crypto_$(date +%Y%m%d_%H%M%S).txt"
  echo "FASFO Crypto Report — $(date)"  > "$REPORT_FILE"
  echo "Target: $target"               >> "$REPORT_FILE"
  echo "---"                           >> "$REPORT_FILE"

  banner
  echo -e "  ${W}Target :${NC} $target"
  echo -e "  ${W}Mode   :${NC} Crypto (Interactive)"
  echo -e "  ${W}Report :${NC} $REPORT_FILE"

  local run_full_crypto=false
  for idx in "${MENU_SELECTED[@]}"; do
    [[ "$idx" == "0" ]] && run_full_crypto=true
  done

  if [[ "$run_full_crypto" == true ]]; then
    mod_cryptography "$target"
  else
    for idx in "${MENU_SELECTED[@]}"; do
      case "$idx" in
        1|2|3|4|5|6|7|8) mod_cryptography "$target" ; break ;;
      esac
    done
  fi

  print_summary

  echo ""
  printf "  ${Y}▶${NC} Jalankan modul crypto lain untuk target yang sama? [y/N]: "
  read -r lagi
  if [[ "$lagi" =~ ^[yY]$ ]]; then
    menu_crypto "$target"
  fi
}


_run_full_scan() {
  local target="$1"
  [[ -f "$target" ]] && mod_file_analysis "$target"
  [[ -f "$target" ]] && mod_steganography "$target"
  [[ -f "$target" ]] && mod_advanced_file "$target"

  if [[ -f "$target" ]] && file "$target" 2>/dev/null | grep -qi "pcap\|tcpdump\|capture"; then
    mod_network_forensics "$target"
    mod_advanced_network "$target"
  fi
  if [[ -f "$target" ]] && file "$target" 2>/dev/null | grep -qi "data\|memory"; then
    mod_memory_forensics "$target"
    mod_advanced_memory "$target"
  fi
  if [[ -f "$target" ]] && file "$target" 2>/dev/null | grep -qiE "zip|rar|7-zip|gzip|bzip|tar archive"; then
    mod_archive "$target"
  fi
  if [[ -f "$target" ]]; then
    local _bn _ft
    _bn=$(basename "$target" | tr '[:upper:]' '[:lower:]')
    _ft=$(file --brief "$target" 2>/dev/null | tr '[:upper:]' '[:lower:]')
    if [[ "$_bn" =~ \.(log|log\.[0-9]+)$ ]] || \
       [[ "$_bn" =~ ^(auth\.log|secure|syslog|messages|kern\.log|access\.log|access_log|error\.log|wtmp|btmp|lastlog|faillog)$ ]] || \
       [[ "$_ft" == *"ascii text"* && $(wc -l < "$target" 2>/dev/null) -gt 20 && "$_ft" != *"html"* ]]; then
      mod_log_analysis "$target"
    fi
    # Registry hive auto-detect (binary + .reg export + memory)
    if [[ "$_bn" =~ ^(sam|system|software|security|ntuser\.dat|usrclass\.dat)$ ]] || \
       [[ "$_bn" == *.reg ]] || \
       [[ "$_ft" == *"registry"* ]] || [[ "$_ft" == *"regf"* ]] || \
       [[ "$_ft" == *"memory"* ]] || [[ "$_ft" == *"dump"* ]] || [[ "$_ft" == *"crash"* ]]; then
      mod_registry "$target"
    fi
    echo "$_ft" | grep -qiE "png|jpeg|gif|bmp|tiff|image|audio|wave|mp3" && \
      mod_advanced_stego "$target"
    # Windows artifact auto-detect
    if [[ "$_ft" == *"shortcut"* ]] || [[ "$_bn" == *.lnk ]] || \
       [[ "$_ft" == *"prefetch"* ]] || [[ "$_bn" == *.pf ]] || \
       [[ "$_ft" == *"evt"* ]] || [[ "$_bn" == *.evtx ]]; then
      mod_windows_artifacts "$target"
    fi
  fi
  mod_osint "$target"
  # Crypto: jalankan pada file teks, pem, key, atau ciphertext
  if [[ -f "$target" ]]; then
    local _bn_fc _ft_fc
    _bn_fc=$(basename "$target" | tr '[:upper:]' '[:lower:]')
    _ft_fc=$(file --brief "$target" 2>/dev/null | tr '[:upper:]' '[:lower:]')
    if echo "$_bn_fc" | grep -qiE '\.(pem|key|crt|cer|pub|txt|enc|cry|cipher|asc|gpg|pgp)$' || \
       echo "$_ft_fc" | grep -qiE 'text|certificate|rsa|pgp|gpg|encrypted'; then
      mod_cryptography "$target"
    fi
  fi
}

# ─────────────────────────────────────────
#  MENU LAPORAN TERSIMPAN
# ─────────────────────────────────────────
menu_laporan() {
  section "Laporan Tersimpan"
  local reports=()
  while IFS= read -r f; do
    reports+=("$(basename "$f") — $(du -sh "$f" 2>/dev/null | cut -f1)")
  done < <(find "$REPORT_DIR" -maxdepth 1 -name "*.txt" -printf "%T@ %p\n" 2>/dev/null | \
    sort -rn | head -10 | awk '{print $2}')

  if [[ ${#reports[@]} -eq 0 ]]; then
    warn "Belum ada laporan tersimpan di $REPORT_DIR"
    return
  fi

  menu_select "Pilih Laporan untuk Dibaca" "${reports[@]}"

  local chosen_file
  chosen_file=$(find "$REPORT_DIR" -maxdepth 1 -name "*.txt" -printf "%T@ %p\n" 2>/dev/null | \
    sort -rn | head -10 | awk '{print $2}' | sed -n "${MENU_IDX}p")

  if [[ -f "$chosen_file" ]]; then
    echo ""
    echo -e "  ${W}── Isi Laporan: $(basename "$chosen_file") ──${NC}"
    cat "$chosen_file" | sed 's/^/  /'
  fi
}

# ─────────────────────────────────────────
#  HELPER — validasi satu target
# ─────────────────────────────────────────
_is_valid_target() {
  local t="$1"
  [[ -f "$t" ]] && return 0
  [[ "$t" =~ ^https?:// ]] && return 0
  [[ "$t" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && return 0
  return 1
}

# ─────────────────────────────────────────
#  HELPER — parse flags dari argumen
# ─────────────────────────────────────────
_parse_flags() {
  # Reset semua flag
  HAS_FORENSICS=false
  MODE_ALL=true
  MOD_FILE=false; MOD_STEGO=false; MOD_NET=false
  MOD_MEM=false;  MOD_OSINT=false; MOD_ARCHIVE=false
  MOD_LOG=false; MOD_REGISTRY=false; MOD_WINDOWS=false
  MOD_ADV_FILE=false; MOD_ADV_MEM=false; MOD_ADV_NET=false; MOD_ADV_STEGO=false
  MOD_CRYPTO=false

  for arg in "$@"; do
    case "$arg" in
      --Forensics) HAS_FORENSICS=true ;;
      --file)      MOD_FILE=true;    MODE_ALL=false ;;
      --stego)     MOD_STEGO=true;   MODE_ALL=false ;;
      --net)       MOD_NET=true;     MODE_ALL=false ;;
      --mem)       MOD_MEM=true;     MODE_ALL=false ;;
      --osint)     MOD_OSINT=true;   MODE_ALL=false ;;
      --archive)   MOD_ARCHIVE=true; MODE_ALL=false ;;
      --log)       MOD_LOG=true;     MODE_ALL=false ;;
      --registry)  MOD_REGISTRY=true; MODE_ALL=false ;;
      --windows)   MOD_WINDOWS=true;  MODE_ALL=false ;;
      --adv-file)  MOD_ADV_FILE=true;    MODE_ALL=false ;;
      --adv-mem)   MOD_ADV_MEM=true;     MODE_ALL=false ;;
      --adv-net)   MOD_ADV_NET=true;     MODE_ALL=false ;;
      --adv-stego) MOD_ADV_STEGO=true;   MODE_ALL=false ;;
      --crypto)    MOD_CRYPTO=true;      MODE_ALL=false ;;
    esac
  done
}

# ─────────────────────────────────────────
#  HELPER — jalankan modul yang dipilih
# ─────────────────────────────────────────
_run_selected_modules() {
  local target="$1"
  if [[ "$MODE_ALL" == true ]]; then
    _run_full_scan "$target"
  else
    $MOD_FILE      && mod_file_analysis     "$target"
    $MOD_STEGO     && mod_steganography     "$target"
    $MOD_NET       && mod_network_forensics "$target"
    $MOD_MEM       && mod_memory_forensics  "$target"
    $MOD_ARCHIVE   && mod_archive           "$target"
    $MOD_LOG       && mod_log_analysis      "$target"
    $MOD_REGISTRY  && mod_registry          "$target"
    $MOD_WINDOWS   && mod_windows_artifacts "$target"
    $MOD_ADV_FILE  && mod_advanced_file     "$target"
    $MOD_ADV_MEM   && mod_advanced_memory   "$target"
    $MOD_ADV_NET   && mod_advanced_network  "$target"
    $MOD_ADV_STEGO && mod_advanced_stego    "$target"
    $MOD_CRYPTO    && mod_cryptography      "$target"
    $MOD_OSINT     && mod_osint             "$target"
  fi
}

# ─────────────────────────────────────────
#  MULTI-FILE SUMMARY
# ─────────────────────────────────────────
_print_multiscan_summary() {
  local -n _targets=$1   # nameref ke array targets
  local -n _results=$2   # nameref ke array hasil (OK/FAIL/SKIP)
  local total=${#_targets[@]}

  echo ""
  echo -e "${BOLD}${C}╔══════════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}${C}║           FASFO MULTI-FILE SCAN SUMMARY              ║${NC}"
  echo -e "${BOLD}${C}╚══════════════════════════════════════════════════════╝${NC}"
  echo -e "  ${W}Total file   :${NC} $total"
  echo -e "  ${W}Waktu selesai:${NC} $(date '+%Y-%m-%d %H:%M:%S')"
  echo ""

  local ok_count=0 fail_count=0 skip_count=0
  for i in "${!_targets[@]}"; do
    local tgt="${_targets[$i]}"
    local res="${_results[$i]}"
    local num=$((i+1))
    case "$res" in
      OK)
        echo -e "  ${G}[✔]${NC} [$num/$total] ${W}$(basename "$tgt")${NC}"
        (( ok_count++ ))
        ;;
      FAIL)
        echo -e "  ${R}[✘]${NC} [$num/$total] ${W}$(basename "$tgt")${NC} ${DIM}— tidak ditemukan / error${NC}"
        (( fail_count++ ))
        ;;
      SKIP)
        echo -e "  ${Y}[~]${NC} [$num/$total] ${W}$(basename "$tgt")${NC} ${DIM}— dilewati${NC}"
        (( skip_count++ ))
        ;;
    esac
  done

  echo ""
  echo -e "  ${G}Berhasil : $ok_count${NC}  ${R}Gagal : $fail_count${NC}  ${Y}Dilewati : $skip_count${NC}"

  # Kumpulkan semua flag yang ditemukan dari semua laporan
  echo ""
  echo -e "  ${M}${BOLD}[FLAG CANDIDATES — SEMUA FILE]${NC}"
  local any_flag=false
  for i in "${!_targets[@]}"; do
    local tgt="${_targets[$i]}"
    local rf="$REPORT_DIR/$(basename "$tgt")_"
    # Cari laporan terbaru untuk file ini
    local latest_report
    latest_report=$(find "$REPORT_DIR" -maxdepth 1 -name "$(basename "$tgt")_*.txt" \
      -printf "%T@ %p\n" 2>/dev/null | sort -rn | head -1 | awk '{print $2}')
    if [[ -f "$latest_report" ]]; then
      local flags
      flags=$(grep -E "(FLAG|FOUND|HIT)" "$latest_report" 2>/dev/null | head -5)
      if [[ -n "$flags" ]]; then
        any_flag=true
        echo -e "  ${W}$(basename "$tgt"):${NC}"
        echo "$flags" | sed 's/^/    /'
      fi
    fi
  done
  [[ "$any_flag" == false ]] && echo -e "  ${DIM}Tidak ada flag yang ditemukan.${NC}"

  echo ""
  echo -e "  ${W}Laporan disimpan di:${NC} ${DIM}$REPORT_DIR/${NC}"
  echo -e "  ${DIM}Scan selesai. Good luck on your CTF! 🚩${NC}"
  echo ""
}

# ─────────────────────────────────────────
#  MULTI-FILE CLI SCAN
# ─────────────────────────────────────────
_run_multiscan_cli() {
  # $@ = semua argumen asli
  # Pisahkan: targets = file/url, flags = --xxx
  local targets=()
  local flags=()
  for arg in "$@"; do
    if [[ "$arg" == --* ]]; then
      flags+=("$arg")
    else
      targets+=("$arg")
    fi
  done

  _parse_flags "${flags[@]}"

  if [[ "$HAS_FORENSICS" != true ]]; then
    echo -e "${R}[!] Error: flag --Forensics wajib disertakan.${NC}"
    echo -e "    Contoh: fasfo file1.png file2.jpg --Forensics"
    echo -e "    Atau  : fasfo file1.png  ${DIM}(tanpa flag → mode interaktif)${NC}"
    exit 1
  fi

  local total=${#targets[@]}
  local scan_results=()

  banner
  echo -e "  ${W}Mode     :${NC} Multi-File Forensics (CLI)"
  echo -e "  ${W}Total    :${NC} $total file"
  echo -e "  ${W}Modul    :${NC} $(
    if [[ "$MODE_ALL" == true ]]; then echo "Full Scan (auto-detect)"
    else
      local mlist=""
      $MOD_FILE    && mlist+="File "
      $MOD_STEGO   && mlist+="Stego "
      $MOD_NET     && mlist+="Network "
      $MOD_MEM     && mlist+="Memory "
      $MOD_ARCHIVE && mlist+="Archive "
      $MOD_LOG     && mlist+="Log "
      $MOD_OSINT   && mlist+="OSINT "
      echo "$mlist"
    fi
  )"
  echo ""

  # Progress bar helper
  _draw_progress() {
    local cur=$1 tot=$2
    local pct=$(( cur * 100 / tot ))
    local filled=$(( cur * 30 / tot ))
    local bar=""
    for ((x=0; x<filled; x++));    do bar+="█"; done
    for ((x=filled; x<30; x++));   do bar+="░"; done
    printf "\r  ${C}[*]${NC} Progress: [${G}%s${NC}] %d/%d (%d%%)" "$bar" "$cur" "$tot" "$pct"
  }

  local i=0
  for tgt in "${targets[@]}"; do
    (( i++ ))

    echo ""
    echo -e "${BOLD}${B}╔══[ ${W}File $i/$total — $(basename "$tgt")${B} ]${NC}"

    if ! _is_valid_target "$tgt"; then
      echo -e "  ${R}[✘]${NC} Target tidak ditemukan: $tgt — dilewati"
      scan_results+=("FAIL")
      _draw_progress "$i" "$total"
      continue
    fi

    # Info singkat file
    local fsize ftype_s
    fsize=$(du -sh "$tgt" 2>/dev/null | cut -f1)
    ftype_s=$(file --brief "$tgt" 2>/dev/null | cut -c1-50)
    echo -e "  ${DIM}Ukuran: $fsize | Tipe: $ftype_s${NC}"

    # Setup report per file
    REPORT_FILE="$REPORT_DIR/$(basename "$tgt")_$(date +%Y%m%d_%H%M%S).txt"
    echo "FASFO Report — $(date)"  > "$REPORT_FILE"
    echo "Target: $tgt"           >> "$REPORT_FILE"
    echo "Batch scan: $i dari $total" >> "$REPORT_FILE"
    echo "---"                    >> "$REPORT_FILE"

    # Jalankan modul
    _run_selected_modules "$tgt"
    print_summary
    scan_results+=("OK")

    _draw_progress "$i" "$total"
  done

  echo ""
  _print_multiscan_summary targets scan_results
}

# ─────────────────────────────────────────
#  MULTI-FILE INTERACTIVE SCAN
# ─────────────────────────────────────────
_run_multiscan_interactive() {
  local -a targets=("$@")
  local total=${#targets[@]}

  # Tampilkan daftar file yang akan di-scan
  echo ""
  echo -e "  ${BOLD}${C}┌─────────────────────────────────────────┐${NC}"
  printf  "  ${BOLD}${C}│${NC}  %-39s${BOLD}${C}│${NC}\n" "📂 File yang akan di-scan ($total file)"
  echo -e "  ${BOLD}${C}├─────────────────────────────────────────┤${NC}"
  local valid_count=0 invalid_count=0
  for i in "${!targets[@]}"; do
    local tgt="${targets[$i]}"
    local status_icon status_info
    if _is_valid_target "$tgt"; then
      status_icon="${G}✔${NC}"
      status_info="$(file --brief "$tgt" 2>/dev/null | cut -c1-22) ($(du -sh "$tgt" 2>/dev/null | cut -f1))"
      (( valid_count++ ))
    else
      status_icon="${R}✘${NC}"
      status_info="tidak ditemukan"
      (( invalid_count++ ))
    fi
    printf "  ${BOLD}${C}│${NC}  [%b] %-35s${BOLD}${C}│${NC}\n" \
      "$status_icon" "$((i+1)). $(basename "$tgt" | cut -c1-32)"
    printf "  ${BOLD}${C}│${NC}      ${DIM}%-37s${NC}${BOLD}${C}│${NC}\n" "$status_info"
  done
  echo -e "  ${BOLD}${C}└─────────────────────────────────────────┘${NC}"
  echo ""
  echo -e "  ${G}Valid: $valid_count${NC}  ${R}Tidak valid: $invalid_count${NC}"

  if [[ "$invalid_count" -gt 0 ]]; then
    echo ""
    printf "  ${Y}▶${NC} Ada file yang tidak ditemukan. Lanjutkan scan untuk yang valid saja? [Y/n]: "
    read -r lanjut
    [[ "$lanjut" =~ ^[nN]$ ]] && echo -e "  ${DIM}Dibatalkan.${NC}" && return
  fi

  # Pilih mode analisis dulu (satu kali, berlaku ke semua file)
  menu_select "Pilih Mode Analisis" \
    "🔍  Forensics — Analisis semua file" \
    "🔐  Crypto    — Analisis kriptografi & enkripsi" \
    "🔧  Dependency Check — Cek tools" \
    "ℹ️   Info & Help"

  case "$MENU_IDX" in
    3) check_deps; return ;;
    4) show_help;  return ;;
  esac

  # Jika pilih Crypto, jalankan menu_crypto untuk tiap file
  if [[ "$MENU_IDX" == "2" ]]; then
    for tgt in "${targets[@]}"; do
      _is_valid_target "$tgt" || continue
      menu_crypto "$tgt"
    done
    return
  fi

  # Pilih modul (berlaku ke semua file)
  local modul_opts=(
    "📁  File Analysis     — magic bytes, strings, binwalk, exiftool"
    "🖼️   Steganography     — zsteg, steghide, outguess, stegsolve"
    "🌐  Network Forensics — PCAP / tshark analysis"
    "🧠  Memory Forensics  — volatility3 / strings"
    "📦  Archive Analysis  — ZIP/RAR/7Z + bruteforce"
    "🗒️   Log Analysis      — auth, http, syslog, wtmp, dll"
    "🕵️   OSINT             — whois, DNS, metadata recon"
    "🔬  Advanced File     — deep inspect, polyglot, XOR, malware triage"
    "🧬  Advanced Memory   — hidden proc, DLL inject, NTFS, timeline"
    "📡  Advanced Network  — file recon, C2 detect, covert channel"
    "🎭  Advanced Stego    — chi-square, audio, frequency, noise"
    "⚡  Full Scan         — Jalankan SEMUA modul sesuai tipe file"
  )

  echo ""
  echo -e "  ${C}[*]${NC} Pilihan modul akan berlaku untuk ${BOLD}semua $total file${NC}."

  # Cek apakah ada file dengan tipe berbeda-beda, berikan saran
  local has_img=false has_pcap=false has_arc=false has_log=false
  for tgt in "${targets[@]}"; do
    _is_valid_target "$tgt" || continue
    local _ft _bn
    _ft=$(file --brief "$tgt" 2>/dev/null | tr '[:upper:]' '[:lower:]')
    _bn=$(basename "$tgt" | tr '[:upper:]' '[:lower:]')
    echo "$_ft" | grep -qiE "png|jpeg|gif|bmp|image" && has_img=true
    echo "$_ft" | grep -qiE "pcap|tcpdump|capture"   && has_pcap=true
    echo "$_ft" | grep -qiE "zip|rar|7-zip|gzip|tar" && has_arc=true
    echo "$_bn" | grep -qiE "\.log$|auth|syslog|messages|wtmp|btmp" && has_log=true
  done

  echo ""
  echo -e "  ${Y}[!]${NC} ${BOLD}Saran modul berdasarkan jenis file yang dideteksi:${NC}"
  $has_img  && echo -e "      ${G}→${NC} Gambar terdeteksi  — disarankan: ${W}[1] File Analysis${NC} + ${W}[2] Steganography${NC}"
  $has_pcap && echo -e "      ${G}→${NC} PCAP terdeteksi    — disarankan: ${W}[3] Network Forensics${NC}"
  $has_arc  && echo -e "      ${G}→${NC} Archive terdeteksi — disarankan: ${W}[5] Archive Analysis${NC}"
  $has_log  && echo -e "      ${G}→${NC} Log terdeteksi     — disarankan: ${W}[6] Log Analysis${NC}"
  echo -e "      ${G}→${NC} Campuran / tidak yakin — pilih: ${W}[12] Full Scan${NC}"

  menu_multiselect "Pilih Modul untuk Semua File" "${modul_opts[@]}"

  # Terjemahkan pilihan menu ke flag modul
  HAS_FORENSICS=true
  MODE_ALL=false
  MOD_FILE=false; MOD_STEGO=false; MOD_NET=false
  MOD_MEM=false;  MOD_OSINT=false; MOD_ARCHIVE=false; MOD_LOG=false
  MOD_ADV_FILE=false; MOD_ADV_MEM=false; MOD_ADV_NET=false; MOD_ADV_STEGO=false
  MOD_CRYPTO=false

  local run_all=false
  for idx in "${MENU_SELECTED[@]}"; do
    case "$idx" in
      0) MOD_FILE=true      ;;
      1) MOD_STEGO=true     ;;
      2) MOD_NET=true       ;;
      3) MOD_MEM=true       ;;
      4) MOD_ARCHIVE=true   ;;
      5) MOD_LOG=true       ;;
      6) MOD_OSINT=true     ;;
      7) MOD_ADV_FILE=true  ;;
      8) MOD_ADV_MEM=true   ;;
      9) MOD_ADV_NET=true   ;;
      10) MOD_ADV_STEGO=true ;;
      11) run_all=true      ;;
    esac
  done
  [[ "$run_all" == true ]] && MODE_ALL=true

  # Mulai scan semua file
  local scan_results=()
  local i=0

  banner
  echo -e "  ${W}Mode     :${NC} Multi-File Forensics (Interactive)"
  echo -e "  ${W}Total    :${NC} $total file"
  echo ""

  for tgt in "${targets[@]}"; do
    (( i++ ))

    echo ""
    echo -e "${BOLD}${B}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${B}║  ${W}[$i/$total]${B} Scanning: ${W}$(basename "$tgt")${NC}"
    echo -e "${BOLD}${B}╚══════════════════════════════════════════════════════╝${NC}"

    if ! _is_valid_target "$tgt"; then
      echo -e "  ${R}[✘]${NC} Target tidak ditemukan — dilewati"
      scan_results+=("FAIL")
      continue
    fi

    local fsize ftype_s
    fsize=$(du -sh "$tgt" 2>/dev/null | cut -f1)
    ftype_s=$(file --brief "$tgt" 2>/dev/null | cut -c1-50)
    echo -e "  ${DIM}Ukuran: $fsize | Tipe: $ftype_s${NC}"

    REPORT_FILE="$REPORT_DIR/$(basename "$tgt")_$(date +%Y%m%d_%H%M%S).txt"
    echo "FASFO Report — $(date)"       > "$REPORT_FILE"
    echo "Target: $tgt"               >> "$REPORT_FILE"
    echo "Batch: $i dari $total"      >> "$REPORT_FILE"
    echo "---"                        >> "$REPORT_FILE"

    _run_selected_modules "$tgt"
    print_summary
    scan_results+=("OK")

    # Pause antar file (kecuali file terakhir)
    if [[ "$i" -lt "$total" ]]; then
      echo ""
      printf "  ${Y}▶${NC} Lanjut ke file berikutnya [$(basename "${targets[$i]}")] ? [Y/n]: "
      read -r next
      if [[ "$next" =~ ^[nN]$ ]]; then
        # Tandai sisa file sebagai SKIP
        for (( j=i; j<total; j++ )); do
          scan_results+=("SKIP")
        done
        break
      fi
    fi
  done

  _print_multiscan_summary targets scan_results
}

# ─────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────
main() {
  # ── Handle flag global tanpa target ─────
  case "${1:-}" in
    --help|-h)   show_help;          exit 0 ;;
    --deps)      banner; check_deps; exit 0 ;;
    --install)   install_self;       exit 0 ;;
    --version)   echo "FASFO v$VERSION"; exit 0 ;;
    --decode)
      # Mode decode langsung: fasfo --decode "string"
      if [[ -n "${2:-}" ]]; then
        run_decode_mode "$2"
      else
        banner
        echo -e "  ${Y}[!]${NC} Masukkan string yang ingin di-decode:"
        printf "  ${Y}▶${NC} String: "
        read -r decode_input
        run_decode_mode "$decode_input"
      fi
      exit 0 ;;
  esac

  # Tidak ada argumen sama sekali → tanya target
  if [[ $# -eq 0 ]]; then
    banner
    echo -e "  ${Y}[!]${NC} Tidak ada target. Masukkan file, URL, atau domain:"
    echo -e "  ${DIM}(Pisahkan dengan spasi untuk scan beberapa file sekaligus)${NC}"
    echo ""
    printf "  ${Y}▶${NC} Target: "
    read -r -a input_targets
    if [[ ${#input_targets[@]} -eq 0 ]]; then
      show_help; exit 0
    fi
    banner
    if [[ ${#input_targets[@]} -eq 1 ]]; then
      _is_valid_target "${input_targets[0]}" || { echo -e "${R}[!] Target tidak ditemukan.${NC}"; exit 1; }
      menu_mode_utama "${input_targets[0]}"
    else
      _run_multiscan_interactive "${input_targets[@]}"
    fi
    return
  fi

  # ── Pisahkan targets dan flags dari argumen ──
  local raw_targets=()
  local raw_flags=()
  local has_cli_flags=false

  for arg in "$@"; do
    if [[ "$arg" == --* ]]; then
      raw_flags+=("$arg")
      [[ "$arg" == --Forensics || "$arg" == --file || "$arg" == --stego || \
         "$arg" == --net       || "$arg" == --mem  || "$arg" == --osint || \
         "$arg" == --archive   || "$arg" == --log  || \
         "$arg" == --adv-file  || "$arg" == --adv-mem || \
         "$arg" == --adv-net   || "$arg" == --adv-stego || \
         "$arg" == --crypto ]] && has_cli_flags=true
    else
      raw_targets+=("$arg")
    fi
  done

  local num_targets=${#raw_targets[@]}

  # ── Mode CLI dengan flags ────────────────────
  if [[ "$has_cli_flags" == true ]]; then
    if [[ "$num_targets" -eq 0 ]]; then
      echo -e "${R}[!] Tidak ada target file/URL yang diberikan.${NC}"
      echo -e "    Contoh: fasfo file.png --Forensics"
      exit 1
    fi

    if [[ "$num_targets" -eq 1 ]]; then
      # ── Single file CLI ──────────────────────
      TARGET="${raw_targets[0]}"
      _parse_flags "${raw_flags[@]}"

      if [[ "$HAS_FORENSICS" != true ]]; then
        echo -e "${R}[!] Error: flag --Forensics wajib disertakan.${NC}"
        echo -e "    Contoh: fasfo $TARGET --Forensics"
        exit 1
      fi
      _is_valid_target "$TARGET" || { echo -e "${R}[!] Target tidak ditemukan: $TARGET${NC}"; exit 1; }

      REPORT_FILE="$REPORT_DIR/$(basename "$TARGET")_$(date +%Y%m%d_%H%M%S).txt"
      echo "FASFO Report — $(date)" > "$REPORT_FILE"
      echo "Target: $TARGET"       >> "$REPORT_FILE"
      echo "---"                   >> "$REPORT_FILE"

      banner
      echo -e "  ${W}Target :${NC} $TARGET"
      echo -e "  ${W}Mode   :${NC} Forensics (CLI)"
      echo -e "  ${W}Report :${NC} $REPORT_FILE"

      _run_selected_modules "$TARGET"
      print_summary

    else
      # ── Multi-file CLI ───────────────────────
      _run_multiscan_cli "${raw_targets[@]}" "${raw_flags[@]}"
    fi
    return
  fi

  # ── Mode Interaktif (tanpa flags) ───────────
  banner

  if [[ "$num_targets" -eq 1 ]]; then
    # Single file → menu interaktif biasa
    TARGET="${raw_targets[0]}"
    _is_valid_target "$TARGET" || {
      echo -e "${R}[!] Target tidak ditemukan: $TARGET${NC}"
      exit 1
    }
    menu_mode_utama "$TARGET"

  elif [[ "$num_targets" -gt 1 ]]; then
    # Multi file → menu interaktif multi-scan
    _run_multiscan_interactive "${raw_targets[@]}"
  fi
}

main "$@"