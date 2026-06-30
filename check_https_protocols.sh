#!/bin/bash
# ==============================================================================
# check_https_protocols.sh
# Audits obsolete cryptographic protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1)
# on a list of URLs and generates a CSV report.
#
# Usage: ./check_https_protocols.sh <url_file> [output_file]
#   url_file    - Text file containing URLs (one per line)
#   output_file - Output CSV file (default: report_YYYYMMDD_HHMMSS.csv)
# ==============================================================================

set -euo pipefail

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────
TIMEOUT=10          # seconds per connection attempt

# ──────────────────────────────────────────────
# Helper: usage message
# ──────────────────────────────────────────────
usage() {
    echo "Usage: $0 <url_file> [output_file]"
    echo ""
    echo "  url_file    - Text file containing URLs (one per line)"
    echo "  output_file - Output CSV file (default: report_YYYYMMDD_HHMMSS.csv)"
    echo ""
    echo "Example:"
    echo "  $0 urls.txt"
    echo "  $0 urls.txt results.csv"
    exit 1
}

# ──────────────────────────────────────────────
# Helper: check required tools
# ──────────────────────────────────────────────
check_dependencies() {
    local missing=0
    for cmd in openssl curl; do
        if ! command -v "$cmd" &>/dev/null; then
            echo "ERROR: Required tool '$cmd' is not installed." >&2
            missing=1
        fi
    done
    if [ "$missing" -eq 1 ]; then
        exit 2
    fi
}

# ──────────────────────────────────────────────
# Helper: extract hostname from a URL or bare host
# ──────────────────────────────────────────────
extract_host() {
    local raw="$1"
    # Strip scheme (http:// or https://)
    raw="${raw#http://}"
    raw="${raw#https://}"
    # Strip path, query, fragment
    raw="${raw%%/*}"
    raw="${raw%%\?*}"
    raw="${raw%%\#*}"
    # Strip port
    raw="${raw%%:*}"
    echo "$raw"
}

# ──────────────────────────────────────────────
# Helper: test a single SSL/TLS protocol
#
# Returns:
#   TRUE  – server accepted a handshake with this protocol
#   FALSE – server rejected the protocol
#   N/A   – openssl on this machine does not support the flag
# ──────────────────────────────────────────────
test_protocol() {
    local host="$1"
    local flag="$2"   # e.g. -ssl2, -ssl3, -tls1, -tls1_1

    local result
    result=$(echo "Q" | timeout "$TIMEOUT" openssl s_client \
        "$flag" \
        -connect "${host}:443" \
        -servername "$host" \
        2>&1 </dev/null) || true

    # openssl does not recognise the flag on this build (e.g. no SSL2 support)
    if echo "$result" | grep -qiE "unknown option|unsupported option"; then
        echo "N/A"
        return
    fi

    # Successful TLS handshake indicators
    if echo "$result" | grep -qE "(Certificate chain|SSL-Session:|Cipher[[:space:]]+:)"; then
        echo "TRUE"
    else
        echo "FALSE"
    fi
}

# ──────────────────────────────────────────────
# Helper: get HTTP status code via curl
# Args: host p443 p8000 p8080 p80
# ──────────────────────────────────────────────
get_http_status() {
    local host="$1"
    local p443="$2"
    local p8000="$3"
    local p8080="$4"
    local p80="$5"
    local code=""

    if [ "$p443" = "TRUE" ]; then
        code=$(curl -s -o /dev/null -w "%{http_code}" \
            --max-time "$TIMEOUT" --connect-timeout "$TIMEOUT" \
            -L "https://${host}" 2>/dev/null) || true
        if [ "$code" != "000" ] && [ -n "$code" ]; then echo "$code"; return; fi
    fi
    if [ "$p8080" = "TRUE" ]; then
        code=$(curl -s -o /dev/null -w "%{http_code}" \
            --max-time "$TIMEOUT" --connect-timeout "$TIMEOUT" \
            -L "http://${host}:8080" 2>/dev/null) || true
        if [ "$code" != "000" ] && [ -n "$code" ]; then echo "$code"; return; fi
    fi
    if [ "$p8000" = "TRUE" ]; then
        code=$(curl -s -o /dev/null -w "%{http_code}" \
            --max-time "$TIMEOUT" --connect-timeout "$TIMEOUT" \
            -L "http://${host}:8000" 2>/dev/null) || true
        if [ "$code" != "000" ] && [ -n "$code" ]; then echo "$code"; return; fi
    fi
    if [ "$p80" = "TRUE" ]; then
        code=$(curl -s -o /dev/null -w "%{http_code}" \
            --max-time "$TIMEOUT" --connect-timeout "$TIMEOUT" \
            -L "http://${host}" 2>/dev/null) || true
        if [ "$code" != "000" ] && [ -n "$code" ]; then echo "$code"; return; fi
    fi
    echo ""
}

# ──────────────────────────────────────────────
# Helper: check if a specific port is open
# Returns 0 if open, 1 if closed/unreachable
# ──────────────────────────────────────────────
test_port() {
    local host="$1"
    local port="$2"
    if timeout "$TIMEOUT" bash -c \
        "echo >/dev/tcp/${host}/${port}" 2>/dev/null; then
        return 0
    fi
    return 1
}

# ──────────────────────────────────────────────
# Helper: check DNS resolution
# Returns 0 if resolved, 1 otherwise
# ──────────────────────────────────────────────
check_dns() {
    local host="$1"
    if getent hosts "$host" &>/dev/null \
        || host "$host" &>/dev/null 2>&1 \
        || nslookup "$host" &>/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
main() {
    if [ $# -lt 1 ]; then
        usage
    fi

    local url_file="$1"
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")
    local output_file="${2:-report_${timestamp}.csv}"

    if [ ! -f "$url_file" ]; then
        echo "ERROR: File '$url_file' not found." >&2
        exit 1
    fi

    check_dependencies

    # Write CSV header (tab-separated)
    printf "URL\tSSL 2.0\tSSL 3.0\tTLS 1.0\tTLS 1.1\tSECURED\t443\t8000\t8080\t80\tREPONSE HTTP\tERREUR\n" \
        > "$output_file"

    local line_number=0
    while IFS= read -r raw_url || [ -n "$raw_url" ]; do
        line_number=$((line_number + 1))

        # Skip empty lines and comment lines
        [[ -z "$raw_url" || "$raw_url" =~ ^[[:space:]]*# ]] && continue
        # Trim leading/trailing whitespace
        raw_url="${raw_url#"${raw_url%%[![:space:]]*}"}"
        raw_url="${raw_url%"${raw_url##*[![:space:]]}"}"
        [ -z "$raw_url" ] && continue

        local host
        host=$(extract_host "$raw_url")

        if [ -z "$host" ]; then
            echo "WARN: Empty hostname on line $line_number, skipping." >&2
            continue
        fi

        echo "  → Testing ${host} ..."

        local ssl2="" ssl3="" tls10="" tls11=""
        local secured=""
        local http_code=""
        local error=""
        local p443="" p8000="" p8080="" p80=""

        # ── 1. DNS resolution ──────────────────────────────────────────────
        if ! check_dns "$host"; then
            error="Le DNS ne résout pas"
            printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
                "$host" "$ssl2" "$ssl3" "$tls10" "$tls11" "$secured" \
                "$p443" "$p8000" "$p8080" "$p80" "$http_code" "$error" \
                >> "$output_file"
            echo "    [DNS FAIL]"
            continue
        fi

        # ── 2. Test all 4 ports ────────────────────────────────────────────
        test_port "$host" 443  && p443="TRUE"  || p443="FALSE"
        test_port "$host" 8000 && p8000="TRUE" || p8000="FALSE"
        test_port "$host" 8080 && p8080="TRUE" || p8080="FALSE"
        test_port "$host" 80   && p80="TRUE"   || p80="FALSE"

        echo "    Ports: 443=${p443}  8000=${p8000}  8080=${p8080}  80=${p80}"

        # ── 3. Check if all ports closed ───────────────────────────────────
        if [ "$p443" = "FALSE" ] && [ "$p8000" = "FALSE" ] \
            && [ "$p8080" = "FALSE" ] && [ "$p80" = "FALSE" ]; then
            error="Tous les ports testés sont fermés"
        else
            # ── 4. HTTP response code ──────────────────────────────────────
            http_code=$(get_http_status "$host" "$p443" "$p8000" "$p8080" "$p80")

            # ── 5. Protocol tests (only if port 443 is open) ──────────────
            if [ "$p443" = "TRUE" ]; then
                ssl2=$(test_protocol  "$host" "-ssl2")
                ssl3=$(test_protocol  "$host" "-ssl3")
                tls10=$(test_protocol "$host" "-tls1")
                tls11=$(test_protocol "$host" "-tls1_1")

                # SECURED = TRUE if no obsolete protocol is confirmed active
                if [ "$ssl2" = "TRUE" ] || [ "$ssl3" = "TRUE" ] \
                    || [ "$tls10" = "TRUE" ] || [ "$tls11" = "TRUE" ]; then
                    secured="FALSE"
                else
                    secured="TRUE"
                fi
            fi
            # If port 443 not open: protocols and SECURED remain empty
        fi

        echo "    SSL2=${ssl2}  SSL3=${ssl3}  TLS1.0=${tls10}  TLS1.1=${tls11}  SECURED=${secured}  HTTP=${http_code}"

        printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
            "$host" "$ssl2" "$ssl3" "$tls10" "$tls11" "$secured" \
            "$p443" "$p8000" "$p8080" "$p80" "$http_code" "$error" \
            >> "$output_file"

    done < "$url_file"

    echo ""
    echo "✔ Report saved to: $output_file"
}

main "$@"
