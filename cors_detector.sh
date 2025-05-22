#!/bin/bash

# CORS Detector Tool by TehanG07
# Safe, Fast, and Reliable

BANNER=$(cat << "EOF"
██████╗  ██████╗ ██████╗ ███████╗       ██████╗ ███████╗███████╗██████╗ 
██╔══██╗██╔═══██╗██╔══██╗██╔════╝      ██╔═══██╗██╔════╝██╔════╝██╔══██╗
██║  ██║██║   ██║██║  ██║█████╗        ██║   ██║███████╗█████╗  ██████╔╝
██║  ██║██║   ██║██║  ██║██╔══╝        ██║   ██║╚════██║██╔══╝  ██╔═══╝ 
██████╔╝╚██████╔╝██████╔╝███████╗█████╗╚██████╔╝███████║███████╗██║     
╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝╚════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝     
      🌐 CORS Vulnerability Scanner - Safe & Accurate - TehanG07
EOF
)

# ANSI Colors
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
GRAY="\e[90m"
RESET="\e[0m"

echo -e "$BANNER"

read -rp "Enter path to URLs file: " INPUT_FILE

if [ ! -f "$INPUT_FILE" ]; then
    echo -e "${RED}[!] Error: File '$INPUT_FILE' not found!${RESET}"
    exit 1
fi

SKIP_FILE="skip-urls.txt"
OUTPUT_FILE="cors.txt"
TEMP_FILE=$(mktemp)

# Extensions to skip (static files and versions in query string for css/js)
SKIP_EXTENSIONS="\.jpg$|\.jpeg$|\.png$|\.gif$|\.svg$|\.woff$|\.ttf$|\.eot$|\.ico$|\.css(\?.*)?$|\.js(\?.*)?$|\.pdf$|\.zip$|\.tar$"

> "$TEMP_FILE"

# Filter URLs
cat "$INPUT_FILE" | \
    grep -E "^https?://" | \
    grep -Ev "$SKIP_EXTENSIONS" | \
    if [ -f "$SKIP_FILE" ]; then
        grep -Evf "$SKIP_FILE"
    else
        cat
    fi | sort -u > "$TEMP_FILE"

echo -e "[*] Starting scan..."
> "$OUTPUT_FILE"

while IFS= read -r url; do
    echo -e "[*] Checking: $url"

    # Get HTTP status code and redirect URL
    response_info=$(curl -s -w "%{http_code} %{redirect_url}" -o /dev/null -I --max-time 10 "$url")
    http_code=$(echo "$response_info" | awk '{print $1}')
    redirect_url=$(echo "$response_info" | awk '{print $2}')

    # Function to get domain from URL
    get_domain() {
        echo "$1" | awk -F/ '{print $3}'
    }

    original_domain=$(get_domain "$url")
    redirect_domain=$(get_domain "$redirect_url")

    # Handle redirects
    if [[ "$http_code" =~ ^3 ]]; then
        if [[ -n "$redirect_url" && "$redirect_domain" != "$original_domain" ]]; then
            echo -e "${YELLOW}[EXTERNAL REDIRECT] $url → $redirect_url${RESET}"
        else
            echo -e "${GRAY}[INTERNAL REDIRECT] $url → $redirect_url${RESET}"
        fi
        # Skip further CORS checks for redirects
        continue
    fi

    if [[ "$http_code" =~ ^2 ]]; then
        # Send CORS header test request with Origin header
        origin_test="https://evil.com"
        response_headers=$(curl -s -I -H "Origin: $origin_test" --max-time 10 "$url")

        # Extract headers (case insensitive)
        acao=$(echo "$response_headers" | grep -i "^Access-Control-Allow-Origin:" | awk '{print $2}' | tr -d '\r')
        acrc=$(echo "$response_headers" | grep -i "^Access-Control-Allow-Credentials:" | awk '{print $2}' | tr -d '\r')
        origin_sent=$(echo "Origin: $origin_test" | awk '{print $2}')

        # Check if Origin header was sent in request (we are sending it, so yes)
        origin_header_present=true

        # Check for presence of Access-Control-Allow-Origin and Access-Control-Allow-Credentials headers
        if [[ "$origin_header_present" == true ]] && [[ -n "$acao" ]] && ([[ "$acao" == "*" ]] || [[ "$acao" == "$origin_test" ]]) && [[ "$acrc" == "true" ]]; then
            # Vulnerable: Reflective or wildcard CORS with credentials allowed
            if [[ "$acao" == "*" ]]; then
                echo -e "${RED}[VULNERABLE] Wildcard CORS with credentials: $url${RESET}"
                echo "$url [*] Wildcard CORS with credentials Allowed: *" >> "$OUTPUT_FILE"
            else
                echo -e "${RED}[VULNERABLE] Reflective CORS with credentials: $url${RESET}"
                echo "$url [*] Reflective CORS with credentials Allowed: $acao" >> "$OUTPUT_FILE"
            fi
        elif [[ "$origin_header_present" == true ]] && [[ -n "$acao" ]] && ([[ "$acao" == "*" ]] || [[ "$acao" == "$origin_test" ]]); then
            # Vulnerable: Reflective or wildcard CORS but no credentials allowed
            if [[ "$acao" == "*" ]]; then
                echo -e "${RED}[VULNERABLE] Wildcard CORS (no credentials): $url${RESET}"
                echo "$url [*] Wildcard CORS Allowed: *" >> "$OUTPUT_FILE"
            else
                echo -e "${RED}[VULNERABLE] Reflective CORS (no credentials): $url${RESET}"
                echo "$url [*] Reflective CORS Allowed: $acao" >> "$OUTPUT_FILE"
            fi
        else
            # Not vulnerable
            echo -e "${GREEN}[LIVE] $url${RESET}"
        fi
    else
        echo -e "${GRAY}[DEAD] $url [Code: $http_code]${RESET}"
    fi

    sleep 0.5
done < "$TEMP_FILE"

echo -e "[✓] ${GREEN}Scan complete. Vulnerable results saved in: $OUTPUT_FILE${RESET}"

rm "$TEMP_FILE"
