GNU nano 8.4                                                                                                                                                                                                                         cors_detector.sh                                                                                                                                                                                                                                  
#!/bin/bash

# Color Codes
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
CYAN="\e[36m"
RESET="\e[0m"

# Show Banner
function banner() {
    clear
    echo -e "${CYAN}"
    echo "██████╗  ██████╗ ██████╗ ███████╗    ██████╗ ███████╗████████╗███████╗ ██████╗████████╗ ██████╗ ██████╗ "
    echo "██╔══██╗██╔═══██╗██╔══██╗██╔════╝    ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗"
    echo "██║  ██║██║   ██║██████╔╝█████╗      ██████╔╝█████╗     ██║   █████╗  ██║        ██║   ██║   ██║██████╔╝"
    echo "██║  ██║██║   ██║██╔═══╝ ██╔══╝      ██╔═══╝ ██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗"
    echo "██████╔╝╚██████╔╝██║     ███████╗    ██║     ███████╗   ██║   ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║"
    echo "╚═════╝  ╚═════╝ ╚═╝     ╚══════╝    ╚═╝     ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝"
    echo -e "${YELLOW}                          Developed by TehanG07${RESET}"
    echo -e "${GREEN}========================= CORS Vulnerability Scanner ==========================${RESET}"
}

# CORS Check Logic
function check_cors() {
    url=$1
    # Send request with Origin header
    response=$(curl -s -I -H "Origin: https://evil.com" "$url")
    header=$(echo "$response" | grep -i "Access-Control-Allow-Origin")

    if [[ "$header" == *"evil.com"* || "$header" == *"*"* ]]; then
        echo -e "${RED}[+] Vulnerable: $url => ${header}${RESET}"
        echo "$url => $header" >> cors_vulnerable.txt
    elif [[ -n "$header" ]]; then
        echo -e "${BLUE}[-] CORS Present but Safe: $url => ${header}${RESET}"
    else
        echo -e "${GREEN}[OK] No CORS header: $url${RESET}"
    fi
}

# Main Flow
banner
read -p "Enter the path of your URL list file: " file_path

if [[ ! -f "$file_path" ]]; then
    echo -e "${RED}[!] File not found. Check your path!${RESET}"
    exit 1
fi

echo -e "${YELLOW}[+] Starting CORS scan...${RESET}"
> cors_vulnerable.txt  # Clear old results

while IFS= read -r url
do
    if [[ "$url" != http* ]]; then
        url="http://$url"
    fi
    check_cors "$url"
    sleep 0.5  # Rate limit
done < "$file_path"

echo -e "${GREEN}[+] Scan Completed! Vulnerable URLs saved in cors_vulnerable.txt${RESET}"
