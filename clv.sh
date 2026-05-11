#!/bin/bash

# =========================
# CLV - Critical Linux Vector
# Privilege Escalation Auditor
# =========================

# -------- Colors --------
RED='\033[1;31m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
GREEN='\033[1;32m'
NC='\033[0m'

# -------- Banner --------
banner() {
clear
echo -e "${RED}"
cat << "EOF"
   ________    _    __
  / ____/ /   | |  / /
 / /   / /    | | / /
/ /___/ /___  | |/ /
\____/_____/  |___/

   Capture Linux vulnerability
EOF
echo -e "${NC}"
}

# -------- Helpers --------
critical() { echo -e "${RED}[CRITICAL]${NC} $1"; }
high()     { echo -e "${YELLOW}[HIGH]${NC} $1"; }
info()     { echo -e "${BLUE}[INFO]${NC} $1"; }
good()     { echo -e "${GREEN}[OK]${NC} $1"; }

# =========================
# GTFOBins CHECK
# =========================
check_gtfobin() {
    bin=$(basename "$1")
    url="https://gtfobins.github.io/gtfobins/$bin/"

    code=$(curl -s -o /dev/null -w "%{http_code}" "$url")

    if [ "$code" == "200" ]; then
        critical "$bin found in GTFOBins -> $url"
    else
        good "$bin not in GTFOBins"
    fi
}

# =========================
# SUDO CHECK + PARSING
# =========================
check_sudo() {

echo
info "Checking sudo privileges..."

sudo_output=$(sudo -l 2>/dev/null)

echo "$sudo_output"

# استخراج الأوامر القابلة للتشغيل
commands=$(echo "$sudo_output" | grep -E "NOPASSWD|=\(.*\)" | \
    sed -E 's/.*\) //g' | tr ',' '\n' | awk '{print $1}' | sort -u)

if [ -z "$commands" ]; then
    info "No sudo commands found or restricted."
    return
fi

echo
info "Testing extracted sudo commands against GTFOBins..."

for cmd in $commands; do
    [ -z "$cmd" ] && continue
    check_gtfobin "$cmd"
done
}

# =========================
# CRON CHECK
# =========================
check_cron() {

echo
info "Checking writable cron jobs..."

cron_locations=(
    "/etc/crontab"
    "/etc/cron.d"
    "/var/spool/cron"
    "/etc/anacrontab"
)

for path in "${cron_locations[@]}"; do

    [ ! -e "$path" ] && continue

    if [ -w "$path" ]; then
        high "Writable cron location: $path"
    fi

    find "$path" -type f 2>/dev/null | while read file; do

        [ -w "$file" ] && critical "Writable cron file -> $file"

        grep -E "\.sh|/bin/" "$file" 2>/dev/null | while read line; do
            script=$(echo "$line" | awk '{print $NF}')
            [ -w "$script" ] && critical "Writable executed script -> $script"
        done

    done
done
}

# =========================
# WORLD WRITABLE FILES
# =========================
check_permissions() {

echo
info "Checking world-writable files..."

find / \
  -path /proc -prune -o \
  -path /sys -prune -o \
  -path /dev -prune -o \
  -type f -perm -o+w -print 2>/dev/null | while read file; do

    high "World writable -> $file"

done
}

# =========================
# SENSITIVE FILES
# =========================
check_sensitive() {

echo
info "Searching sensitive files..."

find /home /root 2>/dev/null \( \
    -name "id_rsa" -o \
    -name "*.pem" -o \
    -name "*.key" -o \
    -name ".bash_history" -o \
    -name ".env" \
\) | while read file; do

    [ -r "$file" ] && critical "Readable sensitive file -> $file"

done
}

# =========================
# SUID (FIXED)
# =========================
check_suid() {

echo
info "Scanning SUID binaries..."

find / \
  -path /proc -prune -o \
  -path /sys -prune -o \
  -path /dev -prune -o \
  -type f -perm -4000 -print 2>/dev/null | while read file; do

    high "SUID -> $file"

    # auto GTFOBins check
    #check_gtfobin "$file"

done
}

# =========================
# CAPABILITIES
# =========================
check_caps() {

echo
info "Checking capabilities..."

command -v getcap >/dev/null 2>&1 || {
    info "getcap not installed"
    return
}

getcap -r / 2>/dev/null | while read line; do
    high "Capability -> $line"
done
}

# =========================
# MENU
# =========================
menu() {

echo
echo "1) Cron Jobs"
echo "2) World Writable Files"
echo "3) Sensitive Files"
echo "4) SUID Scan"
echo "5) Capabilities"
echo "6) Sudo + GTFOBins"
echo "7) Full Scan"
echo "0) Exit"
echo

read -p "Select: " opt

case $opt in

1) check_cron ;;
2) check_permissions ;;
3) check_sensitive ;;
4) check_suid ;;
5) check_caps ;;
6) check_sudo

    ;;
7)  check_cron
    check_permissions
    check_sensitive
    check_suid
    check_caps
    check_sudo
    ;;
0) exit 0 ;;
*) echo "Invalid option" ;;
esac
}

# =========================
# MAIN
# =========================
banner
menu
