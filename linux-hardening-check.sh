#!/bin/bash

# linux-hardening-check.sh
# Script de endurecimiento básico para sistemas Linux

# ====== CONFIGURACIÓN DE COLORES ======
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
NC="\e[0m" # Sin color

# ====== MANEJO DE ARGUMENTOS ======
SKIP_ROOT_CHECK=false
for arg in "$@"; do
    if [[ "$arg" == "--skip-root-check" ]]; then
        SKIP_ROOT_CHECK=true
    fi
done

# ====== VALIDACIÓN DE PERMISOS ======
if [[ "$EUID" -ne 0 && "$SKIP_ROOT_CHECK" == false ]]; then
    echo -e "${RED}⚠️ Este script debe ejecutarse como root. Usa sudo o añade --skip-root-check si solo deseas probarlo.${NC}"
    exit 1
fi

# ====== SPINNER DE CARGA ======
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    tput civis
    while [ -d /proc/$pid ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    tput cnorm
}

# ====== FUNCIONES DE CHEQUEO ======

check_permissions() {
    echo -e "\n🔒 Comprobando permisos de archivos críticos..."
    for file in /etc/passwd /etc/shadow /etc/group; do
        perms=$(stat -c "%a" "$file" 2>/dev/null)
        echo -n "  $file: "
        case "$file" in
            /etc/passwd|/etc/group)
                [[ "$perms" == "644" ]] && echo -e "${GREEN}OK${NC}" || echo -e "${RED}Permisos inseguros ($perms)${NC}"
                ;;
            /etc/shadow)
                [[ "$perms" == "000" || "$perms" == "640" ]] && echo -e "${GREEN}OK${NC}" || echo -e "${RED}Permisos inseguros ($perms)${NC}"
                ;;
        esac
    done
}

check_uid0_users() {
    echo -e "\n🧍 Usuarios con UID 0 distintos de root:"
    awk -F: '$3 == 0 && $1 != "root" { print "  " $1 }' /etc/passwd || echo "  Ninguno detectado."
}

check_password_expiry() {
    echo -e "\n⏳ Comprobando expiración de contraseñas..."
    if [[ -r /etc/shadow ]]; then
        while IFS=: read -r user pass last min max warn inactive expire flag; do
            if [[ -z "$max" || "$max" -eq 99999 ]]; then
                echo -e "  ${YELLOW}Usuario $user sin expiración de contraseña.${NC}"
            fi
        done < /etc/shadow
    else
        echo -e "  ${RED}No se pudo acceder a /etc/shadow (¿ejecutaste como root?)${NC}"
    fi
}

check_insecure_services() {
    echo -e "\n📡 Servicios inseguros activos:"
    for svc in telnet ftp rsh; do
        if systemctl is-active --quiet "$svc"; then
            echo -e "  ${RED}$svc está activo${NC}"
        fi
    done
}

check_root_ssh() {
    echo -e "\n🔐 Comprobando si root puede acceder vía SSH..."
    if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config 2>/dev/null; then
        echo -e "  ${RED}PermitRootLogin está habilitado${NC}"
    else
        echo -e "  ${GREEN}Acceso root por SSH está deshabilitado o restringido${NC}"
    fi
}

check_suid_binaries() {
    echo -e "\n🧨 Escaneando binarios con bit SUID (esto puede tardar)..."

    tmpfile=$(mktemp)
    (find / -perm -4000 -type f 2>/dev/null > "$tmpfile") &
    pid=$!
    spinner $pid
    wait $pid

    echo -e "\n🔍 Binarios SUID encontrados (filtrados):"
    grep -E '/(passwd|sudo|su|pkexec)' "$tmpfile" | while read -r bin; do
        echo -e "  ${YELLOW}$bin tiene SUID${NC}"
    done

    rm -f "$tmpfile"
}

check_firewall() {
    echo -e "\n🛡 Comprobando si hay firewall activo..."
    if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
        echo -e "  ${GREEN}ufw está activo${NC}"
    elif command -v iptables >/dev/null; then
        if iptables -L &>/dev/null; then
            echo -e "  ${GREEN}iptables está configurado${NC}"
        else
            echo -e "  ${RED}No se pudo acceder a iptables (¿ejecutaste como root?)${NC}"
        fi
    else
        echo -e "  ${YELLOW}No se detectó ufw ni iptables en el sistema${NC}"
    fi
}

check_login_logs() {
    echo -e "\n📁 Últimos accesos y errores de autenticación:"
    lastlog | grep -v "Never" | head -5
    echo -e "\nErrores recientes de autenticación:"
    grep "Failed password" /var/log/auth.log 2>/dev/null | tail -5 || echo "  No se pudo leer /var/log/auth.log"
}

# ====== EJECUCIÓN PRINCIPAL ======
echo -e "\n==============================="
echo -e "🔐 Linux Hardening Check Script"
echo -e "===============================\n"

check_permissions
check_uid0_users
check_password_expiry
check_insecure_services
check_root_ssh
check_suid_binaries
check_firewall
check_login_logs

echo -e "\n✅ Revisión finalizada.\n"
