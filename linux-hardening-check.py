#!/usr/bin/env python3

import os
import stat
import pwd
import grp
import subprocess
import time
import sys
import re
import logging
from datetime import datetime
import threading

# === COLORES PARA CONSOLA ===
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
NC = "\033[0m"  # Sin color

# === CONFIGURAR LOGGING ===
log_filename = f"linux_hardening_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    filename=log_filename,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def spinner(message, stop_event):
    spin_chars = "|/-\\"
    idx = 0
    while not stop_event.is_set():
        print(f"\r{message} {spin_chars[idx % len(spin_chars)]}", end='', flush=True)
        idx += 1
        time.sleep(0.1)
    print("\r" + " " * (len(message) + 2), end='\r')  # Limpiar línea

# === VALIDACIÓN DE ROOT ===
def check_root(skip_check=False):
    if os.geteuid() != 0 and not skip_check:
        print(f"{RED}⚠️ Este script debe ejecutarse como root. Usa sudo o añade --skip-root-check para probarlo.{NC}")
        sys.exit(1)

# === CHEQUEO DE PERMISOS DE ARCHIVOS CRÍTICOS ===
def check_permissions():
    print("\n🔒 Comprobando permisos de archivos críticos...")
    critical_files = {
        "/etc/passwd": "644",
        "/etc/group": "644",
        "/etc/shadow": ["000", "640"],
    }

    for file, expected in critical_files.items():
        try:
            perms = oct(os.stat(file).st_mode)[-3:]
            print(f"  {file}: ", end="")
            if isinstance(expected, list):
                if perms in expected:
                    print(f"{GREEN}OK{NC}")
                else:
                    print(f"{RED}Permisos inseguros ({perms}){NC}")
            else:
                if perms == expected:
                    print(f"{GREEN}OK{NC}")
                else:
                    print(f"{RED}Permisos inseguros ({perms}){NC}")
        except FileNotFoundError:
            print(f"{YELLOW}No encontrado{NC}")
        except PermissionError:
            print(f"{RED}Permiso denegado{NC}")

# === CHEQUEO DE USUARIOS CON UID 0 (root alternos) ===
def check_uid0_users():
    print("\n🧍 Usuarios con UID 0 distintos de root:")
    try:
        with open("/etc/passwd", "r") as passwd_file:
            found = False
            for line in passwd_file:
                if line.strip() == "":
                    continue
                parts = line.strip().split(":")
                username, uid = parts[0], parts[2]
                if uid == "0" and username != "root":
                    print(f"  {YELLOW}{username}{NC}")
                    found = True
            if not found:
                print("  Ninguno detectado.")
    except Exception as e:
        print(f"  {RED}Error leyendo /etc/passwd: {e}{NC}")

# === CHEQUEO DE EXPIRACIÓN DE CONTRASEÑAS ===
def check_password_expiry():
    print("\n⏳ Comprobando expiración de contraseñas...")
    expired_users = []

    try:
        with open("/etc/shadow", "r") as shadow_file:
            for line in shadow_file:
                parts = line.strip().split(":")
                if len(parts) < 5:
                    continue
                username, max_days = parts[0], parts[4]
                if max_days in ["", "99999"]:
                    expired_users.append(username)

        if len(expired_users) == 0:
            print(f"  {GREEN}Todos los usuarios tienen políticas de expiración.{NC}")
        else:
            for i, user in enumerate(expired_users[:3]):
                print(f"  {YELLOW}Usuario {user} sin expiración de contraseña.{NC}")
            if len(expired_users) > 3:
                print(f"  {YELLOW}+ {len(expired_users)-3} más. Verifica el log: {log_filename}{NC}")
            for user in expired_users:
                logging.info(f"Usuario {user} sin expiración de contraseña.")
    except PermissionError:
        msg = "/etc/shadow no accesible (requiere root)."
        print(f"  {RED}{msg}{NC}")
        logging.warning(msg)
    except Exception as e:
        msg = f"Error al leer /etc/shadow: {e}"
        print(f"  {RED}{msg}{NC}")
        logging.error(msg)

def check_insecure_services():
    print("\n📡 Comprobando servicios inseguros activos...")
    insecure = ['telnet', 'rsh', 'ftp']
    for svc in insecure:
        try:
            result = subprocess.run(['systemctl', 'is-active', svc], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            if result.stdout.strip() == 'active':
                print(f"  {RED}{svc} está activo{NC}")
                logging.warning(f"Servicio inseguro activo: {svc}")
        except Exception:
            continue

def check_root_ssh():
    print("\n🔐 Comprobando si root puede acceder vía SSH...")
    try:
        with open('/etc/ssh/sshd_config', 'r') as f:
            for line in f:
                if line.strip().startswith("PermitRootLogin") and "yes" in line:
                    print(f"  {RED}PermitRootLogin está habilitado{NC}")
                    logging.warning("Acceso root por SSH está habilitado.")
                    return
        print(f"  {GREEN}Acceso root por SSH está deshabilitado o restringido{NC}")
    except FileNotFoundError:
        print(f"  {YELLOW}No se encontró el archivo sshd_config{NC}")
        logging.warning("No se encontró sshd_config.")

def check_suid_binaries():
    print("\n🧨 Escaneando binarios con bit SUID (esto puede tardar)...")
    stop_event = threading.Event()
    spin_thread = threading.Thread(target=spinner, args=("Buscando archivos con SUID...", stop_event))
    spin_thread.start()

    try:
        result = subprocess.run(
            ['find', '/', '-perm', '-4000', '-type', 'f'],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
    finally:
        stop_event.set()
        spin_thread.join()

    suids = [line for line in result.stdout.strip().split('\n') if line]
    filtered = [s for s in suids if any(b in s for b in ['passwd', 'sudo', 'pkexec', 'su'])]

    if filtered:
        print("\n🔍 Binarios SUID encontrados (filtrados):")
        for path in filtered:
            print(f"  {YELLOW}{path} tiene SUID{NC}")
            logging.info(f"Binario con SUID detectado: {path}")
    else:
        print(f"  {GREEN}No se detectaron binarios SUID críticos.{NC}")

def check_firewall():
    print("\n🛡 Comprobando si hay firewall activo...")

    ufw_status = subprocess.run(['which', 'ufw'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    iptables_status = subprocess.run(['which', 'iptables'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    if ufw_status.stdout.strip():
        status = subprocess.run(['ufw', 'status'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if "Status: active" in status.stdout:
            print(f"  {GREEN}ufw está activo{NC}")
            logging.info("ufw está activo")
        else:
            print(f"  {YELLOW}ufw no está activo{NC}")
            logging.warning("ufw no está activo")
    elif iptables_status.stdout.strip():
        rules = subprocess.run(['iptables', '-L'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if rules.stdout.strip():
            print(f"  {GREEN}iptables está configurado{NC}")
            logging.info("iptables está configurado")
        else:
            print(f"  {RED}iptables está presente pero sin reglas definidas{NC}")
            logging.warning("iptables presente sin reglas definidas")
    else:
        print(f"  {YELLOW}No se detectó ningún firewall instalado{NC}")
        logging.warning("No se detectó firewall (ufw/iptables)")

def check_login_logs():
    print("\n📁 Auditoría de logins y escaladas de privilegios (últimos 7 días):")
    logging.info("📁 Auditoría de logins y escaladas de privilegios (últimos 7 días):")

    log_lines = []

    # === INTENTAMOS CON journalctl ===
    try:
        result = subprocess.run(
            ['journalctl', '--since=7 days ago', '--no-pager'],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        log_lines = result.stdout.strip().split('\n')
        logging.info("📄 Fuente: journalctl")
    except FileNotFoundError:
        if os.path.exists("/var/log/auth.log"):
            try:
                with open("/var/log/auth.log", "r") as f:
                    log_lines = f.readlines()
                    logging.info("📄 Fuente: /var/log/auth.log")
            except Exception as e:
                print(f"  ⚠️ No se pudo leer auth.log.")
                logging.error(f"No se pudo leer auth.log: {e}")
                return
        else:
            print("  ⚠️ No se encontró journalctl ni auth.log.")
            logging.warning("No se encontró journalctl ni auth.log.")
            return

    login_keywords = re.compile(r"(session opened|Accepted password|Failed password|sudo|su)", re.IGNORECASE)
    user_logins = {}

    for line in log_lines:
        if login_keywords.search(line):
            user_match = re.search(r"user\s*=?\s*(\w+)", line, re.IGNORECASE)
            sudo_match = re.search(r"sudo:\s*(\w+)", line)
            su_match = re.search(r"su:\s*session", line)
            root_match = re.search(r"\b(root)\b", line)

            user = None
            if user_match:
                user = user_match.group(1)
            elif sudo_match:
                user = sudo_match.group(1)
            elif su_match:
                user = "unknown (su)"
            elif root_match:
                user = "root"

            if user:
                user_logins.setdefault(user, []).append(line.strip())

    if not user_logins:
        print("  No se encontró actividad relevante de login o escalamiento.")
        logging.warning("No se encontró actividad de login o escalamiento.")
    else:
        for user, entries in user_logins.items():
            logging.info(f"\n👤 Actividad de {user}:")
            for line in entries[-5:]:
                logging.info(f"  {line}")
        print(f"  Actividad detectada para {len(user_logins)} usuarios. Verifica el log: {log_filename}")

def resumen_final():
    print("\n==============================")
    print("📄 Resumen Final de Hallazgos")
    print("==============================")

    try:
        with open(log_filename, 'r') as log:
            lines = log.readlines()
            alerts = [l for l in lines if 'WARNING' in l or 'ERROR' in l]
    except Exception as e:
        print(f"{RED}⚠️ No se pudo leer el log final: {e}{NC}")
        return

    if alerts:
        print(f"{RED}⚠️ Se detectaron {len(alerts)} posibles riesgos de seguridad.{NC}")
        print(f"{YELLOW}📁 Revisa el log: {log_filename}{NC}")
    else:
        print(f"{GREEN}✅ No se detectaron riesgos críticos. Sistema aparentemente endurecido.{NC}")

    print("\n🧭 Fin del análisis. ¡Revisa el log generado para más detalles!\n")


# === MAIN ===
def main():
    skip_check = '--skip-root-check' in sys.argv
    check_root(skip_check=skip_check)

    print("\n===============================")
    print("🔐 Linux Hardening Check Script")
    print("===============================\n")

    check_permissions()
    check_uid0_users()
    check_password_expiry()
    check_insecure_services()
    check_root_ssh()
    #check_suid_binaries()
    check_firewall()
    check_login_logs()

    resumen_final()


    print(f"\n{GREEN}✅ Revisión básica completada.{NC}")

if __name__ == "__main__":
    main()
