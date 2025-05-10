# 🔐 linux-hardening-check.sh

Un script en Bash puro que realiza verificaciones básicas de seguridad ("hardening") en sistemas Linux. Ideal para auditorías rápidas, automatización o revisión en servidores recién desplegados.

---

## 📋 ¿Qué hace este script?

`linux-hardening-check.sh` examina configuraciones clave de seguridad en un sistema Linux y reporta hallazgos relevantes. No modifica nada — solo informa.

### Verificaciones incluidas:

- ✅ Permisos de archivos críticos: `/etc/passwd`, `/etc/shadow`, `/etc/group`
- 👥 Usuarios con UID 0 distintos de `root`
- 🔐 Expiración de contraseñas
- 📡 Servicios inseguros activos (telnet, ftp, rsh)
- 🛑 Acceso root vía SSH habilitado
- 🧨 Binarios con bit SUID (sudo, passwd, etc.)
- 🛡 Estado del firewall (ufw / iptables)
- 📁 Últimos accesos (`lastlog`) y accesos fallidos (`/var/log/auth.log`)

---

## 🚀 Uso

### Requisitos:
- Bash
- Acceso como `root` para resultados completos (recomendado)

### Ejecución típica:

```bash
sudo ./linux-hardening-check.sh

### 🌀 Indicadores de progreso:

Durante tareas más lentas (como el escaneo de binarios SUID), el script muestra un spinner animado para indicar que está trabajando, evitando confusiones sobre posibles cuelgues.

### 📦 Características
✔️ Bash puro, sin dependencias externas

🧱 Funciona en Debian, Ubuntu, CentOS, RHEL y derivados

🛠 Ideal para automatización, scripts de post-instalación o auditoría inicial

🌐 Salida clara y coloreada (compatible con terminales estándar)