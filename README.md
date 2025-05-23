# 🔐 linux-hardening-check.py

Un script en Python que realiza verificaciones clave de seguridad (“hardening”) en sistemas Linux. Pensado para auditorías rápidas, validación de buenas prácticas y revisiones post-instalación. Más potente y detallado que su predecesor en Bash, con salida colorida y logs completos.

---

## 📋 ¿Qué hace este script?

`linux-hardening-check.py` analiza configuraciones comunes de seguridad en sistemas Linux y genera un reporte con hallazgos relevantes. **No realiza cambios en el sistema.**

### Verificaciones incluidas:

- ✅ Permisos de archivos críticos: `/etc/passwd`, `/etc/shadow`, `/etc/group`
- 👥 Usuarios con UID 0 distintos de `root`
- 🔐 Expiración de contraseñas no configurada
- 📡 Servicios inseguros activos (`telnet`, `ftp`, `rsh`)
- 🛑 Acceso SSH como `root` habilitado
- 🧨 Binarios con bit SUID (opcional)
- 🛡 Firewall activo (`ufw`, `iptables`) y configurado
- 📁 Registros recientes de login y escaladas (`journalctl` o `/var/log/auth.log`)
- 📄 Registro detallado (`.log`) con advertencias y errores detectados

---

## 🚀 Uso

### Requisitos

- Python 3.x
- Acceso como `root` (recomendado para resultados completos)

### Ejecución típica

```bash
sudo python3 linux_hardening_check.py
