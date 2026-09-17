# PLAYBOOK AVANZADO DE RESPUESTA A INCIDENTES (DFIR-DÍA 15)

## 1. Resumen Ejecutivo e Hipótesis de la Intrusión
Durante una auditoría híbrida rutinaria en el Host **WIN-DC-01**, el motor SIEM correlacionó múltiples alertas críticas consecutivas. El adversario ejecutó una cadena de ataque completa que abarca Evasión de Defensas, Vaciado de Credenciales en Memoria, Establecimiento de Canal de Comando y Control (C2), y persistencia múltiple en el sistema.

## 2. Línea de Tiempo del Ataque & Mapeo MITRE ATT&CK
* **20:45:10Z** | **T1547.001 (Persistencia):** Modificación del registro en la Run Key (`AMID_Backdoor`) apuntando a un binario sospechoso en `C:\Users\Public\`.
* **20:46:15Z** | **T1562.001 (Evasión de Defensas):** Desactivación forzada del monitoreo en tiempo real de Windows Defender mediante PowerShell.
* **20:47:30Z** | **T1003.001 (Acceso a Credenciales):** Volcado de memoria del proceso LSASS utilizando la herramienta Mimikatz (`mimikatz.exe`) para extraer hashes de administración.
* **20:48:00Z** | **T1071 (Comando y Control):** Conexión de red saliente establecida desde el payload hacia el servidor C2 remoto controlado por el atacante en la IP `103.245.222.11` por el puerto `4444`.
* **20:49:12Z** | **T1053.005 (Persistencia de Respaldo):** Creación de una tarea programada maliciosa encubierta bajo el nombre `\Microsoft\Windows\Update\MaliciousTask`.

## 3. Matriz de Indicadores de Compromiso (IoCs)

| Tipo de Artefacto | Valor / Detalle Técnico | Propósito del Atacante |
| :--- | :--- | :--- |
| **Ruta de Archivo** | `C:\Users\Public\amid_payload.exe` | Ejecutable Backdoor principal |
| **Ruta de Archivo** | `C:\Users\Public\mimikatz.exe` | Herramienta de vaciado de contraseñas |
| **Clave de Registro**| `HKCU\...\Run /v AMID_Backdoor` | Ejecución automática al iniciar sesión |
| **Dirección IP C2** | `103.245.222.11` (Puerto 4444) | Servidor de Control Externo |
| **Tarea Programada**| `\Microsoft\Windows\Update\MaliciousTask` | Persistencia redundante persistente |

## 4. Plan de Acción de Remediación Inmediata (IR-Steps)
1. **Fase de Contención:** Aislar de manera estricta el Host de la red corporativa. Bloquear perimetralmente la IP `103.245.222.11` en el Firewall de borde.
2. **Fase de Erradicación:**
   * Terminar procesos activos asociados a `amid_payload.exe`.
   * Borrar la llave del registro `AMID_Backdoor` y remover la tarea programada mediante comandos administrativos.
   * Eliminar físicamente los binarios de la carpeta pública.
3. **Fase de Recuperación:** Realizar un cambio masivo de credenciales de todas las cuentas comprometidas en LSASS (Cuentas de Administrador de Dominio y Locales). Reactivar la telemetría de Windows Defender.
