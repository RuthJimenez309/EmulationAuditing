# Adversary Emulation & Hybrid SIEM Log Auditing

## Descripción del Proyecto

El portafolio implementa un enfoque híbrido de ciberseguridad (**Purple Teaming**). Se emula la actividad avanzada de un adversario generando telemetría de ataques (ofensivo) y se diseña un motor de correlación de reglas dinímico en PowerShell para detectar y auditar intrusiones basadas en la matriz **MITRE ATT&CK** (defensivo).

## Tecnologías y Disciplinas Utilizadas

- **Ethical Hacking (Ofensivo):** Emulación de persistencia en Run Keys, evasión de defensas (antivirus), vaciado de credenciales en memoria (LSASS/Mimikatz) y establecimiento de canales Command & Control (C2).
- **Threat Hunting & SIEM Analytics (Defensivo):** Monitoreo de feeds JSON, parseo de objetos estructurados y correlación automatizada de eventos.
- **Incident Response (DFIR):** Creación de playbooks estructurados para mitigación y erradicación de amenazas.

## Estructura de Archivos del Proyecto

- `README.md`: Documentación principal del laboratorio.
- `.gitignore`: Filtro de exclusión para control de versiones de archivos de logs temporales.
- `Log_Auditing/siem_rules_engine.ps1`: Script del motor lógico de reglas automáticas SIEM.
- `Log_Auditing/Incident_Response_Playbook.md`: Plan forense y playbook de remediación ante incidentes.

## Reglas de Detección Implementadas (MITRE ATT&CK)

1. **T1547.001:** Modificación de llaves de registro automáticas para persistencia.
2. **T1562.001:** Evasión de defensas mediante la desactivación forzada del antivirus.
3. **T1003.001:** Acceso no autorizado al espacio de memoria LSASS para volcado de credenciales.
4. **T1071:** Detección de trafico de red saliente hacia puertos de control (C2 - Puerto 4444).
5. **T1053.005:** Creación de tareas programadas como persistencia secundaria persistente.
