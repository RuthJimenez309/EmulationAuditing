Write-Host "=== INICIANDO MOTOR DE CORRELACIÓN SIEM HYBRID AUDIT ===" -ForegroundColor Cyan
Write-Host "Cargando reglas de detección basadas en MITRE ATT&CK...`n" -ForegroundColor Gray

$eventos = Get-Content -Raw -Path "Log_Auditing\compromised_siem_feed.json" | ConvertFrom-Json

foreach ($e in $eventos) {
    # Regla 1: Registro (Event 4688)
    if ($e.event_id -eq 4688 -and $e.payload.CommandLine -like "*reg add*") {
        Write-Host "[CRÍTICO] Alerta SIEM: Persistencia en Registro!" -ForegroundColor Red
        Write-Host " -> Técnica: MITRE T1547.001 - Run Key Modification"
        Write-Host " -> Comando: $($e.payload.CommandLine)`n" -ForegroundColor DarkYellow
    }
    
    # Regla 2: Evasión Antivirus (Event 1)
    if (\(e.event_id -eq 1 -and\)e.payload.CommandLine -like "*DisableRealtimeMonitoring*") {
        Write-Host "[CRÍTICO] Alerta SIEM: Desactivación de Antivirus!" -ForegroundColor Red
        Write-Host " -> Técnica: MITRE T1562.001 - Impair Defenses"
        Write-Host " -> Comando: (e.payload.CommandLine)`n" -ForegroundColor DarkYellow
    }
    
    # Regla 3: Acceso a LSASS / Credenciales (Event 10)
    if ($e.event_id -eq 10) {
        Write-Host "[ALERTA MÁXIMA] Alerta SIEM: Volcado de Memoria LSASS (Mimikatz)!" -ForegroundColor White -BackgroundColor DarkRed
        Write-Host " -> Técnica: MITRE T1003.001 - LSASS Dumping"
        Write-Host " -> Origen: $($e.payload.SourceImage)`n" -ForegroundColor Yellow
    }
    
    # Regla 4: Conexión C2 (Event 3)
    if (\$e.event_id -eq 3) {
        Write-Host "[ALTA] Alerta SIEM: Tráfico de Red C2 Confirmado!" -ForegroundColor Magenta
        Write-Host " -> Técnica: MITRE T1071 - Protocolo Externo"
        Write-Host " -> IP C2: (e.payload.DestinationIp) en Puerto (e.payload.DestinationPort)`n" -ForegroundColor DarkYellow
    }
    
    # Regla 5: Tarea Programada (Event 4698)
    if ($e.event_id -eq 4698) {
        Write-Host "[CRÍTICO] Alerta SIEM: Tarea Programada Maliciosa!" -ForegroundColor Red
        Write-Host " -> Técnica: MITRE T1053.005 - Scheduled Task"
        Write-Host " -> Nombre: $($e.payload.TaskName)`n" -ForegroundColor DarkYellow
    }
}
