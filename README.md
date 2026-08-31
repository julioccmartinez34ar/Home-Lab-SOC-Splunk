Reporte de Análisis Técnico: Monitoreo de Telemetría Endpoint (Splunk + Sysmon)
Fecha: 31 de agosto de 2026

"Analista SOC": Julio Conde
"Entorno Monitoreado": Windows Endpoint (pc)
"Plataforma SIEM": Splunk Enterprise
"Fuente de Datos": WinEventLog:Microsoft-Windows-Sysmon/Operational

#Resumen Ejecutivo
Se ha llevado a cabo un análisis de telemetría sobre el endpoint monitoreado utilizando el agente Microsoft Sysmon indexado en Splunk Enterprise. El objetivo principal consistió en auditorizar el comportamiento de ejecución de procesos y las conexiones de red salientes para establecer una línea base de seguridad (Baseline) e identificar posibles discrepancias o anomalías.

#Resultado del Análisis:

No se detectaron actividades maliciosas o indicadores de compromiso (IoC) durante el periodo de evaluación. El tráfico de red saliente observado corresponde a procesos legítimos del sistema operativo (sincronización de Microsoft OneDrive a través de TLS/HTTPS).

"Metodología de Captura y Consultas SPL"
A. Auditoría de Creación de Procesos (EventCode=1)
Para analizar la frecuencia de ejecución de binarios en el sistema y detectar posibles ejecuciones anómalas o desconocidas, se aplicó la siguiente regla en Search Processing Language (SPL): sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| stats count by Image, User
| sort - count
Propósito: Agrupar todos los binarios ejecutados por usuario, contar su frecuencia y ordenarlos descendentemente para identificar ejecutables fuera del patrón habitual.
B. Auditoría de Conexiones de Red Salientes (EventCode=3)
Para verificar las comunicaciones establecidas por los procesos locales hacia direcciones IP externas, se ejecutó la consulta:
 sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| stats count by Image, DestinationIp, DestinationPort, Protocol
| sort - count
Propósito: Mapear la relación entre el ejecutable local (Image), la dirección IP destino (DestinationIp), el puerto (DestinationPort) y el protocolo empleado (Protocol).

Hallazgos Técnicos y Análisis de Evidencia
Conexiones de Red Salientes 
Del análisis del panel de red se extraen los siguientes registros principales:
Proceso Origen: ...\OneDrive.Sync.Service.exe  ...\OneDrive.Sync.Service.exe
IPDestino: 20.184.175.9  4.150.223.100
Puerto Destino: 443 
Protocolo: tcp
Eventos (Count): 3
Evaluación: Legítimo (Microsoft Azure/OneDrive) Legítimo (Microsoft CDN/Cloud)
Análisis de Puerto y Protocolo: La totalidad del tráfico observado utiliza el puerto 443/TCP (HTTPS), garantizando cifrado en tránsito mediante TLS.
Análisis de Reputación IP: Las direcciones IP de destino corresponden a rangos de infraestructura oficial de Microsoft 
Corporation.

"Recomendaciones y Próximos Pasos"
Ajuste de Reglas de Detección: Implementar alertas automáticas en Splunk para detectar ejecuciones de cmd.exe o powershell.exe provenientes de directorios temporales (AppData\Local\Temp).

Monitoreo de Persistencia: Ampliar la telemetría de Sysmon para incluir la auditoría de modificación de registros (EventCode 12/13) y creación de tareas programadas.

![SOC Dashboard Overview](screenshots/03_dashboard_soc.png)
