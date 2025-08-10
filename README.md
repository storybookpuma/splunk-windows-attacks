# Detecting Windows Attacks with Splunk (3 casos clave)

Este proyecto resume tres detecciones prácticas en entornos Windows usando Splunk. Incluye contexto de ataque, consultas SPL y capturas de resultados. Seleccioné tres escenarios de alto impacto: Kerberoasting, Pass‑the‑Hash (PtH) y Pass‑the‑Ticket (PtT).

## 1) Kerberoasting
Ataque sobre cuentas con SPN para obtener TGS cifrados (típicamente RC4-HMAC) y crackearlos offline.

- Indicadores: solicitudes TGS masivas, `cipher="rc4-hmac"`, flags `forwardable/renewable` activas.

Consulta SPL ejemplo:
```spl
index=sharphound sourcetype="bro:kerberos:json" request_type=TGS cipher="rc4-hmac" \
  forwardable="true" renewable="true"
| table _time, id.orig_h, id.resp_h, request_type, cipher, forwardable, renewable, client, service
```

Resultado (muestra TGS sospechosos):

![Kerberoasting TGS](./images/Pasted%20image%2020250729103639.png)
![Kerberoasting tabla](./images/Pasted%20image%2020250729104005.png)
![Kerberoasting cliente](./images/Pasted%20image%2020250729105843.png)

## 2) Pass‑the‑Hash (PtH)
Uso del hash NTLM para autenticarse sin contraseña, a menudo tras acceso de LSASS (Sysmon Event ID 10) y logon con credenciales alternas (LogonType 9).

Consulta SPL (correlación Sysmon 10 con Security 4624 LogonType=9):
```spl
index=main earliest=1690450689 latest=1690451116 \
  (source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="C:\\Windows\\system32\\lsass.exe" SourceImage!="C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\*\\MsMpEng.exe") \
  OR (source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo)
| sort _time, RecordNumber
| transaction host maxspan=1m endswith=(EventCode=4624) startswith=(EventCode=10)
| stats count by _time, Computer, SourceImage, SourceProcessId, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
| fields - count
```

Resultados (acceso a LSASS + logon netonly):

![PtH correlación](./images/Pasted%20image%2020250729124753.png)

## 3) Pass‑the‑Ticket (PtT)
Reutilización/inyección de TGT/TGS robados (sin AS‑REQ previo). Señal: transacciones con TGS sin TGT anterior.

Consulta SPL propuesta:
```spl
index=main earliest=1690392405 latest=1690451745 source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770)
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| table _time, ComputerName, username, src_ip_4, service_name, category
```

Resultados (TGS sin TGT precedente):

![PtT timeline](./images/Pasted%20image%2020250730194655.png)
![PtT diagrama](./images/Pasted%20image%2020250730195237.png)
![PtT listado](./images/Pasted%20image%2020250730201410.png)

## Buenas prácticas generales
- Afinar ventanas de tiempo y campos (host, user, src_ip, service_name)
- Añadir listas de exclusión para procesos legítimos (AV/EDR)
- Enriquecer con lookup de usuarios/activos críticos
- Enviar resultados a dashboards/alertas (severidad media-alta)

## Requisitos
- Splunk (SPL) con fuentes: Security, Sysmon; o datos Zeek si aplica
- Sysmon configurado (Event ID 10, entre otros)

## Nota
Basado en prácticas del path SOC (HTB). Este writeup consolida casos clave para revisión rápida.
