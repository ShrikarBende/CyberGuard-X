---
id: CVE-2021-34527
title: Windows Print Spooler remote code execution advisory
source_type: cve
source_note: NVD and Microsoft Security Response Center advisory; confirm patch and applicability against vendor guidance.
---
# CVE-2021-34527
CVE-2021-34527, commonly called PrintNightmare, concerns Windows Print Spooler security and may permit code execution or privilege escalation on affected configurations. Investigation should establish Windows build and patch state, Print Spooler service configuration, relevant process and service events, and whether the host role requires printing. A process or privilege alert alone does not establish exploitation.

# Response considerations
Use Microsoft guidance to verify affected systems and mitigations. Coordinate any service changes or patch deployment with the system owner and change process. Preserve endpoint and authentication telemetry relevant to the incident.
