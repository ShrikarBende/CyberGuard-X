---
id: CVE-2021-44228
title: Apache Log4j remote code execution advisory
source_type: cve
source_note: CVE Program and CISA KEV; verify affected versions and mitigations in current vendor advisories.
---
# CVE-2021-44228
CVE-2021-44228 affects Apache Log4j 2 in vulnerable versions and can permit remote code execution when attacker-controlled data reaches vulnerable logging configurations. Investigation should verify deployed Log4j versions, application dependency inventories, exploitation indicators, outbound connections, and vendor mitigation status. The CISA Known Exploited Vulnerabilities catalog identifies this vulnerability as exploited in the wild. Do not infer exposure from a generic Java process or network alert alone.

# Evidence and mitigation
Correlate application inventory, package or container manifests, application logs, process creation, and outbound network telemetry. Apply vendor-recommended fixed versions or mitigations only after asset-owner review and change approval. Preserve relevant logs before remediation.
