---
id: T1041
title: Exfiltration Over C2 Channel
source_type: mitre_attack
source_note: Developer-authored summary; verify the current technique details at attack.mitre.org before citing.
---
Summarised by the developer; verify against attack.mitre.org before citing.

# Exfiltration Over C2 Channel

## What it is
Data may be sent out through a communication channel already used to control or communicate with an affected system. Large outbound volume by itself is not proof of data theft.

## Typical indicators
Look for unusual outbound transfer volume, repeated connections to unfamiliar external infrastructure, transfers outside expected workloads, or endpoint activity that temporally aligns with outbound traffic.

## What to check next
Verify whether the destination is external and expected, identify the sending process and data source, compare transfer size with a baseline, and preserve network and endpoint records.

## Containment options
For analyst approval: consider a narrowly scoped egress block or host isolation after validating business impact. Preserve destination, timing, byte counts, and relevant packet or proxy records.
