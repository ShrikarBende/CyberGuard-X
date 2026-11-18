---
id: T1071
title: Application Layer Protocol
source_type: mitre_attack
source_note: Developer-authored summary; verify the current technique details at attack.mitre.org before citing.
---
Summarised by the developer; verify against attack.mitre.org before citing.

# Application Layer Protocol

## What it is
Application protocols such as web or name-resolution traffic may carry ordinary business communication or remote control messages. The protocol alone does not distinguish benign from malicious use.

## Typical indicators
Look for repeated beacon-like timing, unusual destinations, rare protocol behavior, abnormal request sizes, and a process or host that does not normally use the observed service.

## What to check next
Review DNS, proxy, and flow records together; identify the process and destination; compare periodicity and volume with a host baseline; and check for related endpoint indicators.

## Containment options
For analyst approval: consider a scoped block or endpoint isolation only after validating destination ownership and service impact. Preserve relevant name-resolution and proxy evidence.
