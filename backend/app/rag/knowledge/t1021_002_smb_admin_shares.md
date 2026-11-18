---
id: T1021.002
title: SMB and Windows Admin Shares
source_type: mitre_attack
source_note: Developer-authored summary; verify the current technique details at attack.mitre.org before citing.
---
Summarised by the developer; verify against attack.mitre.org before citing.

# SMB and Windows Admin Shares

## What it is
Remote SMB connections and administrative shares can be used for legitimate management or to move between Windows systems and access files or services remotely.

## Typical indicators
Review unusual SMB connections, administrative-share access, unexpected remote service activity, new source-to-destination pairs, and authentication events from the same account.

## What to check next
Check share-access and logon records, identify the initiating process and account, verify the host pair against management tooling, and preserve relevant file and network metadata.

## Containment options
For analyst approval: consider limiting SMB between affected segments or isolating a verified source host. Coordinate with system owners to avoid disrupting administration or file services.
