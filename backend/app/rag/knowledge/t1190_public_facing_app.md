---
id: T1190
title: Exploit Public-Facing Application
source_type: mitre_attack
source_note: Developer-authored summary; verify the current technique details at attack.mitre.org before citing.
---
Summarised by the developer; verify against attack.mitre.org before citing.

# Exploit Public-Facing Application

## What it is
An exposed application may be targeted through a software flaw or unsafe behavior to gain access or run unauthorized actions. Suspicious requests alone do not prove successful exploitation.

## Typical indicators
Review unusual request parameters, repeated errors, unexpected child processes from a service, new files or accounts, and outbound traffic that follows web requests.

## What to check next
Preserve application and reverse-proxy logs, identify the application version and exposed route, compare with vendor guidance, and inspect host changes around the request time.

## Containment options
For analyst approval: consider restricting the affected route or placing the service behind a protective control while owners assess availability and evidence preservation.
