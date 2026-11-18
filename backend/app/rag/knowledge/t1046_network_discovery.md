---
id: T1046
title: Network Service Discovery
source_type: mitre_attack
source_note: Developer-authored summary; verify the current technique details at attack.mitre.org before citing.
---
Summarised by the developer; verify against attack.mitre.org before citing.

# Network Service Discovery

## What it is
An operator or program probes hosts and ports to learn which systems and services are reachable. Inventory tools and vulnerability scanners can produce similar activity.

## Typical indicators
Check for one source contacting many destination hosts or ports in a short period, sequential port patterns, repeated connection failures, and activity from an endpoint that is not an approved scanner.

## What to check next
Identify the source process and owner, compare the activity with scan schedules and asset inventory, review firewall outcomes, and see whether later authentication or exploit-related events followed.

## Containment options
For analyst approval: consider rate limiting or isolating a source only after excluding authorized scanning. Preserve flow records and scanner configuration for review.
