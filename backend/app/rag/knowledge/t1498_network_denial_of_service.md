---
id: T1498
title: Network Denial of Service
source_type: mitre_attack
source_note: Developer-authored summary; verify the current technique details at attack.mitre.org before citing.
---
Summarised by the developer; verify against attack.mitre.org before citing.

# Network Denial of Service

## What it is
Network traffic may be generated or coordinated to reduce the availability of a service or network. Spikes can also result from flash crowds, retries, or misconfiguration.

## Typical indicators
Look for abrupt traffic growth, repeated requests or packets, service latency or loss, concentration on a target, and corroborating availability monitoring.

## What to check next
Compare telemetry with service health and normal peaks, identify affected destinations and traffic sources, check upstream provider alerts, and preserve time-aligned flow and application logs.

## Containment options
For analyst approval: consider provider-assisted filtering, rate limits, or a documented traffic-management change. Confirm the affected service owner and preserve evidence before changing routes or filters.
