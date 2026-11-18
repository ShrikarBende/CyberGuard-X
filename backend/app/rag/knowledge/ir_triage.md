---
id: IR-TRIAGE
title: Security Alert Triage Procedure
source_type: incident_response
source_note: Internal response guidance; follow the organization's approved incident-response plan.
---
# Security Alert Triage Procedure

## Triage steps
Confirm the alert source, time range, affected account and device, and the exact evidence attached. Check whether related events agree across identity, endpoint, and network records. Treat rules and model flags as leads for review, not as proof of compromise.

## Evidence preservation
Record event IDs, timestamps, source and destination details, process data, and relevant account context. Preserve original logs and collection metadata in approved storage. Avoid changing or deleting evidence while gathering context.

## Containment options
Any account disablement, session revocation, host isolation, firewall change, or process termination is recommended for analyst approval. Assess operational impact and follow the response plan; no action is automatic.

## Escalation
Escalate to the incident lead when evidence indicates continuing access, material data exposure, multiple affected systems, or a business-critical service impact. Record uncertainty and the evidence still needed.
