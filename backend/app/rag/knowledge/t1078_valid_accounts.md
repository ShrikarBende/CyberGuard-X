---
id: T1078
title: Valid Accounts
source_type: mitre_attack
source_note: Developer-authored summary; verify the current technique details at attack.mitre.org before citing.
---
Summarised by the developer; verify against attack.mitre.org before citing.

# Valid Accounts

## What it is
An intruder may use a real account's credentials or session to access systems while appearing to be a legitimate user. A valid-account signal alone does not establish that the account was compromised.

## Typical indicators
Review an unfamiliar source address or device, unusual login hours, authentication-method changes, unexpected privilege use, and activity that differs from the user's baseline. Consider VPNs, travel, shared devices, and approved maintenance.

## What to check next
Confirm the login with the user or service owner, compare session and MFA records, inspect access changes, and check whether the same credential or device appears in related events.

## Containment options
For analyst approval: consider revoking sessions, resetting credentials, or requiring a fresh MFA challenge after validating the user's identity and preserving relevant authentication evidence.
