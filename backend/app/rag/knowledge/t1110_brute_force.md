---
id: T1110
title: Brute Force
source_type: mitre_attack
source_note: Developer-authored summary; verify the current technique details at attack.mitre.org before citing.
---
Summarised by the developer; verify against attack.mitre.org before citing.

# Brute Force

## What it is
A person or program repeatedly tries passwords or other authentication secrets to gain access to an account. It can involve guesses, password lists, or reuse of credentials from another source.

## Typical indicators
Look for repeated failed logins for the same account, many accounts targeted from one origin, unusual login timing, and a successful session shortly after a failure burst. These signals need context; lockouts and shared egress can create benign patterns.

## What to check next
Review the authentication events and source addresses, determine whether any attempt succeeded, compare the session with the account's normal devices and locations, and check for MFA or password-reset activity.

## Containment options
For analyst approval: consider temporary rate limiting or account protection, revoke sessions only when evidence supports it, and coordinate credential changes with the account owner. Preserve authentication logs first.
