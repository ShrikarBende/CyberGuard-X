---
id: T1059.001
title: PowerShell
source_type: mitre_attack
source_note: Developer-authored summary; verify the current technique details at attack.mitre.org before citing.
supported_indicators: encoded_powershell, powershell_process_creation
---
Summarised by the developer; verify against attack.mitre.org before citing.

# PowerShell

## What it is
PowerShell is a normal Windows administration and automation tool. Its command interpreter can also be misused to run scripts, so command context and process ancestry matter.

## Typical indicators
Review encoded or heavily obfuscated command lines, unusual parent processes, script execution from temporary paths, unexpected network access, and related script-block or process-creation records.

## What to check next
Preserve the complete command line and process tree, collect available script-block records, identify the user and host, and compare the activity with approved administration jobs.

## Containment options
For analyst approval: consider stopping a confirmed suspicious process or isolating a host under the response plan. Preserve volatile process and network evidence before containment when feasible.
