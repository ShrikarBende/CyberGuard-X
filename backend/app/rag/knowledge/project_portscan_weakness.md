---
id: PROJECT-PORTSCAN-WEAKNESS
title: CICIDS PortScan Model Weakness
source_type: project_doc
source_note: Project evaluation summary; consult the saved evaluation artifacts for the run-specific metrics.
---
# CICIDS PortScan Model Weakness

The current CICIDS model has a known weakness on PortScan traffic: its class-specific performance is less reliable than the strongest classes in the saved evaluation. A PortScan label or a failure to assign that class should therefore be interpreted with care. Review the run-specific confusion details and network evidence; do not treat the model result as ground truth or change thresholds based on one event.
