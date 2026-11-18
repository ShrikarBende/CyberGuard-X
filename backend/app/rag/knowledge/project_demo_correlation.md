---
id: PROJECT-DEMO-CORRELATION
title: Demo Correlation Rules and Limits
source_type: project_doc
source_note: Project behavior summary; demo rules are not calibrated for production.
---
# Demo Correlation Rules and Limits

The demo correlation layer emits named indicators from configured event rules, then links indicators sharing a user, device, or source IP within a time window. It creates an incident only when at least three distinct indicator types span at least two layers. The thresholds are marked NOT CALIBRATED and are demonstration values, not validated production cutoffs. A correlated incident is still suspicious activity for analyst review, not a confirmed attack. Demo events are labelled separately from operational telemetry.
