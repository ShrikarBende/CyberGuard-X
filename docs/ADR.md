# Architecture decisions

## Evaluation uses session-disjoint splits

Repeated network flows from one capture session can be near-duplicates. Keeping sessions together across train, validation, and test reduces that leakage risk. CICIDS2017 has only one capture day per target family in the current development scope, so per-family results at that level are indicative and cannot establish reliable cross-day generalization.

## Model loading fails closed on unsigned bundles

Python pickle/joblib bundles can execute code during deserialization. Runtime loaders verify a SHA-256 digest and HMAC-SHA-256 manifest before deserializing. This requires operators to protect the signing key and sign/register trusted bundles; unsigned or modified bundles are rejected.

## Proxy labels are not ground truth

TFT, GAT, and Fusion branches use heuristic or synthetic weak labels, with feedback where available. Their metrics are labelled proxy-label validated and do not establish performance against independently verified real-world outcomes.
