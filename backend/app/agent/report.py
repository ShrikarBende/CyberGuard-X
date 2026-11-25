"""Structured investigation report and evidence validation."""
from typing import Literal
import re
import unicodedata
from pydantic import BaseModel, ConfigDict, Field, ValidationError

ASSESSMENTS = {"unconfirmed_suspicious", "likely_benign", "insufficient_evidence", "unknown_needs_review"}
TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
CONFIRMATION_LANGUAGE_RE = re.compile(
    r"\b(?:is|was|were|are|been|has\s+been|have\s+been)\s+(?:a\s+)?confirmed\b",
    re.IGNORECASE,
)
CONFIRMATION_LANGUAGE_LIMITATION = (
    "Report text used confirmation language; the assessment field is authoritative and no incident status was changed."
)


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    claim: str = Field(max_length=1200)
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)


class TechniqueMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")
    technique_id: str
    rationale: str = Field(max_length=1200)
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)


class Hypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    statement: str = Field(max_length=1200)
    supports: list[str] = Field(default_factory=list, max_length=20)
    contradicts: list[str] = Field(default_factory=list, max_length=20)


class RecommendedAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_type: str
    target_type: str
    target: str
    rationale: str = Field(max_length=1200)
    confidence: float
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)


class AgentReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(max_length=1200)
    assessment: Literal["unconfirmed_suspicious", "likely_benign", "insufficient_evidence", "unknown_needs_review"]
    key_findings: list[Finding] = Field(default_factory=list, max_length=30)
    attack_mapping: list[TechniqueMapping] = Field(default_factory=list, max_length=30)
    hypotheses: list[Hypothesis] = Field(default_factory=list, max_length=30)
    missing_evidence: list[str] = Field(default_factory=list, max_length=30)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list, max_length=5)
    limitations: list[str] = Field(default_factory=list, max_length=30)


def _safe_ids(values, allowed):
    return [item for item in values if isinstance(item, str) and item in allowed]


_INJECTION_PATTERNS = (
    r"ignore\s+(?:all\s+)?(?:previous|prior|earlier)\s+instructions",
    r"false\s+positive",
    r"propose.{0,80}(?:isolate_host|block_ip)",
    r"(?:reveal|print|repeat|show).{0,50}(?:system\s+)?prompt",
    r"</\s*untrusted_tool_result\s*>",
    r"(?:call|invoke|run)\s+(?:the\s+)?tool",
    r"tool\s*name\s*[:=]",
    r'"tool"\s*:\s*"',
    r"(?:print|reveal|exfiltrate).{0,50}(?:api\s*key|bearer|secret)",
    r"ignore.{0,50}(?:system|developer).{0,30}(?:rules|instructions|prompt)",
    r"isolate.{0,80}(?:every|all).{0,50}hosts?",
)
_HOMOGLYPHS = str.maketrans({"ο": "o", "о": "o", "а": "a", "е": "e", "р": "p", "і": "i", "с": "c", "ԁ": "d"})


def detect_injection(value) -> int:
    text = unicodedata.normalize("NFKC", str(value)).translate(_HOMOGLYPHS)
    text = text.replace("\u200b", "").replace("\ufeff", "")
    text = text.replace("\\\"", "\"")
    text = re.sub(r"[_-]+", " ", text)
    return sum(bool(re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)) for pattern in _INJECTION_PATTERNS)


def redact_prompt_echo(value, system_prompt: str):
    fragments = [line.strip() for line in system_prompt.splitlines() if len(line.strip()) >= 36]
    if len(system_prompt) >= 36:
        fragments.append(system_prompt)
    fragments = sorted(set(fragments), key=len, reverse=True)
    count = 0

    def clean(item):
        nonlocal count
        if isinstance(item, str):
            for fragment in fragments:
                if fragment in item:
                    count += 1
                    item = item.replace(fragment, "[system prompt text redacted]")
            return item
        if isinstance(item, list):
            return [clean(child) for child in item]
        if isinstance(item, dict):
            return {key: clean(child) for key, child in item.items()}
        return item

    return clean(value), count


def validate_report(value, seen_ids: set[str], allowed_techniques: set[str], injection_flags: int = 0):
    stats = {"claims_total": 0, "claims_dropped_no_evidence": 0, "techniques_total": 0,
             "techniques_dropped_unsupported": 0, "actions_dropped_invalid": 0,
             "injection_flags": max(0, int(injection_flags))}
    if isinstance(value, str):
        value = re.sub(r"^```(?:json)?\s*|\s*```$", "", value.strip(), flags=re.I)
        value = __import__("json").loads(value)
    report = AgentReport.model_validate(value).model_dump()
    report_texts = [report["summary"]]
    report_texts.extend(finding["claim"] for finding in report["key_findings"])
    report_texts.extend(hypothesis["statement"] for hypothesis in report["hypotheses"])
    stats["confirmation_language_flags"] = sum(
        len(CONFIRMATION_LANGUAGE_RE.findall(text)) for text in report_texts
    )
    if stats["confirmation_language_flags"]:
        report["limitations"] = report["limitations"][:29] + [CONFIRMATION_LANGUAGE_LIMITATION]
    report_text_flags = sum(1 for term in ("ignore previous", "system prompt", "false positive", "reveal this prompt")
                            if term in report["summary"].lower() or any(term in str(x).lower() for x in report["limitations"]))
    stats["injection_flags"] += report_text_flags
    findings = []
    stats["claims_total"] += len(report["key_findings"])
    for finding in report["key_findings"]:
        ids = _safe_ids(finding["evidence_ids"], seen_ids)
        if not ids:
            stats["claims_dropped_no_evidence"] += 1
            continue
        finding["evidence_ids"] = ids
        findings.append(finding)
    report["key_findings"] = findings
    hypotheses = []
    stats["claims_total"] += len(report["hypotheses"])
    for hypothesis in report["hypotheses"]:
        hypothesis["supports"] = _safe_ids(hypothesis["supports"], seen_ids)
        hypothesis["contradicts"] = _safe_ids(hypothesis["contradicts"], seen_ids)
        if not hypothesis["supports"] and not hypothesis["contradicts"]:
            stats["claims_dropped_no_evidence"] += 1
            continue
        hypotheses.append(hypothesis)
    report["hypotheses"] = hypotheses
    mappings = []
    stats["techniques_total"] = len(report["attack_mapping"])
    for mapping in report["attack_mapping"]:
        tid = mapping["technique_id"].upper()
        ids = _safe_ids(mapping["evidence_ids"], seen_ids)
        if not TECHNIQUE_RE.fullmatch(tid) or tid not in allowed_techniques or not ids:
            stats["techniques_dropped_unsupported"] += 1
            continue
        mapping["technique_id"] = tid
        mapping["evidence_ids"] = ids
        mappings.append(mapping)
    report["attack_mapping"] = mappings
    actions = []
    for action in report["recommended_actions"]:
        action["evidence_ids"] = _safe_ids(action["evidence_ids"], seen_ids)
        if not action["evidence_ids"] or not 0 < action["confidence"] <= 1:
            stats["actions_dropped_invalid"] += 1
            continue
        actions.append(action)
    report["recommended_actions"] = actions
    return report, stats
