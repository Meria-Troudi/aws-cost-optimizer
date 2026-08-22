"""
Post-generation validation of LLM explanations.

Each catalog route declares a `never_invent` list -- the things a model
explaining that recommendation must not assert, because the
deterministic layer either could not establish them or deliberately
refused to. The list was previously used as prompt guidance only, and
prompt guidance is a request, not a guarantee: the model is free to
produce "switch to gp3 and save $40/month" anyway, and nothing checked.

This module is the check. It runs after generation and before the
explanation is persisted or returned.

Design
------
Detection is deliberately conservative and rule-based. Each forbidden
concept maps to patterns whose presence is hard to explain innocently
-- a currency amount, a concrete instance type, an imperative "delete
this". Hedged discussion of the same topic is allowed through, because
"review whether the volume is still required" is exactly what these
recommendations are supposed to say.

That means the guard under-detects rather than over-detects. It is a
backstop against the model asserting a fact the pipeline refused to
compute, not a general-purpose content filter, and it never sees a
number the deterministic layer did not already put in the payload.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

# Concept -> compiled patterns that indicate the model asserted it.
#
# Patterns intentionally target *concrete assertions*:
#   - money amounts / percentages of saving
#   - concrete AWS sizes and types
#   - imperative destructive instructions
_MONEY = r"(?:[$€£]\s?\d[\d,]*(?:\.\d+)?|\d[\d,]*(?:\.\d+)?\s*(?:usd|eur|gbp|dollars?|euros?))"
_INSTANCE_TYPE = (
    r"\b(?:t[234]|m[3-7]|c[3-7]|r[3-7]|x[12]|i[34]|db\.[a-z0-9]+)[a-z]*\.\w+\b"
)

_CONCEPT_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "savings": (
        re.compile(rf"sav(?:e|es|ing|ings)\D{{0,40}}{_MONEY}", re.I),
        re.compile(rf"{_MONEY}\D{{0,25}}sav(?:e|es|ing|ings)", re.I),
        re.compile(r"sav(?:e|es|ing|ings)\D{0,25}\d{1,3}\s*%", re.I),
        re.compile(
            r"\breduce\s+(?:your\s+)?(?:monthly\s+)?(?:bill|cost|spend)\b\D{0,25}"
            rf"(?:{_MONEY}|\d{{1,3}}\s*%)",
            re.I,
        ),
    ),
    "replacement_resource": (re.compile(_INSTANCE_TYPE, re.I),),
    "replacement_size": (re.compile(_INSTANCE_TYPE, re.I),),
    "replacement_capacity": (
        re.compile(
            r"\b(?:set|change|resize)\D{0,30}\b\d+\s*(?:acu|rcu|wcu|vcpu|gib|gb)\b",
            re.I,
        ),
    ),
    "target_capacity": (
        re.compile(
            r"\b(?:set|change|resize|provision)\D{0,30}\b\d+\s*(?:acu|rcu|wcu|vcpu|gib|gb)\b",
            re.I,
        ),
    ),
    "exact_capacity_to_remove": (
        re.compile(r"\bremove\s+\d+\s*(?:node|instance|reader|replica|gib|gb)", re.I),
    ),
    "target_size": (
        re.compile(
            r"\b(?:resize|shrink|reduce)\D{0,25}\bto\s+\d+\s*(?:gib|gb|tb)\b", re.I
        ),
    ),
    "target_storage_type": (
        re.compile(r"\b(?:switch|migrate|change)\D{0,25}\bto\s+gp[23]\b", re.I),
    ),
    "cheaper_mode": (
        re.compile(
            r"\b(?:switch|change|move)\D{0,30}\bto\s+(?:on-?demand|provisioned)\b", re.I
        ),
    ),
    "serverless_migration": (
        re.compile(
            r"\b(?:migrate|switch|move|convert)\D{0,30}\bto\s+(?:aurora\s+)?serverless\b",
            re.I,
        ),
    ),
    "deletion_safety": (
        re.compile(
            r"\b(?:safe|no\s+risk|without\s+risk|risk-free)\b\D{0,30}"
            r"\b(?:delete|remove|terminate)\b",
            re.I,
        ),
        re.compile(
            r"\b(?:delete|remove|terminate)\b\D{0,30}\b(?:is\s+safe|safely)\b", re.I
        ),
    ),
    "resource_deletion": (
        re.compile(r"\byou\s+should\s+(?:delete|remove|terminate)\b", re.I),
        re.compile(
            r"\b(?:delete|terminate)\s+(?:this|the)\s+\w+\s+(?:now|immediately)\b", re.I
        ),
    ),
    "replica_to_delete": (
        re.compile(r"\b(?:delete|remove)\s+(?:the\s+)?(?:reader|replica)\b", re.I),
    ),
    "region_to_remove": (
        re.compile(
            r"\b(?:remove|drop)\D{0,20}\b(?:eu|us|ap|sa|ca|me|af)-\w+-\d\b", re.I
        ),
    ),
    "shutdown_schedule": (
        re.compile(
            r"\b(?:stop|shut\s*down|schedule)\D{0,30}\b\d{1,2}\s*(?::\d{2}|am|pm)\b",
            re.I,
        ),
    ),
    "business_hours": (
        re.compile(
            r"\b\d{1,2}\s*(?::\d{2})?\s*(?:am|pm)?\s*(?:-|to|until)\s*\d{1,2}\s*(?::\d{2}|am|pm)\b",
            re.I,
        ),
    ),
    "commitment_amount": (re.compile(rf"\bcommit\D{{0,30}}{_MONEY}", re.I),),
    "retention_target": (
        re.compile(
            r"\b(?:set|reduce|change)\D{0,30}\bretention\D{0,20}\b\d+\s*days?\b", re.I
        ),
    ),
    "compliance_requirement": (
        re.compile(
            r"\b(?:required|mandated|must\s+comply)\b\D{0,25}"
            r"\b(?:gdpr|hipaa|pci|sox|iso\s?27001)\b",
            re.I,
        ),
    ),
    "scaling_policy": (
        re.compile(
            r"\b(?:set|configure)\D{0,30}\btarget\s+(?:tracking|utilization)\D{0,15}\d+\s*%",
            re.I,
        ),
    ),
    "min_capacity": (re.compile(r"\bmin(?:imum)?\s+capacity\D{0,15}\b\d+", re.I),),
    "max_capacity": (re.compile(r"\bmax(?:imum)?\s+capacity\D{0,15}\b\d+", re.I),),
    "route_change": (
        re.compile(
            r"\b(?:add|change|update)\D{0,25}\broute\b\D{0,25}\b0\.0\.0\.0/0\b", re.I
        ),
    ),
    "replacement_path": (
        re.compile(
            r"\b(?:use|switch\s+to)\D{0,25}\bvpc\s+endpoint\b\D{0,25}\binstead\b", re.I
        ),
    ),
    "architecture_replacement": (
        re.compile(
            r"\b(?:replace|rearchitect|migrate)\D{0,25}\bwith\s+(?:fargate|lambda|ecs)\b",
            re.I,
        ),
    ),
    "required_configuration": (
        re.compile(r"\byou\s+must\s+(?:set|configure|enable)\b", re.I),
    ),
}

# Explanation fields whose free text is checked.
_TEXT_FIELDS = ("summary", "why", "action", "confidence_note", "risk")


def _explanation_text(explanation: Mapping[str, Any]) -> str:
    parts = [
        str(explanation.get(field, ""))
        for field in _TEXT_FIELDS
        if explanation.get(field)
    ]

    return "\n".join(parts)


def violations(
    explanation: Mapping[str, Any],
    never_invent: Iterable[str],
) -> list[str]:
    """Forbidden concepts the explanation appears to assert.

    Returns human-readable reasons. Empty list means the explanation is
    within what the route permits.
    """

    if not isinstance(explanation, Mapping):
        return ["Explanation is not a mapping."]

    text = _explanation_text(explanation)

    if not text.strip():
        return []

    found: list[str] = []

    for concept in never_invent or []:
        key = str(concept).strip()
        patterns = _CONCEPT_PATTERNS.get(key)

        if not patterns:
            # No detector for this concept. Silence is honest here:
            # claiming a clean bill of health for something unchecked
            # would be worse than admitting the gap, which the
            # accompanying test surfaces.
            continue

        for pattern in patterns:
            match = pattern.search(text)

            if match:
                found.append(
                    f"explanation asserts forbidden concept {key!r} "
                    f"(matched {match.group(0)!r})"
                )
                break

    return found


def detectable_concepts() -> frozenset[str]:
    """never_invent concepts this guard can actually detect."""

    return frozenset(_CONCEPT_PATTERNS)
