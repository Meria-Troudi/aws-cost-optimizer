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

Two checks run unconditionally, regardless of the route's `never_invent`
list, because they are never acceptable in this system's output: an AWS
CLI/API command (this system stops at recommending and validating; it
never hands out remediation commands -- see recommendations/plan.py),
and a claim that widens one resource's evidence into an account-wide
statement (the payload is always scoped to a single resource; see
explanation.py's `resource` block).
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
    "replacement_instance": (re.compile(_INSTANCE_TYPE, re.I),),
    "replacement_instance_class": (re.compile(_INSTANCE_TYPE, re.I),),
    "instance_type": (re.compile(_INSTANCE_TYPE, re.I),),
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
    # Same claim shape, different scope (a cluster rather than a single
    # resource) -- catalog routes that operate on clusters declare this
    # as its own concept, but the assertion pattern is identical.
    "cluster_deletion_safety": (
        re.compile(
            r"\b(?:safe|no\s+risk|without\s+risk|risk-free)\b\D{0,30}"
            r"\b(?:delete|remove|terminate)\b",
            re.I,
        ),
        re.compile(
            r"\b(?:delete|remove|terminate)\b\D{0,30}\b(?:is\s+safe|safely)\b", re.I
        ),
    ),
    "migration_safety": (
        re.compile(
            r"\b(?:safe|no\s+risk|without\s+risk|risk-free)\b\D{0,30}\bmigrat\w*\b",
            re.I,
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
    # --- "nothing depends on this" / "no requirement exists" -------------
    # Same claim shape across a whole family of catalog concepts: the
    # deterministic layer explicitly did not establish an absence, so a
    # model asserting "no X" or "not required" for any of these is
    # exactly the failure mode this guard exists to catch.
    "dependency": (
        re.compile(r"\b(?:no|without|has\s+no)\s+dependenc(?:y|ies)\b", re.I),
        re.compile(r"\bnothing\s+depends\s+on\b", re.I),
    ),
    "user_dependency": (
        re.compile(
            r"\b(?:no|without|has\s+no)\s+(?:user|consumer)\s+dependenc(?:y|ies)\b",
            re.I,
        ),
    ),
    "business_requirement": (
        re.compile(r"\b(?:no|not)\s+(?:a\s+)?business\s+requirement\b", re.I),
        re.compile(r"\bnot\s+required\s+(?:by|for)\s+the\s+business\b", re.I),
    ),
    "business_requirements": (
        re.compile(r"\b(?:no|not)\s+(?:a\s+)?business\s+requirements?\b", re.I),
    ),
    "workload_requirements": (
        re.compile(r"\b(?:no|not)\s+workload\s+requirements?\b", re.I),
    ),
    "recovery_requirement": (
        re.compile(r"\b(?:no|not)\s+(?:a\s+)?recovery\s+requirement\b", re.I),
    ),
    "disaster_recovery_requirement": (
        re.compile(
            r"\b(?:no|not)\s+(?:a\s+)?disaster\s+recovery\s+requirement\b", re.I
        ),
    ),
    "failover_requirement": (
        re.compile(r"\b(?:no|not)\s+(?:a\s+)?failover\s+requirement\b", re.I),
    ),
    "read_routing_requirement": (
        re.compile(r"\b(?:no|not)\s+(?:a\s+)?read\s+routing\s+requirement\b", re.I),
    ),
    "replication_requirements": (
        re.compile(r"\b(?:no|not)\s+(?:a\s+)?replication\s+requirements?\b", re.I),
    ),
    "reporting_requirement": (
        re.compile(r"\b(?:no|not)\s+(?:a\s+)?reporting\s+requirement\b", re.I),
    ),
    "retention_requirement": (
        re.compile(r"\b(?:no|not)\s+(?:a\s+)?retention\s+requirement\b", re.I),
    ),
    "backup_requirement": (
        re.compile(r"\b(?:no|not)\s+(?:a\s+)?backup\s+requirement\b", re.I),
    ),
    "production_requirement": (
        re.compile(r"\bnot\s+(?:used|running)\s+in\s+production\b", re.I),
        re.compile(
            r"\b(?:no|not)\s+(?:a\s+)?production\s+(?:use|dependency|requirement)\b",
            re.I,
        ),
    ),
    "production_unsuitability": (
        re.compile(r"\bnot\s+suitable\s+for\s+production\b", re.I),
    ),
    "compatibility": (re.compile(r"\b(?:is|are)\s+compatible\s+with\b", re.I),),
}

# Checked unconditionally, on every explanation, regardless of the
# route's never_invent list -- see module docstring.
# Checked unconditionally, on every explanation, regardless of the
# route's never_invent list -- see module docstring.
_UNCONDITIONAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "aws_cli_command",
        # Require hyphen in the final word so this matches real CLI
        # subcommands like "describe-instances" or "put-object" rather
        # than natural English such as "AWS account has".
        re.compile(r"\baws\s+[a-z0-9][a-z0-9-]*\s+[a-z][a-z-]*-[a-z-]*\b", re.I),
    ),
    (
        "aws_cli_command",
        re.compile(
            r"\b(?:describe|list|get|put|delete|release|create|modify|"
            r"update|terminate|stop|start|attach|detach|associate|"
            r"disassociate|authorize|revoke|enable|disable)-[a-z][a-z-]*\b",
            re.I,
        ),
    ),
    ("code_block_or_shell_flag", re.compile(r"```|(?<!\w)--[a-z][a-z-]*\b", re.I)),
    (
        "account_scope_widening",
        # Only flag explicit account-wide claims that assert a lack of
        # resources/costs/budgets, not legitimate mentions of "the account"
        # in passing (e.g. "the AWS account has no observed data").
        # Add optional "s" to catch plurals ("resources", "budgets").
        re.compile(
            r"\b(?:the|your)\s+(?:aws\s+)?account\b\D{0,40}"
            r"\b(?:has\s+no|has\s+not|does\s+not\s+have|is\s+not)\s+"
            r"\b(?:any\s+|multiple\s+|many\s+|all\s+|entire\s+)?"
            r"\b(?:resource|cost|budget|spend|optimization|savings|"
            r"recommendation|instance|gateway|bucket)s?\b",
            re.I,
        ),
    ),
    (
        "account_scope_widening",
        re.compile(
            r"\b(?:your|the)\s+(?:entire\s+)?(?:infrastructure|environment)\b"
            r"\D{0,25}\b(?:has\s+no|is|does\s+not)\b",
            re.I,
        ),
    ),
    (
        "account_scope_widening",
        re.compile(r"\bacross\s+(?:the|your)\s+(?:aws\s+)?account\b", re.I),
    ),
)


# Explanation fields whose free text is checked. The list fields
# (limitations, what_to_verify, possible_actions) are lists of sentences
# generated directly by the model, so they need their own extraction
# below -- but they must be guarded exactly like the string fields,
# since the model can smuggle a command or a forbidden assertion into a
# bullet just as easily as into prose.
_TEXT_FIELDS = ("summary", "why", "action", "confidence_note", "risk")

_LIST_FIELDS = ("limitations", "what_to_verify", "possible_actions")


def _explanation_text(explanation: Mapping[str, Any]) -> str:
    parts = [
        str(explanation.get(field, ""))
        for field in _TEXT_FIELDS
        if explanation.get(field)
    ]

    for field in _LIST_FIELDS:
        items = explanation.get(field)

        if isinstance(items, (list, tuple)):
            parts.extend(str(item) for item in items if item)

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

    for concept, pattern in _UNCONDITIONAL_PATTERNS:
        match = pattern.search(text)

        if match:
            found.append(
                f"explanation asserts forbidden concept {concept!r} "
                f"(matched {match.group(0)!r})"
            )

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
