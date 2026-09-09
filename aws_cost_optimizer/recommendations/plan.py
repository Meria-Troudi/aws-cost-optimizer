"""
Deterministic recommendation plan.

The catalog's ``procedure`` block is the only source for a
recommendation's objective, validation steps, and possible actions.
This module converts those raw catalog entries into human-readable,
deterministic prose.

Design rules (see llm/guard.py and llm/prompt.py):

- The plan NEVER contains AWS operation names (``aws_operations`` is
  deliberately excluded): the plan is the material the LLM is allowed
  to humanize, and an operation name is the raw ingredient of a
  hallucinated CLI command.
- Humanization is deterministic: no randomness, no model, no invention.
- Both catalog shapes are handled:
    * slugs              ``verify_current_instance_status``
    * plain sentences    ``determine whether the NAT gateway ...``
"""

from __future__ import annotations

from typing import Any

# Words that must keep (or gain) their acronym casing after
# humanization. Everything else is normalized to lowercase.
_ACRONYMS = frozenset(
    {
        "aws",
        "nat",
        "vpc",
        "ebs",
        "s3",
        "rds",
        "ec2",
        "elb",
        "waf",
        "eip",
        "az",
        "api",
        "iam",
        "iops",
        "sns",
        "sqs",
        "ecs",
        "eks",
        "cpu",
        "io",
    }
)


def _render_word(
    token: str,
    *,
    first: bool,
) -> str:
    """Render one whitespace-delimited token."""

    word = token.strip()

    if not word:
        return ""

    lowered = word.lower()

    if lowered in _ACRONYMS:
        return lowered.upper()

    if first:
        return word[0].upper() + word[1:]

    return lowered


def humanize_step(
    raw: str,
) -> str:
    """
    Convert a catalog plan entry into human-readable prose.

    Slug form (contains underscores) is split and lowercased, with the
    first word capitalized and known acronyms preserved::

        verify_current_resource_state -> Verify current resource state
        aws_service_traffic_dependencies -> AWS service traffic dependencies

    Sentence form (contains spaces, no underscores) is normalized by
    capitalizing only the first word and lowercasing non-acronym words,
    so acronyms inside the sentence survive intact::

        determine whether the NAT Gateway is required ...
            -> Determine whether the NAT gateway is required ...
    """

    text = str(raw or "").strip()

    if not text:
        return ""

    if "_" in text:
        words = [
            part
            for part in (
                fragment.strip()
                for fragment in text.split("_")
            )
            if part
        ]

        rendered = [
            _render_word(word, first=(index == 0))
            for index, word in enumerate(words)
        ]

        return " ".join(part for part in rendered if part)

    words = text.split()

    rendered = [
        _render_word(word, first=(index == 0))
        for index, word in enumerate(words)
    ]

    return " ".join(part for part in rendered if part)


_PLAN_FIELDS = (
    "objective",
    "validation_steps",
    "possible_actions",
)


def build_plan(
    definition: Any,
) -> dict[str, Any]:
    """
    Build the deterministic plan dict for one catalog definition.

    Returns ``{}`` when the definition has no procedure block. The
    result never contains ``aws_operations`` or any other collection
    detail -- only human-readable objective / validation_steps /
    possible_actions entries.
    """

    procedure = getattr(definition, "procedure", None)

    if not isinstance(procedure, dict) or not procedure:
        return {}

    plan: dict[str, Any] = {}

    for field in _PLAN_FIELDS:

        entries = procedure.get(field)

        if isinstance(entries, str):
            entries = [entries]

        if not isinstance(entries, list):
            continue

        humanized = [
            humanize_step(str(entry))
            for entry in entries
            if str(entry or "").strip()
        ]

        if humanized:
            plan[field] = humanized

    return plan
