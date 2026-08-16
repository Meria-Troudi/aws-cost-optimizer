"""
Generic historical evidence utilities.
"""

from __future__ import annotations

from typing import Any


def historical_events(
    resource: dict[str, Any] | None,
) -> list[dict[str, Any]]:

    if not isinstance(resource, dict):
        return []

    observations = resource.get(
        "observations",
        {},
    )

    if not isinstance(observations, dict):
        return []

    events: list[dict[str, Any]] = []

    cloudtrail = observations.get(
        "cloudtrail",
        {},
    )

    if isinstance(cloudtrail, dict):

        history = cloudtrail.get(
            "history",
            [],
        )

        events.extend(
            _normalize_events(history)
        )

        cloudtrail_events = cloudtrail.get(
            "events",
            [],
        )

        events.extend(
            _normalize_events(cloudtrail_events)
        )

    historical = observations.get(
        "historical",
        {},
    )

    if isinstance(historical, dict):

        history = historical.get(
            "history",
            [],
        )

        events.extend(
            _normalize_events(history)
        )

        historical_events_value = historical.get(
            "events",
            [],
        )

        events.extend(
            _normalize_events(
                historical_events_value
            )
        )

    return _deduplicate_events(events)


def has_historical_evidence(
    resource: dict[str, Any] | None,
) -> bool:
    return bool(
        historical_events(resource)
    )


def find_historical_matches(
    resource: dict[str, Any] | None,
    *,
    attribute: str,
    value: Any,
) -> list[dict[str, Any]]:

    if not attribute:
        return []

    matches: list[dict[str, Any]] = []

    for event in historical_events(resource):

        if _event_matches_attribute(
            event,
            attribute,
            value,
        ):
            matches.append(event)

    return matches


def historical_values(
    resource: dict[str, Any] | None,
    *,
    attribute: str,
) -> list[Any]:
    values: list[Any] = []

    for event in historical_events(resource):

        extracted = _extract_event_values(
            event,
            attribute,
        )

        for value in extracted:

            if value is None:
                continue

            if value not in values:
                values.append(value)

    return values


def historical_identity_matches(
    resource: dict[str, Any] | None,
    identity: dict[str, Any] | None,
) -> list[dict[str, Any]]:


    if not isinstance(identity, dict):
        return []

    if not identity:
        return []

    matches: list[dict[str, Any]] = []

    for event in historical_events(resource):

        matched = True

        for attribute, value in identity.items():

            if not _event_matches_attribute(
                event,
                attribute,
                value,
            ):
                matched = False
                break

        if matched:
            matches.append(event)

    return matches


def historical_resource_summary(
    resource: dict[str, Any] | None,
) -> dict[str, Any]:

    events = historical_events(
        resource
    )

    timestamps = []

    for event in events:

        timestamp = (
            event.get("timestamp")
            or event.get("event_time")
            or event.get("time")
        )

        if timestamp is not None:
            timestamps.append(timestamp)

    return {
        "available": bool(events),
        "event_count": len(events),
        "timestamps": timestamps,
    }


def _normalize_events(
    value: Any,
) -> list[dict[str, Any]]:

    if not isinstance(value, list):
        return []

    result: list[dict[str, Any]] = []

    for event in value:

        if isinstance(event, dict):
            result.append(
                dict(event)
            )

    return result


def _event_matches_attribute(
    event: dict[str, Any],
    attribute: str,
    expected_value: Any,
) -> bool:

    direct_attribute = event.get(
        "attribute"
    )

    if (
        direct_attribute == attribute
        and (
            event.get("old_value") == expected_value
            or event.get("new_value") == expected_value
            or event.get("value") == expected_value
        )
    ):
        return True

    changes = event.get(
        "changes"
    )

    if isinstance(changes, dict):

        change = changes.get(
            attribute
        )

        if isinstance(change, dict):

            if (
                change.get("old") == expected_value
                or change.get("new") == expected_value
                or change.get("old_value") == expected_value
                or change.get("new_value") == expected_value
            ):
                return True

        elif change == expected_value:
            return True

    attributes = event.get(
        "attributes"
    )

    if isinstance(attributes, dict):

        if attributes.get(attribute) == expected_value:
            return True

    return False


def _extract_event_values(
    event: dict[str, Any],
    attribute: str,
) -> list[Any]:
    values: list[Any] = []

    if event.get("attribute") == attribute:

        for key in (
            "old_value",
            "new_value",
            "value",
        ):
            value = event.get(key)

            if value is not None:
                values.append(value)

    changes = event.get(
        "changes"
    )

    if isinstance(changes, dict):

        change = changes.get(
            attribute
        )

        if isinstance(change, dict):

            for key in (
                "old",
                "new",
                "old_value",
                "new_value",
            ):
                value = change.get(key)

                if value is not None:
                    values.append(value)

        elif change is not None:
            values.append(change)

    attributes = event.get(
        "attributes"
    )

    if isinstance(attributes, dict):

        value = attributes.get(
            attribute
        )

        if value is not None:
            values.append(value)

    return _unique(values)


def _unique(
    values: list[Any],
) -> list[Any]:

    result: list[Any] = []

    for value in values:

        if value not in result:
            result.append(value)

    return result


def _deduplicate_events(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    result: list[dict[str, Any]] = []
    seen: set[str] = set()

    for event in events:

        try:
            key = repr(
                sorted(
                    event.items(),
                    key=lambda item: str(item[0]),
                )
            )

        except Exception:
            key = repr(event)

        if key in seen:
            continue

        seen.add(key)
        result.append(event)

    return result