"""
Contract tests for the collector layer.

Unlike analyzers (registered via explicit static imports in
analyzers/__init__.py, so a broken import raises loudly), collectors are
discovered dynamically: collection/registry.py builds a file path from
each enabled resource_catalog.yaml entry's domain/subdomain, and silently
`continue`s if that path doesn't exist -- no exception, no log. A wrong
domain/subdomain/override mapping (e.g. from a rename) means the
collector just never registers, with the scan reporting success and
collecting nothing for that resource type.

validate_collector_registry() already exists to catch exactly this, but
was never wired into anything that runs automatically -- this test is
that wiring.
"""

from __future__ import annotations

import collection.registry as registry


def test_every_enabled_catalog_entry_has_a_registered_collector():
    registry.load_collectors()

    assert registry.IMPORT_ERRORS == {}
    assert registry.missing_collectors() == []
