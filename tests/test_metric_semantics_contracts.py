"""
Contract tests for CloudWatch metric no-data vs observed-zero semantics.

`metric_summary()` re-keys a raw metric's `status` into its own
"observed"/"zero"/"missing" vocabulary -- it is never "ok". Before the
fix, `metric_has_observed_data()` only recognized the raw shape
(`status == "ok"`), so feeding it a summary -- which every analyzer
that calls `context.metric_summary()` does -- always returned False,
even for a metric that was fully observed at value 0. That silently
disabled every "no traffic" rule built on top of it (see the ELB
analyzer, which lost 4 of its 5 rules this way).
"""

from __future__ import annotations

from analysis.metrics import metric_has_observed_data, metric_summary


def test_raw_shape_observed_nonzero_is_recognized():
    raw = {"status": "ok", "has_data": True, "value": 5.0}
    assert metric_has_observed_data(raw) is True


def test_raw_shape_no_data_is_not_observed():
    raw = {"status": "no_data", "has_data": False, "value": None}
    assert metric_has_observed_data(raw) is False


def test_summary_shape_observed_zero_is_recognized():
    """
    This is the exact case the ELB bug got wrong: a metric that WAS
    observed, and whose value legitimately is 0, must count as
    observed -- not be treated the same as no data at all.
    """

    raw_zero = {
        "status": "ok",
        "has_data": True,
        "value": 0.0,
    }

    summary = metric_summary(raw_zero)

    assert summary["status"] != "ok"  # confirms the shape mismatch exists
    assert summary["observed"] is True
    assert summary["zero"] is True
    assert metric_has_observed_data(summary) is True


def test_summary_shape_no_data_is_not_observed():
    raw_missing = {
        "status": "no_data",
        "has_data": False,
        "value": None,
    }

    summary = metric_summary(raw_missing)

    assert summary["observed"] is False
    assert metric_has_observed_data(summary) is False


def test_summary_of_missing_metric_key_is_not_observed():
    """metric_summary(None) -- the "metric was never queried" case."""

    summary = metric_summary(None)

    assert summary["observed"] is False
    assert metric_has_observed_data(summary) is False
