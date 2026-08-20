"""
Shared cost-analytics constants.

Single source of truth for tuning values used by more than one
cost/dashboard service module.
"""

from __future__ import annotations


# Below this prior-period cost, a percentage change is not meaningful
# (dividing by a near-zero denominator produces a wildly unstable
# percentage), so callers should report the change as unavailable
# instead.
MIN_PRIOR_COST_FOR_PERCENTAGE = 5.0
