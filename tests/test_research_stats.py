"""Checks for the statistics used in the paper (no containers needed)."""
from __future__ import annotations

import math

from research.common import bootstrap_ci, confusion, wilson


def test_wilson_matches_reference_values():
    # Reference: Wilson interval for 8/10 at 95% is about (0.490, 0.943).
    p, lo, hi = wilson(8, 10)
    assert p == 0.8 and abs(lo - 0.490) < 0.002 and abs(hi - 0.943) < 0.002


def test_wilson_edges():
    assert wilson(0, 10)[1] == 0.0
    assert wilson(10, 10)[2] == 1.0
    assert math.isnan(wilson(0, 0)[0])


def test_confusion_metrics():
    c = confusion([True, True, False, False, True], [True, False, True, False, True])
    assert (c.tp, c.fp, c.tn, c.fn) == (2, 1, 1, 1)
    assert abs(c.precision - 2 / 3) < 1e-9 and abs(c.recall - 2 / 3) < 1e-9 and c.fpr == 0.5


def test_bootstrap_brackets_point_estimate():
    labels = [True] * 50 + [False] * 50
    preds = [True] * 40 + [False] * 10 + [False] * 45 + [True] * 5
    lo, hi = bootstrap_ci(labels, preds, "recall")
    assert lo <= confusion(labels, preds).recall <= hi
