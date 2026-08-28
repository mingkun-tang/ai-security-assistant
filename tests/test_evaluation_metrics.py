"""Tests for evaluation metric calculations."""

import pytest

from app.evaluation.metrics import ConfusionCounts, compute_metrics, format_rate


def test_perfect_classifier():
    counts = ConfusionCounts(tp=10, tn=10, fp=0, fn=0)
    metrics = compute_metrics(counts)
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1 == 1.0
    assert metrics.false_positive_rate == 0.0
    assert metrics.accuracy == 1.0


def test_all_false_positives():
    counts = ConfusionCounts(tp=0, tn=0, fp=5, fn=0)
    metrics = compute_metrics(counts)
    assert metrics.precision == 0.0
    assert metrics.recall is None
    assert metrics.f1 is None
    assert metrics.false_positive_rate == 1.0
    assert metrics.accuracy == 0.0


def test_all_false_negatives():
    counts = ConfusionCounts(tp=0, tn=0, fp=0, fn=7)
    metrics = compute_metrics(counts)
    assert metrics.precision is None
    assert metrics.recall == 0.0
    assert metrics.f1 is None
    assert metrics.false_positive_rate is None
    assert metrics.accuracy == 0.0


def test_mixed_results():
    counts = ConfusionCounts(tp=8, tn=7, fp=2, fn=3)
    metrics = compute_metrics(counts)
    assert metrics.precision == 8 / 10
    assert metrics.recall == 8 / 11
    assert metrics.f1 is not None
    assert metrics.false_positive_rate == 2 / 9
    assert metrics.accuracy == 15 / 20


def test_zero_denominator_edge_cases():
    empty = compute_metrics(ConfusionCounts())
    assert empty.precision is None
    assert empty.recall is None
    assert empty.f1 is None
    assert empty.false_positive_rate is None
    assert empty.accuracy is None

    only_tp = compute_metrics(ConfusionCounts(tp=3, tn=0, fp=0, fn=0))
    assert only_tp.precision == 1.0
    assert only_tp.recall == 1.0
    assert only_tp.false_positive_rate is None

    assert format_rate(None) == "n/a"
    assert format_rate(0.5) == "0.500"
