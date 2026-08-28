"""Metric calculations for security benchmark evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ConfusionCounts:
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.tn + self.fp + self.fn


@dataclass
class MetricSummary:
    counts: ConfusionCounts
    precision: float | None
    recall: float | None
    f1: float | None
    false_positive_rate: float | None
    accuracy: float | None


def safe_divide(numerator: float, denominator: float) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


def compute_metrics(counts: ConfusionCounts) -> MetricSummary:
  tp, tn, fp, fn = counts.tp, counts.tn, counts.fp, counts.fn
  precision = safe_divide(tp, tp + fp)
  recall = safe_divide(tp, tp + fn)
  if precision is not None and recall is not None and (precision + recall) > 0:
      f1 = 2 * precision * recall / (precision + recall)
  else:
      f1 = None
  false_positive_rate = safe_divide(fp, fp + tn)
  accuracy = safe_divide(tp + tn, counts.total)
  return MetricSummary(
      counts=counts,
      precision=precision,
      recall=recall,
      f1=f1,
      false_positive_rate=false_positive_rate,
      accuracy=accuracy,
  )


def format_rate(value: float | None, digits: int = 3) -> str:
    if value is None:
        return "n/a"
    return f"{value:.{digits}f}"


def metrics_to_dict(summary: MetricSummary) -> dict[str, Any]:
    return {
        "tp": summary.counts.tp,
        "tn": summary.counts.tn,
        "fp": summary.counts.fp,
        "fn": summary.counts.fn,
        "total": summary.counts.total,
        "precision": summary.precision,
        "recall": summary.recall,
        "f1": summary.f1,
        "false_positive_rate": summary.false_positive_rate,
        "accuracy": summary.accuracy,
    }
