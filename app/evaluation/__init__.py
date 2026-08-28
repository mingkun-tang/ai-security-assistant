"""Independent security benchmark evaluation (separate from unit tests)."""

from app.evaluation.benchmark import (
    SOURCE_ANALYSIS_ISSUE_TYPES,
    run_benchmark,
)
from app.evaluation.metrics import compute_metrics, ConfusionCounts
