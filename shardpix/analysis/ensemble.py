"""The ensemble classifier of Kodovský, Fridrich and Holub (2012).

The standard detector for rich steganalysis features: many Fisher linear
discriminants, each trained on a bootstrap sample of the training set and a
random subspace of the features, combined by majority vote. It scales to tens
of thousands of features and needs nothing beyond numpy.

The subspace dimension is chosen, as in the original, by the out-of-bag
error: every learner is scored on the training samples its bootstrap left
out, which gives an unbiased error estimate without touching the test set.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

REGULARISATION = 1e-10
"""Ridge added to the within-class scatter, relative to its mean diagonal."""


@dataclass
class _Learner:
    subspace: np.ndarray
    weights: np.ndarray
    threshold: float

    def decide(self, x: np.ndarray) -> np.ndarray:
        return (x[:, self.subspace] @ self.weights > self.threshold).astype(np.int8)


def _fld(x0: np.ndarray, x1: np.ndarray) -> tuple[np.ndarray, float]:
    """Fisher linear discriminant and the training threshold with the lowest error."""
    mu0, mu1 = x0.mean(axis=0), x1.mean(axis=0)
    c0, c1 = x0 - mu0, x1 - mu1
    scatter = c0.T @ c0 + c1.T @ c1
    ridge = REGULARISATION * max(float(np.trace(scatter)) / scatter.shape[0], 1e-300)
    scatter[np.diag_indices_from(scatter)] += ridge
    try:
        w = np.linalg.solve(scatter, mu1 - mu0)
    except np.linalg.LinAlgError:
        w = np.linalg.lstsq(scatter, mu1 - mu0, rcond=None)[0]
    p0, p1 = x0 @ w, x1 @ w
    return w, _best_threshold(p0, p1)


def _best_threshold(p0: np.ndarray, p1: np.ndarray) -> float:
    """Threshold on the projections minimising (false alarms + missed detections) / 2."""
    values = np.concatenate([p0, p1])
    labels = np.concatenate([np.zeros(p0.size), np.ones(p1.size)])
    order = np.argsort(values, kind="stable")
    values, labels = values[order], labels[order]
    # Threshold after position i: samples 0..i are called cover, the rest stego.
    missed = np.cumsum(labels) / p1.size
    false_alarm = 1 - np.cumsum(1 - labels) / p0.size
    error = (missed + false_alarm) / 2
    i = int(np.argmin(error))
    if i + 1 < values.size:
        return float((values[i] + values[i + 1]) / 2)
    return float(values[i] + 1)


@dataclass
class Ensemble:
    """A trained ensemble; ``votes`` gives the fraction of learners saying "stego"."""

    learners: list[_Learner]
    subspace_dim: int
    oob_error: float
    mean: np.ndarray = field(repr=False)
    scale: np.ndarray = field(repr=False)

    def _prepare(self, x: np.ndarray) -> np.ndarray:
        return (x - self.mean) / self.scale

    def votes(self, x: np.ndarray) -> np.ndarray:
        x = self._prepare(np.asarray(x, dtype=np.float64))
        return np.mean([learner.decide(x) for learner in self.learners], axis=0)

    def predict(self, x: np.ndarray) -> np.ndarray:
        return (self.votes(x) > 0.5).astype(np.int8)


def _train_learners(
    x0: np.ndarray, x1: np.ndarray, dim: int, count: int, rng: np.random.Generator
) -> tuple[list[_Learner], float]:
    """Train ``count`` learners on ``dim`` features each; return them and the OOB error.

    Covers and stegos are bootstrapped by *pair* index, so a cover and the
    stego made from it are always in or out of a learner's sample together.
    """
    n, d = x0.shape
    oob_votes = np.zeros((2, n))
    oob_counts = np.zeros((2, n))
    learners = []
    for _ in range(count):
        subspace = np.sort(rng.choice(d, size=dim, replace=False))
        sample = rng.integers(0, n, n)
        w, t = _fld(x0[sample][:, subspace], x1[sample][:, subspace])
        learner = _Learner(subspace, w, t)
        learners.append(learner)
        out = np.setdiff1d(np.arange(n), sample, assume_unique=False)
        for label, x in ((0, x0), (1, x1)):
            oob_votes[label, out] += learner.decide(x[out])
            oob_counts[label, out] += 1
    seen = oob_counts > 0
    decided = np.where(seen, oob_votes / np.maximum(oob_counts, 1) > 0.5, 0)
    false_alarm = decided[0][seen[0]].mean() if seen[0].any() else 0.5
    missed = 1 - decided[1][seen[1]].mean() if seen[1].any() else 0.5
    return learners, float((false_alarm + missed) / 2)


def train(
    covers: np.ndarray,
    stegos: np.ndarray,
    *,
    learners: int = 51,
    subspace_dims: tuple[int, ...] | None = None,
    seed: int = 0,
) -> Ensemble:
    """Train an ensemble on paired features (row ``i`` of both comes from the same image).

    ``subspace_dims`` are the candidate subspace dimensions; the one with the
    lowest out-of-bag error, measured with a smaller ensemble, is kept.
    """
    covers = np.asarray(covers, dtype=np.float64)
    stegos = np.asarray(stegos, dtype=np.float64)
    if covers.shape != stegos.shape:
        raise ValueError("covers and stegos must be paired and have the same shape")
    n, d = covers.shape
    rng = np.random.default_rng(seed)

    both = np.concatenate([covers, stegos])
    mean = both.mean(axis=0)
    scale = both.std(axis=0)
    scale[scale == 0] = 1.0
    x0, x1 = (covers - mean) / scale, (stegos - mean) / scale

    if subspace_dims is None:
        # The FLD needs more samples than dimensions; the original searches
        # upward from a small subspace and stops when the OOB error rises.
        cap = max(2, min(d, n // 2))
        subspace_dims = tuple(sorted({max(2, min(cap, k)) for k in (50, 100, 200, 400, 800)}))
    best = (float("inf"), min(subspace_dims[0], d))
    for dim in subspace_dims:
        dim = min(dim, d)
        _, oob = _train_learners(x0, x1, dim, max(11, learners // 3), rng)
        if oob < best[0]:
            best = (oob, dim)
    trained, oob = _train_learners(x0, x1, best[1], learners, rng)
    return Ensemble(trained, best[1], oob, mean, scale)


# --------------------------------------------------------------------------- metrics


def detection_error(cover_scores: np.ndarray, stego_scores: np.ndarray) -> float:
    """Minimum of (P_FA + P_MD) / 2 over all thresholds: 0.5 is a coin toss, 0 is perfect."""
    return float(
        np.min(_error_curve(np.asarray(cover_scores, float), np.asarray(stego_scores, float)))
    )


def _error_curve(p0: np.ndarray, p1: np.ndarray) -> np.ndarray:
    thresholds = np.unique(np.concatenate([p0, p1, [np.inf]]))
    false_alarm = 1 - np.searchsorted(np.sort(p0), thresholds, side="left") / p0.size
    missed = np.searchsorted(np.sort(p1), thresholds, side="left") / p1.size
    return (false_alarm + missed) / 2


def decision_error(cover_decisions: np.ndarray, stego_decisions: np.ndarray) -> float:
    """(P_FA + P_MD) / 2 of fixed 0/1 decisions, the error the detector actually makes."""
    false_alarm = float(np.mean(cover_decisions))
    missed = 1 - float(np.mean(stego_decisions))
    return (false_alarm + missed) / 2


def auc(cover_scores: np.ndarray, stego_scores: np.ndarray) -> float:
    """Area under the ROC curve (probability a stego scores above a cover; ties count 1/2)."""
    p0 = np.asarray(cover_scores, dtype=np.float64)
    p1 = np.asarray(stego_scores, dtype=np.float64)
    values = np.concatenate([p0, p1])
    order = np.argsort(values, kind="stable")
    ranks = np.empty(values.size)
    sorted_values = values[order]
    # Average ranks over ties.
    _, start, counts = np.unique(sorted_values, return_index=True, return_counts=True)
    for s, c in zip(start, counts, strict=True):
        ranks[order[s : s + c]] = s + (c + 1) / 2
    r1 = ranks[p0.size :].sum()
    return float((r1 - p1.size * (p1.size + 1) / 2) / (p0.size * p1.size))
