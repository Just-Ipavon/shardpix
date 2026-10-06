"""Trained steganalysis: features, ensemble classifier and the CNN plumbing.

These check that the detectors are implemented correctly - they learn when
there is something to learn and do not when there is not - on synthetic
data. The measurements themselves are in docs/05, §5.5.5.
"""

from __future__ import annotations

import numpy as np
import pytest

from shardpix.analysis import ensemble, features, ml_benchmark

from .conftest import natural_image


def grey(seed: int, size: int = 64) -> np.ndarray:
    return natural_image(size, size, 1, seed=seed)[..., 0]


class TestFeatures:
    @pytest.mark.parametrize("name", sorted(features.EXTRACTORS))
    def test_dimension(self, name):
        assert features.extract(grey(0), name).shape == (features.DIMENSIONS[name],)

    def test_spam_is_a_set_of_transition_probabilities(self):
        f = features.spam(grey(1))
        rows = f[:343].reshape(49, 7)
        sums = rows.sum(axis=1)
        assert np.all((np.isclose(sums, 1)) | (sums == 0))
        assert np.all(f >= 0)

    def test_srm_lite_blocks_are_distributions(self):
        f = features.srm_lite(grey(2)).reshape(len(features.SRM_RESIDUALS), -1)
        assert np.allclose(f.sum(axis=1), 1)

    def test_constant_image_has_all_mass_at_zero_residual(self):
        f = features.srm_lite(np.full((32, 32), 100, dtype=np.uint8))
        centre = sum(features.SRM_T * 5**k for k in range(features.SRM_ORDER))
        assert np.allclose(f.reshape(5, -1)[:, centre], 1)

    def test_colour_features_average_the_channels(self):
        rgb = natural_image(48, 48, 3, seed=3)
        expected = np.mean([features.spam(rgb[..., c]) for c in range(3)], axis=0)
        assert np.allclose(features.extract(rgb, "spam"), expected)

    def test_embedding_moves_the_features(self):
        cover = grey(4, 96)
        stego = ml_benchmark.embed(cover, 0.5, np.random.default_rng(0))
        for name in features.EXTRACTORS:
            assert not np.allclose(features.extract(cover, name), features.extract(stego, name))


class TestEnsemble:
    def test_learns_a_separable_problem(self):
        rng = np.random.default_rng(0)
        x0 = rng.normal(size=(400, 60))
        x1 = rng.normal(size=(400, 60))
        x1[:, :20] += 1.0
        model = ensemble.train(x0[:200], x1[:200], learners=21)
        error = ensemble.decision_error(model.predict(x0[200:]), model.predict(x1[200:]))
        assert error < 0.1
        assert model.oob_error < 0.15

    def test_guesses_when_there_is_nothing_to_learn(self):
        rng = np.random.default_rng(1)
        x0, x1 = rng.normal(size=(600, 40)), rng.normal(size=(600, 40))
        model = ensemble.train(x0[:300], x1[:300], learners=21)
        v0, v1 = model.votes(x0[300:]), model.votes(x1[300:])
        assert 0.4 < ensemble.decision_error(v0 > 0.5, v1 > 0.5) < 0.6
        assert 0.4 < ensemble.auc(v0, v1) < 0.6

    def test_rejects_unpaired_input(self):
        with pytest.raises(ValueError):
            ensemble.train(np.zeros((10, 4)), np.zeros((9, 4)))

    def test_constant_features_do_not_break_training(self):
        rng = np.random.default_rng(2)
        x0 = np.hstack([rng.normal(size=(100, 10)), np.ones((100, 3))])
        x1 = x0 + np.hstack([np.full((100, 10), 2.0), np.zeros((100, 3))])
        model = ensemble.train(x0, x1, learners=11)
        assert ensemble.decision_error(model.predict(x0), model.predict(x1)) < 0.05


class TestMetrics:
    def test_auc_extremes_and_ties(self):
        assert ensemble.auc([0, 0, 0], [1, 1, 1]) == 1.0
        assert ensemble.auc([1, 1], [0, 0]) == 0.0
        assert ensemble.auc([0.5, 0.5], [0.5, 0.5]) == 0.5

    def test_auc_matches_pairwise_definition(self):
        rng = np.random.default_rng(3)
        p0, p1 = rng.normal(size=50), rng.normal(0.5, size=60)
        pairwise = np.mean((p1[None, :] > p0[:, None]) + 0.5 * (p1[None, :] == p0[:, None]))
        assert ensemble.auc(p0, p1) == pytest.approx(pairwise)

    def test_detection_error(self):
        assert ensemble.detection_error([0, 0], [1, 1]) == 0.0
        assert ensemble.detection_error([1, 1], [1, 1]) == 0.5

    def test_decision_error(self):
        assert ensemble.decision_error(np.array([0, 1]), np.array([1, 1])) == 0.25


class TestBenchmarkPlumbing:
    def test_stegos_are_reproducible_and_change_few_samples(self):
        covers = np.stack([grey(5, 128)])
        a = ml_benchmark.stego_image(covers, 0, 0.01, seed=7)
        b = ml_benchmark.stego_image(covers, 0, 0.01, seed=7)
        assert np.array_equal(a, b)
        changed = np.count_nonzero(a != covers[0])
        assert 0 < changed <= 0.01 * a.size
        assert np.max(np.abs(a.astype(int) - covers[0])) == 1

    def test_split_keeps_pairs_together(self):
        train, test = ml_benchmark.split(11, seed=0)
        assert not set(train) & set(test)
        assert len(train) + len(test) == 11

    def test_share_rate_is_one_share(self):
        rate = ml_benchmark.share_rate(64)
        assert rate == pytest.approx(ml_benchmark.share_rate(64))
        # Salt, cost and frame around a share, one bit per sample.
        assert 0.25 < rate < 0.35


class TestCNN:
    def test_forward_shape_and_fixed_high_pass(self):
        torch = pytest.importorskip("torch")
        from shardpix.analysis import cnn

        model = cnn.StegoNet(width=4)
        out = model(torch.zeros(2, 1, 32, 32))
        assert out.shape == (2, 2)
        assert not model.high_pass.weight.requires_grad
        # High-pass kernels see nothing in a flat image.
        assert torch.allclose(
            model.high_pass(torch.full((1, 1, 16, 16), 90.0))[..., 4:-4, 4:-4],
            torch.zeros(1),
            atol=1e-4,
        )

    def test_training_runs_and_keeps_the_best_epoch(self):
        pytest.importorskip("torch")
        from shardpix.analysis import cnn

        covers = np.stack([grey(s, 32) for s in range(8)])

        def embed(c, rng):
            return ml_benchmark.embed(c, 0.5, rng)

        model, log = cnn.train(
            covers[:6], covers[6:], embed, epochs=1, pairs_per_batch=3, crop=16, log=lambda _: None
        )
        assert log.epochs == 1 and len(log.history) == 1
        scores = cnn.scores(model, covers)
        assert scores.shape == (8,) and np.all((scores >= 0) & (scores <= 1))
