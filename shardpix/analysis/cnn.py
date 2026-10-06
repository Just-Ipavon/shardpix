"""A convolutional steganalysis network, small enough to train on a CPU.

The architecture follows the family of Xu-Net (Xu, Wu and Shi, 2016) and
Yedroudj-Net (Yedroudj, Comby and Chaumont, 2018):

1. A fixed high-pass layer: SRM residual kernels that remove the image
   content and keep the noise, where +-1 embedding lives.
2. A truncated linear unit (TLU) that clips the residuals, as the
   truncation in rich models does.
3. Five convolutional blocks with batch normalisation and average pooling,
   then global average pooling and a linear classifier.

It is trained on *pairs*: every batch holds each cover together with the
stego made from it, so the network cannot learn the image content and must
learn the embedding change. Curriculum learning - starting at a high
embedding rate and fine-tuning down - is the standard way to reach low rates
(Ye, Ni and Yi, 2017) and is what :func:`train` supports through ``init``.

Requires PyTorch (``pip install -e ".[ml]"``).
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass

import numpy as np
import torch
from torch import nn

from .features import _FIRST, _SECOND, _SQUARE3, _SQUARE5, _THIRD


def _high_pass_bank() -> torch.Tensor:
    """Fixed 5x5 SRM kernels: square 3x3 and 5x5, and 1st-3rd order in four orientations."""
    kernels = []

    def place(k: np.ndarray) -> np.ndarray:
        out = np.zeros((5, 5))
        h, w = k.shape
        top, left = (5 - h) // 2, (5 - w) // 2
        out[top : top + h, left : left + w] = k
        return out

    kernels.append(place(_SQUARE5) / 12)
    kernels.append(place(_SQUARE3) / 4)
    for k, q in ((_FIRST, 1), (_SECOND, 2), (_THIRD, 3)):
        horizontal = place(k) / q
        kernels += [horizontal, horizontal.T, horizontal[:, ::-1], horizontal.T[::-1, :]]
    bank = np.stack(kernels)[:, None].astype(np.float32)
    return torch.from_numpy(np.ascontiguousarray(bank))


class TLU(nn.Module):
    """Truncated linear unit: clip to ``[-t, t]``."""

    def __init__(self, threshold: float) -> None:
        super().__init__()
        self.threshold = threshold

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return torch.clamp(x, -self.threshold, self.threshold)


def _block(c_in: int, c_out: int, *, pool: bool, absolute: bool = False) -> nn.Sequential:
    layers: list[nn.Module] = [nn.Conv2d(c_in, c_out, 3, padding=1, bias=False)]
    if absolute:
        layers.append(_Abs())
    layers += [nn.BatchNorm2d(c_out), nn.ReLU(inplace=True)]
    if pool:
        layers.append(nn.AvgPool2d(5, stride=2, padding=2))
    return nn.Sequential(*layers)


class _Abs(nn.Module):
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return torch.abs(x)


class StegoNet(nn.Module):
    """Input: ``N x 1 x H x W`` greyscale in ``[0, 255]``. Output: two logits (cover, stego)."""

    def __init__(self, width: int = 16) -> None:
        super().__init__()
        bank = _high_pass_bank()
        self.high_pass = nn.Conv2d(1, bank.shape[0], 5, padding=2, bias=False)
        self.high_pass.weight.data.copy_(bank)
        self.high_pass.weight.requires_grad_(False)
        self.tlu = TLU(3.0)
        c = bank.shape[0]
        self.features = nn.Sequential(
            _block(c, width, pool=False, absolute=True),
            _block(width, width, pool=True),
            _block(width, 2 * width, pool=True),
            _block(2 * width, 4 * width, pool=True),
            _block(4 * width, 8 * width, pool=False),
        )
        self.classifier = nn.Linear(8 * width, 2)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.tlu(self.high_pass(x))
        x = self.features(x)
        return self.classifier(x.mean(dim=(2, 3)))


Embedder = Callable[[np.ndarray, np.random.Generator], np.ndarray]
"""Turns one ``H x W`` uint8 cover into a stego image."""


@dataclass
class TrainLog:
    epochs: int
    best_epoch: int
    validation_error: float
    history: list[tuple[float, float]]
    """(training loss, validation error) per epoch."""


def _augment(cover: np.ndarray, stego: np.ndarray, rng: np.random.Generator, crop: int | None):
    """The same random crop, flip and rotation for both images of a pair."""
    k = int(rng.integers(4))
    flip = bool(rng.integers(2))
    h, w = cover.shape
    top = int(rng.integers(h - crop + 1)) if crop else 0
    left = int(rng.integers(w - crop + 1)) if crop else 0
    size_h, size_w = (crop, crop) if crop else (h, w)
    out = []
    for x in (cover, stego):
        x = np.rot90(x[top : top + size_h, left : left + size_w], k)
        if flip:
            x = x[:, ::-1]
        out.append(np.ascontiguousarray(x))
    return out


def _to_tensor(images: list[np.ndarray]) -> torch.Tensor:
    return torch.from_numpy(np.stack(images).astype(np.float32))[:, None]


def scores(model: StegoNet, images: np.ndarray, batch: int = 64) -> np.ndarray:
    """Probability of "stego" for each ``H x W`` image."""
    model.eval()
    out = []
    with torch.no_grad():
        for i in range(0, len(images), batch):
            logits = model(_to_tensor(list(images[i : i + batch])))
            out.append(torch.softmax(logits, dim=1)[:, 1].numpy())
    return np.concatenate(out) if out else np.zeros(0)


def _validation_error(model: StegoNet, covers: np.ndarray, stegos: np.ndarray) -> float:
    p0, p1 = scores(model, covers), scores(model, stegos)
    return float(((p0 > 0.5).mean() + (p1 <= 0.5).mean()) / 2)


def train(
    train_covers: np.ndarray,
    valid_covers: np.ndarray,
    embed: Embedder,
    *,
    epochs: int = 30,
    pairs_per_batch: int = 16,
    learning_rate: float = 1e-3,
    crop: int | None = 128,
    init: StegoNet | None = None,
    seed: int = 0,
    log: Callable[[str], None] = print,
) -> tuple[StegoNet, TrainLog]:
    """Train (or fine-tune ``init``) and return the model with the best validation error.

    Training stegos are re-embedded every epoch with fresh randomness - new
    positions and new payload bits - which is how the embedding behaves in
    use and acts as data augmentation. Validation stegos are fixed. Training
    runs on random ``crop`` x ``crop`` windows to fit a CPU budget; the network
    is fully convolutional, so it is validated and tested on whole images.
    """
    torch.manual_seed(seed)
    rng = np.random.default_rng(seed)
    model = copy.deepcopy(init) if init is not None else StegoNet()
    valid_rng = np.random.default_rng(seed + 1)
    valid_stegos = np.stack([embed(c, valid_rng) for c in valid_covers])
    optimiser = torch.optim.Adamax(
        [p for p in model.parameters() if p.requires_grad], lr=learning_rate, weight_decay=1e-4
    )
    schedule = torch.optim.lr_scheduler.CosineAnnealingLR(optimiser, T_max=epochs)
    loss_fn = nn.CrossEntropyLoss()

    best_state = copy.deepcopy(model.state_dict())
    best_error, best_epoch = _validation_error(model, valid_covers, valid_stegos), 0
    history: list[tuple[float, float]] = []
    for epoch in range(1, epochs + 1):
        model.train()
        order = rng.permutation(len(train_covers))
        total, batches = 0.0, 0
        for start in range(0, len(order), pairs_per_batch):
            images, labels = [], []
            for i in order[start : start + pairs_per_batch]:
                cover = train_covers[i]
                pair = _augment(cover, embed(cover, rng), rng, crop)
                images += pair
                labels += [0, 1]
            optimiser.zero_grad()
            loss = loss_fn(model(_to_tensor(images)), torch.tensor(labels))
            loss.backward()
            optimiser.step()
            total += loss.item()
            batches += 1
        schedule.step()
        error = _validation_error(model, valid_covers, valid_stegos)
        history.append((total / max(batches, 1), error))
        log(f"    epoch {epoch:2d}: loss {total / max(batches, 1):.4f}, validation P_E {error:.3f}")
        if error < best_error:
            best_error, best_epoch = error, epoch
            best_state = copy.deepcopy(model.state_dict())
    model.load_state_dict(best_state)
    return model, TrainLog(epochs, best_epoch, best_error, history)
