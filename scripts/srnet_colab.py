"""SRNet against shardpix format 5, on 10,000 ALASKA2 photographs, with the Colab CLI.

This is the script behind docs/05 §5.5.9. It needs a GPU and runs on Google
Colab through the Colab command line client:

    uv tool install google-colab-cli          # or: pip install google-colab-cli
    colab new -s srnet --gpu L4               # or --gpu A100
    colab drivemount -s srnet                 # Drive at /content/drive
    colab exec -s srnet -f scripts/srnet_colab.py
    colab stop -s srnet                       # at the end: release the GPU

Run `colab exec` inside tmux or screen. The work runs on the Colab machine;
progress is also written to `MyDrive/shardpix_alaska/srnet.log`. Colab stops
a machine about an hour after its last client disconnects.

Resuming: every epoch is saved on Drive. If the machine stops, run `colab
new`, `colab drivemount` and `colab exec` again: finished stages are skipped
and training resumes from the last epoch. Do not change the settings below
between runs (except QUALITIES, which may be shortened).

For quality 75, then 95:
1. download 10,000 ALASKA2 covers from alaska.utt.fr (once; they are kept in
   an archive on Drive);
2. measure DCTR on the same images with the same stego images (the
   reference, about half an hour per quality on the CPU);
3. train SRNet with the curriculum 0.4 -> 0.2 -> 0.1 -> one share, on the
   luminance decompressed without rounding, and test it on the same test
   half as DCTR, pooled over 1 to 50 images.

The results land in MyDrive/shardpix_alaska/data (docs/data in this
repository) and the charts in MyDrive/shardpix_alaska/assets.
"""

import concurrent.futures as cf
import json
import multiprocessing as mp
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

# --------------------------------------------------------------------------- settings

QUALITIES = [75, 95]
COUNT = 10000  # covers per quality
STRATEGY = "jpeg"  # format 5
CURRICULUM = ["0.4", "0.2", "0.1", "share"]
EPOCHS_FIRST = 30  # first stage, from scratch
EPOCHS_NEXT = 15  # later stages, starting from the previous one
RUN_DCTR = True  # DCTR on the same images, for comparison
SEED = 0

DRIVE = "/content/drive/MyDrive"
ROOT = f"{DRIVE}/shardpix_alaska"
DATA = f"{ROOT}/data"
CHECKPOINTS = f"{ROOT}/srnet"
LOG = f"{ROOT}/srnet.log"
TAG = "alaska"
COVERS = Path("/content/covers_alaska")
WORK = Path("/content/srnet_work")

# --------------------------------------------------------------------------- start

if not os.path.isdir(DRIVE):
    raise SystemExit("Drive is not mounted: run `colab drivemount -s srnet` first")
for folder in (DATA, CHECKPOINTS, f"{ROOT}/assets"):
    os.makedirs(folder, exist_ok=True)


def log(message):
    line = f"{time.strftime('%d/%m %H:%M')} {message}"
    print(line, flush=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def sh(command):
    subprocess.run(command, shell=True, check=True)


if not os.path.isdir("/content/shardpix"):
    sh("git clone -q https://github.com/Just-Ipavon/shardpix /content/shardpix")
sh("git -C /content/shardpix pull -q origin main")
sh(f"{sys.executable} -m pip install -q -e '/content/shardpix[bench]'")
sys.path.insert(0, "/content/shardpix")

import jpeglib  # noqa: E402
import numpy as np  # noqa: E402
import torch  # noqa: E402
import torch.nn as nn  # noqa: E402
import torch.nn.functional as F  # noqa: E402

from shardpix import jpeg  # noqa: E402
from shardpix.analysis import ensemble, features, jpeg_benchmark, pooled  # noqa: E402
from shardpix.analysis.ml_benchmark import _summary, split  # noqa: E402

if not torch.cuda.is_available():
    raise SystemExit("a GPU runtime is needed: colab new -s srnet --gpu L4")
DEVICE = torch.device("cuda")
torch.backends.cudnn.benchmark = True
# TF32 (A100, L4) rounds inputs to a 10-bit mantissa: on pixels up to 128 the
# error is about 0.1 levels, the size of the signal. It must be off.
torch.backends.cuda.matmul.allow_tf32 = False
torch.backends.cudnn.allow_tf32 = False

GPU_GB = torch.cuda.get_device_properties(0).total_memory / 2**30
# SRNet holds about 0.7 GB of activations per 512x512 image; 2 images per pair.
BATCH_PAIRS = int(max(2, min(16, GPU_GB * 0.6 // 1.4)))
WORKERS = min(8, os.cpu_count() or 2)
log(
    f"start: {torch.cuda.get_device_name(0)}, {GPU_GB:.0f} GB, {os.cpu_count()} CPUs, "
    f"{BATCH_PAIRS} pairs per batch"
)

# --------------------------------------------------------------------------- cover


def complete(path):
    try:
        with open(path, "rb") as f:
            head = f.read(2)
            f.seek(-2, os.SEEK_END)
            return head == b"\xff\xd8" and f.read(2) == b"\xff\xd9"
    except OSError:
        return False


def fetch(args):
    url, target = args
    if complete(target):
        return True
    for attempt in range(6):
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                data = r.read()
            tmp = target.with_suffix(".part")
            tmp.write_bytes(data)
            if complete(tmp):
                tmp.replace(target)
                return True
        except Exception:
            pass
        time.sleep(min(60, 2**attempt))
    return False


def covers_for(q):
    """10,000 covers at quality q: from the archive on Drive, or downloaded and archived."""
    folder = COVERS / f"q{q}"
    archive = Path(ROOT) / f"covers_q{q}.tar"
    if len(list(folder.glob("*.jpg"))) >= COUNT:
        return folder
    folder.mkdir(parents=True, exist_ok=True)
    if archive.exists():
        sh(f"tar -xf '{archive}' -C '{folder}'")
    else:
        base = f"https://alaska.utt.fr/DATASETS/ALASKA_v2_JPG_512_QF{q}_COLOR"
        jobs = [(f"{base}/{i:05d}.jpg", folder / f"{i:05d}.jpg") for i in range(1, COUNT + 1)]
        start = time.time()
        with cf.ThreadPoolExecutor(4) as pool:  # be gentle with the server
            ok = list(pool.map(fetch, jobs))
        if not all(ok):
            raise SystemExit(f"q{q}: {len(ok) - sum(ok)} covers not downloaded: run again")
        log(f"q{q}: {COUNT} covers downloaded in {time.time() - start:.0f} s")
        sh(f"tar -cf '{archive}.tmp' -C '{folder}' . && mv '{archive}.tmp' '{archive}'")
    table = jpeg.standard_table(q)
    for path in sorted(folder.glob("*.jpg"))[:20]:
        image = jpeglib.read_dct(str(path))
        assert np.array_equal(image.qt[image.quant_tbl_no[0]], table), f"{path}: not quality {q}"
    return folder


# --------------------------------------------------------------------------- DCTR


def run_dctr(q, folder):
    cache = WORK / "dctr_cache"
    for strategy in ("naive", "jpeg"):
        jpeg_benchmark.main(
            [
                str(folder), "--quality", str(q), "--strategy", strategy,
                "--payloads", "share,0.1", "--detectors", "dctr", "--tag", TAG,
                "--dataset-name", "ALASKA2 (alaska.utt.fr), 512x512 colour JPEG (luminance)",
                "--cache", str(cache), "--data", DATA, "--limit", str(COUNT),
            ]
        )  # fmt: skip
    pooled.main(
        [
            "--jpeg", str(q), "--tag", TAG, "--detector", "dctr", "--data", DATA,
            "--out", f"{ROOT}/assets", "--dataset-name", "ALASKA2 512x512 colour",
        ]
    )  # fmt: skip
    shutil.rmtree(cache, ignore_errors=True)


# --------------------------------------------------------------------------- coefficients

_PATHS = []


def _blocks(args):
    index, payload = args
    blocks, quant = jpeg_benchmark._load(_PATHS[index])
    if blocks.shape != (64, 64, 8, 8):
        raise ValueError(f"{_PATHS[index].name}: not 512x512")
    if payload != "clean":
        # The seed of jpeg_benchmark._worker: the same stego images as DCTR.
        rng = np.random.default_rng([SEED, index, sum(map(ord, STRATEGY + payload))])
        blocks = jpeg_benchmark.stego_blocks(blocks, quant, STRATEGY, payload, rng)
    return blocks.astype(np.int16)


CHUNK = 1000


def _drive_chunks(q, name, n):
    return Path(ROOT) / "stego_cache" / f"q{q}-{name}-{n}"


def coefficients(q, folder, payload):
    """The coefficients of every cover at quality q, clean or with a payload.

    Embedding takes up to an hour per payload: every chunk of 1,000 images is
    saved, compressed, on Drive as soon as it is ready, so a restart loads it
    in seconds instead of embedding again.
    """
    global _PATHS
    _PATHS = sorted(folder.glob("*.jpg"))[:COUNT]
    n = len(_PATHS)
    name = "clean" if payload == "clean" else f"{STRATEGY}-{payload}"
    path = WORK / f"q{q}" / f"{name}-{n}.npy"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        saved = _drive_chunks(q, name, n)
        saved.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.stem + ".tmp.npy")
        out = np.lib.format.open_memmap(tmp, mode="w+", dtype=np.int16, shape=(n, 64, 64, 8, 8))
        start = time.time()
        with mp.get_context("fork").Pool() as pool:
            for first in range(0, n, CHUNK):
                last = min(first + CHUNK, n)
                chunk_file = saved / f"{first}.npz"
                if chunk_file.exists():
                    out[first:last] = np.load(chunk_file)["blocks"]
                    continue
                jobs = [(i, payload) for i in range(first, last)]
                block = np.stack(pool.map(_blocks, jobs, chunksize=16))
                out[first:last] = block
                tmp_chunk = saved / f"{first}.tmp.npz"
                np.savez_compressed(tmp_chunk, blocks=block)
                os.replace(tmp_chunk, chunk_file)
                log(f"q{q} {name}: {last}/{n} images ready")
        out.flush()
        del out
        tmp.replace(path)
        log(f"q{q} {name}: {n} images ready in {time.time() - start:.0f} s")
    quant = jpeg_benchmark._load(_PATHS[0])[1]
    return np.load(path, mmap_mode="r"), quant, path


# --------------------------------------------------------------------------- SRNet

DCT = torch.tensor(features._DCT, dtype=torch.float32, device=DEVICE)


def decompress(blocks, quant):
    # (B, 64, 64, 8, 8) coefficients -> (B, 1, 512, 512) pixels - 128, not rounded.
    x = blocks.to(DEVICE, torch.float32) * quant
    x = torch.einsum("ux,bhwuv,vy->bhwxy", DCT, x, DCT)
    b, h, w = x.shape[:3]
    return x.permute(0, 1, 3, 2, 4).reshape(b, 1, h * 8, w * 8)


class Plain(nn.Module):  # layers 1-2
    def __init__(self, cin, cout):
        super().__init__()
        self.conv = nn.Conv2d(cin, cout, 3, padding=1, bias=False)
        self.bn = nn.BatchNorm2d(cout)

    def forward(self, x):
        return F.relu(self.bn(self.conv(x)), inplace=True)


class Residual(nn.Module):  # layers 3-7
    def __init__(self, c):
        super().__init__()
        self.a, self.b = Plain(c, c), nn.Conv2d(c, c, 3, padding=1, bias=False)
        self.bn = nn.BatchNorm2d(c)

    def forward(self, x):
        return x + self.bn(self.b(self.a(x)))


class Down(nn.Module):  # layers 8-11
    def __init__(self, cin, cout):
        super().__init__()
        self.a, self.b = Plain(cin, cout), nn.Conv2d(cout, cout, 3, padding=1, bias=False)
        self.bn = nn.BatchNorm2d(cout)
        self.pool = nn.AvgPool2d(3, stride=2, padding=1)
        self.skip = nn.Sequential(
            nn.Conv2d(cin, cout, 1, stride=2, bias=False), nn.BatchNorm2d(cout)
        )

    def forward(self, x):
        return self.skip(x) + self.pool(self.bn(self.b(self.a(x))))


class SRNet(nn.Module):
    def __init__(self):
        super().__init__()
        self.body = nn.Sequential(
            Plain(1, 64),
            Plain(64, 16),
            *[Residual(16) for _ in range(5)],
            Down(16, 16),
            Down(16, 64),
            Down(64, 128),
            Down(128, 256),
            Plain(256, 512),
            nn.Conv2d(512, 512, 3, padding=1, bias=False),
            nn.BatchNorm2d(512),
            nn.AdaptiveAvgPool2d(1),
            nn.Flatten(),
        )
        self.fc = nn.Linear(512, 2)
        for m in self.modules():
            if isinstance(m, nn.Conv2d):
                nn.init.kaiming_normal_(m.weight, nonlinearity="relu")
        nn.init.normal_(self.fc.weight, std=0.01)
        nn.init.zeros_(self.fc.bias)

    def forward(self, x):
        return self.fc(self.body(x))


class Pairs(torch.utils.data.Dataset):
    def __init__(self, covers, stegos, index):
        self.covers, self.stegos, self.index = covers, stegos, index

    def __len__(self):
        return len(self.index)

    def __getitem__(self, i):
        j = self.index[i]
        return torch.from_numpy(np.array(self.covers[j])), torch.from_numpy(
            np.array(self.stegos[j])
        )


def batches(covers, stegos, index, shuffle):
    return torch.utils.data.DataLoader(
        Pairs(covers, stegos, index),
        batch_size=BATCH_PAIRS,
        shuffle=shuffle,
        num_workers=WORKERS,
        pin_memory=True,
        drop_last=shuffle,
    )


def images(cover, stego, quant, augment):
    x = decompress(torch.cat([cover, stego]), quant)
    if augment:
        # The same rotation and flip for a cover and its stego image.
        n = cover.shape[0]
        for i in range(n):
            k, flip = int(torch.randint(4, ())), bool(torch.randint(2, ()))
            for j in (i, i + n):
                y = torch.rot90(x[j], k, (1, 2))
                x[j] = torch.flip(y, (2,)) if flip else y
    y = torch.cat([torch.zeros(cover.shape[0]), torch.ones(stego.shape[0])]).long().to(DEVICE)
    return x, y


@torch.no_grad()
def scores(model, covers, stegos, index, quant):
    # Score of each image: logit(stego) - logit(cover).
    model.eval()
    s0, s1 = [], []
    for cover, stego in batches(covers, stegos, index, False):
        x, _ = images(cover, stego, quant, False)
        out = model(x).float()
        s = (out[:, 1] - out[:, 0]).cpu().numpy()
        s0.append(s[: len(cover)])
        s1.append(s[len(cover) :])
    return np.concatenate(s0), np.concatenate(s1)


def min_error(v0, v1):
    # Smallest P_E over all thresholds: min (P_FA + P_MD) / 2.
    t = np.sort(np.concatenate([v0, v1, [np.inf]]))
    fa = 1 - np.searchsorted(np.sort(v0), t, side="right") / v0.size
    md = np.searchsorted(np.sort(v1), t, side="right") / v1.size
    return float(np.min((fa + md) / 2))


def save(obj, path):
    tmp = str(path) + ".tmp"
    torch.save(obj, tmp)
    os.replace(tmp, path)


def train_stage(q, payload, init, covers, stegos, quant, train, val):
    stage = Path(CHECKPOINTS) / f"{TAG}-q{q}-{STRATEGY}-{payload}"
    best_path, ckpt_path = Path(f"{stage}.best.pt"), Path(f"{stage}.ckpt.pt")
    epochs = EPOCHS_FIRST if init is None else EPOCHS_NEXT
    model = SRNet().to(DEVICE)
    if init is not None:
        model.load_state_dict(init)
    lr = 1e-3 if init is None else 5e-4
    opt = torch.optim.Adamax(model.parameters(), lr=lr, weight_decay=2e-4)
    sched = torch.optim.lr_scheduler.MultiStepLR(opt, [int(epochs * 0.75)], 0.1)
    first, best = 1, (1.0, float("inf"))
    if ckpt_path.exists():
        ckpt = torch.load(ckpt_path, map_location=DEVICE)
        model.load_state_dict(ckpt["model"])
        opt.load_state_dict(ckpt["opt"])
        sched.load_state_dict(ckpt["sched"])
        first, best = ckpt["epoch"] + 1, tuple(ckpt["best"])
        log(f"q{q} {payload}: resuming at epoch {first}")
    loss_fn = nn.CrossEntropyLoss()
    for epoch in range(first, epochs + 1):
        model.train()
        start, total, n = time.time(), 0.0, 0
        for cover, stego in batches(covers, stegos, train, True):
            x, y = images(cover, stego, quant, True)
            opt.zero_grad(set_to_none=True)
            loss = loss_fn(model(x), y)
            loss.backward()
            opt.step()
            total, n = total + loss.item() * len(y), n + len(y)
        sched.step()
        v0, v1 = scores(model, covers, stegos, val, quant)
        val_error = ensemble.decision_error(v0 > 0, v1 > 0)
        val_loss = float(np.mean(np.logaddexp(0, v0)) + np.mean(np.logaddexp(0, -v1))) / 2
        if (val_error, val_loss) < best:
            best = (val_error, val_loss)
            save(model.state_dict(), best_path)
        log(
            f"q{q} {payload:5s} epoch {epoch:3d}/{epochs}: loss {total / n:.4f}, "
            f"validation error {val_error:.3f} (best {best[0]:.3f}), "
            f"{n / (time.time() - start):.1f} img/s"
        )
        save(
            {
                "model": model.state_dict(),
                "opt": opt.state_dict(),
                "sched": sched.state_dict(),
                "epoch": epoch,
                "best": list(best),
            },
            ckpt_path,
        )
    return torch.load(best_path, map_location=DEVICE), epochs


# --------------------------------------------------------------------------- measurement


def run_srnet(q, folder, previous):
    covers, quant_np, _ = coefficients(q, folder, "clean")
    quant = torch.tensor(quant_np, dtype=torch.float32, device=DEVICE)
    n = covers.shape[0]
    train_all, test = split(n, SEED)  # the test half of DCTR
    order = np.random.default_rng(SEED).permutation(train_all)
    val, train = np.sort(order[: n // 20]), np.sort(order[n // 20 :])
    log(f"q{q}: pairs {len(train)} training, {len(val)} validation, {len(test)} test")

    data_path = Path(DATA) / f"srnet_{TAG}_q{q}.json"
    scores_path = data_path.with_suffix(".scores.npz")
    results = json.loads(data_path.read_text()) if data_path.exists() else {}
    if results.get("images") != n:
        results = {}
    results.update(
        {
            "dataset": "ALASKA2 (alaska.utt.fr), 512x512 colour JPEG (luminance)",
            "quality": q,
            "images": n,
            "seed": SEED,
            "detector": "SRNet (Boroumand, Chen and Fridrich 2019)",
            "input": "luminance decompressed from the DCT coefficients without rounding",
            "curriculum": CURRICULUM,
        }
    )
    rows = results.setdefault("rows", [])
    saved = dict(np.load(scores_path)) if scores_path.exists() else {}

    state = previous
    for payload in CURRICULUM:
        key = f"srnet@{STRATEGY}@{payload}"
        best_path = Path(CHECKPOINTS) / f"{TAG}-q{q}-{STRATEGY}-{payload}.best.pt"
        if key in saved and best_path.exists():
            log(f"q{q} {payload}: already measured, skipped")
            state = torch.load(best_path, map_location=DEVICE)
            continue
        stegos, _, stego_path = coefficients(q, folder, payload)
        state, epochs = train_stage(q, payload, state, covers, stegos, quant, train, val)
        model = SRNet().to(DEVICE)
        model.load_state_dict(state)
        v0, v1 = scores(model, covers, stegos, test, quant)
        row = {
            "detector": "srnet",
            "strategy": STRATEGY,
            "payload": payload,
            **_summary(v0, v1, 0.0),
            "p_e_min": min_error(v0, v1),
            "epochs": epochs,
            "train_pairs": int(len(train)),
        }
        if payload == "share":
            row["pooled_llr"] = [
                {
                    "group": g,
                    **{
                        k: v
                        for k, v in vars(pooled.pooled(v0, v1, g, "llr", seed=SEED)).items()
                        if k != "group"
                    },
                }
                for g in pooled.GROUP_SIZES
                if g <= v0.size // 4
            ]
        rows[:] = [r for r in rows if not (r["strategy"] == STRATEGY and r["payload"] == payload)]
        rows.append(row)
        saved["test_index"] = test
        saved[key] = np.stack([v0, v1]).astype(np.float32)
        data_path.write_text(json.dumps(results, indent=2) + "\n")
        np.savez_compressed(scores_path, **saved)
        log(
            f">>> q{q} {payload}: P_E {row['p_e']:.3f} "
            f"[{row['p_e_low']:.3f}, {row['p_e_high']:.3f}], "
            f"P_E min {row['p_e_min']:.3f}, AUC {row['auc']:.3f}"
        )
        del stegos
        stego_path.unlink(missing_ok=True)  # 5 GB per payload: free the disk
        shutil.rmtree(_drive_chunks(q, f"{STRATEGY}-{payload}", n), ignore_errors=True)
    return state


previous = None
for q in QUALITIES:
    folder = covers_for(q)
    if RUN_DCTR and not (Path(DATA) / f"pooled_jpeg_{TAG}_dctr_q{q}.json").exists():
        log(f"q{q}: DCTR on the same images")
        run_dctr(q, folder)
    previous = run_srnet(q, folder, previous)

sh(f"cd '{ROOT}' && zip -qr results_srnet_cli.zip data assets")
log(f"DONE: results in {ROOT}/results_srnet_cli.zip")
