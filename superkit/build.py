"""Repack: ``make_f2fs`` + ``sload_f2fs`` per partition, post-sload xattr fix-ups,
``lpmake`` for the super image.  Everything runs unprivileged.  See DESIGN.md §6 and
docs/tooling-notes.md for the measured tool behaviour this code relies on.
"""
from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
import time
import tomllib
from dataclasses import dataclass, field

from . import fsconfig, xattrw
from .f2fs import F2FSImage, F2FSError
from .lp import LpError, SuperImage

MIB = 1 << 20
BLOCK = 4096
MIN_RW_IMAGE = 46 * MIB      # make_f2fs refuses smaller non-ro images
MIN_RO_IMAGE = 27 * MIB      # ... and smaller ro images
RO_FIXED_OVERHEAD = 27 * MIB # measured: ro image needs content + 27 MiB
INLINE_DATA_MAX = 3344       # sload stores files <= 3344 bytes inline
ADDRS_IN_INODE = 923 - 50
ADDRS_PER_NODE = 1018
DENTRIES_PER_BLOCK = 214

DEFAULTS = {
    "ro": False,
    "slack_percent": 3,
    "slack_min": "8M",
    "fixed_timestamp": True,
    "max_attempts": 6,
    "grow_percent": 8,
    "keep_stock_size": True,   # rw images never shrink below the stock fs size (free space stays in the partition)
}

SLOAD_FAILURE_MARKERS = ("Not enough space", "ASSERT", "Can't find free block", "failed to find",
                         "cannot lookup security context", "Ill-formed line")


class BuildError(Exception):
    pass


# --------------------------------------------------------------------------- config

def parse_size(v) -> int:
    if isinstance(v, bool):
        raise BuildError("size must be a number or string, not bool")
    if isinstance(v, int):
        return v
    s = str(v).strip().upper()
    mult = 1
    for suffix, m in (("GIB", 1 << 30), ("MIB", 1 << 20), ("KIB", 1 << 10),
                      ("G", 1 << 30), ("M", 1 << 20), ("K", 1 << 10), ("B", 1)):
        if s.endswith(suffix):
            s = s[: -len(suffix)]
            mult = m
            break
    try:
        return int(float(s) * mult)
    except ValueError:
        raise BuildError("bad size %r" % v) from None


def load_repack_config(path: str | None) -> dict:
    """``{'defaults': {...}, 'partition': {name: {...}}}`` with DEFAULTS filled in."""
    cfg = {"defaults": dict(DEFAULTS), "partition": {}}
    if path is None:
        return cfg
    with open(path, "rb") as f:
        data = tomllib.load(f)
    known = set(DEFAULTS)
    for k, v in data.get("defaults", {}).items():
        if k not in known:
            raise BuildError("unknown key %r in [defaults] of %s" % (k, path))
        cfg["defaults"][k] = v
    for name, sub in data.get("partition", {}).items():
        for k in sub:
            if k not in known:
                raise BuildError("unknown key %r in [partition.%s] of %s" % (k, name, path))
        cfg["partition"][name] = dict(sub)
    return cfg


def partition_config(cfg: dict, name: str) -> dict:
    out = dict(cfg["defaults"])
    out.update(cfg.get("partition", {}).get(name, {}))
    out["slack_min"] = parse_size(out["slack_min"])
    out["ro"] = bool(out["ro"])
    out["fixed_timestamp"] = bool(out["fixed_timestamp"])
    out["keep_stock_size"] = bool(out.get("keep_stock_size", True))
    return out


# --------------------------------------------------------------------------- sizing

def ovp_ratio(size: int) -> float:
    """make_f2fs auto overprovision ratio by image size (docs/tooling-notes.md §1.4)."""
    mib = size / MIB
    if mib < 100:
        return 0.55
    if mib < 120:
        return 0.30
    if mib < 200:
        return 0.25
    if mib < 400:
        return 0.15
    if mib < 768:
        return 0.10
    if mib < 1536:
        return 0.0527
    if mib < 3000:
        return 0.0358
    if mib < 4000:
        return 0.0257
    return 0.0239


@dataclass
class ContentEstimate:
    data_blocks: int = 0
    node_blocks: int = 0
    dentry_blocks: int = 0
    xattr_nodes: int = 0
    files: int = 0

    @property
    def blocks(self) -> int:
        return self.data_blocks + self.node_blocks + self.dentry_blocks + self.xattr_nodes

    @property
    def bytes(self) -> int:
        return self.blocks * BLOCK


def estimate_content(entries: list[fsconfig.ManifestEntry]) -> ContentEstimate:
    est = ContentEstimate()
    children: dict[str, int] = {}
    for e in entries:
        if e.path:
            parent = e.path.rsplit("/", 1)[0] if "/" in e.path else ""
            children[parent] = children.get(parent, 0) + 1
    for e in entries:
        est.files += 1
        est.node_blocks += 1
        if e.type == "reg":
            if e.size > INLINE_DATA_MAX:
                blocks = -(-e.size // BLOCK)
                est.data_blocks += blocks
                if blocks > ADDRS_IN_INODE:
                    direct = -(-(blocks - ADDRS_IN_INODE) // ADDRS_PER_NODE)
                    est.node_blocks += direct + (1 if direct > 2 else 0) + (1 if direct > 2 + ADDRS_PER_NODE else 0)
        elif e.type == "dir":
            est.dentry_blocks += max(1, -(-(children.get(e.path, 0) + 2) // DENTRIES_PER_BLOCK))
        elif e.type == "lnk" and e.target is not None and len(e.target.encode()) + 1 > 3487:
            est.data_blocks += 1
        if xattrw.needs_xattr_node(e):
            est.xattr_nodes += 1
    return est


def round_up(n: int, unit: int) -> int:
    return -(-n // unit) * unit


def initial_size(content_bytes: int, ro: bool, pcfg: dict, stock_fs_size: int = 0) -> int:
    if ro:
        base = content_bytes + RO_FIXED_OVERHEAD
        floor = MIN_RO_IMAGE
    else:
        size = content_bytes
        for _ in range(5):
            size = int((content_bytes + 12 * MIB) / (1.0 - ovp_ratio(size)) + 14 * MIB)
        base = size
        floor = MIN_RW_IMAGE
    size = int(base * (1 + pcfg["slack_percent"] / 100.0)) + pcfg["slack_min"]
    size = max(size, floor)
    if not ro and stock_fs_size and size < stock_fs_size and pcfg.get("keep_stock_size", True):
        # keep the stock size: the room freed by debloating stays inside the rw partition
        size = stock_fs_size
    return round_up(size, MIB)


def grow(size: int, pcfg: dict) -> int:
    return round_up(int(size * (1 + pcfg["grow_percent"] / 100.0)) + 8 * MIB, MIB)


# --------------------------------------------------------------------------- running tools

class Log:
    def __init__(self, path: str | None):
        self.path = path
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def write(self, text: str) -> None:
        if not self.path:
            return
        with open(self.path, "a", encoding="utf-8", errors="replace") as f:
            f.write(text)
            if not text.endswith("\n"):
                f.write("\n")


def run(cmd: list[str], log: Log, env: dict | None = None, cwd: str | None = None) -> tuple[int, str]:
    """Run a tool, capture combined output, append command + output to the log."""
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    t0 = time.monotonic()
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=full_env, cwd=cwd)
    except FileNotFoundError as ex:
        raise BuildError("tool not found: %s (%s)" % (cmd[0], ex)) from None
    out = p.stdout.decode("utf-8", errors="replace")
    log.write("$ %s\n%s[exit %d, %.1fs]\n" % (" ".join(_q(c) for c in cmd), out, p.returncode, time.monotonic() - t0))
    return p.returncode, out


def _q(s: str) -> str:
    return s if all(c.isalnum() or c in "-_./:=,+@%" for c in s) else repr(s)


# --------------------------------------------------------------------------- partitions

@dataclass
class PartitionResult:
    name: str
    image: str
    size: int
    attempts: int
    ro: bool
    features: list[str]
    content_bytes: int
    fixups: list[str] = field(default_factory=list)
    fsck_ok: bool = False
    seconds: float = 0.0

    def row(self) -> str:
        return "%-11s %6d MiB %s attempts=%d features=%s fixups=%d fsck=%s %.0fs" % (
            self.name, self.size // MIB, "ro" if self.ro else "rw", self.attempts,
            ",".join(self.features) or "-", len(self.fixups), "ok" if self.fsck_ok else "FAIL", self.seconds)


def load_partition(workdir: str, name: str) -> tuple[dict, list[fsconfig.ManifestEntry], str]:
    part_dir = os.path.join(workdir, name)
    meta_path = os.path.join(part_dir, "meta.json")
    manifest_path = os.path.join(part_dir, "manifest.tsv")
    for p in (meta_path, manifest_path, os.path.join(part_dir, "root")):
        if not os.path.exists(p):
            raise BuildError("partition %s: missing %s (run unpack first)" % (name, p))
    with open(meta_path, encoding="utf-8") as f:
        meta = json.load(f)
    entries = fsconfig.read_manifest(manifest_path)
    mount_point = meta.get("mount_point") or ("/" if name == "system" else "/" + name)
    return meta, entries, mount_point


def prepare_sload_sidecars(entries: list[fsconfig.ManifestEntry], mount_point: str, dest_dir: str) -> tuple[str, str, set[str]]:
    """fs_config / file_contexts for sload, with padded labels for files whose final
    xattr set needs an xattr node.  Returns (fs_config, file_contexts, padded paths)."""
    os.makedirs(dest_dir, exist_ok=True)
    padded: set[str] = set()
    sload_entries = []
    for e in entries:
        if e.type in ("chr", "blk", "fifo", "sock"):
            continue
        if e.selinux is None:
            raise BuildError("%r has no SELinux label; sload_f2fs would fail" % e.path)
        if xattrw.needs_xattr_node(e):
            e2 = fsconfig.ManifestEntry(**{f: getattr(e, f) for f in fsconfig.MANIFEST_FIELDS})
            e2.selinux = xattrw.pad_label(e.selinux)
            sload_entries.append(e2)
            padded.add(e.path)
        else:
            sload_entries.append(e)
    fs_config = os.path.join(dest_dir, "fs_config")
    file_contexts = os.path.join(dest_dir, "file_contexts")
    with open(fs_config, "w", encoding="utf-8", newline="\n") as f:
        f.write(fsconfig.write_fs_config(sload_entries, mount_point))
    with open(file_contexts, "w", encoding="utf-8", newline="\n") as f:
        f.write(fsconfig.write_file_contexts(sload_entries, mount_point))
    return fs_config, file_contexts, padded


def sload_failed(rc: int, out: str) -> str | None:
    if rc != 0:
        return "exit status %d" % rc
    for marker in SLOAD_FAILURE_MARKERS:
        if marker in out:
            return "output contains %r" % marker
    return None


def verify_partition_image(image: str, entries: list[fsconfig.ManifestEntry], fixed_timestamp: bool,
                           expect_ro: bool) -> None:
    """Re-read the built image and compare its metadata with the manifest."""
    with F2FSImage(image) as img:
        want_features = {"ro"} if expect_ro else set()
        if set(img.features) != want_features:
            raise BuildError("%s: features %s, expected %s" % (image, sorted(img.features), sorted(want_features)))
        have = [e for _p, e, _i in img.walk()]
    ignore = {"ino", "nlink", "sha256", "mtime", "mtime_ns"}
    d = fsconfig.manifest_diff(entries, have, ignore=ignore)
    types = {e.path: e.type for e in entries}
    problems = []
    for e in d.only_in_a:
        if e.type in ("chr", "blk", "fifo", "sock"):
            continue  # sload skips special files; recorded in the manifest only
        problems.append("- missing in image: %s" % (e.path or "/"))
    for e in d.only_in_b:
        if e.path == "lost_found" or e.path.startswith("lost_found/"):
            continue
        problems.append("+ unexpected in image: %s" % e.path)
    for c in d.changed:
        if c.field == "size" and types.get(c.path) == "dir":
            continue
        if c.field in ("uid", "gid", "mode") and c.path == "":
            pass
        problems.append("~ %s: %s %r -> %r" % (c.path or "/", c.field, c.a, c.b))
    if problems:
        raise BuildError("%s does not match the manifest:\n%s" % (image, "\n".join(problems[:40])))


def build_partition(workdir: str, name: str, outdir: str, cfg: dict, log: Log | None = None,
                    progress=None) -> PartitionResult:
    t0 = time.monotonic()
    log = log or Log(os.path.join(outdir, "build.log"))
    meta, entries, mount_point = load_partition(workdir, name)
    pcfg = partition_config(cfg, name)
    ro = pcfg["ro"]
    f2 = meta.get("f2fs", meta)
    root = f2.get("root", {})
    uuid = f2.get("uuid")
    label = f2.get("label", name)
    root_mtime = int(root.get("mtime", int(time.time())))
    sload_ts = int(f2.get("mtime_hint") or root_mtime)
    stock_fs_size = int(f2.get("fs_size") or 0)

    os.makedirs(outdir, exist_ok=True)
    sidecar_dir = os.path.join(outdir, "sload", name)
    fs_config, file_contexts, padded = prepare_sload_sidecars(entries, mount_point, sidecar_dir)
    root_dir = os.path.join(workdir, name, "root")
    image = os.path.join(outdir, name + ".img")

    est = estimate_content(entries)
    size = initial_size(est.bytes, ro, pcfg, stock_fs_size)
    log.write("== %s: %d entries, estimate %d MiB (data %d, nodes %d, dentry %d, xattr %d blocks), "
              "start %d MiB, %s\n" % (name, len(entries), est.bytes // MIB, est.data_blocks, est.node_blocks,
                                        est.dentry_blocks, est.xattr_nodes, size // MIB, "ro" if ro else "rw"))
    attempts = 0
    while True:
        attempts += 1
        if attempts > int(pcfg["max_attempts"]):
            raise BuildError("%s: sload_f2fs still fails after %d attempts (last size %d MiB); see %s"
                             % (name, attempts - 1, size // MIB, log.path))
        if progress:
            progress("%s: attempt %d, image %d MiB" % (name, attempts, size // MIB))
        with open(image, "wb") as f:
            f.truncate(size)
        mkfs = ["make_f2fs", "-f", "-R", "%d:%d" % (int(root.get("uid", 0)), int(root.get("gid", 0))),
                "-l", str(label), "-T", str(root_mtime)]
        if uuid:
            mkfs += ["-U", str(uuid)]
        if ro:
            mkfs += ["-O", "ro"]
        mkfs.append(image)
        rc, out = run(mkfs, log)
        if rc != 0:
            raise BuildError("make_f2fs failed for %s (exit %d):\n%s" % (name, rc, out[-2000:]))
        sload = ["sload_f2fs", "-C", fs_config, "-s", file_contexts, "-t", mount_point, "-f", root_dir]
        if pcfg["fixed_timestamp"]:
            sload += ["-T", str(sload_ts)]
        sload.append(image)
        rc, out = run(sload, log, env={"LC_ALL": "C"})
        why = sload_failed(rc, out)
        if why is None:
            break
        log.write("sload_f2fs failed (%s); growing image\n" % why)
        if "failed to find" in out or "cannot lookup security context" in out or "Ill-formed" in out:
            raise BuildError("%s: sload_f2fs rejected the sidecars (%s):\n%s" % (name, why, out[-2000:]))
        size = grow(size, pcfg)

    # post-sload: capabilities, user.* xattrs, un-pad labels
    fix_paths = {e.path for e in entries if xattrw.needs_rewrite(e)} | padded
    fixups: list[str] = []
    if fix_paths:
        wanted = {e.path: e for e in entries}
        with xattrw.XattrWriter(image) as w:
            fixups = w.apply_manifest(wanted, only_paths=fix_paths)
        log.write("xattr fix-ups on %d paths: %s\n" % (len(fixups), ", ".join(sorted(fixups)[:20])))

    verify_partition_image(image, entries, pcfg["fixed_timestamp"], ro)
    rc, out = run(["fsck.f2fs", "--dry-run", image], log)
    fsck_ok = rc == 0
    if not fsck_ok:
        raise BuildError("fsck.f2fs reports problems on %s (exit %d):\n%s" % (image, rc, out[-2000:]))
    with F2FSImage(image) as img:
        features = sorted(img.features)
    return PartitionResult(name, image, size, attempts, ro, features, est.bytes, fixups, fsck_ok,
                           time.monotonic() - t0)


# --------------------------------------------------------------------------- super

def partitions_spec(lp: SuperImage, outdir: str, cfg: dict) -> list[dict]:
    spec = []
    for p in lp.partitions:
        image = os.path.join(outdir, p.name + ".img")
        if not os.path.exists(image):
            raise BuildError("missing %s (build every partition before assembling the super image)" % image)
        pcfg = partition_config(cfg, p.name)
        spec.append({"name": p.name, "image_path": image, "size": os.path.getsize(image),
                     "readonly": pcfg["ro"], "group": p.group})
    return spec


def build_super(workdir: str, outdir: str, cfg: dict, output: str | None = None, log: Log | None = None) -> dict:
    log = log or Log(os.path.join(outdir, "build.log"))
    super_json = os.path.join(workdir, "super.json")
    if not os.path.exists(super_json):
        raise BuildError("missing %s (run unpack first)" % super_json)
    lp = SuperImage.load_json(super_json)
    spec = partitions_spec(lp, outdir, cfg)
    report = lp.validate_capacity(spec)
    log.write("capacity:\n%s\n" % report.format())
    if not report.ok:
        raise BuildError("the rebuilt partitions do not fit the super partition:\n%s\n"
                         "Hint: set ro = true for a partition in repack.toml to shrink it." % report.format())
    output = output or os.path.join(outdir, "super.img")
    try:
        args = lp.lpmake_args(spec, output)
    except LpError as ex:
        raise BuildError(str(ex)) from None
    rc, out = run(args, log)
    if rc != 0:
        raise BuildError("lpmake failed (exit %d):\n%s" % (rc, out[-2000:]))
    new = SuperImage(output)
    problems = []
    g_old, g_new = lp.geometry, new.geometry
    for fld in ("metadata_max_size", "metadata_slot_count", "logical_block_size"):
        if getattr(g_old, fld) != getattr(g_new, fld):
            problems.append("geometry %s: %s -> %s" % (fld, getattr(g_old, fld), getattr(g_new, fld)))
    if lp.block_device.size != new.block_device.size:
        problems.append("device size %d -> %d" % (lp.block_device.size, new.block_device.size))
    if [p.name for p in lp.partitions] != [p.name for p in new.partitions]:
        problems.append("partition list changed: %s" % [p.name for p in new.partitions])
    for s in spec:
        try:
            np = new.partition(s["name"])
        except KeyError:
            continue
        if np.size < s["size"]:
            problems.append("%s: partition size %d < image %d" % (s["name"], np.size, s["size"]))
        if np.readonly != s["readonly"]:
            problems.append("%s: readonly attribute %s, expected %s" % (s["name"], np.readonly, s["readonly"]))
    if problems:
        raise BuildError("rebuilt super.img does not match:\n" + "\n".join(problems))
    return {"super": output, "capacity": report.format(), "spec": spec, "size": os.path.getsize(output)}
