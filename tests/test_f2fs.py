"""Tests for superkit.f2fs (DESIGN.md §7.1 / §7.2).

Synthetic images are built under work/tmp/f2fs-tests/ with make_f2fs + sload_f2fs from a
generated tree (long names, > 214 entries per directory, deep nesting, inline-threshold
file sizes, files needing direct and indirect nodes, many/long symlinks, hard links,
capabilities and labels through the sidecars), in four variants: with and without
``-O extra_attr,inode_checksum,sb_checksum`` and with and without ``-O ro``.  Oracles are
the original bytes (sha256), the sidecars that built the image, ``dump.f2fs -r`` (byte
equality of the extracted tree), ``dump.f2fs -n`` (NAT pack / journal) and ``fsck.f2fs``
(inode checksums).  Patched copies exercise holes, NEW_ADDR, out-of-range addresses,
compression markers, encryption, the backup superblock, broken checkpoints, truncated
images, the NAT journal and the NAT version bitmap.  The stock vendor image is compared
with the ``dump.f2fs -r`` reference tree in work/stockdump/vendor.

Set SUPERKIT_SLOW=1 for the full stock system.img extraction; SUPERKIT_KEEP_TMP=1 keeps
the generated images.
"""
import hashlib
import json
import os
import random
import shutil
import stat
import struct
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from superkit import f2fs
from superkit import fsconfig as fc
from superkit.f2fs import F2FSImage
from superkit.fsconfig import ManifestEntry

ROOT = "/home/bigdihh/Documents/A137F-super"
TMP_BASE = os.path.join(ROOT, "work", "tmp", "f2fs-tests")
STOCK_PARTS = os.path.join(ROOT, "stock", "super")
STOCK_VENDOR = os.path.join(STOCK_PARTS, "vendor.img")
STOCK_SYSTEM = os.path.join(STOCK_PARTS, "system.img")
STOCK_ODM = os.path.join(STOCK_PARTS, "odm.img")
STOCKDUMP_VENDOR = os.path.join(ROOT, "work", "stockdump", "vendor")
SLOW = os.environ.get("SUPERKIT_SLOW") == "1"
KEEP = os.environ.get("SUPERKIT_KEEP_TMP") == "1"
TOOLS = ("make_f2fs", "sload_f2fs", "dump.f2fs", "fsck.f2fs")
HAVE_TOOLS = all(shutil.which(t) for t in TOOLS)
T0 = 1230768000          # 2009-01-01, the fixed timestamp
MIB = 1 << 20
ENV = dict(os.environ, LC_ALL="C")
TIMINGS: list[str] = []


def _run(cmd, **kw):
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    kw.setdefault("stdin", subprocess.DEVNULL)
    kw.setdefault("env", ENV)
    return subprocess.run(cmd, **kw)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def snapshot(root: str, skip_top=()) -> dict:
    """{relpath: ('d', None) | ('l', target) | ('f', sha256)} of a host tree."""
    out = {}
    for d, ds, fs in os.walk(root):
        rel = os.path.relpath(d, root)
        rel = "" if rel == "." else rel
        if rel == "":
            ds[:] = [x for x in ds if x not in skip_top]
        for x in ds + fs:
            p = os.path.join(rel, x) if rel else x
            full = os.path.join(d, x)
            if os.path.islink(full):
                out[p] = ("l", os.readlink(full))
            elif os.path.isdir(full):
                out[p] = ("d", None)
            else:
                with open(full, "rb") as f:
                    out[p] = ("f", sha256(f.read()))
    return out


# --------------------------------------------------------------------------- the generated tree

class Tree:
    """A generated source tree + the manifest that describes it (modes/owners/labels)."""

    def __init__(self, src: str, mount: str, seed: int = 1):
        self.src = src
        self.mount = mount
        self.prefix = "system/" if mount == "/" else ""
        self.entries: dict[str, ManifestEntry] = {}
        self.content: dict[str, bytes] = {}      # reg files
        self.targets: dict[str, str] = {}        # symlinks
        self.hardlinks: list[tuple[str, str]] = []
        self.rng = random.Random(seed)
        self.k = 0

    # -- builders
    def _label(self, path):
        base = "".join(c if (c.isascii() and c.isalnum()) else "_" for c in (path or "root"))[:40]
        return "u:object_r:t_%s:s0" % base

    def dir(self, path, mode=0o755, uid=0, gid=0):
        path = self.prefix + path if path else (self.prefix.rstrip("/") if self.prefix else "")
        self.entries[path] = ManifestEntry(path, "dir", mode, uid, gid, selinux=self._label(path))
        os.makedirs(os.path.join(self.src, path), exist_ok=True)
        return path

    def file(self, path, data: bytes, mode=0o644, uid=0, gid=0, caps=0):
        path = self.prefix + path
        self.entries[path] = ManifestEntry(path, "reg", mode, uid, gid, size=len(data), selinux=self._label(path), caps=caps)
        self.content[path] = data
        host = os.path.join(self.src, path)
        with open(host, "wb") as f:
            f.write(data)
        self.k += 1
        os.utime(host, (T0 + self.k, T0 + self.k))
        self.entries[path].mtime = T0 + self.k
        return path

    def link(self, path, target: str, mode=0o777, uid=0, gid=0):
        path = self.prefix + path
        self.entries[path] = ManifestEntry(path, "lnk", mode, uid, gid, size=len(os.fsencode(target)),
                                           selinux=self._label(path), target=target)
        self.targets[path] = target
        host = os.path.join(self.src, path)
        os.symlink(target, host)
        self.k += 1
        os.utime(host, (T0 + self.k, T0 + self.k), follow_symlinks=False)
        self.entries[path].mtime = T0 + self.k
        return path

    def hardlink(self, path, existing):
        path = self.prefix + path
        e = self.entries[self.prefix + existing]
        self.entries[path] = e.copy(path=path, selinux=e.selinux)
        self.content[path] = self.content[self.prefix + existing]
        os.link(os.path.join(self.src, self.prefix + existing), os.path.join(self.src, path))
        self.hardlinks.append((self.prefix + existing, path))
        return path

    def rand(self, n):
        return self.rng.randbytes(n)

    def build(self):
        os.makedirs(self.src, exist_ok=True)
        self.entries[""] = ManifestEntry("", "dir", 0o755, 0, 0, selinux="u:object_r:rootfs:s0" if self.mount == "/" else "u:object_r:vendor_file:s0")
        if self.prefix:
            self.dir("")                                     # the 'system' directory
        self.dir("bin", 0o755, 0, 2000)
        self.file("bin/hello", b"#!/bin/sh\necho hi\n", 0o755, 0, 2000, caps=0xC0)
        self.file("bin/setuid", self.rand(100), 0o4750, 0, 2000)
        self.file("bin/sgid", self.rand(200), 0o2755, 1000, 1001)
        self.file("bin/run-as", self.rand(300), 0o750, 0, 2000, caps=0xC0)
        self.dir("sizes", 0o755, 0, 0)
        for n in (0, 1, 2, 3344, 3345, 3487, 3488, 3489, 4095, 4096, 4097, 8192, 12288, 12289, 65536):
            self.file("sizes/f%d" % n, self.rand(n), 0o644, 1000, 1000)
        self.dir("big", 0o750, 0, 1000)
        self.file("big/four_mib.bin", self.rand(4 * MIB), 0o644, 0, 1000)
        self.file("big/thirteen_mib.bin", self.rand(13 * MIB + 123), 0o640, 0, 1000)
        self.dir("names", 0o755, 65534, 65534)
        self.file("names/" + "n" * 9, b"nine", 0o600, 65534, 65534)
        self.file("names/" + "s" * 16, b"sixteen", 0o600, 65534, 65534)
        self.file("names/" + "l" * 200, b"two hundred", 0o600, 65534, 65534)
        self.file("names/" + "m" * 255, b"max", 0o600, 65534, 65534)
        self.dir("names/" + "D" * 255, 0o755, 0, 0)
        self.file("names/" + "D" * 255 + "/inner", b"inner", 0o644, 0, 0)
        self.dir("many", 0o755, 0, 0)
        for i in range(300):
            self.file("many/e%03d" % i, b"entry %d\n" % i, 0o644, i % 7, i % 5)
        self.dir("manydirs", 0o755, 0, 0)
        for i in range(230):
            self.dir("manydirs/sub%03d" % i, 0o755, 0, 0)
        self.file("manydirs/sub007/f", b"seven", 0o644, 0, 0)
        p = "deep"
        self.dir(p, 0o755, 0, 0)
        for i in range(20):
            p = "%s/d%02d" % (p, i)
            self.dir(p, 0o755, 0, 0)
        self.file(p + "/leaf", b"bottom\n", 0o644, 0, 0)
        self.dir("links", 0o755, 0, 0)
        self.link("links/short", "../bin/hello")
        self.link("links/abs", "/system/bin/sh")
        self.link("links/dotdot", "../../..")
        self.link("links/to_dir", "../many")
        self.link("links/long", "x" * 1000)
        self.link("links/longer", "/".join(["segment%03d" % i for i in range(250)]))     # 2749 bytes, still inline
        self.link("links/odd_target", "a b/c\td/\xfc")
        for i in range(60):
            self.link("links/l%02d" % i, "../sizes/f1")
        self.link("links/mode644", "../bin/hello", mode=0o644)
        self.dir("hard", 0o755, 0, 0)
        self.file("hard/a", self.rand(5000), 0o644, 0, 0)
        self.hardlink("hard/b", "hard/a")
        self.hardlink("hard/c", "hard/a")
        self.dir("odd", 0o755, 0, 0)
        self.file("odd/a.b", b"ab", 0o644, 0, 0)
        self.file("odd/d(1)[2]", b"d", 0o600, 5, 6)
        self.file("odd/\xfc", b"ue", 0o604, 9, 10)
        self.file("odd/c++", b"x", 0o755, 1000, 1001)
        self.dir("odd/sticky", 0o1777, 0, 0)
        self.file("odd/sticky/t", b"t", 0o644, 2000, 2000)
        self.dir("empty", 0o700, 2, 3)
        for e in self.entries.values():
            if e.type == "dir":
                e.nlink = 2 + sum(1 for o in self.entries.values()
                                  if o.type == "dir" and o.path and o.parent == e.path)
            elif e.type == "reg":
                e.nlink = 1
        for a, b in self.hardlinks:
            n = 1 + sum(1 for x, y in self.hardlinks if x == a)
            for p in (a, b):
                self.entries[p].nlink = n
        # directory mtimes last (creating entries bumped them); sload copies them when -T is omitted
        for i, e in enumerate(sorted((e for e in self.entries.values() if e.type == "dir" and e.path),
                                     key=lambda e: -len(e.path))):
            e.mtime = T0 + 500000 + i
            os.utime(os.path.join(self.src, e.path), (e.mtime, e.mtime))
        return self

    def write_sidecars(self, out_dir):
        fs_config = os.path.join(out_dir, "fs_config")
        file_contexts = os.path.join(out_dir, "file_contexts")
        with open(fs_config, "w", encoding="utf-8", errors="surrogateescape") as f:
            f.write(fc.write_fs_config(self.entries.values(), self.mount))
        with open(file_contexts, "w", encoding="ascii") as f:
            f.write(fc.write_file_contexts(self.entries.values(), self.mount))
        return fs_config, file_contexts


def build_image(tree: Tree, img: str, size: int, features: str, sload_T: bool, label: str, uuid: str) -> None:
    fs_config, file_contexts = tree.write_sidecars(os.path.dirname(img))
    with open(img, "wb") as f:
        f.truncate(size)
    cmd = ["make_f2fs", "-R", "0:0", "-T", str(T0), "-l", label, "-U", uuid]
    if features:
        cmd += ["-O", features]
    r = _run(cmd + [img])
    if r.returncode != 0:
        raise RuntimeError("make_f2fs failed: %s%s" % (r.stdout, r.stderr))
    cmd = ["sload_f2fs", "-C", fs_config, "-s", file_contexts, "-t", tree.mount, "-f", tree.src]
    if sload_T:
        cmd += ["-T", str(T0)]
    r = _run(cmd + [img])
    out = r.stdout + r.stderr
    if r.returncode != 0 or "Not enough space" in out or "ASSERT" in out or "cannot lookup" in out:
        raise RuntimeError("sload_f2fs failed (rc %d): %s" % (r.returncode, out[-3000:]))


def dump_tree(img: str, out_dir: str) -> dict:
    """dump.f2fs -r extraction (the oracle) as a snapshot dict."""
    cwd = os.path.join(os.path.dirname(out_dir), "dumpcwd")
    os.makedirs(cwd, exist_ok=True)
    r = _run(["dump.f2fs", "-r", "-o", out_dir, "-f", "-N", "-L", img], cwd=cwd)
    if r.returncode != 0:
        raise RuntimeError("dump.f2fs -r failed: %s%s" % (r.stdout, r.stderr))
    return snapshot(out_dir, skip_top=("lost_found",))


def dump_nat(img: str, nid: int) -> dict:
    """``dump.f2fs -n nid~nid+1`` (end exclusive; it writes a file ``dump_nat`` into the cwd):
    {'blkaddr': int, 'pack': int, 'ino': int} of that nid."""
    cwd = os.path.join(TMP_BASE, "dumpcwd")
    os.makedirs(cwd, exist_ok=True)
    out = os.path.join(cwd, "dump_nat")
    if os.path.exists(out):
        os.unlink(out)
    r = _run(["dump.f2fs", "-n", "%d~%d" % (nid, nid + 1), img], cwd=cwd)
    if r.returncode != 0 or not os.path.exists(out):
        raise RuntimeError("dump.f2fs -n failed: %s%s" % (r.stdout, r.stderr))
    with open(out) as f:
        text = f.read()
    for line in text.splitlines():
        if line.startswith("nid:"):
            d = {}
            for tok in line.split("\t"):
                k, _, v = tok.partition(":")
                d[k.strip()] = v.strip()
            if int(d["nid"]) == nid:
                return {"blkaddr": int(d["blkaddr"]), "pack": int(d["pack"]), "ino": int(d["ino"])}
    raise RuntimeError("no NAT line for nid %d in %r" % (nid, text))


def patch(img: str, offset: int, data: bytes) -> None:
    with open(img, "r+b") as f:
        f.seek(offset)
        f.write(data)


def recompute_cp_crc(blk: bytearray) -> None:
    off = struct.unpack_from("<I", blk, 164)[0]
    crc = f2fs.f2fs_crc32(bytes(blk[:off]))
    if off < 4092:
        crc = f2fs.f2fs_crc32(bytes(blk[off + 4:]), crc)
    struct.pack_into("<I", blk, off, crc)


# --------------------------------------------------------------------------- variants

VARIANTS = {
    # name: (features, ro-size or rw-size, mount point, sload -T)
    "rw_plain": ("", 104 * MIB, "/vendor", False),
    "rw_extra": ("extra_attr,inode_checksum,sb_checksum", 104 * MIB, "/vendor", True),
    "ro_plain": ("ro", 64 * MIB, "/", True),
    "ro_extra": ("ro,extra_attr,inode_checksum,sb_checksum", 64 * MIB, "/vendor", False),
}
_BUILT: dict[str, dict] = {}


def get_variant(name: str) -> dict:
    """Build (once per process) and return {'img', 'tree', 'dir', ...} for a variant."""
    if name in _BUILT:
        return _BUILT[name]
    features, size, mount, sload_T = VARIANTS[name]
    d = os.path.join(TMP_BASE, name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    tree = Tree(os.path.join(d, "src"), mount).build()
    img = os.path.join(d, "fs.img")
    uu = "12345678-9abc-4def-8123-456789abcdef"
    label = "vendor" if mount != "/" else "/"
    t = time.time()
    build_image(tree, img, size, features, sload_T, label, uu)
    TIMINGS.append("build %s: %.1fs" % (name, time.time() - t))
    _BUILT[name] = dict(name=name, img=img, tree=tree, dir=d, features=features, mount=mount,
                        sload_T=sload_T, size=size, uuid=uu, label=label)
    return _BUILT[name]


def tearDownModule():
    for name in sorted(TIMINGS):
        print("[timing]", name, file=sys.stderr)
    if not KEEP:
        for v in _BUILT.values():
            shutil.rmtree(v["dir"], ignore_errors=True)
        for sub in ("stock-vendor", "stock-system", "patched", "probe", "dumpcwd"):
            shutil.rmtree(os.path.join(TMP_BASE, sub), ignore_errors=True)
        for f in ("stock-vendor.manifest.tsv", "stock-system.manifest.tsv"):
            try:
                os.unlink(os.path.join(TMP_BASE, f))
            except FileNotFoundError:
                pass


# --------------------------------------------------------------------------- unit tests (no tools needed)

class HelperTest(unittest.TestCase):
    def test_crc32(self):
        # reference: the bitwise loop from f2fs-tools
        def ref(data, crc=0xF2F52010):
            for b in data:
                crc ^= b
                for _ in range(8):
                    crc = (crc >> 1) ^ (0xEDB88320 if crc & 1 else 0)
            return crc
        for data in (b"", b"a", b"hello world", bytes(range(256)), b"\xff" * 100):
            self.assertEqual(f2fs.f2fs_crc32(data), ref(data))
            self.assertEqual(f2fs.f2fs_crc32(data, 0xFFFFFFFF), ref(data, 0xFFFFFFFF))
            self.assertEqual(f2fs.f2fs_crc32(data, 0x12345678), ref(data, 0x12345678))

    def test_feature_names(self):
        self.assertEqual(f2fs.feature_names(0x4000), ["ro"])
        self.assertEqual(f2fs.feature_names(0x828), ["extra_attr", "inode_checksum", "sb_checksum"])
        self.assertEqual(f2fs.feature_names(0), [])
        self.assertEqual(f2fs.feature_names(0x20000), ["unknown_0x20000"])
        self.assertEqual(f2fs.FEATURE_NAMES[0x2000], "compression")
        self.assertEqual(f2fs.FEATURE_NAMES[0x8], "extra_attr")

    def test_constants(self):
        self.assertEqual(f2fs.DEF_ADDRS_PER_INODE, 923)
        self.assertEqual(f2fs.ADDRS_PER_BLOCK, 1018)
        self.assertEqual(f2fs.NAT_ENTRY_PER_BLOCK, 455)
        self.assertEqual(f2fs.NAT_JOURNAL_ENTRIES, 38)
        self.assertEqual(f2fs.NR_DENTRY_IN_BLOCK, 214)
        self.assertEqual(f2fs.DENTRY_BLOCK_NAMES_OFF, 2384)
        self.assertEqual(f2fs.XATTR_NODE_OFFSET, 0x1FFFFFFF)

    def test_probe_and_open_non_f2fs(self):
        os.makedirs(os.path.join(TMP_BASE, "probe"), exist_ok=True)
        p = os.path.join(TMP_BASE, "probe", "junk.bin")
        with open(p, "wb") as f:
            f.write(b"\0" * 65536)
        self.assertFalse(f2fs.probe(p))
        self.assertFalse(f2fs.probe(p, 4096))
        self.assertFalse(f2fs.probe(os.path.join(TMP_BASE, "probe", "missing")))
        with self.assertRaises(f2fs.NotF2FSError):
            F2FSImage(p)
        with self.assertRaises(f2fs.F2FSError):
            F2FSImage(p, offset=60000)        # too short
        tiny = os.path.join(TMP_BASE, "probe", "tiny.bin")
        with open(tiny, "wb") as f:
            f.write(b"x" * 100)
        self.assertFalse(f2fs.probe(tiny))
        with self.assertRaises(f2fs.NotF2FSError):
            F2FSImage(tiny)


# --------------------------------------------------------------------------- synthetic images

@unittest.skipUnless(HAVE_TOOLS, "needs make_f2fs, sload_f2fs, dump.f2fs and fsck.f2fs on PATH")
class SyntheticImageTest(unittest.TestCase):
    """Runs the full check list on every variant (subTest per variant)."""

    def check_variant(self, name):
        v = get_variant(name)
        tree: Tree = v["tree"]
        img = v["img"]
        t0 = time.time()
        with F2FSImage(img) as fs:
            # -- superblock / checkpoint facts
            want = set(v["features"].split(",")) - {""}
            self.assertEqual(set(fs.features), want)
            self.assertEqual(fs.feature, sum(f2fs.FEATURE_BITS[n] for n in want))
            self.assertEqual(fs.uuid, v["uuid"])
            self.assertEqual(fs.label, v["label"])
            self.assertEqual(fs.block_size, 4096)
            self.assertEqual(fs.root_ino, 3)
            self.assertTrue(v["size"] - 2 * MIB < fs.fs_size <= v["size"])
            self.assertEqual(fs.fs_size, fs.sb.block_count * 4096)
            self.assertIn(fs.cp.pack, (1, 2))
            self.assertEqual(fs.cp.n_nats, 0)
            self.assertIn("unmount", fs.cp.flag_names)
            self.assertEqual(fs.sb.copy, 0)
            if "sb_checksum" in want:
                self.assertEqual(fs.sb.checksum_offset, 3068)
            # -- walk: sorted, complete
            items = list(fs.walk())
            paths = [p for p, _, _ in items]
            self.assertEqual(paths, sorted(paths))
            self.assertEqual(paths[0], "")
            self.assertEqual(set(paths), set(tree.entries))
            self.assertEqual(len(items), len(tree.entries))
            by_path = {p: (e, i) for p, e, i in items}
            counts = {}
            for p, e, i in items:
                counts[e.type] = counts.get(e.type, 0) + 1
            want_counts = {}
            for e in tree.entries.values():
                want_counts[e.type] = want_counts.get(e.type, 0) + 1
            self.assertEqual(counts, want_counts)
            # -- per-entry metadata vs the sidecars that built the image
            for p, e, ino in items:
                exp = tree.entries[p]
                with self.subTest(variant=name, path=p):
                    self.assertEqual(e.type, exp.type)
                    self.assertIsNone(e.sha256)
                    self.assertEqual(e.ino, ino.nid)
                    if p == "":
                        self.assertEqual((e.mode, e.uid, e.gid), (0o755, 0, 0))     # make_f2fs -R 0:0
                        self.assertEqual(e.mtime, T0)
                    else:
                        self.assertEqual(e.mode, exp.mode)
                        self.assertEqual((e.uid, e.gid), (exp.uid, exp.gid))
                        self.assertEqual(e.mtime, T0 if v["sload_T"] else exp.mtime)
                    self.assertEqual(e.mtime_ns, 0)
                    self.assertEqual(e.selinux, exp.selinux)
                    self.assertEqual(e.caps, 0)        # sload_f2fs 1.16 never writes security.capability
                    self.assertEqual(e.xattrs, {})
                    self.assertEqual(e.nlink, exp.nlink, "nlink of %r" % p)
                    if e.type == "lnk":
                        self.assertEqual(e.target, exp.target)
                        self.assertEqual(e.size, len(os.fsencode(exp.target)))
                        self.assertEqual(fs.read_symlink(ino), exp.target)
                    elif e.type == "reg":
                        self.assertEqual(e.size, len(tree.content[p]))
                        self.assertIsNone(e.target)
                    else:
                        self.assertEqual(e.size % 4096, 0)
                        self.assertGreaterEqual(e.size, 4096)
                        self.assertFalse(ino.has_inline_dentry)      # sload never creates inline dentries
                    # extra_attr geometry
                    if "extra_attr" in want:
                        self.assertTrue(ino.has_extra_attr)
                        self.assertEqual(ino.extra_isize, 12)
                        self.assertIsNotNone(ino.inode_checksum)
                    else:
                        self.assertFalse(ino.has_extra_attr)
                        self.assertEqual(ino.extra_isize, 0)
            # hard links: one inode, three names
            a, b, c = (by_path[tree.prefix + x] for x in ("hard/a", "hard/b", "hard/c"))
            self.assertEqual(a[0].ino, b[0].ino)
            self.assertEqual(a[0].ino, c[0].ino)
            self.assertEqual(a[0].nlink, 3)
            # inline thresholds (sload: <= 3344 inline), node usage of the big files
            pre = tree.prefix
            self.assertTrue(by_path[pre + "sizes/f3344"][1].has_inline_data)
            self.assertFalse(by_path[pre + "sizes/f3345"][1].has_inline_data)
            self.assertTrue(by_path[pre + "sizes/f0"][1].has_inline_data)
            four = by_path[pre + "big/four_mib.bin"][1]
            thirteen = by_path[pre + "big/thirteen_mib.bin"][1]
            self.assertNotEqual(four.i_nid[0], 0)
            self.assertEqual(four.i_nid[2], 0)
            self.assertNotEqual(thirteen.i_nid[0], 0)
            self.assertNotEqual(thirteen.i_nid[1], 0)
            self.assertNotEqual(thirteen.i_nid[2], 0, "13 MiB file must use the first indirect node")
            self.assertEqual(thirteen.i_nid[3], 0)
            self.assertTrue(by_path[pre + "links/longer"][1].has_inline_data)
            self.assertTrue(by_path[pre + "links/long"][1].has_inline_data)
            # read_file: every regular file byte-exact, chunk lengths sane
            for p, e, ino in items:
                if e.type != "reg":
                    continue
                chunks = list(fs.read_file(ino))
                data = b"".join(chunks)
                self.assertEqual(len(data), e.size)
                self.assertEqual(data, tree.content[p], "content of %r" % p)
                self.assertEqual(fs.hash_file(ino), sha256(tree.content[p]))
                for ch in chunks:
                    self.assertIsInstance(ch, bytes)
            many = by_path[pre + "many"][1]
            self.assertGreaterEqual(many.size, 2 * 4096)          # 300 entries need >= 2 dentry blocks
            self.assertEqual(len(fs.readdir(many)), 302)          # . and .. included
            t1 = time.time()
            # -- extract + manifest
            dest = os.path.join(v["dir"], "out")
            shutil.rmtree(dest, ignore_errors=True)
            man_path = os.path.join(v["dir"], "manifest.tsv")
            seen = []
            man = fs.extract(dest, manifest_path=man_path, progress=lambda d, t, p: seen.append((d, t)))
            t2 = time.time()
            self.assertEqual(seen[-1], (len(items), len(items)))
            self.assertEqual([e.path for e in man], paths)
            for e in man:
                exp = tree.entries[e.path]
                if e.type == "reg":
                    self.assertEqual(e.sha256, sha256(tree.content[e.path]), "sha256 of %r" % e.path)
                    host = os.path.join(dest, e.path)
                    with open(host, "rb") as f:
                        self.assertEqual(f.read(), tree.content[e.path])
                    st = os.lstat(host)
                    self.assertTrue(stat.S_ISREG(st.st_mode))
                    self.assertEqual(st.st_mtime_ns, e.mtime * 10**9)
                elif e.type == "lnk":
                    host = os.path.join(dest, e.path)
                    self.assertEqual(os.readlink(host), exp.target)
                    self.assertEqual(os.lstat(host).st_mtime_ns, e.mtime * 10**9)
                    self.assertIsNone(e.sha256)
                else:
                    host = os.path.join(dest, e.path) if e.path else dest
                    self.assertTrue(os.path.isdir(host))
                    self.assertEqual(os.lstat(host).st_mtime_ns, e.mtime * 10**9)
            # hard links are recreated as hard links
            sa = os.stat(os.path.join(dest, pre + "hard/a"))
            sb_ = os.stat(os.path.join(dest, pre + "hard/b"))
            self.assertEqual((sa.st_ino, sa.st_nlink), (sb_.st_ino, 3))
            # manifest file round trip
            back = fc.read_manifest(man_path)
            self.assertEqual(back, man)
            self.assertFalse(fc.manifest_diff(back, man))
            # the manifest reproduces the sidecars that built the image (caps aside: sload drops them)
            regen = [e.copy(caps=tree.entries[e.path].caps, sha256=None, ino=0, nlink=1, size=0, mtime=0)
                     for e in man]
            orig = [e.copy(sha256=None, ino=0, nlink=1, size=0, mtime=0) for e in tree.entries.values()]
            self.assertEqual(fc.write_file_contexts(regen, v["mount"]), fc.write_file_contexts(orig, v["mount"]))
            self.assertEqual(fc.write_fs_config(regen, v["mount"]), fc.write_fs_config(orig, v["mount"]))
            # idempotent re-extraction into the same directory
            man2 = fs.extract(dest, hash=False)
            self.assertEqual([(e.path, e.sha256) for e in man2], [(e.path, None) for e in man])
            self.assertEqual(snapshot(dest), snapshot(dest))
            # -- info()
            info = fs.info()
            json.dumps(info)
            self.assertEqual(info["counts"]["reg"], want_counts["reg"])
            self.assertEqual(info["counts"]["dir"], want_counts["dir"])
            self.assertEqual(info["counts"]["lnk"], want_counts["lnk"])
            self.assertEqual(info["counts"]["hardlink_paths"], 3)
            self.assertEqual(info["root"]["mode"], 0o755)
            self.assertEqual(info["root"]["mtime"], T0)
            self.assertEqual(info["uuid"], v["uuid"])
            self.assertEqual(info["label"], v["label"])
            self.assertEqual(info["features"], sorted(want, key=lambda n: f2fs.FEATURE_BITS[n]))
            self.assertEqual(info["mtime_uniform"], v["sload_T"])
            if v["sload_T"]:
                self.assertEqual(info["mtime_hint"], T0)
            self.assertEqual(info["data_bytes"], sum(len(c) for c in tree.content.values()))
        # -- byte-for-byte comparison with dump.f2fs -r
        t3 = time.time()
        dumped = dump_tree(img, os.path.join(v["dir"], "dump"))
        ours = snapshot(dest)
        self.assertEqual(ours, dumped)
        TIMINGS.append("%s: walk+read %.1fs extract %.1fs dump.f2fs %.1fs" % (name, t1 - t0, t2 - t1, time.time() - t3))

    def test_rw_plain(self):
        self.check_variant("rw_plain")

    def test_rw_extra(self):
        self.check_variant("rw_extra")

    def test_ro_plain(self):
        self.check_variant("ro_plain")

    def test_ro_extra(self):
        self.check_variant("ro_extra")

    def test_offset_and_length(self):
        """The same filesystem embedded in a container at a page-aligned and an unaligned offset."""
        v = get_variant("ro_plain")
        with F2FSImage(v["img"]) as fs:
            ref = [(p, e) for p, e, _ in fs.walk()]
            fs_size = fs.fs_size
        with open(v["img"], "rb") as f:
            data = f.read()
        for off in (MIB, 4096 + 512, 17):
            cont = os.path.join(v["dir"], "container_%d.bin" % off)
            with open(cont, "wb") as f:
                f.write(b"\xaa" * off)
                f.write(data)
                f.write(b"\x55" * 12345)            # trailing junk (like an AVB footer)
            self.assertTrue(f2fs.probe(cont, off))
            self.assertFalse(f2fs.probe(cont, 0))
            with F2FSImage(cont, offset=off) as fs:
                self.assertEqual(fs.fs_size, fs_size)
                self.assertEqual([(p, e) for p, e, _ in fs.walk()], ref)
                man = fs.extract(os.path.join(v["dir"], "out_off"), hash=True)
                for e in man:
                    if e.type == "reg":
                        self.assertEqual(e.sha256, sha256(v["tree"].content[e.path]))
            with F2FSImage(cont, offset=off, length=fs_size) as fs:
                self.assertEqual(len(list(fs.walk())), len(ref))
            with self.assertRaises(f2fs.CorruptError):
                F2FSImage(cont, offset=off, length=fs_size - 4096)      # truncated
            os.unlink(cont)

    def test_truncated_and_corrupt(self):
        v = get_variant("ro_plain")
        d = os.path.join(TMP_BASE, "patched")
        os.makedirs(d, exist_ok=True)
        with F2FSImage(v["img"]) as fs:
            cp_blkaddr = fs.sb.cp_blkaddr
            fs_size = fs.fs_size
        # truncated file
        trunc = os.path.join(d, "trunc.img")
        with open(v["img"], "rb") as src, open(trunc, "wb") as dst:
            dst.write(src.read(8 * MIB))
        with self.assertRaises(f2fs.CorruptError) as cm:
            F2FSImage(trunc)
        self.assertIn("truncated", str(cm.exception))
        os.unlink(trunc)
        # primary superblock destroyed -> backup is used
        cp = os.path.join(d, "sb.img")
        shutil.copyfile(v["img"], cp)
        patch(cp, 1024, b"\0" * 3072)
        self.assertTrue(f2fs.probe(cp))
        with F2FSImage(cp) as fs:
            self.assertEqual(fs.sb.copy, 1)
            self.assertEqual(fs.fs_size, fs_size)
            self.assertEqual(len(list(fs.walk())), len(v["tree"].entries))
        # both superblocks destroyed
        patch(cp, 4096 + 1024, b"\0" * 3072)
        self.assertFalse(f2fs.probe(cp))
        with self.assertRaises(f2fs.NotF2FSError):
            F2FSImage(cp)
        os.unlink(cp)
        # both checkpoint packs destroyed
        cp = os.path.join(d, "cp.img")
        shutil.copyfile(v["img"], cp)
        patch(cp, cp_blkaddr * 4096, b"\0" * 4096)
        patch(cp, (cp_blkaddr + 512) * 4096, b"\0" * 4096)
        with self.assertRaises(f2fs.CorruptError) as cm:
            F2FSImage(cp)
        self.assertIn("checkpoint", str(cm.exception))
        os.unlink(cp)

    def test_sb_checksum_enforced(self):
        v = get_variant("rw_extra")
        d = os.path.join(TMP_BASE, "patched")
        os.makedirs(d, exist_ok=True)
        cp = os.path.join(d, "sbcrc.img")
        shutil.copyfile(v["img"], cp)
        patch(cp, 1024 + 124, "X".encode("utf-16-le"))     # change the label without fixing the crc
        with F2FSImage(cp) as fs:
            self.assertEqual(fs.sb.copy, 1, "primary sb must be rejected (crc), backup used")
        patch(cp, 4096 + 1024 + 124, "X".encode("utf-16-le"))
        with self.assertRaises(f2fs.CorruptError) as cm:
            F2FSImage(cp)
        self.assertIn("crc", str(cm.exception))
        os.unlink(cp)

    def test_inode_checksum(self):
        """Our inode checksum equals fsck.f2fs's: a corrupted one is caught by both."""
        v = get_variant("rw_extra")
        d = os.path.join(TMP_BASE, "patched")
        os.makedirs(d, exist_ok=True)
        cp = os.path.join(d, "ichk.img")
        shutil.copyfile(v["img"], cp)
        with F2FSImage(cp) as fs:
            ino = {p: i for p, _, i in fs.walk()}["bin/hello"]
            stored = ino.inode_checksum
        patch(cp, ino.blkaddr * 4096 + 368, struct.pack("<I", stored ^ 0x12345678))
        with self.assertRaises(f2fs.CorruptError) as cm:
            with F2FSImage(cp) as fs:
                list(fs.walk())
        self.assertIn("checksum", str(cm.exception))
        self.assertIn("0x%08x" % stored, str(cm.exception))        # the correct value is what we compute
        r = _run(["fsck.f2fs", "-f", "--dry-run", cp])
        self.assertIn("calculated one is: 0x%x" % stored, r.stdout + r.stderr)
        with F2FSImage(cp, verify_inode_checksums=False) as fs:
            list(fs.walk())                                         # opt-out works
        os.unlink(cp)

    def _inject_xattr(self, img, path, index, name: bytes, value: bytes):
        """Append an xattr entry to the inline xattr area of ``path``'s inode (fixing the inode
        checksum when the feature is on). Returns the nid."""
        with F2FSImage(img) as fs:
            ino = {p: i for p, _, i in fs.walk()}[path]
            raw = bytearray(fs._blk(ino.blkaddr))
            ix = ino.inline_xattr_addrs
            self.assertGreater(ix, 0)
            base = f2fs.I_NID_OFF - 4 * ix
            self.assertEqual(struct.unpack_from("<I", raw, base)[0], f2fs.F2FS_XATTR_MAGIC)
            off = base + 24
            while struct.unpack_from("<I", raw, off)[0] != 0:
                idx, nlen, vsize = struct.unpack_from("<BBH", raw, off)
                off += (4 + nlen + vsize + 3) & ~3
            entry = struct.pack("<BBH", index, len(name), len(value)) + name + value
            entry += b"\0" * (-len(entry) % 4)
            self.assertLessEqual(off + len(entry) + 4, f2fs.I_NID_OFF)
            raw[off:off + len(entry)] = entry
            if fs.feature & f2fs.F_INODE_CHKSUM:
                struct.pack_into("<I", raw, 368, fs._inode_checksum(raw, ino.nid, ino.generation))
            patch(img, ino.blkaddr * 4096, bytes(raw))
            return ino.nid

    def test_capability_and_other_xattrs(self):
        """security.capability (v2, v3, v1) and user.* xattrs read from the inline area; the
        injected inode still passes fsck.f2fs (checksum) and dump.f2fs -i shows the entry."""
        for variant in ("rw_plain", "rw_extra"):
            v = get_variant(variant)
            d = os.path.join(TMP_BASE, "patched")
            os.makedirs(d, exist_ok=True)
            cp = os.path.join(d, "caps_%s.img" % variant)
            shutil.copyfile(v["img"], cp)
            nid = self._inject_xattr(cp, "bin/hello", 6, b"capability", fc.encode_capabilities(0xC0))
            self._inject_xattr(cp, "bin/run-as", 6, b"capability", fc.encode_capabilities(0x1000000C0, version=3, rootid=7))
            self._inject_xattr(cp, "bin/setuid", 6, b"capability", fc.encode_capabilities(0x3, version=1))
            self._inject_xattr(cp, "bin/sgid", 1, b"pa", b"\x30\x82\x01\x00abc")
            self._inject_xattr(cp, "bin/sgid", 4, b"tr", b"")
            self._inject_xattr(cp, "sizes/f1", 6, b"capability", b"\x09\x00\x00\x00junk")   # undecodable
            with F2FSImage(cp) as fs:
                e = {p: e for p, e, _ in fs.walk()}
                self.assertEqual(e["bin/hello"].caps, 0xC0)
                self.assertEqual(e["bin/hello"].xattrs, {})
                self.assertEqual(e["bin/run-as"].caps, 0x1000000C0)
                self.assertEqual(e["bin/setuid"].caps, 0x3)
                self.assertEqual(e["bin/sgid"].caps, 0)
                self.assertEqual(e["bin/sgid"].xattrs, {"user.pa": b"\x30\x82\x01\x00abc", "trusted.tr": b""})
                self.assertEqual(e["sizes/f1"].caps, 0)
                self.assertEqual(e["sizes/f1"].xattrs, {"security.capability": b"\x09\x00\x00\x00junk"})
                self.assertEqual(e["bin/hello"].selinux, v["tree"].entries["bin/hello"].selinux)
                self.assertEqual(fs.info()["counts"]["with_caps"], 3)
                # fs_config regenerated from the manifest carries the caps
                cfg = fc.parse_fs_config(fc.write_fs_config([x for x in e.values()], "/vendor"))
                self.assertEqual(cfg["vendor/bin/hello"].caps, 0xC0)
            r = _run(["fsck.f2fs", "-f", "--dry-run", cp])
            self.assertNotIn("chksum", r.stdout + r.stderr)
            r = _run(["dump.f2fs", "-N", "-i", str(nid), cp], cwd=d)
            self.assertIn("e_name:capability", r.stdout + r.stderr)
            self.assertIn(fc.encode_capabilities(0xC0).hex().upper(), r.stdout + r.stderr)
            os.unlink(cp)

    def test_holes_new_addr_and_bad_addresses(self):
        """NULL_ADDR / NEW_ADDR blocks read as zeros (dump.f2fs -r agrees byte for byte),
        out-of-range addresses and COMPRESS_ADDR raise."""
        v = get_variant("rw_plain")
        tree = v["tree"]
        d = os.path.join(TMP_BASE, "patched")
        os.makedirs(d, exist_ok=True)
        cp = os.path.join(d, "holes.img")
        shutil.copyfile(v["img"], cp)
        with F2FSImage(cp) as fs:
            inos = {p: i for p, _, i in fs.walk()}
            f3 = inos["sizes/f12288"]                       # 3 data blocks in i_addr
            f65k = inos["sizes/f65536"]                     # 16 data blocks
            big = inos["big/thirteen_mib.bin"]
            runs = list(fs.block_runs(f3))
            self.assertEqual(sum(n for _, n in runs), 3)
            slot = f2fs.I_ADDR_OFF + 4 * (f3.addr_base + 1)
            slot65 = f2fs.I_ADDR_OFF + 4 * (f65k.addr_base + 5)
            bc = fs.block_count
            # and one address inside the direct node of the 13 MiB file
            first_direct = big.i_nid[0]
            _ver, _ino, dn_addr = fs.nat_lookup(first_direct)
        content = tree.content["sizes/f12288"]
        content65 = tree.content["sizes/f65536"]
        patch(cp, f3.blkaddr * 4096 + slot, struct.pack("<I", 0))                 # hole
        patch(cp, f65k.blkaddr * 4096 + slot65, struct.pack("<I", 0xFFFFFFFF))    # NEW_ADDR
        patch(cp, dn_addr * 4096 + 4 * 10, struct.pack("<I", 0))                  # hole in a direct node
        exp3 = content[:4096] + bytes(4096) + content[8192:]
        exp65 = content65[:5 * 4096] + bytes(4096) + content65[6 * 4096:]
        bigc = tree.content["big/thirteen_mib.bin"]
        off = (big.addrs_per_inode + 10) * 4096
        expbig = bigc[:off] + bytes(4096) + bigc[off + 4096:]
        with F2FSImage(cp) as fs:
            inos = {p: i for p, _, i in fs.walk()}
            self.assertEqual(b"".join(fs.read_file(inos["sizes/f12288"])), exp3)
            self.assertEqual(b"".join(fs.read_file(inos["sizes/f65536"])), exp65)
            self.assertEqual(fs.hash_file(inos["big/thirteen_mib.bin"]), sha256(expbig))
            runs = list(fs.block_runs(inos["sizes/f12288"]))
            self.assertEqual([n for _, n in runs], [1, 1, 1])
            self.assertEqual(runs[1][0], 0)
            dest = os.path.join(d, "holes_out")
            shutil.rmtree(dest, ignore_errors=True)
            man = {e.path: e for e in fs.extract(dest)}
            self.assertEqual(man["sizes/f12288"].sha256, sha256(exp3))
            self.assertEqual(man["big/thirteen_mib.bin"].sha256, sha256(expbig))
            with open(os.path.join(dest, "sizes/f12288"), "rb") as f:
                self.assertEqual(f.read(), exp3)
            with open(os.path.join(dest, "sizes/f65536"), "rb") as f:
                self.assertEqual(f.read(), exp65)
        dumped = dump_tree(cp, os.path.join(d, "holes_dump"))
        self.assertEqual(snapshot(dest), dumped)
        # out of range / compress marker
        patch(cp, f3.blkaddr * 4096 + slot, struct.pack("<I", bc + 5))
        with F2FSImage(cp) as fs:
            ino = {p: i for p, _, i in fs.walk()}["sizes/f12288"]
            with self.assertRaises(f2fs.BlockRangeError):
                b"".join(fs.read_file(ino))
            with self.assertRaises(f2fs.F2FSError):
                fs.extract(os.path.join(d, "bad_out"))
        patch(cp, f3.blkaddr * 4096 + slot, struct.pack("<I", 1))                  # below main_blkaddr
        with F2FSImage(cp) as fs:
            ino = {p: i for p, _, i in fs.walk()}["sizes/f12288"]
            with self.assertRaises(f2fs.BlockRangeError):
                b"".join(fs.read_file(ino))
        patch(cp, f3.blkaddr * 4096 + slot, struct.pack("<I", 0xFFFFFFFE))
        with F2FSImage(cp) as fs:
            ino = {p: i for p, _, i in fs.walk()}["sizes/f12288"]
            with self.assertRaises(f2fs.CompressionError):
                b"".join(fs.read_file(ino))
        shutil.rmtree(dest, ignore_errors=True)
        shutil.rmtree(os.path.join(d, "holes_dump"), ignore_errors=True)
        os.unlink(cp)

    def test_compression_and_encryption_flags(self):
        v = get_variant("rw_plain")
        d = os.path.join(TMP_BASE, "patched")
        os.makedirs(d, exist_ok=True)
        cp = os.path.join(d, "flags.img")
        shutil.copyfile(v["img"], cp)
        with F2FSImage(cp) as fs:
            ino = {p: i for p, _, i in fs.walk()}["sizes/f4096"]
        patch(cp, ino.blkaddr * 4096 + 80, struct.pack("<I", ino.flags | f2fs.F2FS_COMPR_FL))
        with F2FSImage(cp) as fs:
            with self.assertRaises(f2fs.CompressionError) as cm:
                list(fs.walk())
            self.assertIn("compress", str(cm.exception).lower())
        patch(cp, ino.blkaddr * 4096 + 80, struct.pack("<I", ino.flags))
        patch(cp, ino.blkaddr * 4096 + 2, bytes([ino.advise | f2fs.FADVISE_ENCRYPT_BIT]))
        with F2FSImage(cp) as fs:
            with self.assertRaises(f2fs.UnsupportedError) as cm:
                list(fs.walk())
            self.assertIn("encrypt", str(cm.exception))
        patch(cp, ino.blkaddr * 4096 + 2, bytes([ino.advise]))
        # the compression feature bit alone (no compressed inode) is readable; both sb copies
        with open(cp, "rb") as f:
            feat = struct.unpack_from("<I", f.read(8192), 1024 + 2180)[0]
        patch(cp, 1024 + 2180, struct.pack("<I", feat | 0x2000))
        patch(cp, 4096 + 1024 + 2180, struct.pack("<I", feat | 0x2000))
        with F2FSImage(cp) as fs:
            self.assertIn("compression", fs.features)
            self.assertEqual(len(list(fs.walk())), len(v["tree"].entries))
        os.unlink(cp)

    def test_nat_journal_overrides_nat_area(self):
        """A node relocated through a NAT journal entry is found by us and by dump.f2fs -n."""
        v = get_variant("rw_plain")
        d = os.path.join(TMP_BASE, "patched")
        os.makedirs(d, exist_ok=True)
        cp = os.path.join(d, "journal.img")
        shutil.copyfile(v["img"], cp)
        with F2FSImage(cp) as fs:
            ino = {p: i for p, _, i in fs.walk()}["sizes/f4097"]
            nid = ino.nid
            ver, nat_ino, addr = fs.nat_lookup(nid)
            self.assertEqual((nat_ino, addr), (nid, ino.blkaddr))
            free = fs.block_count - 1
            node = bytes(fs._blk(addr))
            sum_addr = fs.cp.start_blkaddr + fs.cp.cp_pack_start_sum
            joff = 0 if fs.cp.ckpt_flags & f2fs.CP_COMPACT_SUM_FLAG else f2fs.SUM_ENTRIES_SIZE
            self.assertEqual(struct.unpack_from("<H", fs._blk(sum_addr), joff)[0], 0)
        self.assertEqual(dump_nat(cp, nid)["blkaddr"], addr)
        patch(cp, free * 4096, node)
        patch(cp, addr * 4096, b"\0" * 4096)              # the old location is gone
        patch(cp, sum_addr * 4096 + joff, struct.pack("<H", 1) + struct.pack("<IBII", nid, ver, nid, free))
        self.assertEqual(dump_nat(cp, nid)["blkaddr"], free)
        with F2FSImage(cp) as fs:
            self.assertEqual(fs.cp.n_nats, 1)
            self.assertEqual(fs.cp.nat_journal, {nid: (ver, nid, free)})
            self.assertEqual(fs.nat_lookup(nid), (ver, nid, free))
            i2 = fs.read_inode(nid)
            self.assertEqual(i2.blkaddr, free)
            e = {p: e for p, e, _ in fs.walk()}["sizes/f4097"]
            self.assertEqual(fs.hash_file(i2), sha256(v["tree"].content["sizes/f4097"]))
            self.assertEqual(e.ino, nid)
        # too many journal entries -> corrupt
        patch(cp, sum_addr * 4096 + joff, struct.pack("<H", 39))
        with self.assertRaises(f2fs.CorruptError):
            F2FSImage(cp)
        os.unlink(cp)

    def test_nat_version_bitmap_selects_pack2(self):
        """Setting the NAT version bit of a NAT block (MSB-first, as f2fs_test_bit) makes both
        dump.f2fs -n (pack:2) and our reader use the second NAT copy."""
        v = get_variant("rw_plain")
        d = os.path.join(TMP_BASE, "patched")
        os.makedirs(d, exist_ok=True)
        cp = os.path.join(d, "natbitmap.img")
        shutil.copyfile(v["img"], cp)
        with F2FSImage(cp) as fs:
            ino = {p: i for p, _, i in fs.walk()}["sizes/f3489"]
            nid = ino.nid
            block_off = nid // f2fs.NAT_ENTRY_PER_BLOCK
            nat1 = fs.current_nat_addr(nid)
            self.assertEqual(nat1, fs.sb.nat_blkaddr + block_off)          # bitmap bit clear -> copy 1
            self.assertEqual(fs.cp.nat_bitmap[block_off >> 3], 0)
            free = fs.block_count - 1
            node = bytes(fs._blk(ino.blkaddr))
            natblk = bytearray(fs._blk(nat1))
            cp_start, total = fs.cp.start_blkaddr, fs.cp.cp_pack_total_block_count
            nat_off = fs.cp.nat_bitmap_offset
            cp_a = bytearray(fs._blk(cp_start))
            cp_b = bytearray(fs._blk(cp_start + total - 1))
            self.assertEqual(nat_off, 192 + fs.cp.sit_ver_bitmap_bytesize)   # cp_payload == 0 layout
        self.assertEqual(dump_nat(cp, nid), {"blkaddr": ino.blkaddr, "pack": 1, "ino": nid})
        struct.pack_into("<I", natblk, (nid % f2fs.NAT_ENTRY_PER_BLOCK) * 9 + 5, free)
        for blk in (cp_a, cp_b):
            blk[nat_off + (block_off >> 3)] |= 1 << (7 - (block_off & 7))
            recompute_cp_crc(blk)
        patch(cp, free * 4096, node)
        patch(cp, ino.blkaddr * 4096, b"\0" * 4096)
        patch(cp, (nat1 + 512) * 4096, bytes(natblk))
        patch(cp, cp_start * 4096, bytes(cp_a))
        patch(cp, (cp_start + total - 1) * 4096, bytes(cp_b))
        self.assertEqual(dump_nat(cp, nid), {"blkaddr": free, "pack": 2, "ino": nid})
        with F2FSImage(cp) as fs:
            self.assertEqual(fs.current_nat_addr(nid), nat1 + 512)
            self.assertEqual(fs.nat_lookup(nid)[2], free)
            self.assertEqual(fs.read_inode(nid).blkaddr, free)
            self.assertEqual(fs.hash_file(fs.read_inode(nid)), sha256(v["tree"].content["sizes/f3489"]))
            self.assertEqual(len(list(fs.walk())), len(v["tree"].entries))
        os.unlink(cp)

    def test_newer_checkpoint_pack_wins(self):
        """Pack 2 is chosen when its version is newer; a broken pack 2 falls back to pack 1."""
        v = get_variant("rw_plain")
        d = os.path.join(TMP_BASE, "patched")
        os.makedirs(d, exist_ok=True)
        cp = os.path.join(d, "packs.img")
        shutil.copyfile(v["img"], cp)
        with F2FSImage(cp) as fs:
            self.assertEqual(fs.cp.pack, 1)
            ver = fs.cp.checkpoint_ver
            cp_blkaddr = fs.sb.cp_blkaddr
            total = fs.cp.cp_pack_total_block_count
            pack1 = bytes(fs._mv[fs._delta + cp_blkaddr * 4096:fs._delta + (cp_blkaddr + total) * 4096])
            self.assertEqual(fs.cp.pack_versions, (ver, ver))     # sload leaves both packs valid, same version
        # build pack 2 = pack 1 with version + 1 in both cp copies
        p2 = bytearray(pack1)
        for off in (0, (total - 1) * 4096):
            struct.pack_into("<Q", p2, off, ver + 1)
            blk = bytearray(p2[off:off + 4096])
            recompute_cp_crc(blk)
            p2[off:off + 4096] = blk
        patch(cp, (cp_blkaddr + 512) * 4096, bytes(p2))
        with F2FSImage(cp) as fs:
            self.assertEqual(fs.cp.pack, 2)
            self.assertEqual(fs.cp.checkpoint_ver, ver + 1)
            self.assertEqual(fs.cp.pack_versions, (ver, ver + 1))
            self.assertEqual(len(list(fs.walk())), len(v["tree"].entries))
        # pack 2's closing copy broken -> pack 1 again
        patch(cp, (cp_blkaddr + 512 + total - 1) * 4096 + 8, b"\xff" * 8)
        with F2FSImage(cp) as fs:
            self.assertEqual(fs.cp.pack, 1)
        os.unlink(cp)

    def test_closed_image(self):
        v = get_variant("rw_plain")
        fs = F2FSImage(v["img"])
        ino = fs.read_inode(3)
        fs.close()
        fs.close()
        with self.assertRaises(f2fs.F2FSError):
            fs.readdir(ino)
        with self.assertRaises(f2fs.F2FSError):
            list(fs.walk())


# --------------------------------------------------------------------------- stock images

@unittest.skipUnless(os.path.exists(STOCK_VENDOR) and os.path.isdir(STOCKDUMP_VENDOR),
                     "stock/super/vendor.img or work/stockdump/vendor missing")
class StockVendorTest(unittest.TestCase):
    """DESIGN §7.2: our extraction of stock vendor.img equals the dump.f2fs -r reference."""

    def test_facts(self):
        with F2FSImage(STOCK_VENDOR) as fs:
            self.assertEqual(fs.features, frozenset({"ro"}))
            self.assertEqual(fs.feature, 0x4000)
            self.assertEqual(fs.label, "vendor")
            self.assertEqual(fs.fs_size, 429916160)
            self.assertEqual(fs.block_size, 4096)
            self.assertEqual(fs.cp.ckpt_flags, 0x81)
            self.assertEqual(fs.cp.flag_names, ["unmount", "nat_bits"])
            self.assertEqual(fs.cp.n_nats, 0)
            self.assertEqual(fs.cp.pack, 1)
            self.assertEqual(fs.sb.segment_count_ssa, 0)
            self.assertEqual(fs.sb.cp_payload, 0)
            self.assertEqual(fs.sb.init_version, "6.8.0-52-generic")
            root = fs.read_inode(3)
            self.assertEqual((root.mode, root.uid, root.gid, root.inline), (0o40755, 0, 0, 0))
            self.assertEqual(fs.xattrs(root), [("security.selinux", b"u:object_r:vendor_file:s0")])
            info = fs.info()
            json.dumps(info)
            self.assertEqual(info["counts"]["reg"], 1735)
            self.assertEqual(info["counts"]["dir"], 68)
            self.assertEqual(info["counts"]["lnk"], 186)
            self.assertEqual(info["counts"]["hardlink_paths"], 0)
            self.assertEqual(info["counts"]["with_caps"], 0)
            self.assertEqual(info["counts"]["with_other_xattrs"], 6)        # user.pa
            self.assertEqual(info["root"]["selinux"], "u:object_r:vendor_file:s0")
            self.assertEqual(info["root"]["mode"], 0o755)
            self.assertTrue(info["mtime_uniform"])
            self.assertNotEqual(info["mtime_hint"], info["root"]["mtime"])  # root from make_f2fs -T, files from sload -T
            paths = [p for p, _, _ in fs.walk()]
            self.assertEqual(paths, sorted(paths))
            self.assertIn("etc/fstab.mt6768", paths)
            self.assertIn("odm", paths)
            by = {p: e for p, e, _ in fs.walk()}
            self.assertEqual(by["odm"].target, "/odm")
            self.assertEqual(by["etc/fstab.mt6768"].selinux, "u:object_r:vendor_configs_file:s0")
            inos = {p: i for p, _, i in fs.walk()}
            self.assertTrue(all(i.has_inline_data for p, i in inos.items() if by[p].type == "lnk"))
            self.assertTrue(all(i.extra_isize == 0 for i in inos.values()))
            self.assertFalse(any(i.has_inline_dentry for i in inos.values()))

    def test_extract_equals_stockdump(self):
        dest = os.path.join(TMP_BASE, "stock-vendor")
        shutil.rmtree(dest, ignore_errors=True)
        t0 = time.time()
        with F2FSImage(STOCK_VENDOR) as fs:
            items = list(fs.walk())
            t1 = time.time()
            man = fs.extract(dest, manifest_path=os.path.join(TMP_BASE, "stock-vendor.manifest.tsv"))
            t2 = time.time()
        TIMINGS.append("stock vendor: walk %.1fs extract %.1fs (%d entries)" % (t1 - t0, t2 - t1, len(items)))
        self.assertLess(t2 - t0, 180, "vendor walk+extract must stay well under the 2 minute target")
        counts = {}
        for e in man:
            counts[e.type] = counts.get(e.type, 0) + 1
        self.assertEqual(counts, {"reg": 1735, "dir": 68, "lnk": 186})
        for e in man:
            if e.type == "reg":
                self.assertIsNotNone(e.sha256)
        ours = snapshot(dest)
        ref = snapshot(STOCKDUMP_VENDOR, skip_top=("lost_found",))     # dump.f2fs's nested duplicate
        self.assertEqual(len(ref), 1988)
        self.assertEqual(ours, ref)
        for e in man:                                                   # a few spot checks on bytes
            if e.type == "reg" and e.path in ("build.prop", "recovery-from-boot.p", "bin/toybox_vendor"):
                with open(os.path.join(STOCKDUMP_VENDOR, e.path), "rb") as f:
                    self.assertEqual(sha256(f.read()), e.sha256)
        back = fc.read_manifest(os.path.join(TMP_BASE, "stock-vendor.manifest.tsv"))
        self.assertEqual(back, man)
        if not KEEP:
            shutil.rmtree(dest, ignore_errors=True)


@unittest.skipUnless(os.path.exists(STOCK_SYSTEM), "stock/super/system.img missing")
class StockSystemTest(unittest.TestCase):
    def test_walk_caps_and_xattrs(self):
        t0 = time.time()
        with F2FSImage(STOCK_SYSTEM) as fs:
            self.assertEqual(fs.label, "/")
            self.assertEqual(fs.fs_size, 3789553664)
            items = list(fs.walk())
            TIMINGS.append("stock system: walk %.1fs (%d entries)" % (time.time() - t0, len(items)))
            by = {p: e for p, e, _ in items}
            counts = {}
            for e in by.values():
                counts[e.type] = counts.get(e.type, 0) + 1
            self.assertEqual(counts, {"reg": 3811, "dir": 769, "lnk": 264})
            self.assertEqual(by["system/bin/run-as"].caps, 0xC0)
            self.assertEqual(by["system/bin/simpleperf_app_runner"].caps, 0xC0)
            self.assertEqual(sorted(p for p, e in by.items() if e.caps), ["system/bin/run-as", "system/bin/simpleperf_app_runner"])
            self.assertEqual(sorted(p for p, e in by.items() if e.xattrs),
                             ["system/bin/vold", "system/framework/oat/arm/services.odex", "system/framework/services.jar"])
            self.assertEqual(set(by["system/bin/vold"].xattrs), {"user.pa"})
            self.assertEqual(by[""].selinux, "u:object_r:rootfs:s0")
            self.assertEqual(by["system/bin/run-as"].selinux, "u:object_r:runas_exec:s0")
            self.assertEqual(by["system/bin/run-as"].mode, 0o750)
            self.assertEqual((by["system/bin/run-as"].uid, by["system/bin/run-as"].gid), (0, 2000))
            self.assertEqual(fs.info()["counts"]["with_caps"], 2)

    @unittest.skipUnless(SLOW, "set SUPERKIT_SLOW=1 (extracts 3.8 GB)")
    def test_extract_system(self):
        dest = os.path.join(TMP_BASE, "stock-system")
        shutil.rmtree(dest, ignore_errors=True)
        t0 = time.time()
        with F2FSImage(STOCK_SYSTEM) as fs:
            man = fs.extract(dest, manifest_path=os.path.join(TMP_BASE, "stock-system.manifest.tsv"))
            t1 = time.time()
            TIMINGS.append("stock system: walk+extract %.1fs" % (t1 - t0))
            self.assertLess(t1 - t0, 900)
            self.assertEqual(len(man), 4844)
            # bytes on disk equal what the reader hashes; sizes match
            by = {p: i for p, _, i in fs.walk()}
            for e in man:
                if e.type == "reg" and e.size > 50 * MIB:
                    with open(os.path.join(dest, e.path), "rb") as f:
                        self.assertEqual(sha256(f.read()), e.sha256)
                    self.assertEqual(os.path.getsize(os.path.join(dest, e.path)), e.size)
            self.assertEqual(sum(e.size for e in man if e.type == "reg"), fs.info()["data_bytes"])
        shutil.rmtree(dest, ignore_errors=True)


@unittest.skipUnless(os.path.exists(STOCK_ODM), "stock/super/odm.img missing")
class StockOdmTest(unittest.TestCase):
    def test_odm(self):
        with F2FSImage(STOCK_ODM) as fs:
            self.assertEqual(fs.label, "odm")
            self.assertEqual(fs.fs_size, 20971520)
            man = fs.extract(os.path.join(TMP_BASE, "stock-odm"))
            self.assertEqual(len(man), 43)
            self.assertEqual(man[0].selinux, "u:object_r:vendor_file:s0")
            self.assertTrue(f2fs.probe(STOCK_ODM))
        shutil.rmtree(os.path.join(TMP_BASE, "stock-odm"), ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
