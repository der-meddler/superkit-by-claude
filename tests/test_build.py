"""Tests for xattrw (in-place xattr rewrite), build (partition + super) and odin.

Fixtures are tiny synthetic images built with make_f2fs/sload_f2fs under work/tmp/build-tests/.
"""
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from superkit import build, fsconfig, odin, xattrw  # noqa: E402
from superkit.f2fs import F2FSImage  # noqa: E402
from superkit.lp import SuperImage  # noqa: E402

PROJ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP_ROOT = os.path.join(PROJ, "work", "tmp", "build-tests")
MIB = 1 << 20
PA = bytes(range(256)) * 2 + b"\x01\x02"  # 514 bytes: needs an xattr node like Samsung's user.pa


def have_tools():
    return all(shutil.which(t) for t in ("make_f2fs", "sload_f2fs", "dump.f2fs", "fsck.f2fs", "lpmake", "img2simg", "lz4"))


def entry(path, type_, mode, uid=0, gid=0, selinux="u:object_r:vendor_file:s0", **kw):
    return fsconfig.ManifestEntry(path=path, type=type_, mode=mode, uid=uid, gid=gid, selinux=selinux, **kw)


def make_tree(root):
    """A small vendor-like tree; returns the manifest entries describing it."""
    os.makedirs(os.path.join(root, "bin", "hw"), exist_ok=True)
    os.makedirs(os.path.join(root, "etc"), exist_ok=True)
    files = {
        "bin/plain": b"#!/system/bin/sh\necho plain\n",
        "bin/caps": b"\x7fELF" + b"c" * 5000,
        "bin/hw/pa-service": b"\x7fELF" + b"p" * (3 * MIB + 123),
        "etc/cfg.txt": b"key=value\n",
        "etc/big.bin": bytes(range(256)) * 4096 * 4,     # 4 MiB -> direct node
    }
    for rel, data in files.items():
        with open(os.path.join(root, rel), "wb") as f:
            f.write(data)
    os.symlink("/vendor/bin/plain", os.path.join(root, "bin", "link"))
    ents = [
        entry("", "dir", 0o755, nlink=4),
        entry("bin", "dir", 0o755, gid=2000, nlink=3),
        entry("bin/hw", "dir", 0o755, gid=2000, nlink=2),
        entry("bin/plain", "reg", 0o755, gid=2000, selinux="u:object_r:vendor_shell_exec:s0",
              size=len(files["bin/plain"]), sha256=fsconfig_sha(files["bin/plain"])),
        entry("bin/caps", "reg", 0o750, gid=2000, selinux="u:object_r:caps_exec:s0", caps=0xC0,
              size=len(files["bin/caps"]), sha256=fsconfig_sha(files["bin/caps"])),
        entry("bin/hw/pa-service", "reg", 0o755, gid=2000, selinux="u:object_r:hal_pa_default_exec:s0",
              xattrs={"user.pa": PA}, size=len(files["bin/hw/pa-service"]),
              sha256=fsconfig_sha(files["bin/hw/pa-service"])),
        entry("bin/link", "lnk", 0o777, selinux="u:object_r:vendor_file:s0", target="/vendor/bin/plain",
              size=len("/vendor/bin/plain")),
        entry("etc", "dir", 0o755, nlink=2, selinux="u:object_r:vendor_configs_file:s0"),
        entry("etc/cfg.txt", "reg", 0o644, selinux="u:object_r:vendor_configs_file:s0",
              size=len(files["etc/cfg.txt"]), sha256=fsconfig_sha(files["etc/cfg.txt"])),
        entry("etc/big.bin", "reg", 0o644, selinux="u:object_r:vendor_configs_file:s0",
              size=len(files["etc/big.bin"]), sha256=fsconfig_sha(files["etc/big.bin"])),
    ]
    for e in ents:
        e.mtime = 1609459200
    return ents


def fsconfig_sha(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


def make_workdir(workdir, part="vendor", ro_stock=True):
    """A DESIGN §4.1 workdir with one partition and a super.json from a tiny lpmake super."""
    part_dir = os.path.join(workdir, part)
    root = os.path.join(part_dir, "root")
    os.makedirs(root, exist_ok=True)
    ents = make_tree(root)
    fsconfig.write_manifest(os.path.join(part_dir, "manifest.tsv"), ents)
    mp = "/" + part
    with open(os.path.join(part_dir, "fs_config"), "w") as f:
        f.write(fsconfig.write_fs_config(ents, mp))
    with open(os.path.join(part_dir, "file_contexts"), "w") as f:
        f.write(fsconfig.write_file_contexts(ents, mp))
    meta = {"partition": part, "mount_point": mp,
            "f2fs": {"uuid": "f3cc4d5b-560a-4f72-b85e-5b34480670a9", "label": part,
                     "features": ["ro"] if ro_stock else [], "fs_size": 0,
                     "root": {"uid": 0, "gid": 0, "mode": 0o755, "mtime": 1770282435},
                     "mtime_hint": 1609459200}}
    with open(os.path.join(part_dir, "meta.json"), "w") as f:
        json.dump(meta, f)
    return ents


class XattrwUnitTests(unittest.TestCase):
    def test_pack_and_sizes(self):
        buf = xattrw.pack_xattrs([(6, b"selinux", b"u:object_r:x:s0")])
        self.assertEqual(len(buf), 24 + ((4 + 7 + 15 + 3) & ~3) + 4)
        self.assertEqual(buf[:4], (0xF2F52011).to_bytes(4, "little"))
        self.assertEqual(buf[-4:], b"\0\0\0\0")

    def test_split_names(self):
        self.assertEqual(xattrw.split_xattr_name("user.pa"), (1, b"pa"))
        self.assertEqual(xattrw.split_xattr_name("security.capability"), (6, b"capability"))
        self.assertEqual(xattrw.split_xattr_name("trusted.x"), (4, b"x"))
        with self.assertRaises(Exception):
            xattrw.split_xattr_name("bogus.name")

    def test_needs_node_and_padding(self):
        plain = entry("a", "reg", 0o644)
        caps = entry("b", "reg", 0o755, caps=0xC0)
        pa = entry("c", "reg", 0o755, xattrs={"user.pa": PA})
        self.assertFalse(xattrw.needs_xattr_node(plain))
        self.assertFalse(xattrw.needs_xattr_node(caps))
        self.assertTrue(xattrw.needs_xattr_node(pa))
        self.assertFalse(xattrw.needs_rewrite(plain))
        self.assertTrue(xattrw.needs_rewrite(caps))
        padded = xattrw.pad_label("u:object_r:vendor_file:s0")
        self.assertTrue(len(xattrw.pack_xattrs([(6, b"selinux", padded.encode())])) > 200)
        self.assertEqual(xattrw.unpad_label(padded), "u:object_r:vendor_file:s0")


@unittest.skipUnless(have_tools(), "f2fs/lp tools missing")
class BuildPartitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.makedirs(TMP_ROOT, exist_ok=True)
        cls.tmp = tempfile.mkdtemp(prefix="part-", dir=TMP_ROOT)
        cls.workdir = os.path.join(cls.tmp, "work")
        cls.ents = make_workdir(cls.workdir)

    @classmethod
    def tearDownClass(cls):
        if not os.environ.get("SUPERKIT_KEEP_TMP"):
            shutil.rmtree(cls.tmp, ignore_errors=True)

    def _check_image(self, image, ro):
        with F2FSImage(image) as img:
            self.assertEqual(set(img.features), {"ro"} if ro else set())
            have = {p: e for p, e, _ in img.walk()}
            for p, e, inode in img.walk():
                if p == "bin/hw/pa-service":
                    self.assertNotEqual(inode.xattr_nid, 0, "pa-service should own an xattr node")
        want = {e.path: e for e in self.ents}
        for path, w in want.items():
            h = have[path]
            self.assertEqual((h.mode, h.uid, h.gid, h.type), (w.mode, w.uid, w.gid, w.type), path)
            self.assertEqual(h.selinux, w.selinux, path)
            self.assertEqual(h.caps, w.caps, path)
            self.assertEqual(h.xattrs, w.xattrs, path)
            if w.type == "lnk":
                self.assertEqual(h.target, w.target)
        self.assertEqual(set(have) - set(want) - {"lost_found"}, set())
        # the capability is visible to dump.f2fs too
        with F2FSImage(image) as img:
            nid = next(i.nid for p, _e, i in img.walk() if p == "bin/caps")
        out = subprocess.run(["dump.f2fs", "-N", "-i", str(nid), image], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, cwd=self.tmp).stdout.decode(errors="replace")
        self.assertIn("e_name:capability", out)
        rc = subprocess.run(["fsck.f2fs", "--dry-run", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        self.assertEqual(rc, 0, "fsck.f2fs not clean")

    def test_build_rw(self):
        cfg = build.load_repack_config(None)
        out = os.path.join(self.tmp, "out-rw")
        r = build.build_partition(self.workdir, "vendor", out, cfg)
        self.assertEqual(r.features, [])
        self.assertGreaterEqual(r.size, build.MIN_RW_IMAGE)
        self.assertIn("bin/caps", r.fixups)
        self.assertIn("bin/hw/pa-service", r.fixups)
        self.assertTrue(r.fsck_ok)
        self._check_image(r.image, ro=False)
        # content survives: sha256 of extracted files equals the manifest
        with F2FSImage(r.image) as img:
            ext = img.extract(os.path.join(self.tmp, "ext-rw"))
        got = {e.path: e.sha256 for e in ext if e.type == "reg"}
        for e in self.ents:
            if e.type == "reg":
                self.assertEqual(got[e.path], e.sha256, e.path)

    def test_build_ro(self):
        cfg = build.load_repack_config(None)
        cfg["partition"]["vendor"] = {"ro": True}
        out = os.path.join(self.tmp, "out-ro")
        r = build.build_partition(self.workdir, "vendor", out, cfg)
        self.assertEqual(r.features, ["ro"])
        self._check_image(r.image, ro=True)

    def test_sizing_helpers(self):
        est = build.estimate_content(self.ents)
        self.assertGreater(est.data_blocks, 1700)   # ~7 MiB of data
        self.assertEqual(est.xattr_nodes, 1)
        pcfg = build.partition_config(build.load_repack_config(None), "vendor")
        small_rw = build.initial_size(1 * MIB, False, pcfg)
        self.assertTrue(build.MIN_RW_IMAGE <= small_rw <= 56 * MIB, small_rw)   # measured need: 52 MiB
        small_ro = build.initial_size(1 * MIB, True, pcfg)
        self.assertTrue(build.MIN_RO_IMAGE <= small_ro <= 40 * MIB, small_ro)
        big = build.initial_size(3500 * MIB, False, pcfg)
        self.assertTrue(3600 * MIB < big < 3800 * MIB, big)
        self.assertEqual(build.parse_size("32M"), 32 * MIB)
        self.assertEqual(build.parse_size("1.5G"), int(1.5 * (1 << 30)))

    def test_config_file(self):
        p = os.path.join(self.tmp, "repack.toml")
        with open(p, "w") as f:
            f.write('[defaults]\nro = false\nslack_percent = 5\n[partition.odm]\nro = true\n')
        cfg = build.load_repack_config(p)
        self.assertTrue(build.partition_config(cfg, "odm")["ro"])
        self.assertFalse(build.partition_config(cfg, "vendor")["ro"])
        self.assertEqual(build.partition_config(cfg, "vendor")["slack_percent"], 5)
        with open(p, "w") as f:
            f.write('[defaults]\nbogus = 1\n')
        with self.assertRaises(build.BuildError):
            build.load_repack_config(p)


@unittest.skipUnless(have_tools(), "f2fs/lp tools missing")
class BuildSuperAndOdinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.makedirs(TMP_ROOT, exist_ok=True)
        cls.tmp = tempfile.mkdtemp(prefix="super-", dir=TMP_ROOT)
        cls.workdir = os.path.join(cls.tmp, "work")
        make_workdir(cls.workdir, "vendor")
        make_workdir(cls.workdir, "odm")
        # a stock-like super: two readonly partitions, 2 slots, 1 MiB alignment
        imgs = []
        for name in ("vendor", "odm"):
            p = os.path.join(cls.tmp, name + ".stock.img")
            with open(p, "wb") as f:
                f.truncate(27 * MIB)
            subprocess.run(["make_f2fs", "-f", "-O", "ro", "-R", "0:0", p], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            imgs.append(p)
        cls.stock_super = os.path.join(cls.tmp, "super.raw")
        cmd = ["lpmake", "--metadata-size", "65536", "--metadata-slots", "2", "--super-name", "super",
               "--block-size", "4096", "--device", "super:%d:1048576:0" % (256 * MIB),
               "--group", "main:%d" % (252 * MIB)]
        for name, p in zip(("vendor", "odm"), imgs):
            cmd += ["--partition", "%s:readonly:%d:main" % (name, 27 * MIB), "--image", "%s=%s" % (name, p)]
        cmd += ["--output", cls.stock_super]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        SuperImage(cls.stock_super).save_json(os.path.join(cls.workdir, "super.json"))

    @classmethod
    def tearDownClass(cls):
        if not os.environ.get("SUPERKIT_KEEP_TMP"):
            shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_super_round_trip_and_odin(self):
        cfg = build.load_repack_config(None)
        cfg["partition"]["odm"] = {"ro": True}
        out = os.path.join(self.tmp, "out")
        for name in ("vendor", "odm"):
            build.build_partition(self.workdir, name, out, cfg)
        res = build.build_super(self.workdir, out, cfg)
        new = SuperImage(res["super"])
        old = SuperImage(self.stock_super)
        self.assertEqual(new.geometry.metadata_slot_count, 2)
        self.assertEqual(new.block_device.size, old.block_device.size)
        self.assertEqual(new.partition_names, old.partition_names)
        self.assertFalse(new.partition("vendor").readonly)
        self.assertTrue(new.partition("odm").readonly)
        off, length = new.partition_extent_ranges("vendor")[0]
        with F2FSImage(res["super"], off, length) as img:
            self.assertEqual(set(img.features), set())
            self.assertIn("bin/caps", {p for p, _e, _i in img.walk()})
        # capacity failure is reported, not silently ignored
        cfg2 = build.load_repack_config(None)
        huge = os.path.join(out, "vendor.img")
        size = os.path.getsize(huge)
        with open(huge, "r+b") as f:
            f.truncate(300 * MIB)
        try:
            with self.assertRaises(build.BuildError):
                build.build_super(self.workdir, out, cfg2, output=os.path.join(out, "super2.img"))
        finally:
            with open(huge, "r+b") as f:
                f.truncate(size)
        # odin packaging
        odir = os.path.join(self.tmp, "odin")
        vb_src = os.path.join(PROJ, "stock", "BL", "vbmeta.img")
        pk = odin.pack_odin(res["super"], odir, vbmeta_stock=vb_src if os.path.exists(vb_src) else None,
                            name="test", keep_sparse=True)
        self.assertTrue(os.path.exists(pk["super_lz4"]))
        subprocess.run(["lz4", "-t", pk["super_lz4"]], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        back = os.path.join(odir, "back.sparse.img")
        subprocess.run(["lz4", "-d", "-f", pk["super_lz4"], back], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        raw = os.path.join(odir, "back.raw")
        subprocess.run(["simg2img", back, raw], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.assertEqual(SuperImage(raw).partition_names, new.partition_names)
        with open(pk["ap_tar"], "rb") as f:
            data = f.read()
        trailer_len = 32 + 2 + len("AP_superkit_test.tar") + 1
        trailer = data[-trailer_len:].decode()
        self.assertRegex(trailer, r"^[0-9a-f]{32}  AP_superkit_test\.tar\n$")
        names = tarfile.open(fileobj=__import__("io").BytesIO(data[: -len(trailer)])).getnames()
        self.assertIn("super.img.lz4", names)
        if pk.get("vbmeta"):
            self.assertIn("vbmeta.img.lz4", names)
            self.assertEqual(pk["vbmeta_flags"], 3)


if __name__ == "__main__":
    unittest.main()
