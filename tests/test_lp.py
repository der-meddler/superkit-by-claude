"""Tests for superkit.lp: stock super.raw vs lpdump, synthetic lpmake round trips, capacity rules."""

import hashlib
import os
import shutil
import subprocess
import unittest

from superkit import lp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STOCK_RAW = os.path.join(ROOT, "stock", "AP", "super.raw")
STOCK_SPARSE = os.path.join(ROOT, "stock", "AP", "super.img")
STOCK_PARTS = os.path.join(ROOT, "stock", "super")
TMP = os.path.join(ROOT, "work", "tmp", "lp-tests")
SLOW = os.environ.get("SUPERKIT_SLOW") == "1"
MIB = 1 << 20

HAVE_LPDUMP = shutil.which("lpdump") is not None
HAVE_LPMAKE = shutil.which("lpmake") is not None
HAVE_LPUNPACK = shutil.which("lpunpack") is not None
HAVE_SIMG2IMG = shutil.which("simg2img") is not None


def run(*args: str) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def lpdump_slots(path: str, all_slots: bool = False) -> list:
    args = ["lpdump"] + (["-a"] if all_slots else []) + [path]
    return lp.parse_lpdump_text(run(*args))


def read_at(path: str, offset: int, length: int) -> bytes:
    with open(path, "rb") as f:
        f.seek(offset)
        return f.read(length)


def assert_matches_lpdump(tc: unittest.TestCase, img: lp.SuperImage, dump: dict) -> None:
    """Compare every field lpdump prints with our parse of the same slot."""
    tc.assertEqual(img.header.version, dump["version"])
    tc.assertEqual(img.header.metadata_size, dump["metadata_size"])
    tc.assertEqual(img.geometry.metadata_max_size, dump["metadata_max_size"])
    tc.assertEqual(img.geometry.metadata_slot_count, dump["metadata_slot_count"])
    tc.assertEqual(set(img.header.flag_names), dump["header_flags"])
    tc.assertEqual([p.name for p in img.partitions], [p["name"] for p in dump["partitions"]])
    for ours, theirs in zip(img.partitions, dump["partitions"]):
        tc.assertEqual(ours.group, theirs["group"], ours.name)
        tc.assertEqual(ours.attribute_names, theirs["attributes"], ours.name)
        tc.assertEqual(len(ours.extents), len(theirs["extents"]), ours.name)
        first = 0
        for e, d in zip(ours.extents, theirs["extents"]):
            tc.assertEqual(d["first"], first)
            tc.assertEqual(d["last"], first + e.num_sectors - 1)
            tc.assertEqual(d["type"], e.target_type_name)
            if e.is_linear:
                tc.assertEqual(d["device"], img.block_devices[e.target_source].partition_name)
                tc.assertEqual(d["start"], e.target_data)
            first += e.num_sectors
    tc.assertEqual(len(img.block_devices), len(dump["block_devices"]))
    for b, d in zip(img.block_devices, dump["block_devices"]):
        tc.assertEqual(b.partition_name, d["partition_name"])
        tc.assertEqual(b.first_logical_sector, d["first_sector"])
        tc.assertEqual(b.size, d["size"])
        tc.assertEqual(set(b.flag_names), d["flags"])
    tc.assertEqual([g.name for g in img.groups], [g["name"] for g in dump["groups"]])
    for g, d in zip(img.groups, dump["groups"]):
        tc.assertEqual(g.maximum_size, d["maximum_size"])
        tc.assertEqual(set(g.flag_names), d["flags"])


@unittest.skipUnless(os.path.exists(STOCK_RAW), "stock/AP/super.raw not present")
class TestStockSuper(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.makedirs(TMP, exist_ok=True)
        cls.img = lp.SuperImage(STOCK_RAW)

    def test_layout_and_geometry(self):
        img = self.img
        self.assertEqual(img.layout, "super")
        self.assertEqual(img.geometry_offset, 4096)
        self.assertTrue(img.geometry_backup_identical)
        self.assertTrue(img.geometry.checksum_ok)
        self.assertEqual((img.geometry.metadata_max_size, img.geometry.metadata_slot_count,
                          img.geometry.logical_block_size), (65536, 2, 4096))
        self.assertEqual(img.geometry.metadata_region_end, 274432)
        self.assertEqual(img.size, 6417285120)

    def test_header(self):
        h = self.img.header
        self.assertEqual((h.major_version, h.minor_version, h.header_size, h.tables_size), (10, 0, 128, 540))
        self.assertIsNone(h.flags)
        self.assertEqual(h.flag_names, [])
        self.assertTrue(h.header_checksum_ok)
        self.assertTrue(h.tables_checksum_ok)
        self.assertEqual(h.descriptors["partitions"].to_dict(), {"offset": 0, "num_entries": 5, "entry_size": 52})
        self.assertEqual(h.descriptors["extents"].to_dict(), {"offset": 260, "num_entries": 5, "entry_size": 24})
        self.assertEqual(h.descriptors["groups"].to_dict(), {"offset": 380, "num_entries": 2, "entry_size": 48})
        self.assertEqual(h.descriptors["block_devices"].to_dict(), {"offset": 476, "num_entries": 1, "entry_size": 64})

    def test_all_four_copies_agree(self):
        img = self.img
        self.assertEqual(len(img.slots), 4)
        self.assertEqual([(s.index, s.kind, s.offset) for s in img.slots],
                         [(0, "primary", 12288), (1, "primary", 77824), (0, "backup", 143360), (1, "backup", 208896)])
        self.assertTrue(all(s.ok for s in img.slots))
        self.assertTrue(img.slots_agree)
        self.assertEqual((img.slot, img.slot_source), (0, "primary"))
        other = lp.SuperImage(STOCK_RAW, slot=1)
        self.assertEqual(other.metadata_dict(), img.metadata_dict())
        self.assertEqual(other.slot, 1)

    def test_partitions_match_design_facts(self):
        img = self.img
        expect = {  # name: (num_sectors, start_sector, size)
            "system": (7520304, 2048, 3850395648),
            "odm": (41776, 7524352, 21389312),
            "product": (2780160, 7567360, 1423441920),
            "system_ext": (520384, 10348544, 266436608),
            "vendor": (853312, 10870784, 436895744),
        }
        self.assertEqual(img.partition_names, list(expect))
        for p in img.partitions:
            ns, start, size = expect[p.name]
            self.assertEqual(p.attributes, lp.ATTR_READONLY)
            self.assertEqual(p.attribute_names, {"readonly"})
            self.assertTrue(p.readonly)
            self.assertEqual(p.group, "main")
            self.assertEqual(p.group_index, 1)
            self.assertEqual(len(p.extents), 1)
            e = p.extents[0]
            self.assertEqual((e.num_sectors, e.target_type, e.target_data, e.target_source), (ns, 0, start, 0))
            self.assertEqual(p.size, size)
            self.assertEqual(e.start_byte % MIB, 0)
            self.assertEqual(img.partition_extent_ranges(p.name), [(start * 512, size)])
        self.assertEqual([(g.name, g.flags, g.maximum_size) for g in img.groups],
                         [("default", 0, 0), ("main", 0, 6413090816)])
        self.assertEqual(img.block_devices[0].to_dict(), {
            "first_logical_sector": 2048, "alignment": 1048576, "alignment_offset": 0, "size": 6417285120,
            "partition_name": "super", "flags": 0, "flag_names": []})

    @unittest.skipUnless(HAVE_LPDUMP, "lpdump not on PATH")
    def test_matches_lpdump(self):
        dumps = lpdump_slots(STOCK_RAW)
        self.assertEqual(len(dumps), 1)
        assert_matches_lpdump(self, self.img, dumps[0])

    @unittest.skipUnless(HAVE_LPDUMP, "lpdump not on PATH")
    def test_matches_lpdump_every_slot(self):
        dumps = lpdump_slots(STOCK_RAW, all_slots=True)
        self.assertEqual([d["slot"] for d in dumps], [0, 1])
        for d in dumps:
            assert_matches_lpdump(self, lp.SuperImage(STOCK_RAW, slot=d["slot"]), d)
        self.assertEqual(int(run("lpdump", "-d", STOCK_RAW).strip()), 1048576)

    @unittest.skipUnless(os.path.isdir(STOCK_PARTS), "stock/super not present")
    def test_extent_ranges_match_lpunpack_output(self):
        for p in self.img.partitions:
            ref = os.path.join(STOCK_PARTS, p.name + ".img")
            if not os.path.exists(ref):
                self.skipTest(f"{ref} missing")
            ranges = self.img.partition_extent_ranges(p.name)
            self.assertEqual(len(ranges), 1)
            off, length = ranges[0]
            self.assertEqual(length, os.path.getsize(ref), p.name)
            self.assertEqual(read_at(STOCK_RAW, off, MIB), read_at(ref, 0, MIB), p.name)
            self.assertEqual(read_at(STOCK_RAW, off + length - MIB, MIB), read_at(ref, length - MIB, MIB), p.name)

    @unittest.skipUnless(os.path.exists(os.path.join(STOCK_PARTS, "odm.img")), "stock/super/odm.img not present")
    def test_extract_partition_odm(self):
        dest = os.path.join(TMP, "odm_extracted.img")
        n = self.img.extract_partition("odm", dest, chunk_size=1 << 20)
        ref = os.path.join(STOCK_PARTS, "odm.img")
        self.assertEqual(n, os.path.getsize(ref))
        self.assertEqual(os.path.getsize(dest), os.path.getsize(ref))
        with open(dest, "rb") as a, open(ref, "rb") as b:
            self.assertEqual(hashlib.sha256(a.read()).hexdigest(), hashlib.sha256(b.read()).hexdigest())
        os.remove(dest)

    @unittest.skipUnless(os.path.exists(STOCK_SPARSE), "stock/AP/super.img not present")
    def test_sparse_image_refused(self):
        with self.assertRaises(lp.SparseImageError) as cm:
            lp.SuperImage(STOCK_SPARSE)
        self.assertIn("simg2img", str(cm.exception))
        self.assertIsInstance(cm.exception, lp.LpError)

    def test_json_round_trip(self):
        path = os.path.join(TMP, "stock-super.json")
        self.img.save_json(path)
        back = lp.SuperImage.load_json(path)
        self.assertEqual(back.to_dict(), self.img.to_dict())
        self.assertEqual(back.partition_extent_ranges("vendor"), self.img.partition_extent_ranges("vendor"))
        self.assertEqual(back.partition("vendor").attribute_names, {"readonly"})
        self.assertTrue(back.slots_agree)
        self.assertEqual(back.lpmake_args(back.stock_partitions_spec(), "x.img"),
                         self.img.lpmake_args(self.img.stock_partitions_spec(), "x.img"))

    def test_lpmake_args_reproduce_documented_command(self):
        spec = self.img.stock_partitions_spec(STOCK_PARTS)
        args = self.img.lpmake_args(spec, "/out/super.img")
        expected = ["lpmake", "--metadata-size", "65536", "--metadata-slots", "2", "--super-name", "super",
                    "--block-size", "4096", "--device", "super:6417285120:1048576:0", "--group", "main:6413090816"]
        for name, size in (("system", 3850395648), ("odm", 21389312), ("product", 1423441920),
                           ("system_ext", 266436608), ("vendor", 436895744)):
            expected += ["--partition", f"{name}:readonly:{size}:main",
                         "--image", f"{name}={os.path.join(STOCK_PARTS, name + '.img')}"]
        expected += ["--output", "/out/super.img"]
        self.assertEqual(args, expected)
        sparse = self.img.lpmake_args(spec, "/out/super.img", sparse=True)
        self.assertEqual(sparse[-3:], ["--sparse", "--output", "/out/super.img"])
        rw = self.img.lpmake_args([{"name": "vendor", "image_path": None, "size": 1, "readonly": False, "group": "main"}], "o")
        self.assertIn("vendor:none:1:main", rw)
        self.assertNotIn("--image", rw)
        with self.assertRaises(lp.LpError):
            self.img.lpmake_args([{"name": "vendor", "size": 1, "group": "nope"}], "o")

    def test_validate_capacity_stock(self):
        rep = self.img.validate_capacity(self.img.stock_partitions_spec())
        self.assertTrue(rep.ok, rep.errors)
        self.assertEqual(rep.table(), [(p.name, p.size, p.size) for p in self.img.partitions])
        self.assertEqual(rep.group_used["main"], 5998559232)
        self.assertEqual(rep.group_free["main"], 414531584)
        self.assertIsNone(rep.group_free["default"])
        self.assertEqual([r.start_byte for r in rep.rows], [e.start_byte for e in self.img.extents])
        self.assertEqual(rep.device_used, self.img.extents[-1].start_byte + self.img.partitions[-1].size)
        self.assertEqual(rep.free_bytes, 6417285120 - rep.device_used)
        self.assertIn("free 414531584", rep.format())
        # Growing vendor by the whole headroom + 1 block overflows the group.
        spec = self.img.stock_partitions_spec()
        spec[-1]["size"] += 414531584 + 1
        rep = self.img.validate_capacity(spec)
        self.assertFalse(rep.ok)
        self.assertEqual(rep.rows[-1].aligned_size, lp.align_up(spec[-1]["size"], 4096))
        self.assertTrue(any("group main" in e for e in rep.errors), rep.errors)


@unittest.skipUnless(HAVE_LPMAKE, "lpmake not on PATH")
class TestSyntheticSuper(unittest.TestCase):
    """2 small partitions, device 16 MiB, metadata-slots 2, block size 4096, alignment 1 MiB (stock values)."""

    DEVICE = 16 * MIB
    GROUP_MAX = 14 * MIB
    ALPHA = 1 * MIB
    BETA = 1 * MIB + 4096

    @classmethod
    def setUpClass(cls):
        cls.dir = os.path.join(TMP, "synth")
        shutil.rmtree(cls.dir, ignore_errors=True)
        os.makedirs(cls.dir)
        cls.alpha_bin = os.path.join(cls.dir, "alpha.bin")
        cls.beta_bin = os.path.join(cls.dir, "beta.bin")
        with open(cls.alpha_bin, "wb") as f:
            f.write(os.urandom(cls.ALPHA))
        with open(cls.beta_bin, "wb") as f:
            f.write(os.urandom(cls.BETA))
        cls.spec = [
            {"name": "alpha", "image_path": cls.alpha_bin, "size": cls.ALPHA, "readonly": True, "group": "main"},
            {"name": "beta", "image_path": cls.beta_bin, "size": cls.BETA, "readonly": False, "group": "main"},
        ]
        cls.synth = os.path.join(cls.dir, "synth.img")
        cls.base_args = ["lpmake", "--metadata-size", "65536", "--metadata-slots", "2", "--super-name", "super",
                         "--block-size", "4096", "--device", f"super:{cls.DEVICE}:1048576:0",
                         "--group", f"main:{cls.GROUP_MAX}"]
        subprocess.run(cls.base_args + [
            "--partition", f"alpha:readonly:{cls.ALPHA}:main", "--image", f"alpha={cls.alpha_bin}",
            "--partition", f"beta:none:{cls.BETA}:main", "--image", f"beta={cls.beta_bin}",
            "--output", cls.synth], check=True, capture_output=True)
        cls.img = lp.SuperImage(cls.synth)

    def test_parse(self):
        img = self.img
        self.assertEqual(img.layout, "super")
        self.assertEqual(img.size, self.DEVICE)
        self.assertTrue(img.slots_agree)
        self.assertEqual(len(img.slots), 4)
        self.assertEqual(img.header.version, "10.0")
        self.assertEqual(img.header.header_size, 128)
        self.assertEqual(img.partition_names, ["alpha", "beta"])
        a, b = img.partitions
        self.assertEqual((a.size, a.readonly, a.group, a.extents[0].target_data), (self.ALPHA, True, "main", 2048))
        self.assertEqual((b.size, b.readonly, b.group, b.extents[0].target_data), (self.BETA, False, "main", 4096))
        self.assertEqual([(g.name, g.maximum_size) for g in img.groups], [("default", 0), ("main", self.GROUP_MAX)])
        self.assertEqual(img.block_device.to_dict(), {
            "first_logical_sector": 2048, "alignment": 1048576, "alignment_offset": 0, "size": self.DEVICE,
            "partition_name": "super", "flags": 0, "flag_names": []})
        self.assertEqual(img.partition_extent_ranges("beta"), [(2 * MIB, self.BETA)])

    @unittest.skipUnless(HAVE_LPDUMP, "lpdump not on PATH")
    def test_matches_lpdump(self):
        for d in lpdump_slots(self.synth, all_slots=True):
            assert_matches_lpdump(self, lp.SuperImage(self.synth, slot=d["slot"]), d)

    def test_regenerate_and_rebuild(self):
        """lpmake_args from the parse must rebuild metadata identical to the original."""
        rebuilt = os.path.join(self.dir, "rebuilt.img")
        args = self.img.lpmake_args(self.spec, rebuilt)
        self.assertEqual(args[:len(self.base_args)], self.base_args)
        subprocess.run(args, check=True, capture_output=True)
        img2 = lp.SuperImage(rebuilt)
        self.assertEqual(img2.metadata_dict(), self.img.metadata_dict())
        self.assertEqual([s.metadata_sha256 for s in img2.slots], [s.metadata_sha256 for s in self.img.slots])
        end = self.img.geometry.metadata_region_end
        self.assertEqual(read_at(rebuilt, 0, end), read_at(self.synth, 0, end))
        # And via JSON (what unpack writes and repack reads).
        js = os.path.join(self.dir, "synth.json")
        self.img.save_json(js)
        self.assertEqual(lp.SuperImage.load_json(js).lpmake_args(self.spec, rebuilt), args)
        # Partition data is at the same place in both images.
        for name in ("alpha", "beta"):
            for off, length in self.img.partition_extent_ranges(name):
                self.assertEqual(read_at(rebuilt, off, length), read_at(self.synth, off, length))

    @unittest.skipUnless(HAVE_LPUNPACK, "lpunpack not on PATH")
    def test_extract_matches_lpunpack_and_sources(self):
        out = os.path.join(self.dir, "unpacked")
        os.makedirs(out, exist_ok=True)
        subprocess.run(["lpunpack", self.synth, out], check=True, capture_output=True)
        for name, src in (("alpha", self.alpha_bin), ("beta", self.beta_bin)):
            dest = os.path.join(self.dir, f"{name}.extracted")
            n = self.img.extract_partition(name, dest, chunk_size=300000)
            self.assertEqual(n, os.path.getsize(src))
            with open(dest, "rb") as f:
                data = f.read()
            with open(src, "rb") as f:
                self.assertEqual(data, f.read())
            with open(os.path.join(out, name + ".img"), "rb") as f:
                self.assertEqual(data, f.read())

    def test_capacity_rule_matches_lpmake(self):
        """Our placement/group arithmetic must agree with liblp's accept/reject decisions."""
        def lpmake_ok(gamma_size: int, group_max: int) -> bool:
            args = [*self.base_args[:-2], "--group", f"main:{group_max}",
                    "--partition", f"alpha:readonly:{self.ALPHA}:main",
                    "--partition", f"beta:none:{self.BETA}:main",
                    "--partition", f"gamma:none:{gamma_size}:main",
                    "--output", os.path.join(self.dir, "cap.img")]
            return subprocess.run(args, capture_output=True).returncode == 0

        def ours(gamma_size: int, group_max: int) -> lp.CapacityReport:
            img = lp.SuperImage.from_dict(self.img.to_dict())
            img.groups = [lp.Group("default"), lp.Group("main", 0, group_max)]
            return img.validate_capacity([
                {"name": "alpha", "size": self.ALPHA, "readonly": True, "group": "main"},
                {"name": "beta", "size": self.BETA, "group": "main"},
                {"name": "gamma", "size": gamma_size, "group": "main"},
            ])

        # header 1 MiB + alpha 1 MiB + beta (1 MiB + 4 KiB -> 2 MiB footprint) leaves exactly 12 MiB.
        fits = ours(12 * MIB, 0)
        self.assertTrue(fits.ok, fits.errors)
        self.assertEqual(fits.free_bytes, 0)
        self.assertEqual([r.start_byte for r in fits.rows], [1 * MIB, 2 * MIB, 4 * MIB])
        self.assertEqual(fits.rows[1].footprint, 2 * MIB)
        self.assertTrue(lpmake_ok(12 * MIB, 0))
        over = ours(12 * MIB + 4096, 0)
        self.assertFalse(over.ok)
        self.assertIn("beyond device size", over.errors[0])
        self.assertFalse(lpmake_ok(12 * MIB + 4096, 0))
        # Group limit: sizes rounded to block size count; 1000 -> 4096.
        gl = ours(1000, self.ALPHA + self.BETA + 4096)
        self.assertTrue(gl.ok, gl.errors)
        self.assertEqual(gl.rows[-1].aligned_size, 4096)
        self.assertEqual(gl.group_free["main"], 0)
        self.assertTrue(lpmake_ok(1000, self.ALPHA + self.BETA + 4096))
        gl = ours(1000, self.ALPHA + self.BETA + 4095)
        self.assertFalse(gl.ok)
        self.assertFalse(lpmake_ok(1000, self.ALPHA + self.BETA + 4095))
        # Duplicate names are rejected.
        dup = self.img.validate_capacity([{"name": "a", "size": 1}, {"name": "a", "size": 1}])
        self.assertFalse(dup.ok)

    @unittest.skipUnless(HAVE_SIMG2IMG, "simg2img not on PATH")
    def test_sparse_output_refused_and_unsparsed_equal(self):
        sparse = os.path.join(self.dir, "synth.sparse.img")
        subprocess.run(self.img.lpmake_args(self.spec, sparse, sparse=True), check=True, capture_output=True)
        with self.assertRaises(lp.SparseImageError):
            lp.SuperImage(sparse)
        raw = os.path.join(self.dir, "synth.unsparsed.img")
        subprocess.run(["simg2img", sparse, raw], check=True, capture_output=True)
        self.assertEqual(lp.SuperImage(raw).metadata_dict(), self.img.metadata_dict())

    def test_super_empty_layout(self):
        empty = os.path.join(self.dir, "super_empty.img")
        subprocess.run(self.img.lpmake_args([
            {"name": "alpha", "size": self.ALPHA, "readonly": True, "group": "main"},
            {"name": "beta", "size": self.BETA, "group": "main"}], empty), check=True, capture_output=True)
        img = lp.SuperImage(empty)
        self.assertEqual(img.layout, "super_empty")
        self.assertEqual(img.geometry_offset, 0)
        self.assertEqual(len(img.slots), 1)
        self.assertTrue(img.slots_agree)
        self.assertEqual(img.metadata_dict(), self.img.metadata_dict())
        if HAVE_LPDUMP:
            assert_matches_lpdump(self, img, lpdump_slots(empty)[0])

    def test_backup_fallback_and_disagreement(self):
        damaged = os.path.join(self.dir, "damaged.img")
        shutil.copyfile(self.synth, damaged)
        g = self.img.geometry
        with open(damaged, "r+b") as f:
            f.seek(12288 + 100)                      # inside primary slot 0 tables
            f.write(b"\xff" * 8)
            f.seek(4096)                             # primary geometry
            f.write(b"\0" * 52)
        img = lp.SuperImage(damaged)
        self.assertEqual(img.geometry_offset, 8192)
        self.assertFalse(img.geometry_backup_identical)
        self.assertEqual((img.slot, img.slot_source), (0, "backup"))
        self.assertFalse(img.slots_agree)
        self.assertFalse(img.slots[0].ok)
        self.assertIn("checksum", img.slots[0].error)
        self.assertEqual(img.metadata_dict(), self.img.metadata_dict())
        # Both copies of slot 0 broken -> error; slot 1 still fine.
        with open(damaged, "r+b") as f:
            f.seek(12288 + 2 * g.metadata_max_size + 100)
            f.write(b"\xff" * 8)
        with self.assertRaises(lp.LpError):
            lp.SuperImage(damaged)
        self.assertEqual(lp.SuperImage(damaged, slot=1).metadata_dict(), self.img.metadata_dict())
        with self.assertRaises(lp.LpError):
            lp.SuperImage(damaged, slot=2)

    def test_not_a_super_image(self):
        with self.assertRaises(lp.LpError):
            lp.SuperImage(self.alpha_bin)
        tiny = os.path.join(self.dir, "tiny.img")
        with open(tiny, "wb") as f:
            f.write(b"\0" * 100)
        with self.assertRaises(lp.LpError):
            lp.SuperImage(tiny)


class TestPureHelpers(unittest.TestCase):
    def test_align_up(self):
        self.assertEqual(lp.align_up(1000, 4096), 4096)
        self.assertEqual(lp.align_up(4096, 4096), 4096)
        self.assertEqual(lp.align_up(4097, 4096), 8192)
        self.assertEqual(lp.align_up(5, 0), 5)

    def test_attribute_names(self):
        self.assertEqual(lp.attribute_names(0), set())
        self.assertEqual(lp.attribute_names(1), {"readonly"})
        self.assertEqual(lp.attribute_names(0xF), {"readonly", "slot-suffixed", "updated", "disabled"})
        self.assertEqual(lp.header_flag_names(None), [])
        self.assertEqual(lp.header_flag_names(3), ["virtual_ab_device", "overlays_active"])

    def test_parse_lpdump_text(self):
        text = """Slot 0:
Metadata version: 10.2
Metadata size: 668 bytes
Metadata max size: 65536 bytes
Metadata slot count: 2
Header flags: virtual_ab_device
Partition table:
------------------------
  Name: system
  Group: main
  Attributes: readonly
  Extents:
    0 .. 2047 linear super 2048
    2048 .. 4095 zero
------------------------
Super partition layout:
------------------------
super: 2048 .. 4096: system (2048 sectors)
------------------------
Block device table:
------------------------
  Partition name: super
  First sector: 2048
  Size: 16777216 bytes
  Flags: none
------------------------
Group table:
------------------------
  Name: default
  Maximum size: 0 bytes
  Flags: none
------------------------
  Name: main
  Maximum size: 14680064 bytes
  Flags: slot-suffixed
------------------------
"""
        slots = lp.parse_lpdump_text(text)
        self.assertEqual(len(slots), 1)
        s = slots[0]
        self.assertEqual(s["version"], "10.2")
        self.assertEqual(s["header_flags"], {"virtual_ab_device"})
        self.assertEqual(s["partitions"][0]["extents"], [
            {"first": 0, "last": 2047, "type": "linear", "device": "super", "start": 2048},
            {"first": 2048, "last": 4095, "type": "zero"}])
        self.assertEqual(s["block_devices"], [{"partition_name": "super", "first_sector": 2048, "size": 16777216, "flags": set()}])
        self.assertEqual(s["groups"][1], {"name": "main", "maximum_size": 14680064, "flags": {"slot-suffixed"}})

    def test_from_dict_minimal(self):
        d = {
            "geometry": {"metadata_max_size": 65536, "metadata_slot_count": 2, "logical_block_size": 4096},
            "header": {"minor_version": 0},
            "groups": [{"name": "default"}, {"name": "main", "maximum_size": 8 * MIB}],
            "block_devices": [{"first_logical_sector": 2048, "alignment": MIB, "alignment_offset": 0,
                               "size": 16 * MIB, "partition_name": "super"}],
            "partitions": [{"name": "p", "attributes": 1, "group": "main", "group_index": 1,
                            "extents": [{"num_sectors": 2048, "target_data": 2048}]}],
        }
        img = lp.SuperImage.from_dict(d)
        self.assertEqual(img.partition("p").attribute_names, {"readonly"})
        self.assertEqual(img.partition_extent_ranges("p"), [(MIB, MIB)])
        self.assertEqual(img.extents[0].num_bytes, MIB)
        self.assertFalse(img.slots_agree)        # no slot bookkeeping in a hand-written dict
        args = img.lpmake_args([{"name": "p", "size": MIB, "readonly": True, "group": "main"}], "o.img")
        self.assertEqual(args, ["lpmake", "--metadata-size", "65536", "--metadata-slots", "2", "--super-name", "super",
                                "--block-size", "4096", "--device", f"super:{16 * MIB}:{MIB}:0",
                                "--group", f"main:{8 * MIB}", "--partition", f"p:readonly:{MIB}:main",
                                "--output", "o.img"])
        img.header.flags = lp.HEADER_FLAG_VIRTUAL_AB
        self.assertIn("--virtual-ab", img.lpmake_args([], "o.img"))
        with self.assertRaises(KeyError):
            img.partition("nope")
        zero = lp.SuperImage.from_dict({**d, "partitions": [
            {"name": "z", "extents": [{"num_sectors": 8, "target_type": 1}]}]})
        with self.assertRaises(lp.LpError):
            zero.partition_extent_ranges("z")


if __name__ == "__main__":
    unittest.main()
