"""Tests for superkit.avb: footers vs avbtool info_image, strip_footer, vbmeta flag patching."""

import glob
import os
import re
import shutil
import struct
import subprocess
import unittest

from superkit import avb

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STOCK_PARTS = os.path.join(ROOT, "stock", "super")
STOCK_BOOT = os.path.join(ROOT, "stock", "AP", "boot.img")
STOCK_VBMETA = os.path.join(ROOT, "stock", "BL", "vbmeta.img")
STOCK_VBMETA_AP = os.path.join(ROOT, "stock", "AP", "vbmeta.img")
STOCK_VBMETA_SYSTEM = os.path.join(ROOT, "stock", "AP", "vbmeta_system.img")
TMP = os.path.join(ROOT, "work", "tmp", "avb-tests")
SLOW = os.environ.get("SUPERKIT_SLOW") == "1"
MIB = 1 << 20

HAVE_AVBTOOL = shutil.which("avbtool") is not None


def avbtool_info(path: str) -> dict:
    """Top-level 'Key:  value' lines of `avbtool info_image` (descriptors are indented and skipped)."""
    out = subprocess.run(["avbtool", "info_image", "--image", path], check=True, capture_output=True, text=True).stdout
    info = {}
    for line in out.splitlines():
        m = re.match(r"^([A-Za-z][A-Za-z0-9 ()]+?):\s+(.*)$", line)
        if m:
            info[m.group(1)] = m.group(2).strip()
    return info


def ival(s: str) -> int:
    return int(s.split()[0])


def stock_footered_images() -> list:
    paths = sorted(glob.glob(os.path.join(STOCK_PARTS, "*.img")))
    if os.path.exists(STOCK_BOOT):
        paths.append(STOCK_BOOT)
    return paths


def read_at(path: str, offset: int, length: int) -> bytes:
    with open(path, "rb") as f:
        f.seek(offset)
        return f.read(length)


class TestFormats(unittest.TestCase):
    def test_struct_sizes(self):
        self.assertEqual(avb.FOOTER_SIZE, 64)
        self.assertEqual(avb.VBMETA_HEADER_SIZE, 256)
        self.assertEqual(avb.FLAGS_OFFSET, 120)
        self.assertEqual(avb.ROLLBACK_INDEX_OFFSET, 112)

    def test_footer_pack_unpack(self):
        f = avb.Footer(b"AVBf", 1, 0, 20971520, 21311488, 2112)
        blob = f.pack()
        self.assertEqual(len(blob), 64)
        self.assertEqual(blob[:4], b"AVBf")
        self.assertEqual(struct.unpack_from("!Q", blob, 12)[0], 20971520)
        self.assertEqual(avb.parse_footer_bytes(blob), f)
        self.assertEqual(avb.parse_footer_bytes(b"\0" * 4096 + blob), f)
        self.assertIsNone(avb.parse_footer_bytes(b"\0" * 64))
        self.assertIsNone(avb.parse_footer_bytes(b"AVBf"))
        self.assertEqual(f.version, "1.0")
        self.assertEqual(f.to_dict()["magic"], "AVBf")


class TestSynthetic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.makedirs(TMP, exist_ok=True)

    def test_no_footer(self):
        p = os.path.join(TMP, "plain.bin")
        with open(p, "wb") as f:
            f.write(os.urandom(5000))
        self.assertIsNone(avb.parse_footer(p))
        with self.assertRaises(avb.AvbError):
            avb.strip_footer(p, p + ".stripped")
        with self.assertRaises(avb.AvbError):
            avb.vbmeta_info(p)
        with self.assertRaises(avb.AvbError):
            avb.patch_vbmeta_flags(p, p + ".patched")
        tiny = os.path.join(TMP, "tiny.bin")
        with open(tiny, "wb") as f:
            f.write(b"x" * 10)
        self.assertIsNone(avb.parse_footer(tiny))

    def test_synthetic_footer_and_vbmeta(self):
        """Hand-built image: 10000 bytes payload, fake vbmeta header, zero padding, footer."""
        payload = os.urandom(10000)
        header = struct.pack(avb.VBMETA_HEADER_FORMAT, b"AVB0", 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             7, 0, 4, b"superkit test")
        vb_off = 12288
        img = payload + b"\0" * (vb_off - len(payload)) + header
        img += b"\0" * (16384 - 64 - len(img)) + avb.Footer(b"AVBf", 1, 0, len(payload), vb_off, 256).pack()
        p = os.path.join(TMP, "synthetic.img")
        with open(p, "wb") as f:
            f.write(img)
        foot = avb.parse_footer(p)
        self.assertEqual((foot.original_image_size, foot.vbmeta_offset, foot.vbmeta_size), (10000, vb_off, 256))
        info = avb.vbmeta_info(p)
        self.assertEqual((info["vbmeta_offset"], info["rollback_index"], info["flags"], info["rollback_index_location"],
                          info["release_string"], info["algorithm"]), (vb_off, 7, 0, 4, "superkit test", "NONE"))
        self.assertEqual(info["footer"]["original_image_size"], 10000)
        stripped = os.path.join(TMP, "synthetic.stripped")
        self.assertEqual(avb.strip_footer(p, stripped), foot)
        with open(stripped, "rb") as f:
            self.assertEqual(f.read(), payload)
        patched = os.path.join(TMP, "synthetic.patched")
        after = avb.patch_vbmeta_flags(p, patched, flags=1)
        self.assertEqual((after["flags"], after["flag_names"], after["rollback_index"]), (1, ["hashtree_disabled"], 7))
        with open(patched, "rb") as f:
            got = f.read()
        self.assertEqual(len(got), len(img))
        diff = [i for i in range(len(img)) if got[i] != img[i]]
        self.assertEqual(diff, [vb_off + 123])
        with self.assertRaises(ValueError):
            avb.patch_vbmeta_flags(p, patched, flags=-1)
        # Footer pointing past the end of the file is rejected.
        bad = os.path.join(TMP, "badfooter.img")
        with open(bad, "wb") as f:
            f.write(b"\0" * 100 + avb.Footer(b"AVBf", 1, 0, 50, 10 ** 9, 256).pack())
        with self.assertRaises(avb.AvbError):
            avb.parse_footer(bad)


@unittest.skipUnless(os.path.isdir(STOCK_PARTS) and HAVE_AVBTOOL, "stock partition images or avbtool missing")
class TestStockFooters(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.makedirs(TMP, exist_ok=True)

    def test_footers_equal_avbtool(self):
        images = stock_footered_images()
        self.assertTrue(images)
        for path in images:
            with self.subTest(image=os.path.basename(path)):
                foot = avb.parse_footer(path)
                self.assertIsNotNone(foot, path)
                ref = avbtool_info(path)
                self.assertEqual(foot.version, ref["Footer version"])
                self.assertEqual(foot.original_image_size, ival(ref["Original image size"]))
                self.assertEqual(foot.vbmeta_offset, ival(ref["VBMeta offset"]))
                self.assertEqual(foot.vbmeta_size, ival(ref["VBMeta size"]))
                self.assertEqual(os.path.getsize(path), ival(ref["Image size"]))
                info = avb.vbmeta_info(path)
                self.assertEqual(info["vbmeta_offset"], foot.vbmeta_offset)
                self.assertEqual(info["vbmeta_size"], foot.vbmeta_size)
                self.assertEqual(info["rollback_index"], ival(ref["Rollback Index"]))
                self.assertEqual(info["flags"], ival(ref["Flags"]))
                self.assertEqual(info["algorithm"], ref["Algorithm"])
                self.assertEqual(info["authentication_data_block_size"], ival(ref["Authentication Block"]))
                self.assertEqual(info["auxiliary_data_block_size"], ival(ref["Auxiliary Block"]))
                self.assertEqual(info["release_string"], ref["Release String"].strip("'"))

    def test_stock_values_from_design(self):
        odm = avb.parse_footer(os.path.join(STOCK_PARTS, "odm.img"))
        self.assertEqual(odm, avb.Footer(b"AVBf", 1, 0, 20971520, 21311488, 2112))
        vendor = avb.parse_footer(os.path.join(STOCK_PARTS, "vendor.img"))
        self.assertEqual((vendor.original_image_size, vendor.vbmeta_offset, vendor.vbmeta_size),
                         (429916160, 436740096, 2176))

    def test_strip_footer_odm(self):
        src = os.path.join(STOCK_PARTS, "odm.img")
        dst = os.path.join(TMP, "odm.stripped.img")
        foot = avb.strip_footer(src, dst, chunk=1 << 20)
        ref = avbtool_info(src)
        self.assertEqual(os.path.getsize(dst), ival(ref["Original image size"]))
        self.assertEqual(os.path.getsize(dst), foot.original_image_size)
        self.assertEqual(read_at(dst, 0, MIB), read_at(src, 0, MIB))
        n = foot.original_image_size
        self.assertEqual(read_at(dst, n - MIB, MIB), read_at(src, n - MIB, MIB))
        self.assertIsNone(avb.parse_footer(dst))
        # f2fs superblock magic survives at offset 1024 of the stripped image.
        self.assertEqual(read_at(dst, 1024, 4), b"\x10\x20\xf5\xf2")
        os.remove(dst)

    @unittest.skipUnless(SLOW, "set SUPERKIT_SLOW=1")
    def test_strip_footer_all_stock_partitions(self):
        for path in sorted(glob.glob(os.path.join(STOCK_PARTS, "*.img"))):
            with self.subTest(image=os.path.basename(path)):
                dst = os.path.join(TMP, os.path.basename(path) + ".stripped")
                foot = avb.strip_footer(path, dst)
                self.assertEqual(os.path.getsize(dst), foot.original_image_size)
                self.assertEqual(read_at(dst, 0, MIB), read_at(path, 0, MIB))
                os.remove(dst)


@unittest.skipUnless(os.path.exists(STOCK_VBMETA) and HAVE_AVBTOOL, "stock/BL/vbmeta.img or avbtool missing")
class TestStockVbmeta(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.makedirs(TMP, exist_ok=True)

    def test_vbmeta_info_vs_avbtool(self):
        for path in (STOCK_VBMETA, STOCK_VBMETA_AP, STOCK_VBMETA_SYSTEM):
            if not os.path.exists(path):
                continue
            with self.subTest(image=path):
                self.assertIsNone(avb.parse_footer(path))
                info = avb.vbmeta_info(path)
                ref = avbtool_info(path)
                self.assertEqual(info["vbmeta_offset"], 0)
                self.assertEqual(info["required_libavb_version"], ref["Minimum libavb version"])
                self.assertEqual(info["authentication_data_block_size"], ival(ref["Authentication Block"]))
                self.assertEqual(info["auxiliary_data_block_size"], ival(ref["Auxiliary Block"]))
                self.assertEqual(info["algorithm"], ref["Algorithm"])
                self.assertEqual(info["rollback_index"], ival(ref["Rollback Index"]))
                self.assertEqual(info["flags"], ival(ref["Flags"]))
                self.assertEqual(info["rollback_index_location"], ival(ref["Rollback Index Location"]))
                self.assertEqual(info["release_string"], ref["Release String"].strip("'"))
                self.assertEqual(info["trailer_size"], 512)        # Samsung SignerVer02 record
                self.assertEqual(read_at(path, info["vbmeta_size"], 11), b"SignerVer02")

    def test_stock_vbmeta_facts(self):
        info = avb.vbmeta_info(STOCK_VBMETA)
        self.assertEqual((info["algorithm"], info["authentication_data_block_size"], info["auxiliary_data_block_size"],
                          info["rollback_index"], info["flags"], info["vbmeta_size"], info["file_size"]),
                         ("SHA256_RSA4096", 576, 7040, 0, 0, 7872, 8384))
        if os.path.exists(STOCK_VBMETA_AP):
            with open(STOCK_VBMETA, "rb") as a, open(STOCK_VBMETA_AP, "rb") as b:
                self.assertEqual(a.read(), b.read())

    def test_patch_vbmeta_flags(self):
        dst = os.path.join(TMP, "vbmeta_disabled.img")
        after = avb.patch_vbmeta_flags(STOCK_VBMETA, dst)
        self.assertEqual(after["flags"], 3)
        self.assertEqual(after["flag_names"], ["hashtree_disabled", "verification_disabled"])
        ref = avbtool_info(dst)
        self.assertEqual(ival(ref["Flags"]), 3)
        self.assertEqual(ival(ref["Rollback Index"]), 0)
        self.assertEqual(ref["Algorithm"], "SHA256_RSA4096")
        orig_ref = avbtool_info(STOCK_VBMETA)
        self.assertEqual(ref["Rollback Index"], orig_ref["Rollback Index"])
        self.assertEqual(ref["Public key (sha1)"], orig_ref["Public key (sha1)"])
        # Only the 4 flag bytes differ; the Samsung trailer and everything else are untouched.
        with open(STOCK_VBMETA, "rb") as a, open(dst, "rb") as b:
            orig, patched = a.read(), b.read()
        self.assertEqual(len(orig), len(patched))
        diff = [i for i in range(len(orig)) if orig[i] != patched[i]]
        self.assertEqual(diff, [123])
        self.assertEqual(patched[120:124], b"\0\0\0\3")
        self.assertEqual(patched[7872:7883], b"SignerVer02")
        # In-place (src == dst) and other flag values.
        self.assertEqual(avb.patch_vbmeta_flags(dst, dst, flags=2)["flags"], 2)
        self.assertEqual(ival(avbtool_info(dst)["Flags"]), 2)
        self.assertEqual(avb.vbmeta_info(dst)["rollback_index"], 0)
        self.assertEqual(avb.patch_vbmeta_flags(dst, dst, flags=0)["flags"], 0)
        with open(dst, "rb") as f:
            self.assertEqual(f.read(), orig)

    @unittest.skipUnless(os.path.exists(os.path.join(STOCK_PARTS, "odm.img")), "stock/super/odm.img missing")
    def test_patch_embedded_vbmeta_in_footered_image(self):
        src = os.path.join(STOCK_PARTS, "odm.img")
        dst = os.path.join(TMP, "odm.flagged.img")
        after = avb.patch_vbmeta_flags(src, dst, flags=1)
        self.assertEqual(after["vbmeta_offset"], 21311488)
        self.assertEqual(ival(avbtool_info(dst)["Flags"]), 1)
        self.assertEqual(avb.parse_footer(dst), avb.parse_footer(src))
        self.assertEqual(read_at(dst, 0, MIB), read_at(src, 0, MIB))
        os.remove(dst)


if __name__ == "__main__":
    unittest.main()
