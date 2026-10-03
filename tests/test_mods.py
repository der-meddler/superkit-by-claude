"""Tests for superkit.mods (DESIGN.md §4, §7.5): mods.toml loading, fstab and build.prop
editors on copies of the stock files, idempotence, dry runs, and files add/delete with
sidecar resync on a tiny synthetic workdir."""
import hashlib
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from superkit import fsconfig as fc
from superkit.fsconfig import ManifestEntry
from superkit.mods import (ModsError, FilesMod, Mods, apply_mods, load_mods, parse_mods,
                           split_part_path, format_report)
from superkit.mods import fstab, props
from superkit.mods.files import PartitionTree

ROOT = "/home/bigdihh/Documents/A137F-super"
TMP = os.path.join(ROOT, "work", "tmp", "mods-tests")
STOCK_FSTAB = os.path.join(ROOT, "work", "stockdump", "vendor", "etc", "fstab.mt6768")
STOCK_PROP = os.path.join(ROOT, "work", "stockdump", "vendor", "build.prop")
EXAMPLE = os.path.join(ROOT, "mods.example.toml")
HAVE_STOCK = os.path.isfile(STOCK_FSTAB) and os.path.isfile(STOCK_PROP)

VENDOR_FILE = "u:object_r:vendor_file:s0"
CONFIGS = "u:object_r:vendor_configs_file:s0"


def read(path):
    with open(path, encoding="utf-8", errors="surrogateescape", newline="") as f:
        return f.read()


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", errors="surrogateescape", newline="") as f:
        f.write(text)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TmpDirMixin:
    def setUp(self):
        os.makedirs(TMP, exist_ok=True)
        self.wd = tempfile.mkdtemp(prefix="wd-", dir=TMP)

    def tearDown(self):
        shutil.rmtree(self.wd, ignore_errors=True)


# --------------------------------------------------------------------------- fstab editor

class FstabLineTest(unittest.TestCase):
    LINE = "vendor\t/vendor  f2fs\tro \twait,,avb,logical,first_stage_mount\n"

    def test_parse_preserves_separators(self):
        fl = fstab.parse_line(self.LINE)
        self.assertTrue(fl.is_entry)
        self.assertEqual(fl.fields, ["vendor", "/vendor", "f2fs", "ro", "wait,,avb,logical,first_stage_mount"])
        self.assertEqual(fl.seps, ["\t", "  ", "\t", " \t"])
        self.assertEqual(fl.format(), self.LINE)
        self.assertEqual(fstab.parse_line("# comment\n").format(), "# comment\n")
        self.assertEqual(fstab.parse_line("\n").format(), "\n")
        self.assertEqual(fstab.parse_line("a b c\n").format(), "a b c\n")  # too short: raw
        self.assertFalse(fstab.parse_line("a b c\n").is_entry)
        crlf = "a\t/a\tf2fs\tro\twait\r\n"
        self.assertEqual(fstab.parse_line(crlf).format(), crlf)
        self.assertEqual(fstab.parse_line("a /a f2fs ro wait").format(), "a /a f2fs ro wait")
        self.assertEqual(fstab.parse_line("  a /a f2fs ro wait  \n").format(), "  a /a f2fs ro wait  \n")

    def test_remove_flags_exact_and_glob(self):
        self.assertEqual(fstab.remove_flags(self.LINE, ["avb"]),
                         "vendor\t/vendor  f2fs\tro \twait,,logical,first_stage_mount\n")
        # 'avb' does not match 'avb=x'; 'avb=*' does not match 'avb'
        l = "system\t/system\tf2fs\tro\twait,,avb=vbmeta_system,avb,logical,avb_keys=/a:/b\n"
        self.assertEqual(fstab.remove_flags(l, ["avb"]),
                         "system\t/system\tf2fs\tro\twait,,avb=vbmeta_system,logical,avb_keys=/a:/b\n")
        self.assertEqual(fstab.remove_flags(l, ["avb=*"]),
                         "system\t/system\tf2fs\tro\twait,,avb,logical,avb_keys=/a:/b\n")
        self.assertEqual(fstab.remove_flags(l, ["avb", "avb=*", "avb_keys=*"]),
                         "system\t/system\tf2fs\tro\twait,,logical\n")
        # '*' never eats the empty tokens Samsung leaves
        self.assertEqual(fstab.remove_flags(l, ["*"]), "system\t/system\tf2fs\tro\tdefaults\n")
        self.assertEqual(fstab.remove_flags("a /a f2fs ro wait,,\n", ["wait"]), "a /a f2fs ro defaults\n")
        # untouched lines are returned byte-identical
        self.assertEqual(fstab.remove_flags(self.LINE, ["nope"]), self.LINE)
        self.assertEqual(fstab.remove_flags("# avb\n", ["avb"]), "# avb\n")

    def test_add_flags(self):
        self.assertEqual(fstab.add_flags(self.LINE, ["nofail"]),
                         "vendor\t/vendor  f2fs\tro \twait,,avb,logical,first_stage_mount,nofail\n")
        self.assertEqual(fstab.add_flags(self.LINE, ["avb", "wait"]), self.LINE)  # idempotent
        l = "a /a f2fs ro wait,avb=vbmeta_system,logical\n"
        self.assertEqual(fstab.add_flags(l, ["avb=other"]), "a /a f2fs ro wait,avb=other,logical\n")
        self.assertEqual(fstab.add_flags("a /a f2fs ro defaults\n", ["wait"]), "a /a f2fs ro wait\n")
        with self.assertRaises(ValueError):
            fstab.add_flags(l, ["a,b"])

    def test_mount_options_and_fs_type(self):
        l = "/dev/block/by-name/userdata\t/data\tf2fs\tnoatime,nosuid,inlinecrypt\twait,check,,quota\n"
        self.assertEqual(fstab.remove_mount_options(l, ["inlinecrypt"]),
                         "/dev/block/by-name/userdata\t/data\tf2fs\tnoatime,nosuid\twait,check,,quota\n")
        self.assertEqual(fstab.add_mount_options(l, ["discard"]),
                         "/dev/block/by-name/userdata\t/data\tf2fs\tnoatime,nosuid,inlinecrypt,discard\twait,check,,quota\n")
        self.assertEqual(fstab.set_fs_type(l, "ext4"),
                         "/dev/block/by-name/userdata\t/data\text4\tnoatime,nosuid,inlinecrypt\twait,check,,quota\n")

    def test_edit_fstab_selects_by_mount_point(self):
        text = ("# hdr\n"
                "system\t/system\tf2fs\tro\twait,,avb,logical\n"
                "system\t/system\text4\tro\twait,,avb,logical\n"
                "system\t/system\terofs\tro\twait,,avb,logical\n"
                "\n"
                "/dev/block/by-name/prism /prism ext4 ro,barrier=1 nofail,avb,first_stage_mount\n")
        out = fstab.edit_fstab(text, ["/system"], remove_flags_=["avb"])
        self.assertEqual(out, ("# hdr\n"
                               "system\t/system\tf2fs\tro\twait,,logical\n"
                               "system\t/system\text4\tro\twait,,logical\n"
                               "system\t/system\terofs\tro\twait,,logical\n"
                               "\n"
                               "/dev/block/by-name/prism /prism ext4 ro,barrier=1 nofail,avb,first_stage_mount\n"))
        self.assertEqual(fstab.edit_fstab(out, ["/system"], remove_flags_=["avb"]), out)
        self.assertEqual(fstab.edit_fstab(text, ["/nothing"], remove_flags_=["avb"]), text)
        with self.assertRaises(ValueError):
            fstab.edit_fstab(text, ["/nothing"], remove_flags_=["avb"], require_match=True)


# --------------------------------------------------------------------------- props editor

class PropsTest(unittest.TestCase):
    TEXT = ("# header\n"
            "import /vendor/ro.prop\n"
            "ro.a=1\n"
            "\n"
            "ro.b?=2\n"
            "ro.c=x,y\n"
            "# end\n")

    def test_parse_kinds(self):
        kinds = [l.kind for l in props.parse_props(self.TEXT)]
        self.assertEqual(kinds, ["comment", "import", "prop", "blank", "prop", "prop", "comment"])
        self.assertEqual(props.get_props(self.TEXT), {"ro.a": "1", "ro.b": "2", "ro.c": "x,y"})
        self.assertEqual(props.format_props(props.parse_props(self.TEXT)), self.TEXT)

    def test_set(self):
        out = props.set_props(self.TEXT, {"ro.a": "9"})
        self.assertEqual(out, self.TEXT.replace("ro.a=1", "ro.a=9"))
        self.assertEqual(props.set_props(out, {"ro.a": "9"}), out)
        # new keys go to the end
        out = props.set_props(self.TEXT, {"ro.new": "v", "ro.adb.secure": 0})
        self.assertEqual(out, self.TEXT + "ro.new=v\nro.adb.secure=0\n")
        # ... or after an anchor
        out = props.set_props(self.TEXT, {"ro.new": True}, after="ro.a")
        self.assertEqual(out, self.TEXT.replace("ro.a=1\n", "ro.a=1\nro.new=true\n"))
        with self.assertRaises(ValueError):
            props.set_props(self.TEXT, {"ro.new": "1"}, after="ro.missing")
        # ?= lines are not rewritten by set; a hard '=' is appended
        out = props.set_props(self.TEXT, {"ro.b": "3"})
        self.assertEqual(out, self.TEXT + "ro.b=3\n")
        self.assertEqual(props.get_prop(out, "ro.b"), "3")
        with self.assertRaises(ValueError):
            props.set_props(self.TEXT, {"bad key": "1"})
        with self.assertRaises(ValueError):
            props.set_props(self.TEXT, {"ro.x": "a\nb"})

    def test_set_without_trailing_newline(self):
        text = "ro.a=1"
        self.assertEqual(props.set_props(text, {"ro.b": "2"}), "ro.a=1\nro.b=2\n")
        self.assertEqual(props.set_props("ro.a=1\r\n", {"ro.b": "2"}), "ro.a=1\r\nro.b=2\r\n")

    def test_remove(self):
        out = props.remove_props(self.TEXT, ["ro.a", "ro.b", "ro.missing"])
        self.assertEqual(out, "# header\nimport /vendor/ro.prop\n\nro.c=x,y\n# end\n")
        self.assertEqual(props.remove_props(out, ["ro.a"]), out)

    def test_append(self):
        out = props.append_props(self.TEXT, {"ro.c": "z"})
        self.assertEqual(out, self.TEXT.replace("ro.c=x,y", "ro.c=x,y,z"))
        self.assertEqual(props.append_props(out, {"ro.c": "z"}), out)
        self.assertEqual(props.append_props(out, {"ro.c": "x"}), out)
        out = props.append_props(self.TEXT, {"ro.d": "1"})
        self.assertEqual(out, self.TEXT + "ro.d=1\n")
        out = props.append_props(self.TEXT, {"ro.c": "z"}, separator=" ")
        self.assertEqual(out, self.TEXT.replace("ro.c=x,y", "ro.c=x,y z"))

    def test_edit_props_order(self):
        out = props.edit_props(self.TEXT, set={"ro.a": "2"}, remove=["ro.a"], append={"ro.c": "q"})
        # remove first, then set re-adds at the end
        self.assertEqual(out, "# header\nimport /vendor/ro.prop\n\nro.b?=2\nro.c=x,y,q\n# end\nro.a=2\n")


# --------------------------------------------------------------------------- loader

class LoaderTest(unittest.TestCase):
    def test_example(self):
        m = load_mods(EXAMPLE)
        self.assertEqual(len(m.fstab), 2)
        self.assertEqual(len(m.props), 1)
        self.assertEqual(m.files, [])
        self.assertEqual(m.fstab[0].remove_flags, ["avb", "avb=*", "avb_keys=*"])
        self.assertEqual(m.fstab[1].remove_mount_options, ["inlinecrypt"])
        self.assertEqual(m.props[0].set, {"ro.adb.secure": "0"})
        self.assertFalse(m.is_empty)

    def test_split_part_path(self):
        self.assertEqual(split_part_path("vendor/etc/fstab"), ("vendor", "etc/fstab"))
        self.assertEqual(split_part_path("system/system/build.prop"), ("system", "system/build.prop"))
        self.assertEqual(split_part_path("/vendor"), ("vendor", ""))
        for bad in ("", "/", "vendor/../x", "vendor//x", "./vendor/x"):
            with self.assertRaises(ModsError):
                split_part_path(bad)

    def test_validation(self):
        with self.assertRaises(ModsError):
            parse_mods({"fstab": [{"files": ["v/x"], "mount_points": ["/v"], "remove_flags": ["a"], "bogus": 1}]})
        with self.assertRaises(ModsError):
            parse_mods({"fstab": [{"files": ["v/x"], "mount_points": ["/v"]}]})  # no operation
        with self.assertRaises(ModsError):
            parse_mods({"fstab": [{"files": ["v/x"], "mount_points": ["v"], "remove_flags": ["a"]}]})
        with self.assertRaises(ModsError):
            parse_mods({"props": [{"file": "v/x"}]})
        with self.assertRaises(ModsError):
            parse_mods({"files": [{"action": "add", "path": "v/x"}]})  # no source
        with self.assertRaises(ModsError):
            parse_mods({"files": [{"action": "delete", "path": "v/x", "source": "/s"}]})
        with self.assertRaises(ModsError):
            parse_mods({"files": [{"action": "add", "path": "v", "source": "/s"}]})  # partition root
        with self.assertRaises(ModsError):
            parse_mods({"files": [{"action": "add", "path": "v/x", "source": "/s", "mode": "0999"}]})
        with self.assertRaises(ModsError):
            parse_mods({"other": []})
        m = parse_mods({"files": [{"action": "add", "path": "v/x", "source": "/s", "mode": "0755",
                                   "uid": 0, "gid": "2000", "caps": "0x1000000", "optional": True}]})
        f = m.files[0]
        self.assertEqual((f.mode, f.uid, f.gid, f.caps, f.optional), (0o755, 0, 2000, 0x1000000, True))
        m = parse_mods({"props": [{"file": "v/x", "set": {"a": 1, "b": True}}]})
        self.assertEqual(m.props[0].set, {"a": "1", "b": "true"})


# --------------------------------------------------------------------------- stock copies

@unittest.skipUnless(HAVE_STOCK, "work/stockdump/vendor not present")
class ExampleModsOnStockCopiesTest(TmpDirMixin, unittest.TestCase):
    """Bare workdir (no sidecars) with copies of the stock fstab and build.prop."""

    EXPECTED = {
        "system\t/system\tf2fs\tro\twait,,avb=vbmeta_system,logical,first_stage_mount,avb_keys=/avb/q-gsi.avbpubkey:/avb/r-gsi.avbpubkey:/avb/s-gsi.avbpubkey":
            "system\t/system\tf2fs\tro\twait,,logical,first_stage_mount",
        "system\t/system\text4\tro\twait,,avb=vbmeta_system,logical,first_stage_mount,avb_keys=/avb/q-gsi.avbpubkey:/avb/r-gsi.avbpubkey:/avb/s-gsi.avbpubkey":
            "system\t/system\text4\tro\twait,,logical,first_stage_mount",
        "system\t/system\terofs\tro\twait,,avb=vbmeta_system,logical,first_stage_mount,avb_keys=/avb/q-gsi.avbpubkey:/avb/r-gsi.avbpubkey:/avb/s-gsi.avbpubkey":
            "system\t/system\terofs\tro\twait,,logical,first_stage_mount",
        "system_ext\t/system_ext\tf2fs\tro\twait,,avb=vbmeta_system,logical,first_stage_mount,avb_keys=/avb/q-gsi.avbpubkey:/avb/r-gsi.avbpubkey:/avb/s-gsi.avbpubkey":
            "system_ext\t/system_ext\tf2fs\tro\twait,,logical,first_stage_mount",
        "vendor\t/vendor\tf2fs\tro\twait,,avb,logical,first_stage_mount":
            "vendor\t/vendor\tf2fs\tro\twait,,logical,first_stage_mount",
        "product\t/product\tf2fs\tro\twait,,avb,logical,first_stage_mount":
            "product\t/product\tf2fs\tro\twait,,logical,first_stage_mount",
        "odm\t/odm\tf2fs\tro\twait,,avb,logical,first_stage_mount":
            "odm\t/odm\tf2fs\tro\twait,,logical,first_stage_mount",
        "/dev/block/by-name/userdata\t/data\tf2fs\tnoatime,nosuid,nodev,discard,usrquota,grpquota,fsync_mode=nobarrier,reserve_root=32768,resgid=5678,whint_mode=fs-based,inlinecrypt\twait,check,,quota,latemount,,reservedsize=128M,checkpoint=fs,fileencryption=aes-256-xts:aes-256-cts:v2,keydirectory=/metadata/vold/metadata_encryption,fscompress":
            "/dev/block/by-name/userdata\t/data\tf2fs\tnoatime,nosuid,nodev,discard,usrquota,grpquota,fsync_mode=nobarrier,reserve_root=32768,resgid=5678,whint_mode=fs-based\twait,check,,quota,latemount,,reservedsize=128M,checkpoint=fs,fscompress",
    }

    def setUp(self):
        super().setUp()
        self.fstabs = [os.path.join(self.wd, "vendor", "root", "etc", n) for n in ("fstab.mt6768", "fstab.mt6769t")]
        for p in self.fstabs:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            shutil.copyfile(STOCK_FSTAB, p)
        self.prop = os.path.join(self.wd, "system", "root", "system", "build.prop")
        os.makedirs(os.path.dirname(self.prop))
        shutil.copyfile(STOCK_PROP, self.prop)
        self.stock_fstab = read(STOCK_FSTAB)
        self.stock_prop = read(STOCK_PROP)

    def check_fstab(self, text):
        old = self.stock_fstab.split("\n")
        new = text.split("\n")
        self.assertEqual(len(old), len(new))
        seen = set()
        for o, n in zip(old, new):
            if o in self.EXPECTED:
                self.assertEqual(n, self.EXPECTED[o])
                seen.add(o)
            else:
                self.assertEqual(n, o)
        self.assertEqual(seen, set(self.EXPECTED))
        self.assertNotIn("inlinecrypt", text)
        self.assertNotIn("fileencryption", text)
        self.assertNotIn("keydirectory", text)
        # untouched entries keep their avb tokens
        self.assertIn("/vbmeta_system emmc defaults first_stage_mount,nofail,,avb=vbmeta\n", text)
        self.assertIn("/prism ext4 ro,barrier=1 nofail,avb,first_stage_mount\n", text)

    def test_apply_example(self):
        mods = load_mods(EXAMPLE)
        report = apply_mods(self.wd, mods)
        self.assertTrue(report)
        for p in self.fstabs:
            self.check_fstab(read(p))
        self.assertEqual(read(self.prop), self.stock_prop + "ro.adb.secure=0\n")
        # report: 8 changed lines per fstab copy + 1 prop + 2 'no sidecars' notes
        fs_changes = [c for c in report if c.op == "fstab"]
        self.assertEqual(len(fs_changes), 2 * len(self.EXPECTED))
        self.assertEqual({c.file for c in fs_changes}, {"vendor/etc/fstab.mt6768", "vendor/etc/fstab.mt6769t"})
        pc = [c for c in report if c.op == "props"]
        self.assertEqual(len(pc), 1)
        self.assertEqual((pc[0].file, pc[0].before, pc[0].after, pc[0].detail),
                         ("system/system/build.prop", None, "ro.adb.secure=0", "ro.adb.secure"))
        self.assertEqual([c.op for c in report if c.op not in ("fstab", "props")], ["note", "note"])
        self.assertIn("fstab", format_report(report))
        # idempotent: second application changes nothing at all
        snapshot = {p: read(p) for p in self.fstabs + [self.prop]}
        self.assertEqual(apply_mods(self.wd, mods), [])
        self.assertEqual({p: read(p) for p in self.fstabs + [self.prop]}, snapshot)
        # a path given as a toml file works too
        self.assertEqual(apply_mods(self.wd, EXAMPLE), [])

    def test_dry_run(self):
        report = apply_mods(self.wd, load_mods(EXAMPLE), dry_run=True)
        self.assertTrue(any(c.op == "fstab" for c in report))
        for p in self.fstabs:
            self.assertEqual(read(p), self.stock_fstab)
        self.assertEqual(read(self.prop), self.stock_prop)

    def test_missing_file_fails_unless_optional(self):
        m = parse_mods({"fstab": [{"files": ["vendor/etc/fstab.nope"], "mount_points": ["/system"],
                                   "remove_flags": ["avb"]}]})
        with self.assertRaises(ModsError):
            apply_mods(self.wd, m)
        m.fstab[0].optional = True
        report = apply_mods(self.wd, m)
        self.assertEqual([c.op for c in report], ["note"])
        m = parse_mods({"props": [{"file": "odm/etc/build.prop", "set": {"a": "1"}}]})
        with self.assertRaises(ModsError):
            apply_mods(self.wd, m)
        m.props[0].optional = True
        self.assertEqual([c.op for c in apply_mods(self.wd, m)], ["note"])

    def test_props_on_vendor_copy(self):
        write(os.path.join(self.wd, "vendor", "root", "build.prop"), self.stock_prop)
        m = parse_mods({"props": [{"file": "vendor/build.prop",
                                   "set": {"ro.vendor.build.type": "userdebug", "ro.secure": 0},
                                   "remove": ["ro.vendor.qb.id"],
                                   "append": {"ro.vendor.product.cpu.abilist": "arm64-v8a"},
                                   "after": "ro.vendor.build.version.sdk"}]})
        apply_mods(self.wd, m)
        got = read(os.path.join(self.wd, "vendor", "root", "build.prop"))
        exp = (self.stock_prop.replace("ro.vendor.build.type=user\n", "ro.vendor.build.type=userdebug\n")
               .replace("ro.vendor.qb.id=106279844\n", "")
               .replace("ro.vendor.product.cpu.abilist=armeabi-v7a,armeabi\n", "ro.vendor.product.cpu.abilist=armeabi-v7a,armeabi,arm64-v8a\n")
               .replace("ro.vendor.build.version.sdk=31\n", "ro.vendor.build.version.sdk=31\nro.secure=0\n"))
        self.assertEqual(got, exp)
        self.assertEqual(apply_mods(self.wd, m), [])


# --------------------------------------------------------------------------- files + sidecars

class FilesResyncTest(TmpDirMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.part = os.path.join(self.wd, "vendor")
        self.root = os.path.join(self.part, "root")
        write(os.path.join(self.root, "bin", "hello"), "hello\n")
        os.chmod(os.path.join(self.root, "bin", "hello"), 0o755)
        write(os.path.join(self.root, "etc", "cfg.txt"), "k=v\n")
        os.symlink("bin/hello", os.path.join(self.root, "lnk"))
        T = 1230768000
        for rel in ("", "bin", "bin/hello", "etc", "etc/cfg.txt"):
            os.utime(os.path.join(self.root, rel), (T, T))
        self.entries = [
            ManifestEntry("", "dir", 0o755, 0, 0, 5, 4096, T, 0, VENDOR_FILE, 0, {}, None, None, 3),
            ManifestEntry("bin", "dir", 0o755, 0, 2000, 2, 4096, T, 0, VENDOR_FILE, 0, {}, None, None, 4),
            ManifestEntry("bin/hello", "reg", 0o755, 0, 2000, 1, 6, T, 0, "u:object_r:vendor_hello_exec:s0",
                          0x1000000, {}, None, sha(b"hello\n"), 5),
            ManifestEntry("etc", "dir", 0o755, 0, 0, 2, 4096, T, 0, CONFIGS, 0, {}, None, None, 6),
            ManifestEntry("etc/cfg.txt", "reg", 0o644, 0, 0, 1, 4, T, 0, CONFIGS, 0, {}, None, sha(b"k=v\n"), 7),
            ManifestEntry("lnk", "lnk", 0o777, 0, 0, 1, 9, T, 0, VENDOR_FILE, 0, {}, "bin/hello", None, 8),
            ManifestEntry("dev/null", "chr", 0o666, 0, 0, 1, 0, T, 0, VENDOR_FILE, 0, {}, None, None, 9),
            ManifestEntry("dev", "dir", 0o755, 0, 0, 2, 4096, T, 0, VENDOR_FILE, 0, {}, None, None, 10),
        ]
        os.mkdir(os.path.join(self.root, "dev"))
        os.utime(os.path.join(self.root, "dev"), (T, T))
        fc.write_manifest(os.path.join(self.part, "manifest.tsv"), self.entries)
        write(os.path.join(self.part, "fs_config"), fc.write_fs_config(self.entries, "/vendor"))
        write(os.path.join(self.part, "file_contexts"), fc.write_file_contexts(self.entries, "/vendor"))
        write(os.path.join(self.part, "meta.json"), '{"mount_point": "/vendor"}')
        self.src = os.path.join(self.wd, "src")
        write(os.path.join(self.src, "hello.txt"), "new file\n")
        write(os.path.join(self.src, "tree", "a.txt"), "A\n")
        write(os.path.join(self.src, "tree", "sub", "b.sh"), "#!/bin/sh\n")
        os.chmod(os.path.join(self.src, "tree", "sub", "b.sh"), 0o755)
        os.symlink("a.txt", os.path.join(self.src, "tree", "l"))

    def manifest(self):
        return {e.path: e for e in fc.read_manifest(os.path.join(self.part, "manifest.tsv"))}

    def sidecars(self):
        return read(os.path.join(self.part, "fs_config")), read(os.path.join(self.part, "file_contexts"))

    def test_resync_noop_on_clean_tree(self):
        before = (read(os.path.join(self.part, "manifest.tsv")),) + self.sidecars()
        self.assertEqual(PartitionTree(self.part).resync(), [])
        self.assertEqual((read(os.path.join(self.part, "manifest.tsv")),) + self.sidecars(), before)
        self.assertEqual(PartitionTree(self.part).mount_point, "/vendor")

    def test_add_file_inherits_from_parent(self):
        m = Mods(files=[FilesMod("add", "vendor/etc/new/hello.txt", os.path.join(self.src, "hello.txt"))])
        report = apply_mods(self.wd, m)
        self.assertTrue(os.path.isfile(os.path.join(self.root, "etc", "new", "hello.txt")))
        man = self.manifest()
        d, f = man["etc/new"], man["etc/new/hello.txt"]
        self.assertEqual((d.type, d.mode, d.uid, d.gid, d.selinux, d.nlink), ("dir", 0o755, 0, 0, CONFIGS, 2))
        self.assertEqual((f.type, f.mode, f.uid, f.gid, f.selinux, f.caps, f.size, f.sha256),
                         ("reg", 0o644, 0, 0, CONFIGS, 0, 9, sha(b"new file\n")))
        self.assertEqual(man["etc"].nlink, 3)
        self.assertEqual(man["bin/hello"], self.entries[2])  # untouched entries survive verbatim
        self.assertEqual(man["dev/null"], self.entries[6])    # special files are kept
        fs_config, file_contexts = self.sidecars()
        self.assertIn("vendor/etc/new 0 0 0755 capabilities=0x0\n", fs_config)
        self.assertIn("vendor/etc/new/hello.txt 0 0 0644 capabilities=0x0\n", fs_config)
        self.assertIn("/vendor/etc/new  %s\n" % CONFIGS, file_contexts)
        self.assertIn("/vendor/etc/new/hello\\.txt  %s\n" % CONFIGS, file_contexts)
        self.assertIn("/vendor/vendor  %s\n" % VENDOR_FILE, file_contexts)
        self.assertEqual(fs_config, fc.write_fs_config(man.values(), "/vendor"))
        self.assertEqual(file_contexts, fc.write_file_contexts(man.values(), "/vendor"))
        ops = [(c.op, c.file) for c in report]
        self.assertIn(("add", "vendor/etc/new"), ops)
        self.assertIn(("add", "vendor/etc/new/hello.txt"), ops)
        self.assertIn(("sidecar", "vendor/manifest.tsv"), ops)
        self.assertIn(("sidecar", "vendor/fs_config"), ops)
        self.assertIn(("sidecar", "vendor/file_contexts"), ops)
        # idempotent
        self.assertEqual(apply_mods(self.wd, m), [])
        # changed source content -> replaced, hash updated
        write(os.path.join(self.src, "hello.txt"), "v2\n")
        report = apply_mods(self.wd, m)
        self.assertEqual([c.file for c in report if c.op == "add"], ["vendor/etc/new/hello.txt"])
        self.assertEqual(self.manifest()["etc/new/hello.txt"].sha256, sha(b"v2\n"))
        self.assertEqual(apply_mods(self.wd, m), [])

    def test_add_explicit_metadata_and_tree(self):
        m = Mods(files=[
            FilesMod("add", "vendor/bin/tool", os.path.join(self.src, "hello.txt"), uid=0, gid=2000, mode=0o750,
                     selinux="u:object_r:vendor_tool_exec:s0", caps=0x1000000),
            FilesMod("add", "vendor/etc/tree", os.path.join(self.src, "tree")),
        ])
        apply_mods(self.wd, m)
        man = self.manifest()
        t = man["bin/tool"]
        self.assertEqual((t.mode, t.uid, t.gid, t.selinux, t.caps), (0o750, 0, 2000, "u:object_r:vendor_tool_exec:s0", 0x1000000))
        self.assertEqual(man["etc/tree"].mode, 0o755)
        self.assertEqual(man["etc/tree"].selinux, CONFIGS)
        self.assertEqual(man["etc/tree"].nlink, 3)
        self.assertEqual(man["etc"].nlink, 3)
        self.assertEqual((man["etc/tree/a.txt"].mode, man["etc/tree/a.txt"].sha256), (0o644, sha(b"A\n")))
        self.assertEqual(man["etc/tree/sub/b.sh"].mode, 0o755)   # host x bit keeps the parent's exec bits
        self.assertEqual((man["etc/tree/l"].type, man["etc/tree/l"].target, man["etc/tree/l"].mode), ("lnk", "a.txt", 0o777))
        self.assertEqual(os.readlink(os.path.join(self.root, "etc", "tree", "l")), "a.txt")
        fs_config, _ = self.sidecars()
        self.assertIn("vendor/bin/tool 0 2000 0750 capabilities=0x1000000\n", fs_config)
        self.assertIn("vendor/etc/tree/sub/b.sh 0 0 0755 capabilities=0x0\n", fs_config)
        self.assertEqual(apply_mods(self.wd, m), [])

    def test_delete(self):
        m = Mods(files=[FilesMod("delete", "vendor/bin/hello"), FilesMod("delete", "vendor/lnk"),
                        FilesMod("delete", "vendor/nope", optional=True)])
        report = apply_mods(self.wd, m)
        self.assertFalse(os.path.lexists(os.path.join(self.root, "bin", "hello")))
        self.assertFalse(os.path.lexists(os.path.join(self.root, "lnk")))
        man = self.manifest()
        self.assertNotIn("bin/hello", man)
        self.assertNotIn("lnk", man)
        self.assertIn("bin", man)
        fs_config, file_contexts = self.sidecars()
        self.assertNotIn("bin/hello", fs_config)
        self.assertNotIn("bin/hello", file_contexts)
        self.assertIn("vendor/bin 0 2000 0755 capabilities=0x0\n", fs_config)
        self.assertEqual([c.file for c in report if c.op == "delete"], ["vendor/bin/hello", "vendor/lnk"])
        # a delete of a now-missing path fails loudly unless optional; optional deletes are idempotent
        with self.assertRaises(ModsError):
            apply_mods(self.wd, m)
        for f in m.files:
            f.optional = True
        self.assertEqual(apply_mods(self.wd, m), [])
        # deleting a directory removes the subtree from the manifest
        m = Mods(files=[FilesMod("delete", "vendor/etc", optional=True)])
        report = apply_mods(self.wd, m)
        self.assertEqual([c.file for c in report if c.op == "delete"], ["vendor/etc", "vendor/etc/cfg.txt"])
        man = self.manifest()
        self.assertNotIn("etc", man)
        self.assertEqual(man[""].nlink, 4)  # 2 + bin, dev
        self.assertEqual(apply_mods(self.wd, m), [])
        # not optional and missing -> loud failure
        with self.assertRaises(ModsError):
            apply_mods(self.wd, Mods(files=[FilesMod("delete", "vendor/etc")]))
        with self.assertRaises(ModsError):
            apply_mods(self.wd, Mods(files=[FilesMod("add", "vendor/x", "/nonexistent/source")]))
        with self.assertRaises(ModsError):
            apply_mods(self.wd, Mods(files=[FilesMod("delete", "odm/x")]))

    def test_dry_run_writes_nothing(self):
        before = {p: read(os.path.join(self.part, p)) for p in ("manifest.tsv", "fs_config", "file_contexts")}
        m = Mods(files=[FilesMod("add", "vendor/etc/new/hello.txt", os.path.join(self.src, "hello.txt")),
                        FilesMod("delete", "vendor/bin/hello")])
        report = apply_mods(self.wd, m, dry_run=True)
        self.assertTrue(any(c.op == "add" for c in report))
        self.assertTrue(any(c.op == "delete" for c in report))
        self.assertTrue(any(c.op == "sidecar" for c in report))
        self.assertFalse(os.path.exists(os.path.join(self.root, "etc", "new")))
        self.assertTrue(os.path.isfile(os.path.join(self.root, "bin", "hello")))
        self.assertEqual({p: read(os.path.join(self.part, p)) for p in before}, before)

    def test_resync_picks_up_manual_edits(self):
        # content edited in place (as the fstab/props editors do) -> size/sha256 refreshed
        write(os.path.join(self.root, "etc", "cfg.txt"), "k=v\nx=y\n")
        # a file dropped into the tree by hand, and one removed by hand
        write(os.path.join(self.root, "etc", "extra.conf"), "e\n")
        os.unlink(os.path.join(self.root, "lnk"))
        report = PartitionTree(self.part).resync()
        man = self.manifest()
        self.assertEqual((man["etc/cfg.txt"].size, man["etc/cfg.txt"].sha256), (8, sha(b"k=v\nx=y\n")))
        self.assertEqual((man["etc/extra.conf"].mode, man["etc/extra.conf"].selinux, man["etc/extra.conf"].sha256),
                         (0o644, CONFIGS, sha(b"e\n")))
        self.assertNotIn("lnk", man)
        self.assertIn("dev/null", man)
        ops = {(c.op, c.file) for c in report}
        self.assertIn(("sidecar", "vendor/etc/cfg.txt"), ops)
        self.assertIn(("add", "vendor/etc/extra.conf"), ops)
        self.assertIn(("delete", "vendor/lnk"), ops)
        self.assertEqual(PartitionTree(self.part).resync(), [])
        fs_config, file_contexts = self.sidecars()
        self.assertEqual(fs_config, fc.write_fs_config(man.values(), "/vendor"))
        self.assertEqual(file_contexts, fc.write_file_contexts(man.values(), "/vendor"))

    def test_fstab_edit_resyncs_sidecars(self):
        write(os.path.join(self.root, "etc", "fstab.x"), "vendor\t/vendor\tf2fs\tro\twait,,avb,logical\n")
        PartitionTree(self.part).resync()
        old = self.manifest()["etc/fstab.x"]
        m = parse_mods({"fstab": [{"files": ["vendor/etc/fstab.x"], "mount_points": ["/vendor"], "remove_flags": ["avb"]}]})
        report = apply_mods(self.wd, m)
        self.assertEqual(read(os.path.join(self.root, "etc", "fstab.x")), "vendor\t/vendor\tf2fs\tro\twait,,logical\n")
        new = self.manifest()["etc/fstab.x"]
        self.assertNotEqual(old.sha256, new.sha256)
        self.assertEqual(new.size, len("vendor\t/vendor\tf2fs\tro\twait,,logical\n"))
        self.assertEqual({c.op for c in report}, {"fstab", "sidecar"})
        self.assertEqual(apply_mods(self.wd, m), [])


if __name__ == "__main__":
    unittest.main()
