"""Tests for superkit.fsconfig (DESIGN.md §7.5): manifest TSV round trip and diff,
canned fs_config and exact file_contexts writers/parsers, security.capability
codec, and an end-to-end make_f2fs + sload_f2fs build checked with dump.f2fs -i."""
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from superkit import fsconfig as fc
from superkit.fsconfig import ManifestEntry

TOOLS = ("make_f2fs", "sload_f2fs", "dump.f2fs")
HAVE_TOOLS = all(shutil.which(t) for t in TOOLS)
TMP_BASE = "/home/bigdihh/Documents/A137F-super/work/tmp/tests"


def sample_entries():
    return [
        ManifestEntry("", "dir", 0o755, 0, 0, 4, 4096, 1230768000, 0, "u:object_r:vendor_file:s0", 0, {}, None, None, 3),
        ManifestEntry("bin", "dir", 0o755, 0, 2000, 2, 4096, 1230768000, 0, "u:object_r:vendor_file:s0", 0, {}, None, None, 4),
        ManifestEntry("bin/hello", "reg", 0o4755, 0, 2000, 1, 6, 1230768000, 123456789, "u:object_r:vendor_hello_exec:s0",
                      0x1000000, {"user.x": b"\x00\xff"}, None, "a" * 64, 5),
        ManifestEntry("etc/cfg.txt", "reg", 0o640, 1000, 1001, 1, 2, 1230768001, 0, "u:object_r:vendor_configs_file:s0", 0, {}, None, "b" * 64, 6),
        ManifestEntry("etc", "dir", 0o755, 0, 0, 2, 4096, 1230768000, 0, "u:object_r:vendor_configs_file:s0", 0, {}, None, None, 7),
        ManifestEntry("lnk", "lnk", 0o777, 0, 0, 1, 9, 1230768000, 0, "u:object_r:vendor_file:s0", 0, {}, "bin/hello", None, 8),
        ManifestEntry("dev/null", "chr", 0o666, 0, 0, 1, 0, 1230768000, 0, None, 0, {}, None, None, 9),
    ]


class ManifestEntryTest(unittest.TestCase):
    def test_validation(self):
        with self.assertRaises(ValueError):
            ManifestEntry("/abs", "reg", 0o644)
        with self.assertRaises(ValueError):
            ManifestEntry("a/", "dir", 0o755)
        with self.assertRaises(ValueError):
            ManifestEntry("./a", "reg", 0o644)
        with self.assertRaises(ValueError):
            ManifestEntry("a//b", "reg", 0o644)
        with self.assertRaises(ValueError):
            ManifestEntry("a", "reg", 0o100644)  # type bits not allowed
        with self.assertRaises(ValueError):
            ManifestEntry("a", "file", 0o644)
        with self.assertRaises(ValueError):
            ManifestEntry("a", "lnk", 0o777)  # no target
        with self.assertRaises(ValueError):
            ManifestEntry("a", "reg", 0o644, target="x")
        e = ManifestEntry("a/b", "lnk", 0o777, target="../c")
        self.assertEqual((e.name, e.parent, e.is_root, e.full_mode), ("b", "a", False, 0o120777))
        root = ManifestEntry("", "dir", 0o755)
        self.assertEqual((root.name, root.parent, root.is_root), ("", None, True))
        self.assertEqual(ManifestEntry("x", "dir", 0o755).parent, "")

    def test_type_helpers(self):
        self.assertEqual(fc.type_from_mode(0o100644), "reg")
        self.assertEqual(fc.type_from_mode(0o40755), "dir")
        self.assertEqual(fc.type_from_mode(0o120777), "lnk")
        self.assertEqual(fc.type_from_mode(0o20666), "chr")
        self.assertEqual(fc.type_from_mode(0o60660), "blk")
        self.assertEqual(fc.type_from_mode(0o10644), "fifo")
        self.assertEqual(fc.type_from_mode(0o140755), "sock")
        self.assertEqual(fc.mode_bits_from_mode(0o104755), 0o4755)
        with self.assertRaises(ValueError):
            fc.type_from_mode(0o644)


class ManifestTsvTest(unittest.TestCase):
    def test_round_trip_basic(self):
        entries = sample_entries()
        text = fc.manifest_to_text(entries)
        lines = text.splitlines()
        self.assertTrue(lines[0].startswith("#superkit-manifest"))
        self.assertEqual(lines[1].split("\t"), list(fc.MANIFEST_FIELDS))
        back = fc.manifest_from_text(text)
        self.assertEqual(sorted(entries, key=lambda e: e.path), back)
        # mode is octal, caps hex, None is '-'
        row = dict(zip(fc.MANIFEST_FIELDS, lines[2].split("\t")))  # root (path '')
        self.assertEqual(row["path"], "")
        self.assertEqual(row["mode"], "0755")
        self.assertEqual(row["target"], "-")
        hello = [l for l in lines if l.startswith("bin/hello\t")][0]
        row = dict(zip(fc.MANIFEST_FIELDS, hello.split("\t")))
        self.assertEqual(row["mode"], "4755")
        self.assertEqual(row["caps"], "0x1000000")
        self.assertEqual(row["xattrs"], "user.x=00ff")
        self.assertEqual(row["mtime_ns"], "123456789")

    def test_round_trip_nasty_strings(self):
        nasty = "a\tb\nc\\d\re -f\x01ü\udcff"   # tab, newline, backslash, CR, leading-dash-ish, control, unicode, surrogate
        entries = [
            ManifestEntry("", "dir", 0o755, selinux="u:object_r:rootfs:s0"),
            ManifestEntry(nasty, "lnk", 0o777, target="-" + nasty, selinux="-"),
            ManifestEntry("-dash", "reg", 0o644, selinux=None, sha256=None, xattrs={"user.a=b;c\t": b"\x00", "trusted.z": b""}),
            ManifestEntry("empty-label", "reg", 0o644, selinux=""),
        ]
        text = fc.manifest_to_text(entries)
        self.assertEqual(len(text.splitlines()), 2 + len(entries))  # no embedded newlines
        back = fc.manifest_from_text(text)
        self.assertEqual(sorted(entries, key=lambda e: e.path), back)
        by_path = {e.path: e for e in back}
        self.assertIsNone(by_path["-dash"].selinux)
        self.assertEqual(by_path["-dash"].xattrs, {"user.a=b;c\t": b"\x00", "trusted.z": b""})
        self.assertEqual(by_path["empty-label"].selinux, "")
        self.assertEqual(by_path[nasty].selinux, "-")
        self.assertEqual(by_path[nasty].target, "-" + nasty)

    def test_file_round_trip_with_surrogates(self):
        os.makedirs(TMP_BASE, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=TMP_BASE) as d:
            p = os.path.join(d, "manifest.tsv")
            entries = [ManifestEntry("", "dir", 0o755), ManifestEntry(os.fsdecode(b"bad\xff\xfename"), "reg", 0o644)]
            fc.write_manifest(p, entries)
            with open(p, "rb") as f:
                raw = f.read()
            self.assertIn(b"bad\xff\xfename", raw)
            self.assertEqual(fc.read_manifest(p), entries)
            # also via file objects
            buf = io.StringIO()
            fc.write_manifest(buf, entries)
            self.assertEqual(fc.read_manifest(io.StringIO(buf.getvalue())), entries)

    def test_errors(self):
        with self.assertRaises(ValueError):
            fc.manifest_from_text("")
        with self.assertRaises(ValueError):
            fc.manifest_from_text("not\ta\theader\n")
        header = "\t".join(fc.MANIFEST_FIELDS)
        with self.assertRaises(ValueError):
            fc.manifest_from_text(header + "\nonly\tthree\tfields\n")
        with self.assertRaises(ValueError):
            fc._unescape("bad\\q")
        # unknown extra column is tolerated, missing optional columns default
        text = "path\ttype\tmode\tuid\tgid\tnlink\tsize\tmtime\tfuture\n" + "a\treg\t0644\t0\t0\t1\t0\t5\tzzz\n"
        e = fc.manifest_from_text(text)[0]
        self.assertEqual((e.path, e.mode, e.mtime, e.mtime_ns, e.selinux, e.caps, e.ino), ("a", 0o644, 5, 0, None, 0, 0))


class ManifestDiffTest(unittest.TestCase):
    def test_diff(self):
        a = sample_entries()
        b = [e.copy() for e in a]
        self.assertFalse(fc.manifest_diff(a, b))
        self.assertTrue(fc.manifest_diff(a, b).is_empty)
        b[2] = b[2].copy(mode=0o755, caps=0, ino=99, sha256=None)
        b[3] = b[3].copy(selinux="u:object_r:other:s0", xattrs={"user.q": b"1"})
        del b[5]  # lnk
        b.append(ManifestEntry("new", "reg", 0o600))
        d = fc.manifest_diff(a, b, ignore=("ino",))
        self.assertEqual([e.path for e in d.only_in_a], ["lnk"])
        self.assertEqual([e.path for e in d.only_in_b], ["new"])
        changes = {(c.path, c.field): (c.a, c.b) for c in d.changed}
        self.assertEqual(changes, {
            ("bin/hello", "mode"): (0o4755, 0o755),
            ("bin/hello", "caps"): (0x1000000, 0),
            ("etc/cfg.txt", "selinux"): ("u:object_r:vendor_configs_file:s0", "u:object_r:other:s0"),
            ("etc/cfg.txt", "xattrs"): ({}, {"user.q": b"1"}),
        })  # sha256 None on one side is not a difference; ino ignored
        self.assertEqual(d.changed_paths(), ["bin/hello", "etc/cfg.txt"])
        self.assertIn("~ bin/hello: mode 04755 -> 0755", d.format())
        self.assertIn("- only in a: lnk (lnk)", d.format())
        d2 = fc.manifest_diff(a, b)
        self.assertIn(("bin/hello", "ino"), {(c.path, c.field) for c in d2.changed})
        with self.assertRaises(ValueError):
            fc.manifest_diff(a, b, ignore=("nonexistent",))


class FsConfigTest(unittest.TestCase):
    def test_write_vendor(self):
        text = fc.write_fs_config(sample_entries(), "/vendor")
        lines = text.splitlines()
        self.assertEqual(lines[0], "vendor 0 0 0755 capabilities=0x0")  # root entry, no leading slash
        self.assertIn("vendor/bin/hello 0 2000 4755 capabilities=0x1000000", lines)
        self.assertIn("vendor/etc/cfg.txt 1000 1001 0640 capabilities=0x0", lines)
        self.assertIn("vendor/lnk 0 0 0777 capabilities=0x0", lines)
        self.assertIn("vendor/dev/null 0 0 0666 capabilities=0x0", lines)
        for l in lines:   # the loader's lexical rules
            self.assertNotIn("\t", l)
            self.assertFalse(l.startswith("/") or l.startswith("#") or l == "")
            self.assertEqual(len(l.split(" ")), 5)
        self.assertTrue(text.endswith("\n"))

    def test_write_root_mount(self):
        entries = [ManifestEntry("", "dir", 0o755), ManifestEntry("system", "dir", 0o755),
                   ManifestEntry("system/bin/sh", "reg", 0o755, 0, 2000), ManifestEntry("init", "reg", 0o750)]
        text = fc.write_fs_config(entries, "/")
        self.assertEqual(text.splitlines(), [
            "init 0 0 0750 capabilities=0x0",
            "system 0 0 0755 capabilities=0x0",
            "system/bin/sh 0 2000 0755 capabilities=0x0",
        ])  # no root line for '/', paths without prefix
        self.assertEqual(fc.fs_config_path("", "/vendor"), "vendor")
        self.assertEqual(fc.fs_config_path("a/b", "/vendor/"), "vendor/a/b")
        self.assertEqual(fc.fs_config_path("a", "/"), "a")

    def test_write_errors(self):
        with self.assertRaises(ValueError):
            fc.write_fs_config([ManifestEntry("a b", "reg", 0o644)], "/vendor")
        with self.assertRaises(ValueError):
            fc.write_fs_config([ManifestEntry("a", "reg", 0o644, uid=70000)], "/vendor")
        with self.assertRaises(ValueError):
            fc.write_fs_config([], "vendor")
        with self.assertRaises(ValueError):
            fc.write_fs_config([], "/a/b")

    def test_parse_round_trip_and_tolerance(self):
        entries = sample_entries()
        parsed = fc.parse_fs_config(fc.write_fs_config(entries, "/vendor"))
        self.assertEqual(set(parsed), {fc.fs_config_path(e.path, "/vendor") for e in entries})
        h = parsed["vendor/bin/hello"]
        self.assertEqual((h.uid, h.gid, h.mode, h.caps), (0, 2000, 0o4755, 0x1000000))
        self.assertEqual(parsed["vendor"].mode, 0o755)
        # loader-compatible parsing: leading slash stripped, decimal/octal caps, extra tokens ignored,
        # and (beyond the loader) comments, blank lines, tabs, CRLF
        p = fc.parse_fs_config("# c\n\n/vendor/a\t0\t2000\t0750 foo capabilities=16777216 bar\r\nvendor/b 1 2 644\nvendor/b 3 4 0600 capabilities=010\n")
        self.assertEqual((p["vendor/a"].uid, p["vendor/a"].gid, p["vendor/a"].mode, p["vendor/a"].caps), (0, 2000, 0o750, 0x1000000))
        self.assertEqual((p["vendor/b"].uid, p["vendor/b"].mode, p["vendor/b"].caps), (3, 0o600, 8))  # last duplicate wins
        with self.assertRaises(ValueError):
            fc.parse_fs_config("vendor/a 0 0\n")
        with self.assertRaises(ValueError):
            fc.parse_fs_config("vendor/a root root 0644\n")


class FileContextsTest(unittest.TestCase):
    def test_escape(self):
        esc = fc.escape_file_contexts_path
        self.assertEqual(esc("/vendor/bin/hello_world-1"), "/vendor/bin/hello_world-1")
        self.assertEqual(esc("/v/a.b"), "/v/a\\.b")
        self.assertEqual(esc("/v/c++"), "/v/c\\+\\+")
        self.assertEqual(esc("/v/d(1)[2]{3}*?$^|\\"), "/v/d\\(1\\)\\[2\\]\\{3\\}\\*\\?\\$\\^\\|\\\\")
        self.assertEqual(esc("/v/a b#c~d=e%f,g:h@i"), "/v/a\\x20b\\x23c\\x7ed\\x3de\\x25f\\x2cg\\x3ah\\x40i")
        self.assertEqual(esc("/v/ü"), "/v/\\xc3\\xbc")
        self.assertEqual(esc("/v/" + os.fsdecode(b"\xff")), "/v/\\xff")
        self.assertTrue(esc("/v/\x01\n\t").isascii())
        for s in ("/vendor/bin/hello", "/v/a.b", "/v/c++", "/v/d(1)[2]{3}*?$^|\\", "/v/a b#c~d", "/v/ü", "/v/" + os.fsdecode(b"\xff\xfe"), "/v/\x01\n"):
            self.assertEqual(fc.unescape_file_contexts_pattern(esc(s)), s)
        self.assertIsNone(fc.unescape_file_contexts_pattern("/vendor(/.*)?"))
        self.assertIsNone(fc.unescape_file_contexts_pattern("/vendor/a.b"))
        self.assertIsNone(fc.unescape_file_contexts_pattern("/vendor/a\\sb"))
        self.assertEqual(fc.unescape_file_contexts_pattern("/v/\\x{c3}\\x{bc}"), "/v/ü")

    def test_write_vendor(self):
        text = fc.write_file_contexts(sample_entries(), "/vendor")
        lines = text.splitlines()
        self.assertEqual(lines, [
            "/vendor  u:object_r:vendor_file:s0",
            "/vendor/bin  u:object_r:vendor_file:s0",
            "/vendor/bin/hello  u:object_r:vendor_hello_exec:s0",
            "/vendor/etc  u:object_r:vendor_configs_file:s0",
            "/vendor/etc/cfg\\.txt  u:object_r:vendor_configs_file:s0",
            "/vendor/lnk  u:object_r:vendor_file:s0",
            "/vendor/vendor  u:object_r:vendor_file:s0",   # sload's root lookup key
        ])  # dev/null (selinux None) skipped; sorted; exact escaped lines
        self.assertEqual(fc.root_context_keys("/vendor"), ["/vendor", "/vendor/vendor"])
        self.assertEqual(fc.root_context_keys("/"), ["/"])
        self.assertEqual(fc.file_contexts_path("", "/"), "/")
        self.assertEqual(fc.file_contexts_path("a", "/"), "/a")
        self.assertEqual(fc.file_contexts_path("", "/vendor/"), "/vendor")

    def test_write_root_mount_and_collision(self):
        entries = [ManifestEntry("", "dir", 0o755, selinux="u:object_r:rootfs:s0"),
                   ManifestEntry("system", "dir", 0o755, selinux="u:object_r:system_file:s0"),
                   ManifestEntry("system/bin/sh", "reg", 0o755, selinux="u:object_r:shell_exec:s0")]
        self.assertEqual(fc.write_file_contexts(entries, "/").splitlines(), [
            "/  u:object_r:rootfs:s0",
            "/system  u:object_r:system_file:s0",
            "/system/bin/sh  u:object_r:shell_exec:s0",
        ])
        ok = [ManifestEntry("", "dir", 0o755, selinux="u:object_r:R:s0"), ManifestEntry("vendor", "reg", 0o644, selinux="u:object_r:R:s0")]
        self.assertEqual(fc.write_file_contexts(ok, "/vendor").splitlines(), ["/vendor  u:object_r:R:s0", "/vendor/vendor  u:object_r:R:s0"])
        bad = [ManifestEntry("", "dir", 0o755, selinux="u:object_r:R:s0"), ManifestEntry("vendor", "reg", 0o644, selinux="u:object_r:X:s0")]
        with self.assertRaises(ValueError):
            fc.write_file_contexts(bad, "/vendor")
        with self.assertRaises(ValueError):
            fc.write_file_contexts([ManifestEntry("a", "reg", 0o644, selinux="u:object_r:x y:s0")], "/vendor")

    def test_parse_round_trip(self):
        entries = sample_entries()
        lines = fc.parse_file_contexts(fc.write_file_contexts(entries, "/vendor"))
        got = {fc.unescape_file_contexts_pattern(l.pattern): l.label for l in lines}
        want = {fc.file_contexts_path(e.path, "/vendor"): e.selinux for e in entries if e.selinux}
        want["/vendor/vendor"] = want["/vendor"]
        self.assertEqual(got, want)
        self.assertTrue(all(l.ftype is None for l in lines))
        parsed = fc.parse_file_contexts("# c\n\n/vendor(/.*)?\tu:object_r:vendor_file:s0\n/vendor/l -l u:object_r:L:s0\n")
        self.assertEqual([(l.pattern, l.ftype, l.label) for l in parsed],
                         [("/vendor(/.*)?", None, "u:object_r:vendor_file:s0"), ("/vendor/l", "-l", "u:object_r:L:s0")])
        with self.assertRaises(ValueError):
            fc.parse_file_contexts("/vendor/a b u:object_r:AB:s0\n")


class CapabilityTest(unittest.TestCase):
    STOCK_RUN_AS = bytes.fromhex("01000002c0000000000000000000000000000000")  # from stock system.img

    def test_v2_default(self):
        data = fc.encode_capabilities(0xc0)
        self.assertEqual(data, self.STOCK_RUN_AS)
        self.assertEqual(len(data), fc.XATTR_CAPS_SZ_2)
        v = fc.decode_vfs_cap(data)
        self.assertEqual((v.version, v.effective, v.permitted, v.inheritable, v.rootid, v.magic_etc),
                         (2, True, 0xc0, 0, 0, fc.VFS_CAP_REVISION_2 | fc.VFS_CAP_FLAGS_EFFECTIVE))
        self.assertEqual(fc.decode_capabilities(data), 0xc0)
        self.assertEqual(v.mask, 0xc0)

    def test_v2_high_bits_and_flags(self):
        mask = (1 << 40) | (1 << 24) | 1   # CAP_BLOCK_SUSPEND-ish high word + CAP_SYS_RESOURCE + CAP_CHOWN
        data = fc.encode_capabilities(mask, effective=False, inheritable=0x3 | (1 << 33))
        self.assertEqual(data[:4], bytes.fromhex("00000002"))
        self.assertEqual(fc.decode_capabilities(data), mask)
        v = fc.decode_vfs_cap(data)
        self.assertEqual((v.effective, v.inheritable), (False, 0x3 | (1 << 33)))

    def test_v3_and_v1(self):
        data = fc.encode_capabilities(0x1000000, version=3, rootid=1000)
        self.assertEqual(len(data), fc.XATTR_CAPS_SZ_3)
        self.assertEqual(data[:4], bytes.fromhex("01000003"))
        v = fc.decode_vfs_cap(data)
        self.assertEqual((v.version, v.rootid, v.permitted, v.effective), (3, 1000, 0x1000000, True))
        self.assertEqual(fc.decode_capabilities(data), 0x1000000)
        d1 = fc.encode_capabilities(0x40, version=1, effective=False)
        self.assertEqual(len(d1), fc.XATTR_CAPS_SZ_1)
        self.assertEqual(fc.decode_vfs_cap(d1).version, 1)
        self.assertEqual(fc.decode_capabilities(d1), 0x40)

    def test_errors(self):
        with self.assertRaises(ValueError):
            fc.decode_capabilities(b"\x01\x00\x00\x02" + b"\x00" * 10)
        with self.assertRaises(ValueError):
            fc.decode_capabilities(b"\x00\x00\x00\x09" + b"\x00" * 16)
        with self.assertRaises(ValueError):
            fc.encode_capabilities(1 << 64)
        with self.assertRaises(ValueError):
            fc.encode_capabilities(1 << 33, version=1)
        with self.assertRaises(ValueError):
            fc.encode_capabilities(1, version=4)


# --------------------------------------------------------------------------- end to end

def dump_inode(img, nid, cwd):
    """Fields and xattrs of inode `nid` via `dump.f2fs -N -i` (prints, dumps nothing to disk)."""
    p = subprocess.run(["dump.f2fs", "-N", "-i", str(nid), img], capture_output=True, text=True,
                       stdin=subprocess.DEVNULL, cwd=cwd)
    out = p.stdout + p.stderr
    if "is inode" not in out:
        return None
    d = {}
    for m in re.finditer(r"^(i_\w+)\s+\[0x\s*[0-9a-f]+ : (\d+)\]", out, re.M):
        d.setdefault(m.group(1), int(m.group(2)))
    m = re.search(r"^i_name\s+\[(.*)\]$", out, re.M)
    d["name"] = m.group(1) if m else ""
    d["xattrs"] = {}
    for m in re.finditer(r"xattr: e_name_index:(\d+) e_name:(\S+) e_name_len:\d+ e_value_size:\d+ e_value:\n([0-9A-F]*)", out):
        d["xattrs"][(int(m.group(1)), m.group(2))] = bytes.fromhex(m.group(3))
    return d


def inode_table(img, cwd):
    rows = {}
    nid, miss = 3, 0
    while miss < 8:
        d = dump_inode(img, nid, cwd)
        if d is None:
            miss += 1
        else:
            miss = 0
            rows[nid] = d
        nid += 1
    # path reconstruction via i_pino
    paths = {3: ""}
    pending = dict(rows)
    pending.pop(3)
    while pending:
        progressed = False
        for nid, d in list(pending.items()):
            if d["i_pino"] in paths:
                paths[nid] = (paths[d["i_pino"]] + "/" + d["name"]).lstrip("/")
                pending.pop(nid)
                progressed = True
        if not progressed:
            raise AssertionError("orphan inodes: %r" % pending)
    return {paths[nid]: d for nid, d in rows.items()}


@unittest.skipUnless(HAVE_TOOLS, "needs make_f2fs, sload_f2fs and dump.f2fs on PATH")
class EndToEndTest(unittest.TestCase):
    """Generate a tree, write both sidecars from a hand-built manifest, build an image with
    make_f2fs + sload_f2fs and verify with dump.f2fs -i that modes/uids/gids/labels match."""

    def setUp(self):
        os.makedirs(TMP_BASE, exist_ok=True)
        self.dir = tempfile.mkdtemp(prefix="fsconfig_e2e_", dir=TMP_BASE)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_build_and_verify(self):
        T = 1230768000
        src = os.path.join(self.dir, "src")
        tree = {
            "bin": None, "bin/hello": b"hello\n", "bin/c++": b"x", "etc": None, "etc/a.b": b"ab",
            "etc/d(1)[2]": b"d", "etc/sp ace": b"s", "etc/ü": b"u", "lib": None, "lib/libc.so": b"\x7fELF",
            "lnk": "bin/hello", "deep": None, "deep/er": None, "deep/er/file": b"",
        }
        for rel, content in tree.items():
            p = os.path.join(src, rel)
            if content is None:
                os.makedirs(p, exist_ok=True)
            elif isinstance(content, str):
                os.symlink(content, p)
            else:
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "wb") as f:
                    f.write(content)
        M = ManifestEntry
        entries = [
            M("", "dir", 0o755, 0, 0, selinux="u:object_r:vendor_file:s0"),
            M("bin", "dir", 0o755, 0, 2000, selinux="u:object_r:vendor_file:s0"),
            M("bin/hello", "reg", 0o4750, 0, 2000, selinux="u:object_r:vendor_hello_exec:s0", caps=0x1000000),
            M("bin/c++", "reg", 0o755, 1000, 1001, selinux="u:object_r:cpp_exec:s0"),
            M("etc", "dir", 0o750, 0, 1000, selinux="u:object_r:vendor_configs_file:s0"),
            M("etc/a.b", "reg", 0o640, 0, 0, selinux="u:object_r:adotb_file:s0"),
            M("etc/d(1)[2]", "reg", 0o600, 5, 6, selinux="u:object_r:d12_file:s0"),
            M("etc/sp ace", "reg", 0o644, 7, 8, selinux="u:object_r:space_file:s0"),
            M("etc/ü", "reg", 0o604, 9, 10, selinux="u:object_r:ue_file:s0"),
            M("lib", "dir", 0o755, 0, 0, selinux="u:object_r:vendor_file:s0"),
            M("lib/libc.so", "reg", 0o644, 0, 0, selinux="u:object_r:same_process_hal_file:s0"),
            M("lnk", "lnk", 0o777, 0, 0, selinux="u:object_r:vendor_link:s0", target="bin/hello"),
            M("deep", "dir", 0o711, 0, 0, selinux="u:object_r:vendor_file:s0"),
            M("deep/er", "dir", 0o700, 2, 3, selinux="u:object_r:deep_file:s0"),
            M("deep/er/file", "reg", 0o400, 65534, 65534, selinux="u:object_r:deep_file:s0"),
        ]
        # 'etc/sp ace' cannot be expressed in fs_config -> the writer refuses; build the sidecars without it
        with self.assertRaises(ValueError):
            fc.write_fs_config(entries, "/vendor")
        os.unlink(os.path.join(src, "etc/sp ace"))
        entries = [e for e in entries if e.path != "etc/sp ace"]
        fs_config = os.path.join(self.dir, "fs_config")
        file_contexts = os.path.join(self.dir, "file_contexts")
        with open(fs_config, "w", encoding="utf-8") as f:
            f.write(fc.write_fs_config(entries, "/vendor"))
        with open(file_contexts, "w", encoding="ascii") as f:   # must be pure ASCII for libselinux
            f.write(fc.write_file_contexts(entries, "/vendor"))
        img = os.path.join(self.dir, "vendor.img")
        with open(img, "wb") as f:
            f.truncate(64 << 20)
        r = subprocess.run(["make_f2fs", "-R", "0:0", "-T", str(T), "-l", "vendor", img], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = subprocess.run(["sload_f2fs", "-C", fs_config, "-s", file_contexts, "-t", "/vendor", "-T", str(T), "-f", src, img],
                           capture_output=True, text=True, stdin=subprocess.DEVNULL)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("Not enough space", r.stdout + r.stderr)
        self.assertNotIn("cannot lookup", r.stdout + r.stderr)

        table = inode_table(img, self.dir)
        self.assertEqual(set(table), {e.path for e in entries})
        for e in entries:
            d = table[e.path]
            with self.subTest(path=e.path):
                self.assertEqual(d["i_mode"], e.full_mode, "mode of %r" % e.path)
                self.assertEqual((d["i_uid"], d["i_gid"]), (e.uid, e.gid))
                self.assertEqual(d["i_mtime"], T)
                self.assertEqual(d["xattrs"].get((6, "selinux")), e.selinux.encode())
                if e.type == "lnk":
                    self.assertEqual(d["i_size"], len(e.target))
                # AOSP sload_f2fs 1.16 parses capabilities= but never writes security.capability
                # (docs/tooling-notes.md §3.1); the value only survives through fs_config/manifest.
                self.assertNotIn((6, "capability"), d["xattrs"])
        # fs_config round trip of what was fed to sload
        with open(fs_config, encoding="utf-8") as f:
            parsed = fc.parse_fs_config(f.read())
        self.assertEqual(parsed["vendor/bin/hello"].caps, 0x1000000)
        self.assertEqual(fc.decode_capabilities(fc.encode_capabilities(parsed["vendor/bin/hello"].caps)), 0x1000000)


if __name__ == "__main__":
    unittest.main()
