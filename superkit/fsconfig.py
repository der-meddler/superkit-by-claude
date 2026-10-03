"""Sidecar formats for superkit (DESIGN.md §4.1, §7.5).

* ``ManifestEntry`` – one row of ``manifest.tsv`` (every inode of a partition).
* ``write_manifest`` / ``read_manifest`` – TSV with a header line and
  backslash escaping that is safe for tabs, newlines, backslashes and non-UTF-8
  bytes (paths are ``str`` decoded with ``surrogateescape``).
* ``manifest_diff`` – structured comparison of two manifests.
* ``write_fs_config`` / ``parse_fs_config`` – the *canned* fs_config format that
  the AOSP ``sload_f2fs -C`` loader (libcutils ``load_canned_fs_config``)
  accepts.  Empirical rules (docs/tooling-notes.md §3.1): one entry per line,
  fields separated by single spaces (no tabs), ``<path> <uid> <gid> <mode>
  [capabilities=0x..]``, NO comments, NO blank lines, path without a leading
  slash (a leading slash is tolerated by the loader, so ``parse_fs_config``
  strips it), path must be exact (no ``./``, ``//`` or trailing ``/``), paths
  can not contain whitespace, mode is parsed as octal, uid/gid are truncated to
  16 bits by sload, every path that sload creates MUST have an entry (missing
  → fatal ``failed to find <path> in canned fs_config``), extra entries are
  harmless, the root entry is accepted but ignored (root owner/mode come from
  ``make_f2fs -R`` and are always 0755).  sload parses ``capabilities=`` but
  (AOSP 1.16 build) never writes the ``security.capability`` xattr; the value
  is kept in the file for the manifest round trip and for a future fix-up.
* ``write_file_contexts`` / ``parse_file_contexts`` – exact-path
  file_contexts for ``sload_f2fs -s``: one anchored, escaped line per path.
  The root inode is looked up by sload under ``<mount>/<basename(mount)>``
  (``/vendor/vendor`` for ``-t /vendor``; ``/`` for ``-t /``), so the root
  label is emitted under that key as well.
* ``encode_capabilities`` / ``decode_capabilities`` – ``security.capability``
  (``struct vfs_cap_data`` v2 and v3) as the kernel stores it.
"""
from __future__ import annotations

import io
import os
import re
import stat
import struct
from dataclasses import dataclass, field, fields, replace
from typing import Iterable, Iterator, TextIO

__all__ = [
    "ManifestEntry", "FILE_TYPES", "MANIFEST_FIELDS", "MANIFEST_VERSION",
    "type_from_mode", "mode_bits_from_mode",
    "write_manifest", "read_manifest", "manifest_to_text", "manifest_from_text",
    "manifest_diff", "ManifestDiff", "FieldChange",
    "write_fs_config", "parse_fs_config", "FsConfigEntry", "fs_config_path",
    "write_file_contexts", "parse_file_contexts", "FileContextLine",
    "file_contexts_path", "escape_file_contexts_path", "unescape_file_contexts_pattern",
    "root_context_keys",
    "encode_capabilities", "decode_capabilities", "decode_vfs_cap", "VfsCapData",
    "VFS_CAP_REVISION_1", "VFS_CAP_REVISION_2", "VFS_CAP_REVISION_3",
    "VFS_CAP_REVISION_MASK", "VFS_CAP_FLAGS_MASK", "VFS_CAP_FLAGS_EFFECTIVE",
    "XATTR_CAPS_SZ_2", "XATTR_CAPS_SZ_3",
]

MANIFEST_VERSION = 1
FILE_TYPES = ("reg", "dir", "lnk", "chr", "blk", "fifo", "sock")

_MODE_TO_TYPE = {
    stat.S_IFREG: "reg", stat.S_IFDIR: "dir", stat.S_IFLNK: "lnk", stat.S_IFCHR: "chr",
    stat.S_IFBLK: "blk", stat.S_IFIFO: "fifo", stat.S_IFSOCK: "sock",
}
_TYPE_TO_MODE = {v: k for k, v in _MODE_TO_TYPE.items()}


def type_from_mode(mode: int) -> str:
    """'reg'/'dir'/... from a full st_mode / f2fs i_mode (raises on unknown type)."""
    t = _MODE_TO_TYPE.get(stat.S_IFMT(mode))
    if t is None:
        raise ValueError("unknown file type in mode 0o%o" % mode)
    return t


def mode_bits_from_mode(mode: int) -> int:
    """Permission bits (incl. suid/sgid/sticky) of a full mode."""
    return mode & 0o7777


# --------------------------------------------------------------------------- manifest

@dataclass(slots=True)
class ManifestEntry:
    """One inode of a partition tree.

    path     relative to the partition root, no leading slash, '/' separated; '' is the root dir.
             Non-UTF-8 names are carried as surrogate escapes (os.fsdecode).
    type     one of FILE_TYPES
    mode     permission bits only (0..0o7777)
    uid, gid 32-bit owner ids as stored in the inode (sload truncates fs_config values to 16 bits)
    nlink    i_links as stored (dirs: 2 + subdirs); hard links share an ino and have nlink > 1
    size     i_size (bytes; symlinks: target length; dirs: dentry bytes)
    mtime    seconds; mtime_ns the nanosecond part (0..999_999_999)
    selinux  security.selinux value without the trailing NUL, or None if absent
    caps     capability mask (permitted bits of security.capability), 0 if absent
    xattrs   other xattrs: full name -> raw bytes (hex-encoded in the TSV)
    target   symlink target (lnk only) else None
    sha256   hex digest of file content (reg only; None if not computed / not a reg file)
    ino      inode number in the image it was read from (0 if unknown)
    """
    path: str
    type: str
    mode: int
    uid: int = 0
    gid: int = 0
    nlink: int = 1
    size: int = 0
    mtime: int = 0
    mtime_ns: int = 0
    selinux: str | None = None
    caps: int = 0
    xattrs: dict[str, bytes] = field(default_factory=dict)
    target: str | None = None
    sha256: str | None = None
    ino: int = 0

    def __post_init__(self) -> None:
        if self.type not in FILE_TYPES:
            raise ValueError("bad type %r for %r" % (self.type, self.path))
        if not 0 <= self.mode <= 0o7777:
            raise ValueError("mode 0o%o of %r has type bits or is out of range" % (self.mode, self.path))
        if self.path.startswith("/") or self.path in (".", "./") or self.path.startswith("./") \
                or "//" in self.path or self.path.endswith("/"):
            raise ValueError("manifest path must be relative, normalised and without trailing slash: %r" % self.path)
        if self.type == "lnk" and self.target is None:
            raise ValueError("symlink %r without target" % self.path)
        if self.type != "lnk" and self.target is not None:
            raise ValueError("target given for non-symlink %r" % self.path)
        if not 0 <= self.mtime_ns < 1_000_000_000:
            raise ValueError("mtime_ns out of range for %r" % self.path)

    @property
    def full_mode(self) -> int:
        """Mode with the S_IFMT type bits (what f2fs i_mode / stat would show)."""
        return _TYPE_TO_MODE[self.type] | self.mode

    @property
    def is_root(self) -> bool:
        return self.path == ""

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]

    @property
    def parent(self) -> str | None:
        if self.is_root:
            return None
        return self.path.rsplit("/", 1)[0] if "/" in self.path else ""

    def copy(self, **changes) -> "ManifestEntry":
        e = replace(self, **changes)
        e.xattrs = dict(e.xattrs)
        return e


MANIFEST_FIELDS = tuple(f.name for f in fields(ManifestEntry))
_INT_FIELDS = {"mode", "uid", "gid", "nlink", "size", "mtime", "mtime_ns", "caps", "ino"}
_OPT_STR_FIELDS = {"selinux", "target", "sha256"}

# TSV escaping: \t \n \r \\ are escaped with backslashes; the None marker is "-",
# so a literal "-" field is written as "\-".  An empty string is written as "".
_ESC = {"\\": "\\\\", "\t": "\\t", "\n": "\\n", "\r": "\\r"}
_UNESC = {"\\": "\\", "t": "\t", "n": "\n", "r": "\r", "-": "-"}


def _escape(s: str) -> str:
    out = "".join(_ESC.get(c, c) for c in s)
    if out.startswith("-"):
        out = "\\" + out
    return out


def _unescape(s: str) -> str:
    if "\\" not in s:
        return s
    out = []
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 1
            if i >= n:
                raise ValueError("dangling backslash in manifest field %r" % s)
            try:
                out.append(_UNESC[s[i]])
            except KeyError:
                raise ValueError("bad escape \\%s in manifest field %r" % (s[i], s)) from None
        else:
            out.append(c)
        i += 1
    return "".join(out)


def _fmt_field(name: str, v) -> str:
    if name == "mode":
        return "%04o" % v
    if name == "caps":
        return "0x%x" % v
    if name in _INT_FIELDS:
        return str(v)
    if name == "xattrs":
        if not v:
            return ""
        return ";".join("%s=%s" % (_escape(k).replace("=", "\\x3d").replace(";", "\\x3b"), bytes(val).hex())
                        for k, val in sorted(v.items()))
    if v is None:
        return "-"
    return _escape(v)


def _parse_field(name: str, s: str):
    if name == "mode":
        return int(s, 8)
    if name == "caps":
        return int(s, 0)
    if name in _INT_FIELDS:
        return int(s, 10)
    if name == "xattrs":
        d: dict[str, bytes] = {}
        if s:
            for item in s.split(";"):
                k, _, hx = item.partition("=")
                d[_unescape(k.replace("\\x3d", "=").replace("\\x3b", ";"))] = bytes.fromhex(hx)
        return d
    if s == "-" and (name in _OPT_STR_FIELDS):
        return None
    if s == "-":
        return None
    return _unescape(s)


def _entry_to_row(e: ManifestEntry) -> str:
    return "\t".join(_fmt_field(n, getattr(e, n)) for n in MANIFEST_FIELDS)


def _row_to_entry(row: str, header: list[str], lineno: int) -> ManifestEntry:
    parts = row.split("\t")
    if len(parts) != len(header):
        raise ValueError("manifest line %d: expected %d fields, got %d" % (lineno, len(header), len(parts)))
    kw = {}
    for name, s in zip(header, parts):
        if name not in MANIFEST_FIELDS:
            continue  # tolerate unknown (future) columns
        kw[name] = _parse_field(name, s)
    missing = set(MANIFEST_FIELDS) - set(kw)
    if missing - {"mtime_ns", "ino", "sha256", "xattrs", "caps", "selinux", "target"}:
        raise ValueError("manifest header lacks required columns: %s" % sorted(missing))
    return ManifestEntry(**kw)


def manifest_to_text(entries: Iterable[ManifestEntry]) -> str:
    """Serialise entries (sorted by path) as TSV text with a header line."""
    lines = ["#superkit-manifest\tv%d" % MANIFEST_VERSION, "\t".join(MANIFEST_FIELDS)]
    for e in sorted(entries, key=lambda e: e.path):
        lines.append(_entry_to_row(e))
    return "\n".join(lines) + "\n"


def manifest_from_text(text: str) -> list[ManifestEntry]:
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    it = iter(enumerate(lines, 1))
    header: list[str] | None = None
    entries: list[ManifestEntry] = []
    for lineno, line in it:
        if header is None:
            if line.startswith("#superkit-manifest"):
                continue
            header = line.split("\t")
            if "path" not in header or "type" not in header:
                raise ValueError("manifest line %d: not a manifest header: %r" % (lineno, line[:80]))
            continue
        if line == "":
            continue
        entries.append(_row_to_entry(line, header, lineno))
    if header is None:
        raise ValueError("empty manifest")
    return entries


def _open_text(path_or_file, mode: str):
    if isinstance(path_or_file, (str, bytes, os.PathLike)):
        return open(path_or_file, mode, encoding="utf-8", errors="surrogateescape", newline="")
    return _NoClose(path_or_file)


class _NoClose:
    def __init__(self, f):
        self.f = f

    def __enter__(self):
        return self.f

    def __exit__(self, *a):
        return False


def write_manifest(path_or_file, entries: Iterable[ManifestEntry]) -> None:
    with _open_text(path_or_file, "w") as f:
        f.write(manifest_to_text(entries))


def read_manifest(path_or_file) -> list[ManifestEntry]:
    with _open_text(path_or_file, "r") as f:
        return manifest_from_text(f.read())


# --------------------------------------------------------------------------- diff

@dataclass(slots=True)
class FieldChange:
    path: str
    field: str
    a: object
    b: object


@dataclass(slots=True)
class ManifestDiff:
    only_in_a: list[ManifestEntry] = field(default_factory=list)
    only_in_b: list[ManifestEntry] = field(default_factory=list)
    changed: list[FieldChange] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.only_in_a or self.only_in_b or self.changed)

    @property
    def is_empty(self) -> bool:
        return not self

    def changed_paths(self) -> list[str]:
        seen: dict[str, None] = {}
        for c in self.changed:
            seen.setdefault(c.path, None)
        return list(seen)

    def format(self, a_name: str = "a", b_name: str = "b") -> str:
        out = []
        for e in self.only_in_a:
            out.append("- only in %s: %s (%s)" % (a_name, e.path or "/", e.type))
        for e in self.only_in_b:
            out.append("+ only in %s: %s (%s)" % (b_name, e.path or "/", e.type))
        for c in self.changed:
            out.append("~ %s: %s %s -> %s" % (c.path or "/", c.field, _fmt_val(c.field, c.a), _fmt_val(c.field, c.b)))
        return "\n".join(out)


def _fmt_val(name: str, v):
    if name == "mode" and isinstance(v, int):
        return "0%o" % v
    if name == "caps" and isinstance(v, int):
        return "0x%x" % v
    if isinstance(v, dict):
        return "{%s}" % ", ".join("%s=%s" % (k, val.hex()) for k, val in sorted(v.items()))
    return repr(v)


def manifest_diff(a: Iterable[ManifestEntry], b: Iterable[ManifestEntry],
                  ignore: Iterable[str] = ()) -> ManifestDiff:
    """Compare two manifests by path.

    ``ignore`` lists field names that are not compared (e.g. ``("ino", "mtime", "mtime_ns")``).
    ``sha256`` is compared only when both sides have a value.
    """
    ignore = set(ignore)
    bad = ignore - set(MANIFEST_FIELDS)
    if bad:
        raise ValueError("unknown manifest fields in ignore: %s" % sorted(bad))
    da = {e.path: e for e in a}
    db = {e.path: e for e in b}
    d = ManifestDiff()
    for p in sorted(set(da) - set(db)):
        d.only_in_a.append(da[p])
    for p in sorted(set(db) - set(da)):
        d.only_in_b.append(db[p])
    for p in sorted(set(da) & set(db)):
        ea, eb = da[p], db[p]
        for name in MANIFEST_FIELDS:
            if name == "path" or name in ignore:
                continue
            va, vb = getattr(ea, name), getattr(eb, name)
            if name == "sha256" and (va is None or vb is None):
                continue
            if va != vb:
                d.changed.append(FieldChange(p, name, va, vb))
    return d


# --------------------------------------------------------------------------- fs_config

@dataclass(slots=True)
class FsConfigEntry:
    path: str      # canned path (no leading slash), e.g. 'vendor/bin/sh'; '' is impossible, root is 'vendor'
    uid: int
    gid: int
    mode: int      # permission bits (octal in the file)
    caps: int = 0


def _mount_prefix(mount_point: str) -> str:
    if not mount_point.startswith("/"):
        raise ValueError("mount point must be absolute (sload -t), got %r" % mount_point)
    prefix = mount_point.strip("/")
    if "/" in prefix:
        raise ValueError("nested mount points are not supported: %r" % mount_point)
    return prefix


def fs_config_path(path: str, mount_point: str) -> str:
    """Canned fs_config key of a manifest path: '<mnt>/<path>' without leading slash."""
    prefix = _mount_prefix(mount_point)
    if path == "":
        return prefix
    return prefix + "/" + path if prefix else path


_WS_RE = re.compile(r"[\s]")


def write_fs_config(entries: Iterable[ManifestEntry], mount_point: str) -> str:
    """Canned fs_config text for ``sload_f2fs -C``.

    Every entry (all types; sload ignores entries for files it does not create and
    skips special files) gets ``<mnt>/<path> <uid> <gid> <mode> capabilities=0x<caps>``.
    The root entry (``<mnt>`` alone) is written for completeness except for
    mount point ``/`` where it cannot be expressed (and sload ignores it anyway).
    Paths containing whitespace cannot be represented → ValueError.
    """
    _mount_prefix(mount_point)
    lines = []
    for e in sorted(entries, key=lambda e: e.path):
        key = fs_config_path(e.path, mount_point)
        if key == "":
            continue
        if _WS_RE.search(key):
            raise ValueError("fs_config cannot represent a path with whitespace: %r" % e.path)
        if e.uid > 0xFFFF or e.gid > 0xFFFF:
            raise ValueError("uid/gid %d:%d of %r exceed 16 bits (sload truncates fs_config ids)" % (e.uid, e.gid, e.path))
        lines.append("%s %d %d %04o capabilities=0x%x" % (key, e.uid, e.gid, e.mode, e.caps))
    return "".join(l + "\n" for l in lines)


def _c_strtoll(s: str) -> int:
    """Like C strtoll(s, NULL, 0): 0x → hex, leading 0 → octal, else decimal (stops at junk)."""
    m = re.match(r"\s*([+-]?)(0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*)", s)
    if not m:
        return 0
    sign, num = m.groups()
    if num[:2].lower() == "0x":
        v = int(num[2:], 16)
    elif num.startswith("0") and len(num) > 1:
        v = int(num[1:], 8)
    else:
        v = int(num, 10)
    return -v if sign == "-" else v


def parse_fs_config(text: str) -> dict[str, FsConfigEntry]:
    """Parse canned fs_config like libcutils does (space separated, mode octal,
    capabilities with base-0 int), plus tolerance for a leading slash, tabs,
    comments and blank lines.  Returns {path: FsConfigEntry}; a later duplicate
    replaces an earlier one (sload's own behaviour for duplicates is undefined).
    """
    out: dict[str, FsConfigEntry] = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        toks = line.split()
        if len(toks) < 4:
            raise ValueError("fs_config line %d: need 'path uid gid mode': %r" % (lineno, raw))
        path = toks[0]
        if path.startswith("/"):
            path = path[1:]
        caps = 0
        for t in toks[4:]:
            if t.startswith("capabilities="):
                caps = _c_strtoll(t[len("capabilities="):])
                break
        try:
            uid, gid, mode = int(toks[1], 10), int(toks[2], 10), int(toks[3], 8)
        except ValueError as ex:
            raise ValueError("fs_config line %d: %s" % (lineno, ex)) from None
        out[path] = FsConfigEntry(path, uid, gid, mode, caps)
    return out


# --------------------------------------------------------------------------- file_contexts

@dataclass(slots=True)
class FileContextLine:
    pattern: str            # regex as written (escaped)
    ftype: str | None       # '-l', '--', '-d', ... or None
    label: str              # e.g. 'u:object_r:vendor_file:s0' or '<<none>>'


_FC_SAFE = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-")
_FC_BACKSLASH = frozenset(b".+()[]{}*?$^|\\")


def escape_file_contexts_path(path: str) -> str:
    """Escape a path so that, as a file_contexts regex, it matches exactly itself.

    Verified against the AOSP libselinux (pcre2) used by sload_f2fs: the regex
    metacharacters ``. + ( ) [ ] { } * ? $ ^ | \\`` get a backslash, every other
    byte outside ``[A-Za-z0-9/_-]`` (space, ``#``, ``~``, non-ASCII, …) is written
    as ``\\xHH`` (works for all bytes; file_contexts itself must stay ASCII).
    """
    out = []
    for b in os.fsencode(path):
        if b in _FC_SAFE:
            out.append(chr(b))
        elif b in _FC_BACKSLASH:
            out.append("\\" + chr(b))
        else:
            out.append("\\x%02x" % b)
    return "".join(out)


_UNESC_RE = re.compile(r"\\x([0-9a-fA-F]{2})|\\x\{([0-9a-fA-F]{1,2})\}|\\(.)|(.)", re.S)
_META = set(".+()[]{}*?$^|")


def unescape_file_contexts_pattern(pattern: str) -> str | None:
    """Inverse of escape_file_contexts_path; None if the pattern is not an exact path
    (contains an unescaped regex metacharacter)."""
    out = bytearray()
    for m in _UNESC_RE.finditer(pattern):
        hx, hx2, esc, plain = m.groups()
        if hx is not None:
            out.append(int(hx, 16))
        elif hx2 is not None:
            out.append(int(hx2, 16))
        elif esc is not None:
            if esc.isalnum():      # \d \s \w … are classes, not literals
                return None
            out.extend(esc.encode("latin-1"))
        else:
            if plain in _META:
                return None
            out.extend(plain.encode("utf-8", "surrogateescape"))
    return os.fsdecode(bytes(out))


def file_contexts_path(path: str, mount_point: str) -> str:
    """Absolute (unescaped) path of a manifest entry: '/vendor/bin/sh', root → '/vendor'."""
    if not mount_point.startswith("/"):
        raise ValueError("mount point must be absolute, got %r" % mount_point)
    mp = mount_point.rstrip("/")
    if path == "":
        return mp or "/"
    return mp + "/" + path


def root_context_keys(mount_point: str) -> list[str]:
    """Paths under which sload_f2fs looks up the ROOT inode's label.

    sload builds the key as ``mount_point + mount_point`` and libselinux collapses
    duplicate slashes: ``-t /`` → ``/``; ``-t /vendor`` → ``/vendor/vendor``.
    The conventional ``/vendor`` line is returned too (for other consumers).
    """
    mp = mount_point.rstrip("/")
    if mp == "":
        return ["/"]
    return [mp, mp + mp]


def write_file_contexts(entries: Iterable[ManifestEntry], mount_point: str) -> str:
    """Exact-match file_contexts for ``sload_f2fs -s``.

    One line ``<escaped abs path>  <label>`` per entry that has a label (entries
    with ``selinux=None`` are skipped – sload then fails with "cannot lookup
    security context" for them, so a caller must label everything).  Exact lines
    take precedence over regex lines in libselinux, and among exact lines the
    last one wins, so order does not matter; lines are sorted by path.
    The root label is emitted under every key of ``root_context_keys``; a real
    entry that collides with such a key must carry the same label (ValueError).
    """
    entries = sorted(entries, key=lambda e: e.path)
    root_keys = root_context_keys(mount_point)
    labels: dict[str, str] = {}
    root_label = None
    for e in entries:
        if e.selinux is None:
            continue
        if "\n" in e.selinux or " " in e.selinux or "\t" in e.selinux:
            raise ValueError("bad SELinux label %r for %r" % (e.selinux, e.path))
        if e.is_root:
            root_label = e.selinux
            continue
        labels[file_contexts_path(e.path, mount_point)] = e.selinux
    if root_label is not None:
        for k in root_keys:
            if k in labels and labels[k] != root_label:
                raise ValueError("%s is both the root lookup key (label %s) and a real entry (label %s)"
                                 % (k, root_label, labels[k]))
            labels[k] = root_label
    return "".join("%s  %s\n" % (escape_file_contexts_path(p), labels[p]) for p in sorted(labels))


def parse_file_contexts(text: str) -> list[FileContextLine]:
    """Parse file_contexts lines (``pattern [-type] label``; ``#`` comments, blank lines)."""
    out = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        toks = line.split()
        if len(toks) == 2:
            out.append(FileContextLine(toks[0], None, toks[1]))
        elif len(toks) == 3 and toks[1].startswith("-") and len(toks[1]) == 2:
            out.append(FileContextLine(toks[0], toks[1], toks[2]))
        else:
            raise ValueError("file_contexts line %d: cannot parse %r" % (lineno, raw))
    return out


# --------------------------------------------------------------------------- security.capability

# include/uapi/linux/capability.h
VFS_CAP_REVISION_MASK = 0xFF000000
VFS_CAP_REVISION_SHIFT = 24
VFS_CAP_FLAGS_MASK = ~VFS_CAP_REVISION_MASK & 0xFFFFFFFF
VFS_CAP_FLAGS_EFFECTIVE = 0x000001
VFS_CAP_REVISION_1 = 0x01000000   # u32 permitted, u32 inheritable (8 + 4 bytes)
VFS_CAP_REVISION_2 = 0x02000000   # two u32 pairs: [0] = low 32 bits, [1] = high 32 bits (20 bytes)
VFS_CAP_REVISION_3 = 0x03000000   # v2 + u32 rootid (24 bytes); namespaced caps
XATTR_CAPS_SZ_1 = 12
XATTR_CAPS_SZ_2 = 20
XATTR_CAPS_SZ_3 = 24


@dataclass(slots=True)
class VfsCapData:
    version: int           # 1, 2 or 3
    effective: bool        # VFS_CAP_FLAGS_EFFECTIVE in magic_etc
    permitted: int         # 64-bit mask
    inheritable: int       # 64-bit mask
    rootid: int = 0        # v3 only (0 for v1/v2)
    magic_etc: int = 0     # raw header word

    @property
    def mask(self) -> int:
        return self.permitted


def encode_capabilities(mask: int, *, version: int = 2, effective: bool = True,
                        inheritable: int = 0, rootid: int = 0) -> bytes:
    """Encode a ``security.capability`` value.

    ``mask`` is the permitted set (the fs_config ``capabilities=`` value).  The
    default is what Android's build tools and the kernel write for file caps set
    from fs_config: **v2 with VFS_CAP_FLAGS_EFFECTIVE** (magic_etc 0x02000001),
    permitted = mask, inheritable = 0.  magic_etc layout: bits 31..24 revision,
    bits 23..0 flags (only bit 0 = effective is defined).
    """
    if not 0 <= mask < (1 << 64) or not 0 <= inheritable < (1 << 64):
        raise ValueError("capability masks are 64-bit")
    magic = (version << VFS_CAP_REVISION_SHIFT) | (VFS_CAP_FLAGS_EFFECTIVE if effective else 0)
    if version == 1:
        if mask >> 32 or inheritable >> 32:
            raise ValueError("v1 capability data is 32-bit")
        return struct.pack("<III", magic, mask, inheritable)
    if version == 2:
        return struct.pack("<IIIII", magic, mask & 0xFFFFFFFF, inheritable & 0xFFFFFFFF,
                           mask >> 32, inheritable >> 32)
    if version == 3:
        return struct.pack("<IIIIII", magic, mask & 0xFFFFFFFF, inheritable & 0xFFFFFFFF,
                           mask >> 32, inheritable >> 32, rootid)
    raise ValueError("unsupported vfs_cap_data version %d" % version)


def decode_vfs_cap(data: bytes) -> VfsCapData:
    """Decode raw ``security.capability`` bytes (v1, v2 or v3)."""
    if len(data) < 4:
        raise ValueError("security.capability too short: %d bytes" % len(data))
    magic = struct.unpack_from("<I", data, 0)[0]
    version = (magic & VFS_CAP_REVISION_MASK) >> VFS_CAP_REVISION_SHIFT
    effective = bool(magic & VFS_CAP_FLAGS_EFFECTIVE)
    if version == 1 and len(data) == XATTR_CAPS_SZ_1:
        _, p, i = struct.unpack("<III", data)
        return VfsCapData(1, effective, p, i, 0, magic)
    if version == 2 and len(data) == XATTR_CAPS_SZ_2:
        _, p0, i0, p1, i1 = struct.unpack("<IIIII", data)
        return VfsCapData(2, effective, p0 | (p1 << 32), i0 | (i1 << 32), 0, magic)
    if version == 3 and len(data) == XATTR_CAPS_SZ_3:
        _, p0, i0, p1, i1, rootid = struct.unpack("<IIIIII", data)
        return VfsCapData(3, effective, p0 | (p1 << 32), i0 | (i1 << 32), rootid, magic)
    raise ValueError("security.capability: unsupported version %d / length %d" % (version, len(data)))


def decode_capabilities(data: bytes) -> int:
    """Permitted capability mask of a raw ``security.capability`` value."""
    return decode_vfs_cap(data).permitted
