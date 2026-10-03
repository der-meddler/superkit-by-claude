"""mods.toml loader and dispatcher (DESIGN.md §4, ``superkit mod <workdir> <mods.toml>``).

Paths in a mods file are ``<part>/<path inside the partition>`` and resolve to
``<workdir>/<part>/root/<path>`` (DESIGN §4.1), e.g. ``vendor/etc/fstab.mt6768`` or
``system/system/build.prop``.

Sections (arrays of tables, applied in the order fstab → props → files; sidecars of
every touched partition are resynced at the end):

    [[fstab]]
    files = ["vendor/etc/fstab.mt6768", "vendor/etc/fstab.mt6769t"]
    mount_points = ["/system", "/vendor"]           # every fs-type variant of each mount point
    remove_flags = ["avb", "avb=*", "avb_keys=*"]    # glob patterns on the fs_mgr flags field
    add_flags = ["nofail"]                           # exact tokens; key=value replaces key=...
    remove_mount_options = ["inlinecrypt"]           # glob patterns on the mount options field
    add_mount_options = ["noatime"]
    fs_type = "f2fs"                                  # optional
    optional = false                                  # true: silently skip missing files

    [[props]]
    file = "system/system/build.prop"
    set = { "ro.adb.secure" = "0" }                   # replace or append (after `after` if given)
    remove = ["ro.foo"]
    append = { "ro.list" = "x" }                      # add an element to a separator-joined value
    separator = ","
    after = "ro.build.type"                           # anchor for new keys
    optional = false

    [[files]]
    action = "add"                                    # or "delete"
    path = "vendor/etc/hello.txt"                     # destination (add) / victim (delete)
    source = "/host/path/hello.txt"                   # file, symlink or directory tree (add only)
    mode = "0644"   uid = 0   gid = 2000              # optional, else inherited from the parent dir
    selinux = "u:object_r:vendor_configs_file:s0"     # optional, else inherited
    caps = "0x0"                                      # optional, default 0
    optional = false                                  # delete: ignore a missing path; add: missing source

Every operation is idempotent: applying the same mods twice yields an empty report the
second time.  Operations on files that do not exist raise ``ModsError`` unless
``optional = true`` — this includes a ``delete`` whose path is already gone, so mark
deletes ``optional = true`` in a mods file that is meant to be re-applied.
"""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from typing import Any, Mapping

from superkit.mods import fstab as fstab_mod
from superkit.mods import props as props_mod
from superkit.mods.files import PartitionTree
from superkit.mods.report import Change

__all__ = [
    "ModsError", "Mods", "FstabMod", "PropsMod", "FilesMod", "Change",
    "load_mods", "parse_mods", "apply_mods", "split_part_path", "format_report",
]


class ModsError(ValueError):
    """Bad mods file or an operation that cannot be applied."""


@dataclass(slots=True)
class FstabMod:
    files: list[str]
    mount_points: list[str]
    remove_flags: list[str] = field(default_factory=list)
    add_flags: list[str] = field(default_factory=list)
    remove_mount_options: list[str] = field(default_factory=list)
    add_mount_options: list[str] = field(default_factory=list)
    fs_type: str | None = None
    optional: bool = False


@dataclass(slots=True)
class PropsMod:
    file: str
    set: dict[str, str] = field(default_factory=dict)
    remove: list[str] = field(default_factory=list)
    append: dict[str, str] = field(default_factory=dict)
    separator: str = ","
    after: str | None = None
    optional: bool = False


@dataclass(slots=True)
class FilesMod:
    action: str                      # 'add' | 'delete'
    path: str
    source: str | None = None
    uid: int | None = None
    gid: int | None = None
    mode: int | None = None
    selinux: str | None = None
    caps: int | None = None
    optional: bool = False


@dataclass(slots=True)
class Mods:
    fstab: list[FstabMod] = field(default_factory=list)
    props: list[PropsMod] = field(default_factory=list)
    files: list[FilesMod] = field(default_factory=list)
    source: str = ""

    @property
    def is_empty(self) -> bool:
        return not (self.fstab or self.props or self.files)


# --------------------------------------------------------------------------- loading

def split_part_path(path: str) -> tuple[str, str]:
    """'vendor/etc/fstab' -> ('vendor', 'etc/fstab'); 'vendor' -> ('vendor', '')."""
    if not isinstance(path, str):
        raise ModsError("path must be a string, got %r" % (path,))
    p = path.strip("/")
    if not p or p.startswith("./") or any(x in ("", ".", "..") for x in p.split("/")):
        raise ModsError("bad path %r (want <part>/<path inside partition>)" % path)
    part, _, rest = p.partition("/")
    return part, rest


def _check_keys(section: str, idx: int, d: Mapping[str, Any], allowed: set[str], required: set[str]) -> None:
    if not isinstance(d, Mapping):
        raise ModsError("[[%s]] #%d must be a table" % (section, idx))
    unknown = set(d) - allowed
    if unknown:
        raise ModsError("[[%s]] #%d: unknown key(s) %s" % (section, idx, ", ".join(sorted(unknown))))
    missing = required - set(d)
    if missing:
        raise ModsError("[[%s]] #%d: missing key(s) %s" % (section, idx, ", ".join(sorted(missing))))


def _str_list(section: str, idx: int, d: Mapping[str, Any], key: str, required: bool = False) -> list[str]:
    v = d.get(key)
    if v is None:
        if required:
            raise ModsError("[[%s]] #%d: %s is required" % (section, idx, key))
        return []
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
        raise ModsError("[[%s]] #%d: %s must be a list of non-empty strings" % (section, idx, key))
    return list(v)


def _str_map(section: str, idx: int, d: Mapping[str, Any], key: str) -> dict[str, str]:
    v = d.get(key)
    if v is None:
        return {}
    if not isinstance(v, Mapping):
        raise ModsError("[[%s]] #%d: %s must be a table" % (section, idx, key))
    out = {}
    for k, val in v.items():
        try:
            out[str(k)] = props_mod.format_value(val)
        except ValueError as e:
            raise ModsError("[[%s]] #%d: %s.%s: %s" % (section, idx, key, k, e)) from None
    return out


def _bool(section: str, idx: int, d: Mapping[str, Any], key: str, default: bool = False) -> bool:
    v = d.get(key, default)
    if not isinstance(v, bool):
        raise ModsError("[[%s]] #%d: %s must be true/false" % (section, idx, key))
    return v


def _opt_str(section: str, idx: int, d: Mapping[str, Any], key: str) -> str | None:
    v = d.get(key)
    if v is None:
        return None
    if not isinstance(v, str) or not v:
        raise ModsError("[[%s]] #%d: %s must be a non-empty string" % (section, idx, key))
    return v


def _opt_int(section: str, idx: int, d: Mapping[str, Any], key: str, base: int) -> int | None:
    """int as is; strings parsed in ``base`` (8 for mode, 0 for caps: 0x.. / decimal)."""
    v = d.get(key)
    if v is None:
        return None
    if isinstance(v, bool):
        raise ModsError("[[%s]] #%d: %s must be an integer" % (section, idx, key))
    if isinstance(v, int):
        n = v
    elif isinstance(v, str):
        try:
            n = int(v, base)
        except ValueError:
            raise ModsError("[[%s]] #%d: %s: cannot parse %r" % (section, idx, key, v)) from None
    else:
        raise ModsError("[[%s]] #%d: %s must be an integer or string" % (section, idx, key))
    if n < 0:
        raise ModsError("[[%s]] #%d: %s must not be negative" % (section, idx, key))
    return n


_FSTAB_KEYS = {"files", "mount_points", "remove_flags", "add_flags", "remove_mount_options",
               "add_mount_options", "fs_type", "optional"}
_PROPS_KEYS = {"file", "set", "remove", "append", "separator", "after", "optional"}
_FILES_KEYS = {"action", "path", "source", "uid", "gid", "mode", "selinux", "caps", "optional"}


def parse_mods(data: Mapping[str, Any], source: str = "") -> Mods:
    if not isinstance(data, Mapping):
        raise ModsError("mods document must be a table")
    unknown = set(data) - {"fstab", "props", "files"}
    if unknown:
        raise ModsError("unknown top-level section(s): %s" % ", ".join(sorted(unknown)))
    mods = Mods(source=source)
    for section in ("fstab", "props", "files"):
        items = data.get(section, [])
        if not isinstance(items, list):
            raise ModsError("%s must be an array of tables ([[%s]])" % (section, section))
        for i, d in enumerate(items, 1):
            if section == "fstab":
                _check_keys(section, i, d, _FSTAB_KEYS, {"files", "mount_points"})
                m = FstabMod(
                    files=_str_list(section, i, d, "files", True),
                    mount_points=_str_list(section, i, d, "mount_points", True),
                    remove_flags=_str_list(section, i, d, "remove_flags"),
                    add_flags=_str_list(section, i, d, "add_flags"),
                    remove_mount_options=_str_list(section, i, d, "remove_mount_options"),
                    add_mount_options=_str_list(section, i, d, "add_mount_options"),
                    fs_type=_opt_str(section, i, d, "fs_type"),
                    optional=_bool(section, i, d, "optional"),
                )
                for f in m.files:
                    split_part_path(f)
                for mp in m.mount_points:
                    if not mp.startswith("/"):
                        raise ModsError("[[fstab]] #%d: mount point %r must be absolute" % (i, mp))
                if not (m.remove_flags or m.add_flags or m.remove_mount_options or m.add_mount_options or m.fs_type):
                    raise ModsError("[[fstab]] #%d has no operation" % i)
                mods.fstab.append(m)
            elif section == "props":
                _check_keys(section, i, d, _PROPS_KEYS, {"file"})
                m = PropsMod(
                    file=_opt_str(section, i, d, "file"),
                    set=_str_map(section, i, d, "set"),
                    remove=_str_list(section, i, d, "remove"),
                    append=_str_map(section, i, d, "append"),
                    separator=_opt_str(section, i, d, "separator") or ",",
                    after=_opt_str(section, i, d, "after"),
                    optional=_bool(section, i, d, "optional"),
                )
                split_part_path(m.file)
                if not (m.set or m.remove or m.append):
                    raise ModsError("[[props]] #%d has no operation" % i)
                mods.props.append(m)
            else:
                _check_keys(section, i, d, _FILES_KEYS, {"action", "path"})
                action = _opt_str(section, i, d, "action")
                if action not in ("add", "delete"):
                    raise ModsError("[[files]] #%d: action must be 'add' or 'delete'" % i)
                m = FilesMod(
                    action=action,
                    path=_opt_str(section, i, d, "path"),
                    source=_opt_str(section, i, d, "source"),
                    uid=_opt_int(section, i, d, "uid", 10),
                    gid=_opt_int(section, i, d, "gid", 10),
                    mode=_opt_int(section, i, d, "mode", 8),
                    selinux=_opt_str(section, i, d, "selinux"),
                    caps=_opt_int(section, i, d, "caps", 0),
                    optional=_bool(section, i, d, "optional"),
                )
                part, rest = split_part_path(m.path)
                if not rest:
                    raise ModsError("[[files]] #%d: path %r names a partition root" % (i, m.path))
                if action == "add" and not m.source:
                    raise ModsError("[[files]] #%d: add needs a source" % i)
                if action == "delete" and any(getattr(m, k) is not None for k in ("source", "uid", "gid", "mode", "selinux", "caps")):
                    raise ModsError("[[files]] #%d: delete takes only path/optional" % i)
                if m.mode is not None and m.mode > 0o7777:
                    raise ModsError("[[files]] #%d: mode out of range" % i)
                mods.files.append(m)
    return mods


def load_mods(path: str) -> Mods:
    with open(path, "rb") as f:
        try:
            data = tomllib.load(f)
        except tomllib.TOMLDecodeError as e:
            raise ModsError("%s: %s" % (path, e)) from None
    return parse_mods(data, source=os.path.abspath(path))


# --------------------------------------------------------------------------- applying

def _read_text(path: str) -> str:
    with open(path, encoding="utf-8", errors="surrogateescape", newline="") as f:
        return f.read()


def _write_text(path: str, text: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", errors="surrogateescape", newline="") as f:
        f.write(text)
    os.replace(tmp, path)


def _line_changes(label: str, op: str, old: str, new: str) -> list[Change]:
    """Per-line diff of two texts with the same line count (token edits), else a block diff."""
    a = old.splitlines()
    b = new.splitlines()
    out = []
    if len(a) == len(b):
        for x, y in zip(a, b):
            if x != y:
                out.append(Change(label, op, x, y))
        return out
    import difflib
    sm = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        out.append(Change(label, op, "\n".join(a[i1:i2]) or None, "\n".join(b[j1:j2]) or None))
    return out


def _prop_changes(label: str, old: str, new: str) -> list[Change]:
    def lines_by_key(text):
        d: dict[str, list[str]] = {}
        for l in props_mod.parse_props(text):
            if l.kind == "prop":
                d.setdefault(l.key, []).append(l.raw)
        return d
    a, b = lines_by_key(old), lines_by_key(new)
    out = []
    for k in sorted(set(a) | set(b)):
        if a.get(k) != b.get(k):
            out.append(Change(label, "props", "\n".join(a[k]) if k in a else None,
                              "\n".join(b[k]) if k in b else None, k))
    if not out and old != new:
        out = _line_changes(label, "props", old, new)
    return out


class _Workdir:
    def __init__(self, workdir: str):
        self.workdir = os.path.abspath(workdir)
        if not os.path.isdir(self.workdir):
            raise ModsError("workdir %s does not exist" % self.workdir)
        self.trees: dict[str, PartitionTree] = {}
        self.touched: list[str] = []

    def tree(self, part: str) -> PartitionTree:
        t = self.trees.get(part)
        if t is None:
            part_dir = os.path.join(self.workdir, part)
            if not os.path.isdir(os.path.join(part_dir, "root")):
                raise ModsError("partition %r is not in the workdir (%s/root missing)" % (part, part_dir))
            try:
                t = PartitionTree(part_dir, part_name=part)
            except (OSError, ValueError) as e:
                raise ModsError("partition %r: %s" % (part, e)) from None
            self.trees[part] = t
        return t

    def host_file(self, path: str, optional: bool) -> tuple[str, str, str] | None:
        part, rel = split_part_path(path)
        part_dir = os.path.join(self.workdir, part)
        if not os.path.isdir(os.path.join(part_dir, "root")):
            if optional:
                return None
            raise ModsError("partition %r is not in the workdir (%s/root missing)" % (part, part_dir))
        hp = os.path.join(part_dir, "root", rel)
        if not os.path.isfile(hp) or os.path.islink(hp):
            if optional and not os.path.lexists(hp):
                return None
            raise ModsError("%s is not a regular file in the workdir (%s)" % (path, hp))
        return part, rel, hp

    def touch(self, part: str) -> None:
        if part not in self.touched:
            self.touched.append(part)


def apply_mods(workdir: str, mods: Mods | str, dry_run: bool = False) -> list[Change]:
    """Apply ``mods`` (a Mods object or a mods.toml path) to an unpacked workdir.

    Returns the list of changes (empty when everything was already applied).  With
    ``dry_run`` nothing is written; the report still lists the content changes (sidecar
    resync results are reported for the in-memory state).
    """
    if isinstance(mods, str):
        mods = load_mods(mods)
    wd = _Workdir(workdir)
    report: list[Change] = []

    for m in mods.fstab:
        for f in m.files:
            loc = wd.host_file(f, m.optional)
            if loc is None:
                report.append(Change(f, "note", None, None, "optional file missing, skipped"))
                continue
            part, rel, hp = loc
            old = _read_text(hp)
            try:
                new = fstab_mod.edit_fstab(old, m.mount_points, remove_flags_=m.remove_flags,
                                           add_flags_=m.add_flags, remove_mount_options_=m.remove_mount_options,
                                           add_mount_options_=m.add_mount_options, fs_type=m.fs_type)
            except ValueError as e:
                raise ModsError("%s: %s" % (f, e)) from None
            if new == old:
                continue
            report.extend(_line_changes(f, "fstab", old, new))
            if not dry_run:
                _write_text(hp, new)
            wd.touch(part)

    for m in mods.props:
        loc = wd.host_file(m.file, m.optional)
        if loc is None:
            report.append(Change(m.file, "note", None, None, "optional file missing, skipped"))
            continue
        part, rel, hp = loc
        old = _read_text(hp)
        try:
            new = props_mod.edit_props(old, set=m.set, remove=m.remove, append=m.append,
                                       separator=m.separator, after=m.after)
        except ValueError as e:
            raise ModsError("%s: %s" % (m.file, e)) from None
        if new == old:
            continue
        report.extend(_prop_changes(m.file, old, new))
        if not dry_run:
            _write_text(hp, new)
        wd.touch(part)

    for m in mods.files:
        part, rel = split_part_path(m.path)
        if m.action == "add":
            if not os.path.lexists(m.source):
                if m.optional:
                    report.append(Change(m.path, "note", None, None, "optional source %s missing, skipped" % m.source))
                    continue
                raise ModsError("%s: source %s does not exist" % (m.path, m.source))
            t = wd.tree(part)
            try:
                changes = t.add(rel, m.source, uid=m.uid, gid=m.gid, mode=m.mode, selinux=m.selinux,
                                caps=m.caps, dry_run=dry_run)
            except (OSError, ValueError) as e:
                raise ModsError("%s: %s" % (m.path, e)) from None
        else:
            part_dir = os.path.join(wd.workdir, part)
            if not os.path.isdir(os.path.join(part_dir, "root")):
                if m.optional:
                    report.append(Change(m.path, "note", None, None, "optional, partition missing, skipped"))
                    continue
            t = wd.tree(part)
            try:
                changes = t.delete(rel, optional=m.optional, dry_run=dry_run)
            except FileNotFoundError as e:
                raise ModsError(str(e)) from None
            except (OSError, ValueError) as e:
                raise ModsError("%s: %s" % (m.path, e)) from None
        if changes:
            report.extend(changes)
            wd.touch(part)

    for part in wd.touched:
        t = wd.tree(part)
        if not t.has_sidecars:
            report.append(Change(part, "note", None, None, "no sidecars in %s, resync skipped" % t.part_dir))
            continue
        try:
            report.extend(t.resync(dry_run=dry_run))
        except (OSError, ValueError) as e:
            raise ModsError("%s: resync failed: %s" % (part, e)) from None
    return report


def format_report(report: list[Change]) -> str:
    if not report:
        return "no changes\n"
    return "".join(c.format() + "\n" for c in report)
