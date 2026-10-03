"""Add / delete files in an unpacked partition tree and keep its sidecars in sync.

Workdir layout (DESIGN.md §4.1): ``<workdir>/<part>/root/`` is the tree, next to it
``manifest.tsv``, ``fs_config``, ``file_contexts`` and ``meta.json`` (mount point).

``PartitionTree`` loads the manifest once, applies ``add``/``delete`` operations to the
host tree *and* the in-memory manifest, and ``resync`` reconciles the manifest with the
host tree (new paths get entries, vanished paths lose theirs, modified regular files get a
fresh size/sha256/mtime, symlink targets are refreshed, directory nlink is corrected) and
rewrites ``manifest.tsv``, ``fs_config`` and ``file_contexts`` with the ``fsconfig``
writers, only when their text actually changes.

Metadata inheritance for added paths (when not given explicitly): uid, gid and the SELinux
label come from the parent directory's manifest entry; a directory gets the parent's mode;
a regular file gets the parent's mode without the execute bits, unless the host source is
executable (owner x bit), in which case it keeps the parent's mode; symlinks are 0777;
capabilities default to 0 and other xattrs are never inherited.  Special files (chr, blk,
fifo, sock) are carried in the manifest only and are never touched by resync.

A tree without any sidecar (no manifest.tsv, fs_config, file_contexts) is a *bare* tree:
``resync`` is a no-op there (``has_sidecars`` is False) so the text editors can be used on
plain copies of files.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from typing import Iterable

from superkit import fsconfig as fc
from superkit.fsconfig import ManifestEntry
from superkit.mods.report import Change

__all__ = ["PartitionTree", "sha256_file", "guess_mount_point", "SIDECARS", "SPECIAL_TYPES",
           "add_path", "delete_path", "resync"]

SIDECARS = ("manifest.tsv", "fs_config", "file_contexts")
SPECIAL_TYPES = frozenset(("chr", "blk", "fifo", "sock"))
_DIR_SIZE = 4096


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def guess_mount_point(part_dir: str) -> str:
    """meta.json ``mount_point`` if present, else '/' for system and '/<part>' otherwise."""
    meta = os.path.join(part_dir, "meta.json")
    if os.path.isfile(meta):
        try:
            with open(meta, encoding="utf-8") as f:
                d = json.load(f)
            for key in ("mount_point", "mount"):
                v = d.get(key)
                if isinstance(v, str) and v.startswith("/"):
                    return v
        except (OSError, ValueError):
            pass
    name = os.path.basename(os.path.normpath(part_dir))
    return "/" if name == "system" else "/" + name


def _check_rel(rel: str) -> str:
    rel = rel.strip("/")
    if rel in ("", ".") or rel.startswith("./") or "/./" in rel or rel.endswith("/."):
        raise ValueError("bad partition-relative path %r" % rel)
    parts = rel.split("/")
    if any(p in ("", "..") for p in parts):
        raise ValueError("bad partition-relative path %r" % rel)
    return rel


def _summary(e: ManifestEntry) -> str:
    s = "%s %04o %d:%d %s" % (e.type, e.mode, e.uid, e.gid, e.selinux or "-")
    if e.caps:
        s += " caps=0x%x" % e.caps
    if e.type == "reg":
        s += " size=%d sha256=%s" % (e.size, (e.sha256 or "-")[:16])
    elif e.type == "lnk":
        s += " -> %s" % e.target
    return s


class PartitionTree:
    def __init__(self, part_dir: str, mount_point: str | None = None, part_name: str | None = None):
        self.part_dir = os.path.abspath(part_dir)
        self.part = part_name or os.path.basename(self.part_dir)
        self.root = os.path.join(self.part_dir, "root")
        if not os.path.isdir(self.root):
            raise FileNotFoundError("partition tree %s has no root/ directory" % self.part_dir)
        self.mount_point = mount_point or guess_mount_point(self.part_dir)
        self.manifest_path = os.path.join(self.part_dir, "manifest.tsv")
        self.has_sidecars = any(os.path.exists(os.path.join(self.part_dir, s)) for s in SIDECARS)
        self.entries: dict[str, ManifestEntry] = {}
        if self.has_sidecars:
            if not os.path.isfile(self.manifest_path):
                raise FileNotFoundError("%s has sidecars but no manifest.tsv" % self.part_dir)
            for e in fc.read_manifest(self.manifest_path):
                self.entries[e.path] = e
            if "" not in self.entries:
                raise ValueError("%s: manifest has no root entry" % self.manifest_path)
        self._nlink_dirty: set[str] = set()

    # ------------------------------------------------------------------ helpers
    def host_path(self, rel: str) -> str:
        return os.path.join(self.root, rel) if rel else self.root

    def _label(self, rel: str) -> str:
        return "%s/%s" % (self.part, rel) if rel else self.part

    def _parent_entry(self, rel: str) -> ManifestEntry | None:
        if not self.has_sidecars:
            return None
        parent = rel.rsplit("/", 1)[0] if "/" in rel else ""
        e = self.entries.get(parent)
        if e is None:
            raise ValueError("parent directory %r of %r is not in the manifest" % (parent, rel))
        if e.type != "dir":
            raise ValueError("parent %r of %r is not a directory" % (parent, rel))
        return e

    def _inherit(self, rel: str, kind: str, host_exec: bool, uid, gid, mode, selinux, caps,
                 target: str | None = None) -> ManifestEntry:
        parent = self._parent_entry(rel)
        if parent is None:
            parent = ManifestEntry("", "dir", 0o755)
        if mode is None:
            if kind == "dir":
                mode = parent.mode & 0o777
            elif kind == "lnk":
                mode = 0o777
            else:
                mode = parent.mode & 0o777 if host_exec else parent.mode & 0o666
        if uid is None:
            uid = parent.uid
        if gid is None:
            gid = parent.gid
        if selinux is None:
            selinux = parent.selinux
        size = _DIR_SIZE if kind == "dir" else len(os.fsencode(target)) if kind == "lnk" else 0
        return ManifestEntry(rel, kind, mode, uid, gid, 2 if kind == "dir" else 1, size, 0, 0,
                             selinux, caps or 0, {}, target, None, 0)

    def _entry_from_host(self, rel: str, st: os.stat_result, hp: str, **meta) -> ManifestEntry:
        """Manifest entry for host path ``hp`` (content hashed, metadata inherited unless in meta)."""
        kind = fc.type_from_mode(st.st_mode)
        target = os.readlink(hp) if kind == "lnk" else None
        e = self._inherit(rel, kind, bool(st.st_mode & stat.S_IXUSR), meta.get("uid"), meta.get("gid"),
                          meta.get("mode"), meta.get("selinux"), meta.get("caps"), target)
        e.mtime = int(st.st_mtime)
        e.mtime_ns = st.st_mtime_ns % 1_000_000_000
        if kind == "reg":
            e.size = st.st_size
            e.sha256 = sha256_file(hp)
        return e

    def _set_entry(self, e: ManifestEntry) -> None:
        old = self.entries.get(e.path)
        self.entries[e.path] = e
        if e.type == "dir" and (old is None or old.type != "dir"):
            self._nlink_dirty.add(e.parent)
        elif old is not None and old.type == "dir" and e.type != "dir":
            self._nlink_dirty.add(e.parent)

    def _del_entry(self, rel: str) -> ManifestEntry | None:
        old = self.entries.pop(rel, None)
        if old is not None and old.type == "dir":
            self._nlink_dirty.add(old.parent)
        return old

    def _fix_nlinks(self) -> list[Change]:
        changes = []
        for d in sorted(self._nlink_dirty, key=lambda p: (p is None, p)):
            if d is None:
                continue
            e = self.entries.get(d)
            if e is None or e.type != "dir":
                continue
            subdirs = sum(1 for x in self.entries.values() if x.type == "dir" and x.parent == d)
            if e.nlink != 2 + subdirs:
                changes.append(Change(self._label(d), "sidecar", "nlink=%d" % e.nlink,
                                      "nlink=%d" % (2 + subdirs), "manifest nlink"))
                e.nlink = 2 + subdirs
        self._nlink_dirty.clear()
        return changes

    # ------------------------------------------------------------------ add
    def add(self, rel: str, source: str, *, uid: int | None = None, gid: int | None = None,
            mode: int | None = None, selinux: str | None = None, caps: int | None = None,
            dry_run: bool = False) -> list[Change]:
        """Copy ``source`` (file, symlink or directory tree) to ``rel`` in the partition.

        Explicit metadata applies to ``rel`` itself; children of a directory source
        inherit from their (new) parent.  Existing content is replaced; an identical
        file with identical metadata is reported as no change.
        """
        rel = _check_rel(rel)
        source = os.path.abspath(source)
        st = os.lstat(source)
        kind = fc.type_from_mode(st.st_mode)
        if kind in SPECIAL_TYPES:
            raise ValueError("cannot add special file %s" % source)
        if mode is not None and not 0 <= mode <= 0o7777:
            raise ValueError("bad mode 0o%o" % mode)
        changes: list[Change] = []
        self._ensure_parents(rel, changes, dry_run)
        self._add_one(rel, source, st, kind, dict(uid=uid, gid=gid, mode=mode, selinux=selinux, caps=caps),
                      changes, dry_run)
        if kind == "dir":
            for dirpath, dirnames, filenames in os.walk(source):
                dirnames.sort()
                base = os.path.relpath(dirpath, source)
                for name in sorted(dirnames + filenames):
                    sp = os.path.join(dirpath, name)
                    cst = os.lstat(sp)
                    ck = fc.type_from_mode(cst.st_mode)
                    if ck in SPECIAL_TYPES:
                        raise ValueError("cannot add special file %s" % sp)
                    crel = rel + "/" + (name if base == "." else base + "/" + name)
                    self._add_one(crel, sp, cst, ck, {}, changes, dry_run)
        changes.extend(self._fix_nlinks())
        return changes

    def _ensure_parents(self, rel: str, changes: list[Change], dry_run: bool) -> None:
        parts = rel.split("/")[:-1]
        cur = ""
        for p in parts:
            cur = cur + "/" + p if cur else p
            hp = self.host_path(cur)
            e = self.entries.get(cur)
            if os.path.lexists(hp) and (not self.has_sidecars or e is not None):
                if os.path.isdir(hp) and not os.path.islink(hp) and (e is None or e.type == "dir"):
                    continue
                raise ValueError("%s exists and is not a directory" % self._label(cur))
            if e is None and os.path.lexists(hp):
                # host dir not yet in the manifest: adopt it
                if not os.path.isdir(hp) or os.path.islink(hp):
                    raise ValueError("%s exists and is not a directory" % self._label(cur))
            elif not dry_run:
                os.mkdir(hp, 0o755)
            if not self.has_sidecars:
                changes.append(Change(self._label(cur), "add", None, "dir", "implicit parent"))
                continue
            if os.path.isdir(hp):
                ne = self._entry_from_host(cur, os.lstat(hp), hp)
            else:  # dry run: the directory was not created
                ne = self._inherit(cur, "dir", False, None, None, None, None, None)
            self._set_entry(ne)
            changes.append(Change(self._label(cur), "add", None, _summary(ne), "implicit parent"))

    def _add_one(self, rel: str, source: str, st: os.stat_result, kind: str, meta: dict,
                 changes: list[Change], dry_run: bool) -> None:
        hp = self.host_path(rel)
        old = self.entries.get(rel)
        exists = os.path.lexists(hp)
        if self.has_sidecars:
            target = os.readlink(source) if kind == "lnk" else None
            new = self._inherit(rel, kind, bool(st.st_mode & stat.S_IXUSR), meta.get("uid"), meta.get("gid"),
                                meta.get("mode"), meta.get("selinux"), meta.get("caps"), target)
            new.mtime, new.mtime_ns = int(st.st_mtime), st.st_mtime_ns % 1_000_000_000
            if kind == "reg":
                new.size, new.sha256 = st.st_size, sha256_file(source)
            if old is not None and exists and self._same(old, new):
                return
        else:
            new = None
            if exists and self._host_same(hp, source, st, kind):
                return
        before = _summary(old) if old is not None else ("host:%s" % fc.type_from_mode(os.lstat(hp).st_mode) if exists else None)
        if not dry_run:
            self._write_host(hp, source, st, kind)
        if new is not None:
            # a replaced directory loses the entries of its children
            if old is not None and old.type == "dir" and kind != "dir":
                for p in [p for p in self.entries if p.startswith(rel + "/")]:
                    self._del_entry(p)
            self._set_entry(new)
            after = _summary(new)
        else:
            after = "host:%s" % kind
        changes.append(Change(self._label(rel), "add", before, after))

    @staticmethod
    def _same(old: ManifestEntry, new: ManifestEntry) -> bool:
        if (old.type, old.mode, old.uid, old.gid, old.selinux, old.caps, old.target) != \
           (new.type, new.mode, new.uid, new.gid, new.selinux, new.caps, new.target):
            return False
        if old.type == "reg":
            return old.sha256 is not None and old.sha256 == new.sha256 and old.size == new.size
        return True

    @staticmethod
    def _host_same(hp: str, source: str, st: os.stat_result, kind: str) -> bool:
        hst = os.lstat(hp)
        if fc.type_from_mode(hst.st_mode) != kind:
            return False
        if kind == "reg":
            return hst.st_size == st.st_size and sha256_file(hp) == sha256_file(source)
        if kind == "lnk":
            return os.readlink(hp) == os.readlink(source)
        return True

    @staticmethod
    def _write_host(hp: str, source: str, st: os.stat_result, kind: str) -> None:
        if os.path.lexists(hp):
            if os.path.isdir(hp) and not os.path.islink(hp):
                if kind == "dir":
                    return
                shutil.rmtree(hp)
            else:
                os.unlink(hp)
        if kind == "dir":
            os.mkdir(hp, 0o755)
            os.utime(hp, ns=(st.st_atime_ns, st.st_mtime_ns))
        elif kind == "lnk":
            os.symlink(os.readlink(source), hp)
            try:
                os.utime(hp, ns=(st.st_atime_ns, st.st_mtime_ns), follow_symlinks=False)
            except (NotImplementedError, OSError):
                pass
        else:
            shutil.copyfile(source, hp)
            os.chmod(hp, stat.S_IMODE(st.st_mode) & 0o777 | 0o600)
            os.utime(hp, ns=(st.st_atime_ns, st.st_mtime_ns))

    # ------------------------------------------------------------------ delete
    def delete(self, rel: str, *, optional: bool = False, dry_run: bool = False) -> list[Change]:
        rel = _check_rel(rel)
        hp = self.host_path(rel)
        old = self.entries.get(rel)
        exists = os.path.lexists(hp)
        if not exists and old is None:
            if optional:
                return []
            raise FileNotFoundError("%s does not exist" % self._label(rel))
        changes: list[Change] = []
        host_kind = fc.type_from_mode(os.lstat(hp).st_mode) if exists else None
        if not dry_run and exists:
            if host_kind == "dir":
                shutil.rmtree(hp)
            else:
                os.unlink(hp)
        victims = sorted(p for p in self.entries if p == rel or p.startswith(rel + "/"))
        for p in victims:
            e = self._del_entry(p)
            changes.append(Change(self._label(p), "delete", _summary(e), None))
        if not victims:
            changes.append(Change(self._label(rel), "delete", "host:%s" % host_kind, None))
        changes.extend(self._fix_nlinks())
        return changes

    # ------------------------------------------------------------------ resync
    def _walk_host(self) -> dict[str, os.stat_result]:
        found: dict[str, os.stat_result] = {}
        for dirpath, dirnames, filenames in os.walk(self.root):
            base = os.path.relpath(dirpath, self.root)
            base = "" if base == "." else base
            for name in dirnames + filenames:
                hp = os.path.join(dirpath, name)
                rel = name if base == "" else base + "/" + name
                found[os.fsdecode(rel)] = os.lstat(hp)
        return found

    def resync(self, *, dry_run: bool = False) -> list[Change]:
        """Reconcile the manifest with the host tree and rewrite the sidecars if needed."""
        changes: list[Change] = []
        if not self.has_sidecars:
            return changes
        host = self._walk_host()
        # 1. entries whose host path vanished (or changed type)
        for rel in sorted(self.entries):
            e = self.entries[rel]
            if rel == "" or e.type in SPECIAL_TYPES:
                continue
            st = host.get(rel)
            if st is None or fc.type_from_mode(st.st_mode) != e.type:
                self._del_entry(rel)
                changes.append(Change(self._label(rel), "delete", _summary(e), None, "resync: gone from tree"))
        # 2. host paths without an entry (parents first)
        for rel in sorted(host, key=lambda p: (p.count("/"), p)):
            if rel in self.entries:
                continue
            st = host[rel]
            kind = fc.type_from_mode(st.st_mode)
            if kind in SPECIAL_TYPES:
                continue
            e = self._entry_from_host(rel, st, self.host_path(rel))
            self._set_entry(e)
            changes.append(Change(self._label(rel), "add", None, _summary(e), "resync: new in tree"))
        # 3. modified regular files / symlinks
        for rel, e in self.entries.items():
            if rel == "" or e.type not in ("reg", "lnk"):
                continue
            st = host[rel]
            hp = self.host_path(rel)
            if e.type == "reg":
                if e.size == st.st_size and e.mtime == int(st.st_mtime) and e.sha256 is not None:
                    continue
                digest = sha256_file(hp)
                if digest == e.sha256 and e.size == st.st_size:
                    continue
                before = _summary(e)
                e.size, e.sha256 = st.st_size, digest
                e.mtime, e.mtime_ns = int(st.st_mtime), st.st_mtime_ns % 1_000_000_000
                changes.append(Change(self._label(rel), "sidecar", before, _summary(e), "resync: content changed"))
            else:
                target = os.readlink(hp)
                if target != e.target:
                    before = _summary(e)
                    e.target, e.size = target, len(os.fsencode(target))
                    changes.append(Change(self._label(rel), "sidecar", before, _summary(e), "resync: target changed"))
        changes.extend(self._fix_nlinks())
        changes.extend(self._write_sidecars(dry_run))
        return changes

    def _write_sidecars(self, dry_run: bool) -> list[Change]:
        entries = [self.entries[p] for p in sorted(self.entries)]
        texts = {
            "manifest.tsv": fc.manifest_to_text(entries),
            "fs_config": fc.write_fs_config(entries, self.mount_point),
            "file_contexts": fc.write_file_contexts(entries, self.mount_point),
        }
        changes = []
        for name, text in texts.items():
            path = os.path.join(self.part_dir, name)
            old = None
            if os.path.isfile(path):
                with open(path, encoding="utf-8", errors="surrogateescape", newline="") as f:
                    old = f.read()
            if old == text:
                continue
            changes.append(Change("%s/%s" % (self.part, name), "sidecar",
                                  None if old is None else "%d lines" % old.count("\n"),
                                  "%d lines" % text.count("\n")))
            if not dry_run:
                tmp = path + ".tmp"
                with open(tmp, "w", encoding="utf-8", errors="surrogateescape", newline="") as f:
                    f.write(text)
                os.replace(tmp, path)
        return changes

    def save(self, dry_run: bool = False) -> list[Change]:
        """Write the sidecars from the in-memory manifest without reconciling the host tree."""
        if not self.has_sidecars:
            return []
        changes = self._fix_nlinks()
        changes.extend(self._write_sidecars(dry_run))
        return changes


# ---------------------------------------------------------------------- functional API

def add_path(part_dir: str, rel: str, source: str, *, mount_point: str | None = None,
             dry_run: bool = False, **meta) -> list[Change]:
    t = PartitionTree(part_dir, mount_point)
    changes = t.add(rel, source, dry_run=dry_run, **meta)
    changes.extend(t.resync(dry_run=dry_run))
    return changes


def delete_path(part_dir: str, rel: str, *, mount_point: str | None = None, optional: bool = False,
                dry_run: bool = False) -> list[Change]:
    t = PartitionTree(part_dir, mount_point)
    changes = t.delete(rel, optional=optional, dry_run=dry_run)
    changes.extend(t.resync(dry_run=dry_run))
    return changes


def resync(part_dir: str, *, mount_point: str | None = None, dry_run: bool = False) -> list[Change]:
    return PartitionTree(part_dir, mount_point).resync(dry_run=dry_run)
