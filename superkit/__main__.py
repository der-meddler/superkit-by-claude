"""superkit command line: inventory, unpack, mod, repack, verify, pack-odin.

Every step runs unprivileged.  Paths are explicit; nothing is written outside the given
work/out directories.  Progress goes to stderr, results to stdout.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import avb, build, fsconfig
from .f2fs import F2FSError, F2FSImage, probe
from .lp import LpError, SparseImageError, SuperImage

MIB = 1 << 20


def log(msg: str) -> None:
    sys.stderr.write(msg.rstrip("\n") + "\n")
    sys.stderr.flush()


def mount_point_for(name: str, label: str | None) -> str:
    if name == "system" or label == "/":
        return "/"
    return "/" + name


def open_super(path: str) -> SuperImage:
    try:
        return SuperImage(path)
    except SparseImageError as ex:
        raise SystemExit("%s\nrun: simg2img %s %s.raw" % (ex, path, os.path.splitext(path)[0]))
    except LpError as ex:
        raise SystemExit("not a super image: %s" % ex)


def single_extent(lp: SuperImage, name: str) -> tuple[int, int]:
    ranges = lp.partition_extent_ranges(name)
    if len(ranges) != 1:
        raise SystemExit("partition %s has %d extents; only single linear extents are supported" % (name, len(ranges)))
    return ranges[0]


def footer_in_super(super_path: str, off: int, length: int):
    with open(super_path, "rb") as f:
        f.seek(off + length - avb.FOOTER_SIZE)
        return avb.parse_footer_bytes(f.read(avb.FOOTER_SIZE))


# --------------------------------------------------------------------------- inventory

def cmd_inventory(args) -> int:
    lp = open_super(args.super)
    g = lp.geometry
    bd = lp.block_device
    print("super: %s (%d bytes)" % (args.super, lp.size))
    print("LP metadata %s, max size %d, slots %d, block size %d, header flags %s, slots agree: %s"
          % (lp.header.version, g.metadata_max_size, g.metadata_slot_count, g.logical_block_size,
             lp.header.flag_names or "none", lp.slots_agree))
    print("block device %s: size %d, first sector %d, alignment %d, offset %d"
          % (bd.partition_name, bd.size, bd.first_logical_sector, bd.alignment, bd.alignment_offset))
    for grp in lp.groups:
        print("group %-10s max %d" % (grp.name, grp.maximum_size))
    used = 0
    for p in lp.partitions:
        used += p.size
        print("%-11s group=%-6s attrs=%-9s size=%11d (%5d MiB) extents=%s"
              % (p.name, p.group, ",".join(sorted(p.attribute_names)) or "none", p.size, p.size // MIB,
                 ["%d+%d" % (e.target_data, e.num_sectors) for e in p.extents]))
    print("used %d of %d bytes (%d MiB free before alignment)" % (used, bd.size, (bd.size - used) // MIB))
    for p in lp.partitions:
        off, length = single_extent(lp, p.name)
        footer = footer_in_super(args.super, off, length)
        if not probe(args.super, off):
            print("%-11s: not f2fs" % p.name)
            continue
        try:
            with F2FSImage(args.super, off, length) as img:
                info = img.info()
        except F2FSError as ex:
            print("%-11s: f2fs error: %s" % (p.name, ex))
            continue
        c = info.get("counts", {})
        print("%-11s: f2fs label=%r uuid=%s features=%s fs_size=%d (%d MiB) entries=%s caps=%s xattrs=%s%s"
              % (p.name, info.get("label"), info.get("uuid"), ",".join(info.get("features", [])) or "none",
                 info.get("fs_size", 0), info.get("fs_size", 0) // MIB, c.get("total"), c.get("with_caps"),
                 c.get("with_other_xattrs"),
                 ("; AVB footer v%s original %d" % (footer.version, footer.original_image_size)) if footer else "; no AVB footer"))
    return 0


# --------------------------------------------------------------------------- unpack

def cmd_unpack(args) -> int:
    lp = open_super(args.super)
    os.makedirs(args.workdir, exist_ok=True)
    lp.save_json(os.path.join(args.workdir, "super.json"))
    names = args.partitions or lp.partition_names
    for name in names:
        if name not in lp.partition_names:
            raise SystemExit("no partition %r in %s (have %s)" % (name, args.super, lp.partition_names))
    t_all = time.monotonic()
    for name in names:
        t0 = time.monotonic()
        off, length = single_extent(lp, name)
        footer = footer_in_super(args.super, off, length)
        part_dir = os.path.join(args.workdir, name)
        root = os.path.join(part_dir, "root")
        os.makedirs(part_dir, exist_ok=True)
        log("unpack %s: offset %d, %d bytes" % (name, off, length))
        try:
            with F2FSImage(args.super, off, length) as img:
                info = img.info()
                mp = mount_point_for(name, info.get("label"))
                last = [0.0]

                def progress(done, total, path, _last=last):
                    now = time.monotonic()
                    if now - _last[0] > 2.0:
                        _last[0] = now
                        log("  %s: %d/%d %s" % (name, done, total, path[:60]))

                entries = img.extract(root, manifest_path=os.path.join(part_dir, "manifest.tsv"),
                                      hash=not args.no_hash, progress=progress)
        except F2FSError as ex:
            raise SystemExit("%s: %s" % (name, ex))
        meta = {
            "partition": name,
            "mount_point": mp,
            "lp": {"offset": off, "length": length, "readonly": lp.partition(name).readonly,
                   "group": lp.partition(name).group},
            "avb_footer": footer.to_dict() if footer else None,
            "f2fs": info,
            "unpacked_from": os.path.abspath(args.super),
            "unpacked_at": int(time.time()),
        }
        with open(os.path.join(part_dir, "meta.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=1, sort_keys=True)
        with open(os.path.join(part_dir, "fs_config"), "w", encoding="utf-8", newline="\n") as f:
            f.write(fsconfig.write_fs_config(entries, mp))
        with open(os.path.join(part_dir, "file_contexts"), "w", encoding="utf-8", newline="\n") as f:
            f.write(fsconfig.write_file_contexts(entries, mp))
        c = info.get("counts", {})
        log("  %s: %d entries (%s files, %s dirs, %s links), features=%s, fs %d MiB, %.1fs"
            % (name, len(entries), c.get("reg"), c.get("dir"), c.get("lnk"),
               ",".join(info.get("features", [])) or "none", info.get("fs_size", 0) // MIB, time.monotonic() - t0))
    log("unpack done in %.1fs -> %s" % (time.monotonic() - t_all, args.workdir))
    return 0


# --------------------------------------------------------------------------- mod

def cmd_mod(args) -> int:
    from .mods import ModsError, apply_mods, format_report, load_mods
    try:
        mods = load_mods(args.mods)
        report = apply_mods(args.workdir, mods, dry_run=args.dry_run)
    except (ModsError, OSError, ValueError) as ex:
        raise SystemExit("mod failed: %s" % ex)
    print(format_report(report) if report else "nothing to do (already applied)")
    if args.dry_run:
        return 0
    # remember modified paths so verify can expect them
    mod_file = os.path.join(args.workdir, "modified.json")
    modified: dict[str, list[str]] = {}
    if os.path.exists(mod_file):
        with open(mod_file, encoding="utf-8") as f:
            modified = json.load(f)
    wd = os.path.abspath(args.workdir)
    for ch in report:
        p = os.path.abspath(ch.file) if os.path.isabs(ch.file) else os.path.abspath(os.path.join(wd, ch.file))
        rel = os.path.relpath(p, wd)
        parts = rel.split(os.sep)
        if len(parts) >= 3 and parts[1] == "root":
            modified.setdefault(parts[0], [])
            sub = "/".join(parts[2:])
            if sub not in modified[parts[0]]:
                modified[parts[0]].append(sub)
    with open(mod_file, "w", encoding="utf-8") as f:
        json.dump(modified, f, indent=1, sort_keys=True)
    return 0


# --------------------------------------------------------------------------- repack

def load_cfg(path: str | None) -> dict:
    if path is None and os.path.exists("repack.toml"):
        path = "repack.toml"
    try:
        return build.load_repack_config(path)
    except (build.BuildError, OSError) as ex:
        raise SystemExit("bad repack config: %s" % ex)


def cmd_repack(args) -> int:
    cfg = load_cfg(args.config)
    os.makedirs(args.outdir, exist_ok=True)
    logfile = build.Log(os.path.join(args.outdir, "build.log"))
    super_json = os.path.join(args.workdir, "super.json")
    if not os.path.exists(super_json):
        raise SystemExit("missing %s (run unpack first)" % super_json)
    lp = SuperImage.load_json(super_json)
    names = args.partitions or lp.partition_names
    results = []
    for name in names:
        if not os.path.isdir(os.path.join(args.workdir, name)):
            raise SystemExit("partition %s is not unpacked in %s" % (name, args.workdir))
        try:
            r = build.build_partition(args.workdir, name, args.outdir, cfg, logfile, progress=log)
        except (build.BuildError, F2FSError) as ex:
            raise SystemExit("repack %s failed: %s" % (name, ex))
        results.append(r)
        log("  " + r.row())
    print("partitions:")
    for r in results:
        print("  " + r.row())
    if args.partitions_only or set(names) != set(lp.partition_names):
        print("super.img not assembled (not all partitions built)")
        return 0
    try:
        res = build.build_super(args.workdir, args.outdir, cfg, log=logfile)
    except (build.BuildError, LpError) as ex:
        raise SystemExit("assembling super.img failed: %s" % ex)
    print("capacity:\n" + res["capacity"])
    print("super image: %s (%d bytes)" % (res["super"], res["size"]))
    return 0


# --------------------------------------------------------------------------- verify

def cmd_verify(args) -> int:
    new = open_super(args.super)
    super_json = os.path.join(args.workdir, "super.json")
    problems: list[str] = []
    if os.path.exists(super_json):
        old = SuperImage.load_json(super_json)
        for fld in ("metadata_max_size", "metadata_slot_count", "logical_block_size"):
            a, b = getattr(old.geometry, fld), getattr(new.geometry, fld)
            if a != b:
                problems.append("geometry %s: %s -> %s" % (fld, a, b))
        if old.block_device.size != new.block_device.size:
            problems.append("device size %d -> %d" % (old.block_device.size, new.block_device.size))
        if [g.name for g in old.groups] != [g.name for g in new.groups]:
            problems.append("groups %s -> %s" % ([g.name for g in old.groups], [g.name for g in new.groups]))
        if old.partition_names != new.partition_names:
            problems.append("partitions %s -> %s" % (old.partition_names, new.partition_names))
    modified: dict[str, list[str]] = {}
    mod_file = os.path.join(args.workdir, "modified.json")
    if os.path.exists(mod_file):
        with open(mod_file, encoding="utf-8") as f:
            modified = json.load(f)
    names = args.partitions or [n for n in new.partition_names
                                if os.path.exists(os.path.join(args.workdir, n, "manifest.tsv"))]
    for name in names:
        manifest = os.path.join(args.workdir, name, "manifest.tsv")
        if not os.path.exists(manifest):
            problems.append("%s: no manifest in workdir" % name)
            continue
        want = fsconfig.read_manifest(manifest)
        off, length = single_extent(new, name)
        p = new.partition(name)
        try:
            with F2FSImage(args.super, off, length) as img:
                have = []
                for path, e, inode in img.walk():
                    if args.hash and e.type == "reg":
                        e.sha256 = img.hash_file(inode)
                    have.append(e)
                features = sorted(img.features)
                fs_size = img.fs_size
        except F2FSError as ex:
            problems.append("%s: %s" % (name, ex))
            continue
        ignore = {"ino", "nlink", "mtime", "mtime_ns"}
        d = fsconfig.manifest_diff(want, have, ignore=ignore)
        types = {e.path: e.type for e in want}
        changed_ok = set(modified.get(name, []))
        lines = []
        for e in d.only_in_a:
            if e.type in ("chr", "blk", "fifo", "sock"):
                continue
            lines.append("- missing: %s" % (e.path or "/"))
        for e in d.only_in_b:
            if e.path == "lost_found" or e.path.startswith("lost_found/"):
                continue
            lines.append("+ extra: %s" % e.path)
        for c in d.changed:
            if c.field == "size" and types.get(c.path) == "dir":
                continue
            if c.path in changed_ok and c.field in ("size", "sha256", "mtime", "mtime_ns"):
                continue
            lines.append("~ %s: %s %s -> %s" % (c.path or "/", c.field, fsconfig._fmt_val(c.field, c.a),
                                                fsconfig._fmt_val(c.field, c.b)))
        print("%s: features=%s fs_size=%d MiB lp_size=%d MiB readonly=%s entries=%d%s"
              % (name, ",".join(features) or "none", fs_size // MIB, p.size // MIB, p.readonly, len(have),
                 (" expected changes: %d" % len(changed_ok)) if changed_ok else ""))
        if lines:
            problems.extend("%s: %s" % (name, l) for l in lines)
            for l in lines[:50]:
                print("  " + l)
            if len(lines) > 50:
                print("  ... %d more" % (len(lines) - 50))
        else:
            print("  OK: matches the unpacked manifest%s" % ("" if args.hash else " (metadata; add --hash for content)"))
    if problems:
        print("VERIFY FAILED: %d problem(s)" % len(problems))
        return 1
    print("VERIFY OK")
    return 0


# --------------------------------------------------------------------------- pack-odin

def cmd_pack_odin(args) -> int:
    from . import odin
    try:
        res = odin.pack_odin(args.super, args.outdir, vbmeta_stock=args.vbmeta, name=args.name,
                             keep_sparse=args.keep_sparse, progress=log, stock_super=args.stock_super)
    except (odin.OdinError, avb.AvbError, OSError) as ex:
        raise SystemExit("pack-odin failed: %s" % ex)
    for k, v in res.items():
        print("%-14s %s" % (k, v))
    return 0


# --------------------------------------------------------------------------- main

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="superkit", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("inventory", help="LP table and per-partition facts of a raw super image")
    s.add_argument("super")
    s.set_defaults(fn=cmd_inventory)

    s = sub.add_parser("unpack", help="extract every partition with its metadata sidecars")
    s.add_argument("super")
    s.add_argument("workdir")
    s.add_argument("--partitions", "-p", nargs="+", metavar="NAME")
    s.add_argument("--no-hash", action="store_true", help="skip sha256 of file data")
    s.set_defaults(fn=cmd_unpack)

    s = sub.add_parser("mod", help="apply a mods.toml to an unpacked workdir")
    s.add_argument("workdir")
    s.add_argument("mods")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(fn=cmd_mod)

    s = sub.add_parser("repack", help="rebuild partitions and the super image")
    s.add_argument("workdir")
    s.add_argument("outdir")
    s.add_argument("--config", "-c", help="repack.toml (default: ./repack.toml if present)")
    s.add_argument("--partitions", "-p", nargs="+", metavar="NAME")
    s.add_argument("--partitions-only", action="store_true", help="do not assemble super.img")
    s.set_defaults(fn=cmd_repack)

    s = sub.add_parser("verify", help="compare a rebuilt super image with the unpacked workdir")
    s.add_argument("super")
    s.add_argument("workdir")
    s.add_argument("--partitions", "-p", nargs="+", metavar="NAME")
    s.add_argument("--hash", action="store_true", help="also compare file contents (reads everything)")
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("pack-odin", help="sparse + lz4 + AP tar.md5, plus a verification-disabled vbmeta")
    s.add_argument("super")
    s.add_argument("outdir")
    s.add_argument("--vbmeta", help="stock vbmeta.img to patch (flags 3)")
    s.add_argument("--stock-super", help="stock raw super: copy its Samsung signature record into the rebuilt super "
                                         "(download mode rejects a super without it: SW REV CHECK FAIL)")
    s.add_argument("--name", help="tag for the tar file name")
    s.add_argument("--keep-sparse", action="store_true")
    s.set_defaults(fn=cmd_pack_odin)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
