"""Odin packaging: sparse + lz4 + tar(.md5), and the verification-disabled vbmeta.

Measured against the stock A137FXXSCEZB1 files (docs/format-lp-avb-odin.md §4):
``lz4 -B6 --content-size`` reproduces Samsung's lz4 frames byte for byte, the AP tar
is a plain tar with the images at its root, and ``.tar.md5`` is the tar followed by the
``md5sum`` text line of the tar.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tarfile
import time

from . import avb, sparse
from .lp import SuperImage

LZ4_ARGS = ["-f", "-B6", "--content-size"]
RESERVED_BYTES = 4096          # liblp never touches the first 4 KiB of super
SIGNER_END_SECTOR_OFFSET = 0x400  # u32 LE: end sector of the signed extent in Samsung's record


class OdinError(Exception):
    pass


def _run(cmd: list[str]) -> str:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except FileNotFoundError:
        raise OdinError("tool not found: %s" % cmd[0]) from None
    out = p.stdout.decode("utf-8", errors="replace")
    if p.returncode != 0:
        raise OdinError("%s failed (exit %d):\n%s" % (" ".join(cmd), p.returncode, out[-2000:]))
    return out


def make_sparse(raw: str, out: str) -> str:
    """Samsung-style Android sparse image: RAW (<= 64 MiB) and DONT_CARE chunks only.

    Not img2simg: that encodes zero runs as FILL chunks, and the SM-A137F bootloader stalls
    on FILL chunks (measured 2026-10-03: stock content as img2simg output hangs at 66 %,
    the same content written RAW/DONT_CARE flashes)."""
    sparse.raw_to_sparse(raw, out)
    return out


def compress_lz4(src: str, dst: str) -> str:
    _run(["lz4"] + LZ4_ARGS + [src, dst])
    return dst


def check_lz4(path: str) -> None:
    _run(["lz4", "-t", path])


def make_tar(out_path: str, members: list[tuple[str, str]], md5: bool = True) -> str:
    """POSIX ustar with the given (arcname, file) members, uid/gid 0, mode 0644.
    With ``md5`` the md5sum line of the tar is appended and the file is named ``.tar.md5``
    (``out_path`` may end in ``.tar`` or ``.tar.md5``)."""
    if out_path.endswith(".tar.md5"):
        tar_path = out_path[: -len(".md5")]
    elif out_path.endswith(".tar"):
        tar_path = out_path
    else:
        tar_path = out_path + ".tar"
    os.makedirs(os.path.dirname(os.path.abspath(tar_path)), exist_ok=True)
    with tarfile.open(tar_path, "w", format=tarfile.USTAR_FORMAT) as tf:
        for arcname, path in members:
            info = tf.gettarinfo(path, arcname=arcname)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o644
            with open(path, "rb") as f:
                tf.addfile(info, f)
    if not md5:
        return tar_path
    h = hashlib.md5()
    with open(tar_path, "rb") as f:
        for chunk in iter(lambda: f.read(8 << 20), b""):
            h.update(chunk)
    md5_path = tar_path + ".md5"
    with open(tar_path, "ab") as f:
        f.write(("%s  %s\n" % (h.hexdigest(), os.path.basename(tar_path))).encode())
    os.replace(tar_path, md5_path)
    return md5_path


def copy_signer_record(stock_super: str, dst_super: str) -> dict:
    """Copy Samsung's Odin signature record (first 4 KiB of the stock super) into a rebuilt
    super image and point its end-sector field at the rebuilt layout.

    Samsung's download mode derives the image's SW REV from the build string in this record
    (A137FXXSCEZB1 -> revision 12) and refuses an image without it ("SW REV CHECK FAIL |super|
    Fused 12 < Binary 0") before writing anything.  The RSA signature in the record cannot be
    valid for a rebuilt image; an OEM-unlocked bootloader does not enforce it (the flag-patched
    vbmeta with the same record flashes fine), but it does enforce the revision."""
    with open(stock_super, "rb") as f:
        rec = bytearray(f.read(RESERVED_BYTES))
    if len(rec) != RESERVED_BYTES or rec.count(0) == RESERVED_BYTES:
        raise OdinError("%s has no Samsung signature record in its first 4 KiB" % stock_super)
    if b"SignerVer" not in rec:
        raise OdinError("%s: first 4 KiB do not look like a Samsung SignerVer record" % stock_super)
    lp = SuperImage(dst_super)
    end_sector = max((e.target_data + e.num_sectors for part in lp.partitions for e in part.extents), default=0)
    old_end = int.from_bytes(rec[SIGNER_END_SECTOR_OFFSET:SIGNER_END_SECTOR_OFFSET + 4], "little")
    rec[SIGNER_END_SECTOR_OFFSET:SIGNER_END_SECTOR_OFFSET + 4] = end_sector.to_bytes(4, "little")
    with open(dst_super, "r+b") as f:
        f.seek(0)
        f.write(rec)
    build = rec[0x320:0x340].split(b"\0", 1)[0].decode(errors="replace")
    return {"build": build, "stock_end_sector": old_end, "end_sector": end_sector}


def disabled_vbmeta(stock_vbmeta: str, dst: str) -> dict:
    """Copy of the stock vbmeta with flags = hashtree-disabled | verification-disabled."""
    return avb.patch_vbmeta_flags(stock_vbmeta, dst, flags=avb.FLAG_HASHTREE_DISABLED | avb.FLAG_VERIFICATION_DISABLED)


def pack_odin(super_img: str, outdir: str, vbmeta_stock: str | None = None, name: str | None = None,
              keep_sparse: bool = False, progress=None, stock_super: str | None = None) -> dict:
    """Produce ``super.img.lz4`` (sparse, lz4), ``vbmeta.img`` / ``vbmeta.img.lz4``
    (verification disabled, from ``vbmeta_stock``) and an Odin AP tar.md5 holding them.
    With ``stock_super`` the Samsung signature record is copied into ``super_img`` first
    (required for download mode to accept the image, see copy_signer_record)."""
    os.makedirs(outdir, exist_ok=True)
    stamp = name or time.strftime("%Y%m%d-%H%M%S")
    result: dict = {}
    if stock_super:
        if progress:
            progress("copying Samsung signature record from %s" % stock_super)
        result["signer_record"] = copy_signer_record(stock_super, super_img)
    sparse = os.path.join(outdir, "super.sparse.img")
    if progress:
        progress("sparse (RAW/DONT_CARE) -> %s" % sparse)
    make_sparse(super_img, sparse)
    lz4_path = os.path.join(outdir, "super.img.lz4")
    if progress:
        progress("lz4 -> %s" % lz4_path)
    compress_lz4(sparse, lz4_path)
    check_lz4(lz4_path)
    result["super_sparse"] = sparse
    result["super_lz4"] = lz4_path
    members = [("super.img.lz4", lz4_path)]
    if vbmeta_stock:
        vb = os.path.join(outdir, "vbmeta.img")
        info = disabled_vbmeta(vbmeta_stock, vb)
        vb_lz4 = compress_lz4(vb, vb + ".lz4")
        result["vbmeta"] = vb
        result["vbmeta_lz4"] = vb_lz4
        result["vbmeta_flags"] = info.get("flags")
        members.append(("vbmeta.img.lz4", vb_lz4))
    tar_path = make_tar(os.path.join(outdir, "AP_superkit_%s.tar.md5" % stamp), members)
    result["ap_tar"] = tar_path
    if not keep_sparse:
        os.remove(sparse)
        result["super_sparse"] = None
    return result
