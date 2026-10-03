"""AVB (Android Verified Boot 2.0) footer and vbmeta header handling.

Format reference: docs/format-lp-avb-odin.md section 3 (avbtool 1.4.0 struct formats).
All AVB structures are big-endian.

* :func:`parse_footer` – read the 64-byte ``AVBf`` footer at the end of a partition image.
* :func:`strip_footer` – copy only ``original_image_size`` bytes (the bare filesystem),
  dropping hashtree/FEC/vbmeta/footer.
* :func:`vbmeta_info` – decode the 256-byte ``AVB0`` header of a ``vbmeta*.img`` (or of the
  vbmeta blob embedded in a footered partition image).
* :func:`patch_vbmeta_flags` – rewrite only the ``flags`` u32 at header offset 120
  (1 = hashtree disabled, 2 = verification disabled, 3 = both).

Standard library only; streaming, so multi-GB images are fine.
"""

from __future__ import annotations

import dataclasses
import os
import shutil
import struct
from dataclasses import dataclass

__all__ = [
    "AvbError",
    "FOOTER_MAGIC",
    "FOOTER_SIZE",
    "VBMETA_MAGIC",
    "VBMETA_HEADER_SIZE",
    "FLAGS_OFFSET",
    "ROLLBACK_INDEX_OFFSET",
    "FLAG_HASHTREE_DISABLED",
    "FLAG_VERIFICATION_DISABLED",
    "ALGORITHM_NAMES",
    "Footer",
    "parse_footer",
    "parse_footer_bytes",
    "strip_footer",
    "vbmeta_header_offset",
    "vbmeta_info",
    "patch_vbmeta_flags",
]

FOOTER_MAGIC = b"AVBf"
FOOTER_FORMAT = "!4s2LQQQ28x"
FOOTER_SIZE = struct.calcsize(FOOTER_FORMAT)              # 64
assert FOOTER_SIZE == 64

VBMETA_MAGIC = b"AVB0"
VBMETA_HEADER_FORMAT = "!4s2L2QL2Q2Q2Q2Q2QQLL47sx80x"
VBMETA_HEADER_SIZE = struct.calcsize(VBMETA_HEADER_FORMAT)  # 256
assert VBMETA_HEADER_SIZE == 256
ROLLBACK_INDEX_OFFSET = 112          # u64 BE
FLAGS_OFFSET = 120                   # u32 BE
ROLLBACK_INDEX_LOCATION_OFFSET = 124
RELEASE_STRING_OFFSET = 128

FLAG_HASHTREE_DISABLED = 1
FLAG_VERIFICATION_DISABLED = 2
_FLAG_NAMES = ((FLAG_HASHTREE_DISABLED, "hashtree_disabled"),
               (FLAG_VERIFICATION_DISABLED, "verification_disabled"))

ALGORITHM_NAMES = {
    0: "NONE",
    1: "SHA256_RSA2048",
    2: "SHA256_RSA4096",
    3: "SHA256_RSA8192",
    4: "SHA512_RSA2048",
    5: "SHA512_RSA4096",
    6: "SHA512_RSA8192",
}

_COPY_CHUNK = 8 << 20


class AvbError(Exception):
    """Missing or malformed AVB structure."""


def flag_names(flags: int) -> list[str]:
    return [name for bit, name in _FLAG_NAMES if flags & bit]


@dataclass(frozen=True)
class Footer:
    """AvbFooter: the last 64 bytes of an AVB-signed partition image."""
    magic: bytes
    version_major: int
    version_minor: int
    original_image_size: int
    vbmeta_offset: int
    vbmeta_size: int

    @property
    def version(self) -> str:
        return f"{self.version_major}.{self.version_minor}"

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["magic"] = self.magic.decode("ascii", "replace")
        d["version"] = self.version
        return d

    def pack(self) -> bytes:
        return struct.pack(FOOTER_FORMAT, self.magic, self.version_major, self.version_minor,
                           self.original_image_size, self.vbmeta_offset, self.vbmeta_size)


def parse_footer_bytes(data: bytes) -> Footer | None:
    """Decode a 64-byte footer blob; None if the magic does not match."""
    if len(data) < FOOTER_SIZE:
        return None
    magic, major, minor, orig, voff, vsize = struct.unpack(FOOTER_FORMAT, data[-FOOTER_SIZE:])
    if magic != FOOTER_MAGIC:
        return None
    return Footer(magic, major, minor, orig, voff, vsize)


def parse_footer(path: str | os.PathLike) -> Footer | None:
    """Return the AVB footer of ``path`` or None when the file carries none."""
    size = os.path.getsize(path)
    if size < FOOTER_SIZE:
        return None
    with open(path, "rb") as f:
        f.seek(size - FOOTER_SIZE)
        footer = parse_footer_bytes(f.read(FOOTER_SIZE))
    if footer is None:
        return None
    if footer.original_image_size > size or footer.vbmeta_offset + footer.vbmeta_size > size:
        raise AvbError(f"{os.fspath(path)}: AVB footer values exceed file size {size}: {footer}")
    return footer


def _copy_range(src, dst, length: int, chunk: int = _COPY_CHUNK) -> int:
    remaining = length
    while remaining:
        buf = src.read(min(chunk, remaining))
        if not buf:
            raise AvbError("unexpected end of file while copying")
        dst.write(buf)
        remaining -= len(buf)
    return length


def strip_footer(src: str | os.PathLike, dst: str | os.PathLike, chunk: int = _COPY_CHUNK) -> Footer:
    """Write the first ``original_image_size`` bytes of ``src`` to ``dst`` (streaming).

    Raises :class:`AvbError` if ``src`` has no AVB footer. Returns the footer that was stripped.
    """
    footer = parse_footer(src)
    if footer is None:
        raise AvbError(f"{os.fspath(src)}: no AVB footer, nothing to strip")
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        _copy_range(fin, fout, footer.original_image_size, chunk)
    return footer


def vbmeta_header_offset(path: str | os.PathLike) -> int:
    """Where the AVB0 header lives: ``vbmeta_offset`` from a footer, else 0 (a bare vbmeta image)."""
    footer = parse_footer(path)
    return footer.vbmeta_offset if footer is not None else 0


def _unpack_vbmeta_header(data: bytes, where: str) -> dict:
    if len(data) < VBMETA_HEADER_SIZE:
        raise AvbError(f"{where}: too small for an AVB vbmeta header ({len(data)} < {VBMETA_HEADER_SIZE})")
    (magic, req_major, req_minor, auth_size, aux_size, algorithm, hash_off, hash_size, sig_off, sig_size,
     pk_off, pk_size, pkmd_off, pkmd_size, desc_off, desc_size, rollback, flags, rb_loc,
     release) = struct.unpack(VBMETA_HEADER_FORMAT, data[:VBMETA_HEADER_SIZE])
    if magic != VBMETA_MAGIC:
        raise AvbError(f"{where}: bad vbmeta magic {magic!r} (expected {VBMETA_MAGIC!r})")
    return {
        "magic": magic.decode("ascii"),
        "required_libavb_version_major": req_major,
        "required_libavb_version_minor": req_minor,
        "required_libavb_version": f"{req_major}.{req_minor}",
        "authentication_data_block_size": auth_size,
        "auxiliary_data_block_size": aux_size,
        "algorithm_type": algorithm,
        "algorithm": ALGORITHM_NAMES.get(algorithm, f"UNKNOWN({algorithm})"),
        "hash_offset": hash_off,
        "hash_size": hash_size,
        "signature_offset": sig_off,
        "signature_size": sig_size,
        "public_key_offset": pk_off,
        "public_key_size": pk_size,
        "public_key_metadata_offset": pkmd_off,
        "public_key_metadata_size": pkmd_size,
        "descriptors_offset": desc_off,
        "descriptors_size": desc_size,
        "rollback_index": rollback,
        "flags": flags,
        "flag_names": flag_names(flags),
        "rollback_index_location": rb_loc,
        "release_string": release.split(b"\0", 1)[0].decode("utf-8", "replace"),
        "header_size": VBMETA_HEADER_SIZE,
        "vbmeta_size": VBMETA_HEADER_SIZE + auth_size + aux_size,
    }


def vbmeta_info(path: str | os.PathLike, offset: int | None = None) -> dict:
    """Decode the vbmeta header of ``path``.

    ``offset`` defaults to the footer's ``vbmeta_offset`` if the file has an AVB footer, else 0.
    The dict holds every header field plus ``vbmeta_size`` (header + auth + aux blocks),
    ``vbmeta_offset``, ``file_size``, ``trailer_size`` (bytes after the blob: Samsung appends a
    512-byte SignerVer02 record to vbmeta*.img) and ``footer`` (dict or None).
    """
    path = os.fspath(path)
    footer = parse_footer(path)
    if offset is None:
        offset = footer.vbmeta_offset if footer is not None else 0
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read(VBMETA_HEADER_SIZE)
    info = _unpack_vbmeta_header(data, f"{path}@{offset}")
    info["vbmeta_offset"] = offset
    info["file_size"] = size
    blob_end = offset + info["vbmeta_size"]
    if blob_end > size:
        raise AvbError(f"{path}: vbmeta blob [{offset}, {blob_end}) exceeds file size {size}")
    info["trailer_size"] = (size - blob_end) if footer is None else None
    info["footer"] = footer.to_dict() if footer is not None else None
    return info


def patch_vbmeta_flags(src: str | os.PathLike, dst: str | os.PathLike, flags: int = 3,
                       offset: int | None = None) -> dict:
    """Copy ``src`` to ``dst`` and overwrite only the u32 ``flags`` field of its vbmeta header.

    Every other byte is left untouched (so the Samsung trailer, descriptors and the now-invalid
    signature stay as they were). ``src`` and ``dst`` may be the same path (in-place patch).
    Returns :func:`vbmeta_info` of the patched file.
    """
    src, dst = os.fspath(src), os.fspath(dst)
    if not 0 <= flags <= 0xFFFFFFFF:
        raise ValueError(f"flags {flags} out of u32 range")
    # Validate before touching anything.
    before = vbmeta_info(src, offset)
    hdr_offset = before["vbmeta_offset"]
    if not (os.path.exists(dst) and os.path.samefile(src, dst)):
        shutil.copyfile(src, dst)
    with open(dst, "r+b") as f:
        f.seek(hdr_offset)
        if f.read(4) != VBMETA_MAGIC:
            raise AvbError(f"{dst}: vbmeta magic not found at {hdr_offset} after copy")
        f.seek(hdr_offset + FLAGS_OFFSET)
        f.write(struct.pack("!I", flags))
    after = vbmeta_info(dst, hdr_offset)
    if after["flags"] != flags or after["rollback_index"] != before["rollback_index"]:
        raise AvbError(f"{dst}: patch verification failed ({after['flags']=}, {after['rollback_index']=})")
    return after
