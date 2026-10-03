"""Userland, read-only f2fs reader (DESIGN.md §5, docs/format-f2fs.md).

Opens an f2fs image (or an f2fs partition inside a bigger file, via ``offset`` /
``length``) with ``mmap``, validates the superblock and the checkpoint, resolves
nodes through the NAT (+ the NAT journal of the hot-data summary block), and
offers:

* ``F2FSImage.walk()`` – every inode as ``(path, ManifestEntry, Inode)`` sorted by
  path (root is ``''``); reads metadata only (xattrs, symlink targets), never
  file data.
* ``F2FSImage.read_file(inode)`` – file content as block-run chunks (holes and
  ``NEW_ADDR`` blocks come back as zeros, the last block is cut to ``i_size``).
* ``F2FSImage.read_symlink(inode)`` – symlink target (inline or data block).
* ``F2FSImage.extract(dest_dir, ...)`` – writes the tree to the host (regular
  files, dirs, symlinks, hard links; mtimes; sha256 while writing; special
  files only recorded) and returns / writes the manifest.
* ``F2FSImage.info()`` – JSON-serialisable facts for ``meta.json``.
* ``probe(path, offset)`` – cheap "is this f2fs" test.

Everything that is not supported (compression, encryption, device aliasing,
multi-device images, non-4 KiB blocks) raises an ``F2FSError`` subclass with a
clear message instead of producing silently wrong output.  Every block address
that is dereferenced is checked against ``main_blkaddr .. block_count`` and the
mapped length, so a corrupt image can never make the reader read outside the
image.

Only the standard library is used.  All multi-byte fields are little-endian.
"""
from __future__ import annotations

import hashlib
import mmap
import os
import stat
import struct
import uuid as _uuid
import zlib
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Iterator

from .fsconfig import ManifestEntry, decode_capabilities, type_from_mode, write_manifest

__all__ = [
    "F2FSImage", "Inode", "SuperBlock", "Checkpoint", "probe",
    "F2FSError", "NotF2FSError", "CorruptError", "BlockRangeError", "UnsupportedError",
    "CompressionError", "FEATURE_NAMES", "CP_FLAG_NAMES", "feature_names", "f2fs_crc32",
    "BLOCK_SIZE", "NULL_ADDR", "NEW_ADDR", "COMPRESS_ADDR",
]

# --------------------------------------------------------------------------- constants

BLOCK_SIZE = 4096
F2FS_SUPER_MAGIC = 0xF2F52010
F2FS_SUPER_OFFSET = 1024
SB_SIZE = 3072
F2FS_XATTR_MAGIC = 0xF2F52011

NULL_ADDR = 0x00000000
NEW_ADDR = 0xFFFFFFFF
COMPRESS_ADDR = 0xFFFFFFFE

LOG_BLOCKS_PER_SEG = 9
BLOCKS_PER_SEG = 1 << LOG_BLOCKS_PER_SEG            # 512

DEF_ADDRS_PER_INODE = (BLOCK_SIZE - 360 - 20 - 24) // 4   # 923
ADDRS_PER_BLOCK = (BLOCK_SIZE - 24) // 4                  # 1018
NIDS_PER_BLOCK = ADDRS_PER_BLOCK                          # 1018
NAT_ENTRY_SIZE = 9
NAT_ENTRY_PER_BLOCK = BLOCK_SIZE // NAT_ENTRY_SIZE        # 455
ENTRIES_IN_SUM = BLOCK_SIZE // 8                          # 512
SUM_ENTRIES_SIZE = 7 * ENTRIES_IN_SUM                     # 3584
SUM_JOURNAL_SIZE = BLOCK_SIZE - 5 - SUM_ENTRIES_SIZE      # 507
NAT_JOURNAL_ENTRY_SIZE = 13
NAT_JOURNAL_ENTRIES = (SUM_JOURNAL_SIZE - 2) // NAT_JOURNAL_ENTRY_SIZE   # 38
NR_DENTRY_IN_BLOCK = (8 * BLOCK_SIZE) // ((11 + 8) * 8 + 1)             # 214
SIZE_OF_DENTRY_BITMAP = (NR_DENTRY_IN_BLOCK + 7) // 8                   # 27
SIZE_OF_RESERVED = BLOCK_SIZE - ((11 + 8) * NR_DENTRY_IN_BLOCK + SIZE_OF_DENTRY_BITMAP)  # 3
DENTRY_BLOCK_DENTRIES_OFF = SIZE_OF_DENTRY_BITMAP + SIZE_OF_RESERVED      # 30
DENTRY_BLOCK_NAMES_OFF = DENTRY_BLOCK_DENTRIES_OFF + 11 * NR_DENTRY_IN_BLOCK  # 2384
DENTRY_SLOT_LEN = 8
DEFAULT_INLINE_XATTR_ADDRS = 50
DEF_INLINE_RESERVED_SIZE = 1
XATTR_NODE_OFFSET = 0xFFFFFFFF >> 3                      # 0x1FFFFFFF
VALID_XATTR_BLOCK_SIZE = BLOCK_SIZE - 24                 # 4072
XATTR_HEADER_SIZE = 24
F2FS_NAME_LEN = 255
MAX_SYMLINK_LEN = BLOCK_SIZE - 1

I_ADDR_OFF = 360
I_NID_OFF = I_ADDR_OFF + 4 * DEF_ADDRS_PER_INODE         # 4052
NODE_FOOTER_OFF = I_NID_OFF + 20                         # 4072
F2FS_TOTAL_EXTRA_ATTR_SIZE = 36
I_INODE_CHECKSUM_OFF = 368

# i_inline
F2FS_INLINE_XATTR = 0x01
F2FS_INLINE_DATA = 0x02
F2FS_INLINE_DENTRY = 0x04
F2FS_DATA_EXIST = 0x08
F2FS_INLINE_DOTS = 0x10
F2FS_EXTRA_ATTR = 0x20
F2FS_PIN_FILE = 0x40
F2FS_COMPRESS_RELEASED = 0x80

# i_flags
F2FS_COMPR_FL = 0x00000004
F2FS_NODUMP_FL = 0x00000040
F2FS_CASEFOLD_FL = 0x40000000
F2FS_DEVICE_ALIAS_FL = 0x80000000

# i_advise
FADVISE_ENCRYPT_BIT = 0x04
FADVISE_ENC_NAME_BIT = 0x08

# superblock features (mkfs -O names)
FEATURE_NAMES: dict[int, str] = {
    0x0001: "encrypt",
    0x0002: "blkzoned",
    0x0004: "atomic_write",
    0x0008: "extra_attr",
    0x0010: "project_quota",
    0x0020: "inode_checksum",
    0x0040: "flexible_inline_xattr",
    0x0080: "quota",
    0x0100: "inode_crtime",
    0x0200: "lost_found",
    0x0400: "verity",
    0x0800: "sb_checksum",
    0x1000: "casefold",
    0x2000: "compression",
    0x4000: "ro",
    0x8000: "device_alias",
    0x10000: "packed_ssa",
}
FEATURE_BITS: dict[str, int] = {v: k for k, v in FEATURE_NAMES.items()}
F_ENCRYPT, F_EXTRA_ATTR, F_INODE_CHKSUM, F_FLEX_XATTR = 0x1, 0x8, 0x20, 0x40
F_SB_CHKSUM, F_COMPRESSION, F_RO, F_DEVICE_ALIAS = 0x800, 0x2000, 0x4000, 0x8000

CP_FLAG_NAMES: dict[int, str] = {
    0x0001: "unmount",
    0x0002: "orphan_present",
    0x0004: "compact_sum",
    0x0008: "error",
    0x0010: "fsck",
    0x0020: "fastboot",
    0x0040: "crc_recovery",
    0x0080: "nat_bits",
    0x0100: "trimmed",
    0x0200: "nocrc_recovery",
    0x0400: "large_nat_bitmap",
    0x0800: "quota_need_fsck",
    0x1000: "disabled",
    0x4000: "resizefs",
}
CP_UMOUNT_FLAG = 0x1
CP_ORPHAN_PRESENT_FLAG = 0x2
CP_COMPACT_SUM_FLAG = 0x4
CP_LARGE_NAT_BITMAP_FLAG = 0x400

XATTR_INDEX_PREFIX: dict[int, str] = {
    1: "user.",
    2: "system.posix_acl_access",
    3: "system.posix_acl_default",
    4: "trusted.",
    5: "lustre.",
    6: "security.",
    7: "f2fs.advise",          # F2FS_XATTR_INDEX_ADVISE (virtual, never on disk)
    9: "f2fs.encryption.",     # fscrypt context ("c")
    11: "f2fs.verity.",        # fs-verity descriptor ("v")
}
XATTR_INDEX_ENCRYPTION = 9

# f2fs dentry file_type
FT_UNKNOWN, FT_REG_FILE, FT_DIR, FT_CHRDEV, FT_BLKDEV, FT_FIFO, FT_SOCK, FT_SYMLINK = range(8)
FT_NAMES = {1: "reg", 2: "dir", 3: "chr", 4: "blk", 5: "fifo", 6: "sock", 7: "lnk"}

_RUN_CHUNK_BYTES = 32 << 20        # largest single write/hash chunk of one block run
_ZERO_CHUNK = bytes(1 << 20)       # shared zero buffer for holes (read_file / hashing)

_u16 = struct.Struct("<H").unpack_from
_u32 = struct.Struct("<I").unpack_from
_u64 = struct.Struct("<Q").unpack_from
_unpack_from = struct.unpack_from
_DENTRY = struct.Struct("<IIHB").unpack_from
_NAT_ENTRY = struct.Struct("<BII").unpack_from
_NAT_JOURNAL = struct.Struct("<IBII").unpack_from
_XATTR_ENTRY = struct.Struct("<BBH").unpack_from
_FOOTER = struct.Struct("<IIIQI").unpack_from
_INODE_HEAD = struct.Struct("<HBBIIIQQQQQIIIIIIIII").unpack_from
_ADDRS = {n: struct.Struct("<%dI" % n).unpack_from for n in (ADDRS_PER_BLOCK, DEF_ADDRS_PER_INODE)}


# --------------------------------------------------------------------------- errors

class F2FSError(Exception):
    """Base class of every error raised by this module."""


class NotF2FSError(F2FSError):
    """The data does not carry an f2fs superblock (magic mismatch, too short)."""


class CorruptError(F2FSError):
    """A structure is inconsistent (bad checksum, footer mismatch, bad dentry, ...)."""


class BlockRangeError(CorruptError):
    """A block address points outside main_blkaddr .. block_count (or the mapped image)."""


class UnsupportedError(F2FSError):
    """The image uses a feature the reader refuses (encryption, device alias, multi-device, ...)."""


class CompressionError(UnsupportedError):
    """A compressed inode / cluster was found (DESIGN non-goal: refuse, never corrupt)."""


# --------------------------------------------------------------------------- helpers

def f2fs_crc32(data, seed: int = F2FS_SUPER_MAGIC) -> int:
    """``f2fs_cal_crc32``: reflected CRC-32 (0xEDB88320) with initial register ``seed``
    and no final inversion (verified equal to the C loop)."""
    return zlib.crc32(data, seed ^ 0xFFFFFFFF) ^ 0xFFFFFFFF


def feature_names(feature: int) -> list[str]:
    """mkfs ``-O`` names of the bits set in ``feature`` (unknown bits as ``unknown_0x...``)."""
    out = []
    bit = 1
    while bit <= feature:
        if feature & bit:
            out.append(FEATURE_NAMES.get(bit, "unknown_0x%x" % bit))
        bit <<= 1
    return out


def _cp_flag_names(flags: int) -> list[str]:
    out = []
    bit = 1
    while bit <= flags:
        if flags & bit:
            out.append(CP_FLAG_NAMES.get(bit, "unknown_0x%x" % bit))
        bit <<= 1
    return out


def _cstr(buf) -> str:
    b = bytes(buf)
    i = b.find(b"\0")
    if i >= 0:
        b = b[:i]
    return b.decode("utf-8", "replace")


# --------------------------------------------------------------------------- superblock / checkpoint

@dataclass(slots=True)
class SuperBlock:
    """``struct f2fs_super_block`` (3072 bytes at byte 1024 of block 0; backup in block 1)."""
    magic: int
    major_ver: int
    minor_ver: int
    log_sectorsize: int
    log_sectors_per_block: int
    log_blocksize: int
    log_blocks_per_seg: int
    segs_per_sec: int
    secs_per_zone: int
    checksum_offset: int
    block_count: int
    section_count: int
    segment_count: int
    segment_count_ckpt: int
    segment_count_sit: int
    segment_count_nat: int
    segment_count_ssa: int
    segment_count_main: int
    segment0_blkaddr: int
    cp_blkaddr: int
    sit_blkaddr: int
    nat_blkaddr: int
    ssa_blkaddr: int
    main_blkaddr: int
    root_ino: int
    node_ino: int
    meta_ino: int
    uuid_bytes: bytes
    volume_name: str
    extension_count: int
    extension_list: list[str]
    cp_payload: int
    version: str
    init_version: str
    feature: int
    encryption_level: int
    encrypt_pw_salt: bytes
    devs: list[tuple[str, int]]
    qf_ino: tuple[int, int, int]
    hot_ext_count: int
    s_encoding: int
    s_encoding_flags: int
    s_stop_reason: bytes
    s_errors: bytes
    crc: int
    copy: int = 0                  # which copy was used: 0 = block 0, 1 = backup in block 1

    @property
    def uuid(self) -> str:
        return str(_uuid.UUID(bytes=self.uuid_bytes))

    @property
    def block_size(self) -> int:
        return 1 << self.log_blocksize

    @property
    def sector_size(self) -> int:
        return 1 << self.log_sectorsize

    @property
    def features(self) -> list[str]:
        return feature_names(self.feature)

    @property
    def cold_extensions(self) -> list[str]:
        return self.extension_list[:self.extension_count]

    @property
    def hot_extensions(self) -> list[str]:
        return self.extension_list[self.extension_count:self.extension_count + self.hot_ext_count]

    @property
    def nat_blocks(self) -> int:
        return (self.segment_count_nat // 2) << self.log_blocks_per_seg

    @property
    def max_nid(self) -> int:
        return self.nat_blocks * NAT_ENTRY_PER_BLOCK


def _parse_superblock(raw: bytes) -> SuperBlock:
    """Parse 3072 superblock bytes (no validation beyond field extraction)."""
    f = _unpack_from("<IHHIIIIIII", raw, 0)
    (magic, major, minor, log_sectorsize, log_spb, log_blocksize, log_bps,
     segs_per_sec, secs_per_zone, checksum_offset) = f
    block_count = _u64(raw, 36)[0]
    g = _unpack_from("<16I", raw, 44)
    exts = [_cstr(raw[1152 + 8 * i:1160 + 8 * i]) for i in range(64)]
    devs = []
    for i in range(8):
        off = 2201 + 68 * i
        devs.append((_cstr(raw[off:off + 64]), _u32(raw, off + 64)[0]))
    volume_name = raw[124:124 + 1024].decode("utf-16-le", "replace")
    volume_name = volume_name.split("\0", 1)[0]
    return SuperBlock(
        magic=magic, major_ver=major, minor_ver=minor, log_sectorsize=log_sectorsize,
        log_sectors_per_block=log_spb, log_blocksize=log_blocksize, log_blocks_per_seg=log_bps,
        segs_per_sec=segs_per_sec, secs_per_zone=secs_per_zone, checksum_offset=checksum_offset,
        block_count=block_count, section_count=g[0], segment_count=g[1], segment_count_ckpt=g[2],
        segment_count_sit=g[3], segment_count_nat=g[4], segment_count_ssa=g[5],
        segment_count_main=g[6], segment0_blkaddr=g[7], cp_blkaddr=g[8], sit_blkaddr=g[9],
        nat_blkaddr=g[10], ssa_blkaddr=g[11], main_blkaddr=g[12], root_ino=g[13],
        node_ino=g[14], meta_ino=g[15], uuid_bytes=bytes(raw[108:124]), volume_name=volume_name,
        extension_count=_u32(raw, 1148)[0], extension_list=exts, cp_payload=_u32(raw, 1664)[0],
        version=_cstr(raw[1668:1668 + 256]), init_version=_cstr(raw[1924:1924 + 256]),
        feature=_u32(raw, 2180)[0], encryption_level=raw[2184], encrypt_pw_salt=bytes(raw[2185:2201]),
        devs=devs, qf_ino=tuple(_unpack_from("<3I", raw, 2745)), hot_ext_count=raw[2757],
        s_encoding=_u16(raw, 2758)[0], s_encoding_flags=_u16(raw, 2760)[0],
        s_stop_reason=bytes(raw[2762:2794]), s_errors=bytes(raw[2794:2810]), crc=_u32(raw, 3068)[0],
    )


@dataclass(slots=True)
class Checkpoint:
    """``struct f2fs_checkpoint`` of the valid pack plus where its pieces live."""
    checkpoint_ver: int
    user_block_count: int
    valid_block_count: int
    rsvd_segment_count: int
    overprov_segment_count: int
    free_segment_count: int
    cur_node_segno: tuple
    cur_node_blkoff: tuple
    cur_data_segno: tuple
    cur_data_blkoff: tuple
    ckpt_flags: int
    cp_pack_total_block_count: int
    cp_pack_start_sum: int
    valid_node_count: int
    valid_inode_count: int
    next_free_nid: int
    sit_ver_bitmap_bytesize: int
    nat_ver_bitmap_bytesize: int
    checksum_offset: int
    elapsed_time: int
    alloc_type: bytes
    crc: int
    pack: int                      # 1 or 2
    start_blkaddr: int             # first block of the chosen pack
    pack_versions: tuple           # (version of pack 1 or None, version of pack 2 or None)
    nat_bitmap: bytes
    sit_bitmap: bytes
    nat_bitmap_offset: int         # byte offset of the NAT version bitmap inside the cp block(s)
    sit_bitmap_offset: int
    nat_journal: dict = field(default_factory=dict)   # nid -> (version, ino, block_addr)
    n_nats: int = 0

    @property
    def flag_names(self) -> list[str]:
        return _cp_flag_names(self.ckpt_flags)


def _parse_checkpoint_fields(raw) -> dict:
    f = _unpack_from("<QQQIII", raw, 0)
    g = _unpack_from("<IIIIIIIIIQ", raw, 132)
    return dict(
        checkpoint_ver=f[0], user_block_count=f[1], valid_block_count=f[2],
        rsvd_segment_count=f[3], overprov_segment_count=f[4], free_segment_count=f[5],
        cur_node_segno=tuple(_unpack_from("<8I", raw, 36)), cur_node_blkoff=tuple(_unpack_from("<8H", raw, 68)),
        cur_data_segno=tuple(_unpack_from("<8I", raw, 84)), cur_data_blkoff=tuple(_unpack_from("<8H", raw, 116)),
        ckpt_flags=g[0], cp_pack_total_block_count=g[1], cp_pack_start_sum=g[2],
        valid_node_count=g[3], valid_inode_count=g[4], next_free_nid=g[5],
        sit_ver_bitmap_bytesize=g[6], nat_ver_bitmap_bytesize=g[7], checksum_offset=g[8],
        elapsed_time=g[9], alloc_type=bytes(raw[176:192]),
    )


def cp_crc_ok(blk) -> bool:
    """``f2fs_checkpoint_chksum`` check of one checkpoint block."""
    off = _u32(blk, 164)[0]
    if off < 192 or off > BLOCK_SIZE - 4:
        return False
    crc = f2fs_crc32(blk[:off])
    if off < BLOCK_SIZE - 4:                 # crc sits before the bitmaps: skip it, hash the rest
        crc = f2fs_crc32(blk[off + 4:], crc)
    return crc == _u32(blk, off)[0]


# --------------------------------------------------------------------------- inode

class Inode:
    """Parsed ``struct f2fs_inode`` (+ node footer / NAT facts).  The raw block is not kept;
    ``F2FSImage`` re-reads it from ``blkaddr`` when it needs the address arrays."""

    __slots__ = (
        "nid", "blkaddr", "mode", "advise", "inline", "uid", "gid", "links", "size", "blocks",
        "atime", "ctime", "mtime", "atime_nsec", "ctime_nsec", "mtime_nsec", "generation",
        "current_depth", "xattr_nid", "flags", "pino", "name", "dir_level", "i_nid",
        "extra_isize", "inline_xattr_addrs", "addrs_per_inode", "addr_base", "inline_data_off",
        "max_inline_data", "projid", "inode_checksum", "crtime", "crtime_nsec", "rdev",
        "footer_flag", "footer_cp_ver",
    )

    # ---- convenience
    @property
    def ino(self) -> int:
        return self.nid

    @property
    def type(self) -> str:
        return type_from_mode(self.mode)

    @property
    def is_dir(self) -> bool:
        return stat.S_ISDIR(self.mode)

    @property
    def is_reg(self) -> bool:
        return stat.S_ISREG(self.mode)

    @property
    def is_lnk(self) -> bool:
        return stat.S_ISLNK(self.mode)

    @property
    def is_special(self) -> bool:
        return not (stat.S_ISDIR(self.mode) or stat.S_ISREG(self.mode) or stat.S_ISLNK(self.mode))

    @property
    def has_inline_data(self) -> bool:
        return bool(self.inline & F2FS_INLINE_DATA)

    @property
    def has_inline_dentry(self) -> bool:
        return bool(self.inline & F2FS_INLINE_DENTRY)

    @property
    def has_inline_xattr(self) -> bool:
        return self.inline_xattr_addrs > 0

    @property
    def has_extra_attr(self) -> bool:
        return bool(self.inline & F2FS_EXTRA_ATTR)

    @property
    def ofs_in_node(self) -> int:
        return self.footer_flag >> 3

    @property
    def nblocks(self) -> int:
        """Data blocks covered by i_size (0 for inline data)."""
        if self.inline & F2FS_INLINE_DATA:
            return 0
        return (self.size + BLOCK_SIZE - 1) // BLOCK_SIZE

    def __repr__(self) -> str:
        return "Inode(nid=%d, mode=0o%o, size=%d, links=%d, inline=0x%x, blkaddr=%d)" % (
            self.nid, self.mode, self.size, self.links, self.inline, self.blkaddr)


# --------------------------------------------------------------------------- the image

class F2FSImage:
    """Read-only, mmap-based view of one f2fs filesystem.

    ``path``   file holding the filesystem (raw image, or a super.raw with ``offset``)
    ``offset`` byte offset of block 0 inside the file (any alignment)
    ``length`` bytes available to the filesystem from ``offset`` (default: to end of file);
               an AVB footer after ``block_count * 4096`` is harmless.

    Attributes after open: ``sb``, ``cp``, ``feature`` (int), ``features`` (frozenset of
    names), ``block_size``, ``block_count``, ``fs_size``, ``uuid``, ``label``, ``root_ino``,
    ``path``, ``offset``, ``length``.  Use as a context manager or call ``close()``.
    """

    def __init__(self, path, offset: int = 0, length: int | None = None,
                 verify_inode_checksums: bool = True):
        self.path = os.fspath(path)
        self.offset = int(offset)
        self.verify_inode_checksums = verify_inode_checksums
        self._mm = None
        self._mv = None
        self._closed = True
        self._nat_cache: dict[int, bytes] = {}
        self._entries: list | None = None
        if self.offset < 0:
            raise ValueError("offset must be >= 0")
        fd = os.open(self.path, os.O_RDONLY)
        try:
            fsize = os.fstat(fd).st_size
            if length is None:
                length = fsize - self.offset
            length = int(length)
            if length < 2 * BLOCK_SIZE or self.offset + length > fsize:
                raise NotF2FSError("%s: %d bytes at offset %d cannot hold an f2fs superblock (file size %d)"
                                   % (self.path, length, self.offset, fsize))
            gran = mmap.ALLOCATIONGRANULARITY
            map_off = self.offset - self.offset % gran
            self._delta = self.offset - map_off
            self._mm = mmap.mmap(fd, length + self._delta, offset=map_off, access=mmap.ACCESS_READ)
        finally:
            os.close(fd)
        self.length = length
        self._mv = memoryview(self._mm)
        self._closed = False
        self._avail_blocks = length // BLOCK_SIZE
        try:
            self._open_superblock()
            self._open_checkpoint()
        except Exception:
            self.close()
            raise

    # ---- lifecycle
    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._nat_cache.clear()
        self._entries = None
        if self._mv is not None:
            self._mv.release()
            self._mv = None
        if self._mm is not None:
            try:
                self._mm.close()
            except BufferError:
                pass                 # a caller still holds a chunk; the mapping goes when it is dropped
            self._mm = None

    def __enter__(self) -> "F2FSImage":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __repr__(self) -> str:
        return "F2FSImage(%r, offset=%d, length=%d)" % (self.path, self.offset, self.length)

    # ---- raw access
    def _blk(self, addr: int):
        """memoryview of block ``addr`` (any block of the image, range-checked)."""
        if self._closed:
            raise F2FSError("image %r is closed" % self.path)
        if addr < 0 or addr >= self._block_limit:
            raise BlockRangeError("block %d outside the image (%d blocks mapped, block_count %d)"
                                  % (addr, self._avail_blocks, getattr(self, "block_count", 0)))
        off = self._delta + addr * BLOCK_SIZE
        return self._mv[off:off + BLOCK_SIZE]

    def _check_data_addr(self, addr: int, what: str = "block address") -> None:
        if addr == COMPRESS_ADDR:
            raise CompressionError("%s is COMPRESS_ADDR: compressed cluster, unsupported" % what)
        if addr < self.sb.main_blkaddr or addr >= self.block_count:
            raise BlockRangeError("%s %d outside main area %d..%d"
                                  % (what, addr, self.sb.main_blkaddr, self.block_count - 1))

    # ---- superblock
    def _open_superblock(self) -> None:
        self._block_limit = self._avail_blocks
        errors = []
        sb = None
        for copy in (0, 1):
            raw = bytes(self._blk(copy)[F2FS_SUPER_OFFSET:F2FS_SUPER_OFFSET + SB_SIZE])
            try:
                cand = _parse_superblock(raw)
                self._sanity_check_sb(cand, raw)
            except F2FSError as ex:
                errors.append("block %d: %s" % (copy, ex))
                continue
            cand.copy = copy
            sb = cand
            break
        if sb is None:
            if all(e.endswith("not f2fs (bad magic)") for e in errors):
                raise NotF2FSError("%s: no f2fs superblock at offset %d (%s)" % (self.path, self.offset, "; ".join(errors)))
            raise CorruptError("%s: no valid superblock (%s)" % (self.path, "; ".join(errors)))
        self.sb = sb
        self.feature = sb.feature
        self.features = frozenset(sb.features)
        self.block_size = sb.block_size
        self.block_count = sb.block_count
        self.fs_size = sb.block_count * sb.block_size
        self.uuid = sb.uuid
        self.label = sb.volume_name
        self.root_ino = sb.root_ino
        if self.fs_size > self.length:
            raise CorruptError("%s: superblock says %d blocks (%d bytes) but only %d bytes are mapped: truncated image"
                               % (self.path, sb.block_count, self.fs_size, self.length))
        self._block_limit = sb.block_count
        self._max_nid = sb.max_nid
        if self.feature & F_INODE_CHKSUM:
            self._chksum_seed = f2fs_crc32(sb.uuid_bytes, 0xFFFFFFFF)

    @staticmethod
    def _sanity_check_sb(sb: SuperBlock, raw: bytes) -> None:
        if sb.magic != F2FS_SUPER_MAGIC:
            raise NotF2FSError("not f2fs (bad magic)")
        if sb.feature & F_SB_CHKSUM:
            if sb.checksum_offset != SB_SIZE - 4:
                raise CorruptError("sb checksum_offset %d != %d" % (sb.checksum_offset, SB_SIZE - 4))
            calc = f2fs_crc32(raw[:SB_SIZE - 4])
            if calc != sb.crc:
                raise CorruptError("superblock crc mismatch (stored 0x%08x, computed 0x%08x)" % (sb.crc, calc))
        if sb.log_blocksize != 12:
            raise UnsupportedError("block size 2^%d is not 4096 (only 4 KiB blocks are supported)" % sb.log_blocksize)
        if sb.log_sectorsize + sb.log_sectors_per_block != sb.log_blocksize:
            raise CorruptError("log_sectorsize %d + log_sectors_per_block %d != log_blocksize %d"
                               % (sb.log_sectorsize, sb.log_sectors_per_block, sb.log_blocksize))
        if sb.log_blocks_per_seg != LOG_BLOCKS_PER_SEG:
            raise UnsupportedError("log_blocks_per_seg %d != %d" % (sb.log_blocks_per_seg, LOG_BLOCKS_PER_SEG))
        if (sb.node_ino, sb.meta_ino, sb.root_ino) != (1, 2, 3):
            raise CorruptError("reserved inode numbers are %d/%d/%d, expected 1/2/3" % (sb.node_ino, sb.meta_ino, sb.root_ino))
        if sb.cp_payload > BLOCKS_PER_SEG - 2:
            raise CorruptError("cp_payload %d too large" % sb.cp_payload)
        if sb.devs[0][0]:
            raise UnsupportedError("multi-device image (devs[0] = %r)" % sb.devs[0][0])
        if sb.segment_count_nat < 2 or sb.segment_count_nat % 2:
            raise CorruptError("segment_count_nat %d is not an even number >= 2" % sb.segment_count_nat)
        if not (0 < sb.main_blkaddr < sb.block_count):
            raise CorruptError("main_blkaddr %d outside 1..block_count %d" % (sb.main_blkaddr, sb.block_count))
        if sb.main_blkaddr + sb.segment_count_main * BLOCKS_PER_SEG > sb.block_count:
            raise CorruptError("main area (%d + %d segments) exceeds block_count %d"
                               % (sb.main_blkaddr, sb.segment_count_main, sb.block_count))
        if not (sb.cp_blkaddr < sb.sit_blkaddr < sb.nat_blkaddr <= sb.ssa_blkaddr <= sb.main_blkaddr):
            raise CorruptError("metadata areas are not in order cp %d < sit %d < nat %d <= ssa %d <= main %d"
                               % (sb.cp_blkaddr, sb.sit_blkaddr, sb.nat_blkaddr, sb.ssa_blkaddr, sb.main_blkaddr))
        if sb.nat_blkaddr + sb.segment_count_nat * BLOCKS_PER_SEG > sb.main_blkaddr:
            raise CorruptError("NAT area overlaps the main area")

    # ---- checkpoint
    def _validate_pack(self, start: int):
        try:
            a = self._blk(start)
            if not cp_crc_ok(a):
                return None
            total = _u32(a, 136)[0]
            if total < 2 or total > BLOCKS_PER_SEG:
                return None
            b = self._blk(start + total - 1)
            if not cp_crc_ok(b):
                return None
            if _u64(a, 0)[0] != _u64(b, 0)[0]:
                return None
            return _u64(a, 0)[0]
        except BlockRangeError:
            return None

    def _open_checkpoint(self) -> None:
        sb = self.sb
        v1 = self._validate_pack(sb.cp_blkaddr)
        v2 = self._validate_pack(sb.cp_blkaddr + BLOCKS_PER_SEG)
        if v1 is not None and v2 is not None:
            d = (v2 - v1) & 0xFFFFFFFFFFFFFFFF
            cur = 2 if 0 < d < (1 << 63) else 1          # ver_after(): signed 64-bit difference
        elif v1 is not None:
            cur = 1
        elif v2 is not None:
            cur = 2
        else:
            raise CorruptError("%s: no valid checkpoint pack (both crc/version checks failed)" % self.path)
        start = sb.cp_blkaddr + (BLOCKS_PER_SEG if cur == 2 else 0)
        raw = bytes(self._blk(start))
        if sb.cp_payload:
            raw += b"".join(bytes(self._blk(start + 1 + i)) for i in range(sb.cp_payload))
        fields = _parse_checkpoint_fields(raw)
        flags = fields["ckpt_flags"]
        nat_sz, sit_sz = fields["nat_ver_bitmap_bytesize"], fields["sit_ver_bitmap_bytesize"]
        if flags & CP_LARGE_NAT_BITMAP_FLAG:            # NAT first, then SIT, both inline
            base = 192 + (4 if fields["checksum_offset"] == 192 else 0)
            nat_off, sit_off = base, base + nat_sz
        elif sb.cp_payload > 0:                          # NAT inline, SIT in the payload blocks
            nat_off, sit_off = 192, BLOCK_SIZE
        else:                                            # SIT first, then NAT, both inline
            sit_off, nat_off = 192, 192 + sit_sz
        if nat_off + nat_sz > len(raw) or sit_off + sit_sz > len(raw):
            raise CorruptError("checkpoint version bitmaps (nat %d B @%d, sit %d B @%d) exceed the checkpoint area (%d B)"
                               % (nat_sz, nat_off, sit_sz, sit_off, len(raw)))
        nat_bitmap = raw[nat_off:nat_off + nat_sz]
        if len(nat_bitmap) * 8 < sb.nat_blocks:
            raise CorruptError("NAT version bitmap has %d bits for %d NAT blocks" % (len(nat_bitmap) * 8, sb.nat_blocks))
        total = fields["cp_pack_total_block_count"]
        start_sum = fields["cp_pack_start_sum"]
        if not (1 <= start_sum < total):
            raise CorruptError("cp_pack_start_sum %d not inside the pack (%d blocks)" % (start_sum, total))
        self.cp = Checkpoint(
            **fields, crc=_u32(raw, fields["checksum_offset"])[0], pack=cur, start_blkaddr=start,
            pack_versions=(v1, v2), nat_bitmap=nat_bitmap, sit_bitmap=raw[sit_off:sit_off + sit_sz],
            nat_bitmap_offset=nat_off, sit_bitmap_offset=sit_off,
        )
        self._nat_bitmap = nat_bitmap
        self._read_nat_journal(flags, start + start_sum)

    def _read_nat_journal(self, flags: int, sum_addr: int) -> None:
        """NAT journal of the hot-data summary block: entries newer than the NAT area."""
        sumblk = self._blk(sum_addr)
        joff = 0 if flags & CP_COMPACT_SUM_FLAG else SUM_ENTRIES_SIZE
        n_nats = _u16(sumblk, joff)[0]
        if n_nats > NAT_JOURNAL_ENTRIES:
            raise CorruptError("NAT journal claims %d entries (max %d)" % (n_nats, NAT_JOURNAL_ENTRIES))
        journal = {}
        for i in range(n_nats):
            nid, ver, ino, blk = _NAT_JOURNAL(sumblk, joff + 2 + NAT_JOURNAL_ENTRY_SIZE * i)
            journal[nid] = (ver, ino, blk)
        self.cp.nat_journal = journal
        self.cp.n_nats = n_nats
        self._nat_journal = journal

    # ---- NAT
    def current_nat_addr(self, nid: int) -> int:
        """Block address of the NAT block holding ``nid`` (copy chosen by the version bitmap)."""
        block_off = nid // NAT_ENTRY_PER_BLOCK
        seg_off = block_off >> LOG_BLOCKS_PER_SEG
        addr = self.sb.nat_blkaddr + (seg_off << (LOG_BLOCKS_PER_SEG + 1)) + (block_off & (BLOCKS_PER_SEG - 1))
        if (self._nat_bitmap[block_off >> 3] >> (7 - (block_off & 7))) & 1:    # f2fs_test_bit: MSB first
            addr += BLOCKS_PER_SEG
        return addr

    def nat_lookup(self, nid: int) -> tuple[int, int, int]:
        """``(version, ino, block_addr)`` of ``nid`` (journal first, then the NAT area)."""
        if nid <= 0 or nid >= self._max_nid:
            raise CorruptError("nid %d outside 1..%d" % (nid, self._max_nid - 1))
        j = self._nat_journal.get(nid)
        if j is not None:
            return j
        addr = self.current_nat_addr(nid)
        blk = self._nat_cache.get(addr)
        if blk is None:
            blk = bytes(self._blk(addr))
            self._nat_cache[addr] = blk
        return _NAT_ENTRY(blk, (nid % NAT_ENTRY_PER_BLOCK) * NAT_ENTRY_SIZE)

    # ---- nodes
    def _read_node(self, nid: int, expect_ino: int | None = None):
        """memoryview of node ``nid`` after NAT + footer validation; returns (block, ino, addr, footer_flag)."""
        if nid < 3:
            raise CorruptError("nid %d is reserved (node/meta inode), not a real node" % nid)
        ver, ino, addr = self.nat_lookup(nid)
        if addr == NULL_ADDR or addr == NEW_ADDR:
            raise CorruptError("nid %d is not allocated (NAT block_addr 0x%x)" % (nid, addr))
        self._check_data_addr(addr, "node %d block address" % nid)
        blk = self._blk(addr)
        f_nid, f_ino, f_flag, _cpver, _next = _FOOTER(blk, NODE_FOOTER_OFF)
        if f_nid != nid or f_ino != ino:
            raise CorruptError("node block %d (nid %d, NAT ino %d) has footer nid %d ino %d"
                               % (addr, nid, ino, f_nid, f_ino))
        if expect_ino is not None and ino != expect_ino:
            raise CorruptError("node %d belongs to inode %d, expected %d" % (nid, ino, expect_ino))
        return blk, ino, addr, f_flag

    def _inode_block(self, inode: Inode):
        """Re-read the inode's node block (footer re-checked)."""
        blk = self._blk(inode.blkaddr)
        if _u32(blk, NODE_FOOTER_OFF)[0] != inode.nid:
            raise CorruptError("inode %d block %d changed under us" % (inode.nid, inode.blkaddr))
        return blk

    def read_inode(self, nid: int) -> Inode:
        """Parse inode ``nid`` (footer ino must equal nid)."""
        blk, ino, addr, f_flag = self._read_node(nid)
        if ino != nid:
            raise CorruptError("nid %d is not an inode (footer ino %d)" % (nid, ino))
        return self._parse_inode(blk, nid, addr, f_flag)

    def _parse_inode(self, blk, nid: int, addr: int, f_flag: int) -> Inode:
        h = _INODE_HEAD(blk, 0)
        i = Inode()
        i.nid, i.blkaddr, i.footer_flag = nid, addr, f_flag
        i.footer_cp_ver = _u64(blk, NODE_FOOTER_OFF + 12)[0]
        (i.mode, i.advise, i.inline, i.uid, i.gid, i.links, i.size, i.blocks,
         i.atime, i.ctime, i.mtime, i.atime_nsec, i.ctime_nsec, i.mtime_nsec,
         i.generation, i.current_depth, i.xattr_nid, i.flags, i.pino, namelen) = h
        i.name = bytes(blk[92:92 + min(namelen, F2FS_NAME_LEN)])
        i.dir_level = blk[347]
        i.i_nid = _unpack_from("<5I", blk, I_NID_OFF)
        inline = i.inline
        i.projid = i.inode_checksum = i.crtime = i.crtime_nsec = None
        if inline & F2FS_EXTRA_ATTR:
            if not self.feature & F_EXTRA_ATTR:
                raise CorruptError("inode %d has F2FS_EXTRA_ATTR but the superblock lacks extra_attr" % nid)
            extra = _u16(blk, I_ADDR_OFF)[0]
            if extra < 4 or extra > F2FS_TOTAL_EXTRA_ATTR_SIZE or extra % 4:
                raise CorruptError("inode %d: i_extra_isize %d invalid" % (nid, extra))
            if extra >= 8:
                i.projid = _u32(blk, 364)[0]
            if extra >= 12:
                i.inode_checksum = _u32(blk, I_INODE_CHECKSUM_OFF)[0]
                if self.verify_inode_checksums and self.feature & F_INODE_CHKSUM:
                    calc = self._inode_checksum(blk, nid, i.generation)
                    if calc != i.inode_checksum:
                        raise CorruptError("inode %d checksum mismatch (stored 0x%08x, computed 0x%08x)"
                                           % (nid, i.inode_checksum, calc))
            if extra >= 24:
                i.crtime, i.crtime_nsec = _u64(blk, 372)[0], _u32(blk, 380)[0]
        else:
            if self.feature & F_FLEX_XATTR:
                raise CorruptError("inode %d lacks F2FS_EXTRA_ATTR although flexible_inline_xattr is on" % nid)
            extra = 0
        i.extra_isize = extra
        if self.feature & F_FLEX_XATTR:
            ix = _u16(blk, 362)[0]
        elif inline & (F2FS_INLINE_XATTR | F2FS_INLINE_DENTRY):
            ix = DEFAULT_INLINE_XATTR_ADDRS
        else:
            ix = 0
        base = extra // 4
        if ix + base + DEF_INLINE_RESERVED_SIZE >= DEF_ADDRS_PER_INODE:
            raise CorruptError("inode %d: inline xattr size %d slots + extra %d leave no data slots" % (nid, ix, extra))
        i.inline_xattr_addrs = ix
        i.addr_base = base
        i.addrs_per_inode = DEF_ADDRS_PER_INODE - base - ix
        i.inline_data_off = I_ADDR_OFF + 4 * (base + DEF_INLINE_RESERVED_SIZE)
        i.max_inline_data = 4 * (DEF_ADDRS_PER_INODE - ix - base - DEF_INLINE_RESERVED_SIZE)
        i.rdev = None
        fmt = stat.S_IFMT(i.mode)
        if fmt in (stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK):
            a0, a1 = _unpack_from("<II", blk, I_ADDR_OFF + 4 * base)
            if a0:                                  # old 16-bit encoding
                i.rdev = ((a0 >> 8) & 0xFF, a0 & 0xFF)
            else:                                   # new encoding
                i.rdev = ((a1 >> 8) & 0xFFF, (a1 & 0xFF) | ((a1 >> 12) & 0xFFF00))
        return i

    def _inode_checksum(self, blk, footer_ino: int, generation: int) -> int:
        c = f2fs_crc32(struct.pack("<I", footer_ino), self._chksum_seed)
        c = f2fs_crc32(struct.pack("<I", generation), c)
        c = f2fs_crc32(blk[:I_INODE_CHECKSUM_OFF], c)
        c = f2fs_crc32(b"\0\0\0\0", c)
        return f2fs_crc32(blk[I_INODE_CHECKSUM_OFF + 4:BLOCK_SIZE], c)

    def _check_readable(self, inode: Inode) -> None:
        if inode.advise & (FADVISE_ENCRYPT_BIT | FADVISE_ENC_NAME_BIT):
            raise UnsupportedError("inode %d is encrypted (i_advise 0x%x): fscrypt is not supported" % (inode.nid, inode.advise))
        if inode.flags & F2FS_COMPR_FL:
            raise CompressionError("inode %d is compressed (F2FS_COMPR_FL): compression is not supported" % inode.nid)
        if inode.flags & F2FS_DEVICE_ALIAS_FL:
            raise UnsupportedError("inode %d aliases a device (F2FS_DEVICE_ALIAS_FL)" % inode.nid)
        if inode.inline & F2FS_INLINE_DATA and inode.size > inode.max_inline_data:
            raise CorruptError("inode %d: inline data of %d bytes exceeds max_inline_data %d"
                               % (inode.nid, inode.size, inode.max_inline_data))

    # ---- block map
    def _addr_chunks(self, inode: Inode, nblocks: int) -> Iterator[tuple]:
        """Yield tuples of consecutive data block addresses for file blocks 0..nblocks-1."""
        if nblocks <= 0:
            return
        blk = self._inode_block(inode)
        a = inode.addrs_per_inode
        n = min(a, nblocks)
        if n > 0:
            yield _unpack_from("<%dI" % n, blk, I_ADDR_OFF + 4 * inode.addr_base)
        remaining = nblocks - a
        if remaining <= 0:
            return
        i_nid = inode.i_nid
        for k, level in enumerate((0, 0, 1, 1, 2)):
            if remaining <= 0:
                return
            span = ADDRS_PER_BLOCK * NIDS_PER_BLOCK ** level
            yield from self._node_chunks(i_nid[k], level, min(remaining, span), inode.nid)
            remaining -= span

    def _node_chunks(self, nid: int, level: int, count: int, ino: int) -> Iterator[tuple]:
        if count <= 0:
            return
        if nid == 0:                                     # hole for the whole subtree
            while count > 0:
                n = min(count, ADDRS_PER_BLOCK)
                yield (0,) * n
                count -= n
            return
        blk, _ino, _addr, _flag = self._read_node(nid, expect_ino=ino)
        if level == 0:
            n = min(count, ADDRS_PER_BLOCK)
            yield _ADDRS[n](blk, 0) if n in _ADDRS else _unpack_from("<%dI" % n, blk, 0)
            return
        child_span = ADDRS_PER_BLOCK * NIDS_PER_BLOCK ** (level - 1)
        nids = _ADDRS[NIDS_PER_BLOCK](blk, 0)
        for child in nids:
            if count <= 0:
                return
            yield from self._node_chunks(child, level - 1, min(count, child_span), ino)
            count -= child_span

    def block_runs(self, inode: Inode, nblocks: int | None = None) -> Iterator[tuple[int, int]]:
        """Yield ``(block_addr, nblocks)`` runs of the file's data blocks in file order;
        ``block_addr == 0`` means a run of holes (NULL_ADDR / NEW_ADDR: read as zeros).
        Every real address is validated against the main area."""
        if nblocks is None:
            nblocks = inode.nblocks
        main, bc = self.sb.main_blkaddr, self.block_count
        run_start = run_len = hole = 0
        for chunk in self._addr_chunks(inode, nblocks):
            n = len(chunk)
            a0 = chunk[0]
            if n > 1 and a0 >= main and a0 + n <= bc and chunk == tuple(range(a0, a0 + n)):
                if hole:                                 # fully contiguous chunk: fast path
                    yield 0, hole
                    hole = 0
                if run_len and a0 == run_start + run_len:
                    run_len += n
                else:
                    if run_len:
                        yield run_start, run_len
                    run_start, run_len = a0, n
                continue
            for a in chunk:
                if a == 0 or a == NEW_ADDR:
                    if run_len:
                        yield run_start, run_len
                        run_len = 0
                    hole += 1
                elif a < main or a >= bc:
                    self._check_data_addr(a, "data block of inode %d" % inode.nid)
                else:
                    if hole:
                        yield 0, hole
                        hole = 0
                    if run_len and a == run_start + run_len:
                        run_len += 1
                    else:
                        if run_len:
                            yield run_start, run_len
                        run_start, run_len = a, 1
        if run_len:
            yield run_start, run_len
        if hole:
            yield 0, hole

    # ---- data
    def _inline_data(self, inode: Inode) -> bytes:
        if inode.size > inode.max_inline_data:
            raise CorruptError("inode %d: inline data of %d bytes exceeds max_inline_data %d"
                               % (inode.nid, inode.size, inode.max_inline_data))
        if not inode.inline & F2FS_DATA_EXIST:
            return bytes(inode.size)
        blk = self._inode_block(inode)
        return bytes(blk[inode.inline_data_off:inode.inline_data_off + inode.size])

    def _data_chunks(self, inode: Inode) -> Iterator:
        """Yield the file content as memoryviews (real data) or ``(None, nbytes)`` holes, exactly
        ``i_size`` bytes in total.  Views alias the mapping: consume before the next step."""
        self._check_readable(inode)
        size = inode.size
        if inode.inline & F2FS_INLINE_DATA:
            if size:
                yield memoryview(self._inline_data(inode))
            return
        remaining = size
        for addr, n in self.block_runs(inode, (size + BLOCK_SIZE - 1) // BLOCK_SIZE):
            nbytes = min(n * BLOCK_SIZE, remaining)
            if addr == 0:
                yield (None, nbytes)
            else:
                off = self._delta + addr * BLOCK_SIZE
                while nbytes > _RUN_CHUNK_BYTES:
                    yield self._mv[off:off + _RUN_CHUNK_BYTES]
                    off += _RUN_CHUNK_BYTES
                    nbytes -= _RUN_CHUNK_BYTES
                    remaining -= _RUN_CHUNK_BYTES
                yield self._mv[off:off + nbytes]
            remaining -= nbytes
        if remaining:
            raise CorruptError("inode %d: block map covers %d bytes less than i_size %d"
                               % (inode.nid, remaining, size))

    def read_file(self, inode: Inode) -> Iterator[bytes]:
        """Content of a regular file (or a symlink's target bytes) as ``bytes`` chunks, one per
        block run; holes / NEW_ADDR blocks are zeros; total length == i_size."""
        if inode.is_dir or inode.is_special:
            raise F2FSError("inode %d is a %s, it has no file content" % (inode.nid, inode.type))
        for chunk in self._data_chunks(inode):
            if isinstance(chunk, tuple):
                n = chunk[1]
                while n > 0:
                    k = min(n, len(_ZERO_CHUNK))
                    yield _ZERO_CHUNK[:k]
                    n -= k
            else:
                yield bytes(chunk)

    def read_symlink(self, inode: Inode) -> str:
        """Symlink target (``i_size`` bytes, inline or in data block 0), decoded with surrogateescape."""
        if not inode.is_lnk:
            raise F2FSError("inode %d is not a symlink" % inode.nid)
        if inode.size > MAX_SYMLINK_LEN:
            raise CorruptError("inode %d: symlink target of %d bytes is too long" % (inode.nid, inode.size))
        return os.fsdecode(b"".join(self.read_file(inode)))

    # ---- xattrs
    def raw_xattrs(self, inode: Inode) -> list[tuple[int, bytes, bytes]]:
        """``[(name_index, name, value)]`` from the inline area + xattr node (one header)."""
        parts = []
        ix = inode.inline_xattr_addrs
        if ix:
            blk = self._inode_block(inode)
            parts.append(bytes(blk[I_NID_OFF - 4 * ix:I_NID_OFF]))
        if inode.xattr_nid:
            xblk, _ino, _addr, f_flag = self._read_node(inode.xattr_nid, expect_ino=inode.nid)
            if (f_flag >> 3) != XATTR_NODE_OFFSET:
                raise CorruptError("xattr node %d of inode %d has ofs_in_node 0x%x, expected XATTR_NODE_OFFSET"
                                   % (inode.xattr_nid, inode.nid, f_flag >> 3))
            parts.append(bytes(xblk[:VALID_XATTR_BLOCK_SIZE]))
        if not parts:
            return []
        buf = parts[0] if len(parts) == 1 else b"".join(parts)
        end = len(buf)
        if end < XATTR_HEADER_SIZE or _u32(buf, 0)[0] != F2FS_XATTR_MAGIC:
            return []
        out = []
        off = XATTR_HEADER_SIZE
        while off + 4 <= end:
            if _u32(buf, off)[0] == 0:          # IS_XATTR_LAST_ENTRY
                break
            idx, nlen, vsize = _XATTR_ENTRY(buf, off)
            if off + 4 + nlen + vsize > end:
                raise CorruptError("inode %d: xattr entry at %d (name %d B, value %d B) crosses the end of the xattr space"
                                   % (inode.nid, off, nlen, vsize))
            out.append((idx, buf[off + 4:off + 4 + nlen], buf[off + 4 + nlen:off + 4 + nlen + vsize]))
            off += (4 + nlen + vsize + 3) & ~3
        return out

    def xattrs(self, inode: Inode) -> list[tuple[str, bytes]]:
        """``[(full_name, value)]`` with the index prefix applied (``security.selinux`` ...)."""
        out = []
        for idx, name, value in self.raw_xattrs(inode):
            prefix = XATTR_INDEX_PREFIX.get(idx)
            if prefix is None:
                prefix = "f2fs.index%d." % idx
            if idx in (2, 3):
                full = prefix
            else:
                full = prefix + name.decode("utf-8", "surrogateescape")
            out.append((full, value))
        return out

    # ---- directories
    def readdir(self, inode: Inode) -> list[tuple[bytes, int, int]]:
        """``[(name, ino, file_type)]`` in slot order, including ``.`` and ``..``."""
        if not inode.is_dir:
            raise F2FSError("inode %d is not a directory" % inode.nid)
        self._check_readable(inode)
        out: list = []
        if inode.inline & F2FS_INLINE_DENTRY:
            mid = inode.max_inline_data
            nr = mid * 8 // ((11 + DENTRY_SLOT_LEN) * 8 + 1)
            bsz = (nr + 7) // 8
            rsv = mid - ((11 + DENTRY_SLOT_LEN) * nr + bsz)
            base = inode.inline_data_off
            self._parse_dentries(self._inode_block(inode), base, bsz, nr, base + bsz + rsv,
                                 base + bsz + rsv + 11 * nr, inode.nid, out)
            return out
        nblocks = (inode.size + BLOCK_SIZE - 1) // BLOCK_SIZE
        for addr, n in self.block_runs(inode, nblocks):
            if addr == 0:
                continue
            for k in range(n):
                self._parse_dentries(self._blk(addr + k), 0, SIZE_OF_DENTRY_BITMAP, NR_DENTRY_IN_BLOCK,
                                     DENTRY_BLOCK_DENTRIES_OFF, DENTRY_BLOCK_NAMES_OFF, inode.nid, out)
        return out

    @staticmethod
    def _parse_dentries(buf, bitmap_off: int, bitmap_len: int, nr: int, dent_off: int, names_off: int,
                        dir_nid: int, out: list) -> None:
        bm = int.from_bytes(buf[bitmap_off:bitmap_off + bitmap_len], "little")
        i = 0
        while bm >> i:
            if not (bm >> i) & 1:
                i += 1
                continue
            _hash, ino, nlen, ftype = _DENTRY(buf, dent_off + 11 * i)
            if nlen == 0 or nlen > F2FS_NAME_LEN:
                raise CorruptError("directory %d: dentry slot %d has name_len %d" % (dir_nid, i, nlen))
            slots = (nlen + DENTRY_SLOT_LEN - 1) // DENTRY_SLOT_LEN
            if i + slots > nr:
                raise CorruptError("directory %d: dentry slot %d (%d slots) overflows the block" % (dir_nid, i, slots))
            name = bytes(buf[names_off + DENTRY_SLOT_LEN * i:names_off + DENTRY_SLOT_LEN * i + nlen])
            out.append((name, ino, ftype))
            i += slots

    # ---- walk
    def _make_entry(self, path: str, inode: Inode) -> ManifestEntry:
        self._check_readable(inode)
        try:
            t = type_from_mode(inode.mode)
        except ValueError:
            raise CorruptError("inode %d (%s): unknown file type in i_mode 0o%o" % (inode.nid, path or "/", inode.mode)) from None
        selinux = None
        caps = 0
        other: dict[str, bytes] = {}
        for name, value in self.xattrs(inode):
            if name == "security.selinux":
                selinux = value.rstrip(b"\0").decode("utf-8", "surrogateescape")
            elif name == "security.capability":
                try:
                    caps = decode_capabilities(value)
                except ValueError:
                    other[name] = value          # unknown vfs_cap_data layout: keep the raw bytes
            else:
                other[name] = value
        target = self.read_symlink(inode) if t == "lnk" else None
        if inode.mtime_nsec >= 1_000_000_000:
            raise CorruptError("inode %d: i_mtime_nsec %d out of range" % (inode.nid, inode.mtime_nsec))
        return ManifestEntry(path, t, inode.mode & 0o7777, inode.uid, inode.gid, inode.links, inode.size,
                             inode.mtime, inode.mtime_nsec, selinux, caps, other, target, None, inode.nid)

    def _collect(self) -> list[tuple[str, ManifestEntry, Inode]]:
        """Walk the whole tree once (metadata only); cached, sorted by path."""
        if self._entries is not None:
            return self._entries
        if self._closed:
            raise F2FSError("image is closed")
        # A compression feature bit alone is harmless: only inodes carrying F2FS_COMPR_FL
        # (refused in _check_readable) and COMPRESS_ADDR markers (refused in block_runs) matter.
        root = self.read_inode(self.root_ino)
        if not root.is_dir:
            raise CorruptError("root inode %d is not a directory (i_mode 0o%o)" % (self.root_ino, root.mode))
        out: list[tuple[str, ManifestEntry, Inode]] = []
        dir_seen: dict[int, str] = {}
        stack = [("", root, ())]
        while stack:
            path, inode, ancestors = stack.pop()
            out.append((path, self._make_entry(path, inode), inode))
            if not inode.is_dir:
                continue
            if inode.nid in dir_seen:
                raise CorruptError("directory inode %d reachable as both %r and %r (loop or hard-linked directory)"
                                   % (inode.nid, dir_seen[inode.nid], path or "/"))
            dir_seen[inode.nid] = path or "/"
            children = []
            names_seen = set()
            for name, cino, ftype in self.readdir(inode):
                if name in (b".", b".."):
                    continue
                if b"/" in name or b"\0" in name:
                    raise CorruptError("directory %d: dentry name %r contains '/' or NUL" % (inode.nid, name))
                if name in names_seen:
                    raise CorruptError("directory %d: duplicate dentry %r" % (inode.nid, name))
                names_seen.add(name)
                if cino in ancestors or cino == inode.nid:
                    raise CorruptError("directory %d: dentry %r points to an ancestor (ino %d)" % (inode.nid, name, cino))
                children.append((name, cino, ftype))
            children.sort(key=lambda c: c[0], reverse=True)      # pop order -> ascending by name
            child_anc = ancestors + (inode.nid,)
            for name, cino, ftype in children:
                child = self.read_inode(cino)
                if (ftype == FT_DIR) != child.is_dir:
                    raise CorruptError("directory %d: dentry %r has file_type %d but inode %d has i_mode 0o%o"
                                       % (inode.nid, name, ftype, cino, child.mode))
                cpath = (path + "/" + os.fsdecode(name)) if path else os.fsdecode(name)
                stack.append((cpath, child, child_anc))
        out.sort(key=lambda t: t[0])
        self._entries = out
        return out

    def walk(self) -> Iterator[tuple[str, ManifestEntry, Inode]]:
        """Every inode reachable from the root as ``(path, ManifestEntry, Inode)``, sorted by
        path (``''`` first = root).  Reads metadata, xattrs and symlink targets only; the
        manifest entries carry ``sha256=None``.  Hard links appear once per path (same ``ino``,
        ``nlink > 1``)."""
        return iter(self._collect())

    # ---- extraction
    def extract(self, dest_dir, manifest_path=None, hash: bool = True,
                progress: Callable[[int, int, str], None] | None = None) -> list[ManifestEntry]:
        """Write the tree below ``dest_dir`` (created if needed).

        Regular files are streamed in block runs (holes stay sparse), hard links are
        recreated with ``os.link``, symlinks with ``os.symlink`` (never followed), mtimes
        are applied with ``os.utime(follow_symlinks=False)`` (directories last, bottom-up).
        Nothing is chowned, no xattrs are set, special files (chr/blk/fifo/sock) are only
        recorded.  ``sha256`` is computed while writing when ``hash`` is true.  Existing
        files/symlinks at a destination path are replaced; an existing directory where a
        non-directory should go is an error.  ``progress(done, total, path)`` is called
        after every entry.  Returns the manifest (sorted by path) and writes it to
        ``manifest_path`` when given.
        """
        items = self._collect()
        dest_dir = os.fspath(dest_dir)
        os.makedirs(dest_dir, exist_ok=True)
        result: list[ManifestEntry] = []
        dir_times: list[tuple[str, int]] = []
        linked: dict[int, tuple[str, str | None]] = {}      # ino -> (host path, sha256) of the first name
        total = len(items)
        for done, (path, entry, inode) in enumerate(items, 1):
            host = os.path.join(dest_dir, path) if path else dest_dir
            e = entry.copy()
            t = e.type
            ns = inode.mtime * 1_000_000_000 + inode.mtime_nsec
            if t == "dir":
                if path and not self._prepare_host(host, want_dir=True):
                    os.mkdir(host, 0o755)
                dir_times.append((host, ns))
            elif t == "reg":
                self._prepare_host(host, want_dir=False)
                first = linked.get(inode.nid) if inode.links > 1 else None
                if first is not None:
                    try:
                        os.link(first[0], host)
                        e.sha256 = first[1]
                    except OSError:                       # destination fs without hard links: copy
                        e.sha256 = self._write_file(inode, host, hash)
                else:
                    e.sha256 = self._write_file(inode, host, hash)
                    if inode.links > 1:
                        linked[inode.nid] = (host, e.sha256)
                os.utime(host, ns=(ns, ns), follow_symlinks=False)
            elif t == "lnk":
                self._prepare_host(host, want_dir=False)
                os.symlink(e.target, host)
                os.utime(host, ns=(ns, ns), follow_symlinks=False)
            # chr/blk/fifo/sock: recorded only
            result.append(e)
            if progress is not None:
                progress(done, total, path)
        for host, ns in reversed(dir_times):
            os.utime(host, ns=(ns, ns), follow_symlinks=False)
        if manifest_path is not None:
            write_manifest(manifest_path, result)
        return result

    @staticmethod
    def _prepare_host(host: str, want_dir: bool) -> bool:
        """Clear the way at ``host``: an existing directory is kept when a directory is wanted
        (returns True), a file/symlink is unlinked, a directory in the way of a file is an error."""
        try:
            st = os.lstat(host)
        except FileNotFoundError:
            return False
        if stat.S_ISDIR(st.st_mode):
            if want_dir:
                return True
            raise F2FSError("refusing to replace existing directory %r with a non-directory" % host)
        os.unlink(host)
        return False

    def _write_file(self, inode: Inode, host: str, do_hash: bool) -> str | None:
        h = hashlib.sha256() if do_hash else None
        with open(host, "wb") as f:
            for chunk in self._data_chunks(inode):
                if isinstance(chunk, tuple):
                    n = chunk[1]
                    f.seek(n, os.SEEK_CUR)                   # sparse hole
                    if h is not None:
                        while n > 0:
                            k = min(n, len(_ZERO_CHUNK))
                            h.update(_ZERO_CHUNK[:k])
                            n -= k
                else:
                    f.write(chunk)
                    if h is not None:
                        h.update(chunk)
            f.flush()
            f.truncate(inode.size)
        return h.hexdigest() if h is not None else None

    def hash_file(self, inode: Inode) -> str:
        """sha256 hex digest of a regular file's content (no host write)."""
        h = hashlib.sha256()
        for chunk in self._data_chunks(inode):
            if isinstance(chunk, tuple):
                n = chunk[1]
                while n > 0:
                    k = min(n, len(_ZERO_CHUNK))
                    h.update(_ZERO_CHUNK[:k])
                    n -= k
            else:
                h.update(chunk)
        return h.hexdigest()

    # ---- facts
    def info(self) -> dict:
        """JSON-serialisable facts for meta.json (DESIGN §4.1): superblock, checkpoint, root
        inode, mtime hint, per-type counts.  Walks the tree (cached)."""
        sb, cp = self.sb, self.cp
        items = self._collect()
        root_entry = items[0][1]
        counts = Counter(e.type for _p, e, _i in items)
        mtimes = Counter(e.mtime for p, e, _i in items if p)
        hint = mtimes.most_common(1)[0][0] if mtimes else root_entry.mtime
        hardlinks = sum(1 for _p, e, _i in items if e.type != "dir" and e.nlink > 1)
        data_bytes = sum(e.size for _p, e, _i in items if e.type == "reg")
        inline_data = sum(1 for _p, _e, i in items if i.inline & F2FS_INLINE_DATA)
        xattr_nodes = sum(1 for _p, _e, i in items if i.xattr_nid)
        return {
            "format": "f2fs",
            "path": self.path,
            "offset": self.offset,
            "length": self.length,
            "uuid": self.uuid,
            "label": self.label,
            "feature": sb.feature,
            "features": sb.features,
            "major_ver": sb.major_ver,
            "minor_ver": sb.minor_ver,
            "block_size": sb.block_size,
            "sector_size": sb.sector_size,
            "sectors_per_block": 1 << sb.log_sectors_per_block,
            "block_count": sb.block_count,
            "fs_size": self.fs_size,
            "segment_count": sb.segment_count,
            "section_count": sb.section_count,
            "segs_per_sec": sb.segs_per_sec,
            "secs_per_zone": sb.secs_per_zone,
            "segment_count_ckpt": sb.segment_count_ckpt,
            "segment_count_sit": sb.segment_count_sit,
            "segment_count_nat": sb.segment_count_nat,
            "segment_count_ssa": sb.segment_count_ssa,
            "segment_count_main": sb.segment_count_main,
            "cp_blkaddr": sb.cp_blkaddr,
            "sit_blkaddr": sb.sit_blkaddr,
            "nat_blkaddr": sb.nat_blkaddr,
            "ssa_blkaddr": sb.ssa_blkaddr,
            "main_blkaddr": sb.main_blkaddr,
            "cp_payload": sb.cp_payload,
            "version": sb.version,
            "init_version": sb.init_version,
            "encryption_level": sb.encryption_level,
            "encoding": sb.s_encoding,
            "encoding_flags": sb.s_encoding_flags,
            "cold_extensions": sb.cold_extensions,
            "hot_extensions": sb.hot_extensions,
            "qf_ino": list(sb.qf_ino),
            "sb_copy_used": sb.copy,
            "sb_stop_reason": sb.s_stop_reason.hex() if any(sb.s_stop_reason) else "",
            "sb_errors": sb.s_errors.hex() if any(sb.s_errors) else "",
            "checkpoint": {
                "version": cp.checkpoint_ver,
                "pack": cp.pack,
                "pack_versions": [cp.pack_versions[0], cp.pack_versions[1]],
                "flags": cp.ckpt_flags,
                "flag_names": cp.flag_names,
                "user_block_count": cp.user_block_count,
                "valid_block_count": cp.valid_block_count,
                "valid_node_count": cp.valid_node_count,
                "valid_inode_count": cp.valid_inode_count,
                "free_segment_count": cp.free_segment_count,
                "overprov_segment_count": cp.overprov_segment_count,
                "rsvd_segment_count": cp.rsvd_segment_count,
                "next_free_nid": cp.next_free_nid,
                "elapsed_time": cp.elapsed_time,
                "cp_pack_total_block_count": cp.cp_pack_total_block_count,
                "cp_pack_start_sum": cp.cp_pack_start_sum,
                "n_nats": cp.n_nats,
            },
            "root": {
                "ino": root_entry.ino,
                "uid": root_entry.uid,
                "gid": root_entry.gid,
                "mode": root_entry.mode,
                "mtime": root_entry.mtime,
                "mtime_ns": root_entry.mtime_ns,
                "selinux": root_entry.selinux,
                "nlink": root_entry.nlink,
            },
            "mtime_hint": hint,
            "mtime_uniform": len(mtimes) <= 1,
            "counts": {
                "total": len(items),
                "reg": counts.get("reg", 0),
                "dir": counts.get("dir", 0),
                "lnk": counts.get("lnk", 0),
                "chr": counts.get("chr", 0),
                "blk": counts.get("blk", 0),
                "fifo": counts.get("fifo", 0),
                "sock": counts.get("sock", 0),
                "hardlink_paths": hardlinks,
                "inline_data": inline_data,
                "xattr_nodes": xattr_nodes,
                "with_caps": sum(1 for _p, e, _i in items if e.caps),
                "with_other_xattrs": sum(1 for _p, e, _i in items if e.xattrs),
            },
            "data_bytes": data_bytes,
        }


# --------------------------------------------------------------------------- probe

def probe(path, offset: int = 0) -> bool:
    """True if an f2fs superblock magic sits at ``offset + 1024`` (or in the backup block)."""
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            head = f.read(2 * BLOCK_SIZE)
    except OSError:
        return False
    for base in (F2FS_SUPER_OFFSET, BLOCK_SIZE + F2FS_SUPER_OFFSET):
        if len(head) >= base + 4 and _u32(head, base)[0] == F2FS_SUPER_MAGIC:
            return True
    return False
