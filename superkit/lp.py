"""LP (Android dynamic partition / "super") metadata reader and lpmake argument builder.

On-disk format reference: docs/format-lp-avb-odin.md section 1 (struct layouts from AOSP
liblp metadata_format.h). This module only parses; writing is delegated to ``lpmake`` via
:meth:`SuperImage.lpmake_args` (DESIGN.md section 6).

Everything is pure Python 3 standard library and works on an unprivileged user.

Layout of a super image (all little-endian)::

    0        4096  reserved (liblp ignores it; Samsung stores an Odin signature here)
    4096     4096  primary geometry block (52-byte LpMetadataGeometry, zero padded)
    8192     4096  backup geometry block (identical copy)
    12288    N*M   primary metadata slots (slot i at 12288 + i*M)
    12288+N*M N*M  backup metadata slots  (slot i at 12288 + (N+i)*M)
    first_logical_sector*512 ...  logical partition data

``lpmake`` without ``--image``/``-F`` writes the *super_empty* layout instead: geometry at
offset 0, one metadata copy at 4096.  :class:`SuperImage` accepts both; ``layout`` tells which.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import struct
from dataclasses import dataclass, field
from typing import Iterable, Iterator

__all__ = [
    "LpError",
    "SparseImageError",
    "SECTOR_SIZE",
    "RESERVED_BYTES",
    "GEOMETRY_MAGIC",
    "HEADER_MAGIC",
    "SPARSE_MAGIC",
    "Geometry",
    "Header",
    "TableDescriptor",
    "Extent",
    "Partition",
    "Group",
    "BlockDevice",
    "SlotInfo",
    "CapacityRow",
    "CapacityReport",
    "SuperImage",
    "align_up",
    "attribute_names",
    "group_flag_names",
    "header_flag_names",
    "parse_lpdump_text",
]

# --- constants (metadata_format.h) ----------------------------------------------------------

SECTOR_SIZE = 512
RESERVED_BYTES = 4096            # LP_PARTITION_RESERVED_BYTES
GEOMETRY_BLOCK_SIZE = 4096       # LP_METADATA_GEOMETRY_SIZE
GEOMETRY_MAGIC = 0x616C4467      # LP_METADATA_GEOMETRY_MAGIC ("gDla")
GEOMETRY_STRUCT_SIZE = 52
HEADER_MAGIC = 0x414C5030        # LP_METADATA_HEADER_MAGIC ("0PLA")
HEADER_SIZE_V1_0 = 128
HEADER_SIZE_V1_2 = 256
HEADER_MAJOR = 10
SPARSE_MAGIC = 0xED26FF3A        # Android sparse image magic (little-endian u32 at offset 0)
LP_NAME_LEN = 36

# Partition attributes
ATTR_READONLY = 0x1
ATTR_SLOT_SUFFIXED = 0x2
ATTR_UPDATED = 0x4
ATTR_DISABLED = 0x8
_ATTR_NAMES = (
    (ATTR_READONLY, "readonly"),
    (ATTR_SLOT_SUFFIXED, "slot-suffixed"),
    (ATTR_UPDATED, "updated"),
    (ATTR_DISABLED, "disabled"),
)

# Extent target types
TARGET_LINEAR = 0
TARGET_ZERO = 1
_TARGET_NAMES = {TARGET_LINEAR: "linear", TARGET_ZERO: "zero"}

# Header flags (only present when header_size >= 132, i.e. minor version >= 2)
HEADER_FLAG_VIRTUAL_AB = 0x1
HEADER_FLAG_OVERLAYS_ACTIVE = 0x2
_HEADER_FLAG_NAMES = ((HEADER_FLAG_VIRTUAL_AB, "virtual_ab_device"),
                      (HEADER_FLAG_OVERLAYS_ACTIVE, "overlays_active"))

# Group / block device flags
GROUP_FLAG_SLOT_SUFFIXED = 0x1
BLOCK_DEVICE_FLAG_SLOT_SUFFIXED = 0x1

_GEOMETRY_FMT = "<II32sIII"                      # 52 bytes
_HEADER_FMT = "<IHHI32sI32s"                     # first 80 bytes
_DESCRIPTOR_FMT = "<III"
_PARTITION_FMT = "<36sIIII"                      # 52 bytes
_EXTENT_FMT = "<QIQI"                            # 24 bytes
_GROUP_FMT = "<36sIQ"                            # 48 bytes
_BLOCK_DEVICE_FMT = "<QIIQ36sI"                  # 64 bytes
PARTITION_ENTRY_SIZE = struct.calcsize(_PARTITION_FMT)
EXTENT_ENTRY_SIZE = struct.calcsize(_EXTENT_FMT)
GROUP_ENTRY_SIZE = struct.calcsize(_GROUP_FMT)
BLOCK_DEVICE_ENTRY_SIZE = struct.calcsize(_BLOCK_DEVICE_FMT)

_TABLE_NAMES = ("partitions", "extents", "groups", "block_devices")


class LpError(Exception):
    """Malformed or unsupported LP metadata."""


class SparseImageError(LpError):
    """The file is an Android sparse image, not a raw super image."""


# --- helpers --------------------------------------------------------------------------------

def align_up(value: int, alignment: int) -> int:
    """Round ``value`` up to the next multiple of ``alignment`` (alignment 0 means no rounding)."""
    if alignment <= 0:
        return value
    return (value + alignment - 1) // alignment * alignment


def _cstr(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("ascii", "replace")


def _flag_names(value: int, table: Iterable[tuple[int, str]]) -> list[str]:
    return [name for bit, name in table if value & bit]


def attribute_names(attributes: int) -> set[str]:
    """Partition attribute bits -> names as lpdump prints them ({'readonly', ...})."""
    return set(_flag_names(attributes, _ATTR_NAMES))


def header_flag_names(flags: int | None) -> list[str]:
    return [] if flags is None else _flag_names(flags, _HEADER_FLAG_NAMES)


def group_flag_names(flags: int) -> list[str]:
    return ["slot-suffixed"] if flags & GROUP_FLAG_SLOT_SUFFIXED else []


# --- dataclasses ----------------------------------------------------------------------------

@dataclass
class Geometry:
    """LpMetadataGeometry (52 bytes at offset 4096 and 8192)."""
    magic: int = GEOMETRY_MAGIC
    struct_size: int = GEOMETRY_STRUCT_SIZE
    checksum: str = ""                    # hex of the stored SHA-256
    metadata_max_size: int = 0
    metadata_slot_count: int = 0
    logical_block_size: int = 0
    checksum_ok: bool = True

    @classmethod
    def unpack(cls, buf: bytes | memoryview, offset: int = 0) -> "Geometry":
        if len(buf) - offset < GEOMETRY_STRUCT_SIZE:
            raise LpError("buffer too small for LpMetadataGeometry")
        magic, struct_size, csum, mms, slots, lbs = struct.unpack_from(_GEOMETRY_FMT, buf, offset)
        if magic != GEOMETRY_MAGIC:
            raise LpError(f"bad geometry magic 0x{magic:08x} at offset {offset}")
        if struct_size < GEOMETRY_STRUCT_SIZE or struct_size > GEOMETRY_BLOCK_SIZE:
            raise LpError(f"unsupported geometry struct_size {struct_size}")
        blob = bytes(buf[offset:offset + struct_size])
        calc = hashlib.sha256(blob[:8] + b"\0" * 32 + blob[40:]).digest()
        return cls(magic, struct_size, csum.hex(), mms, slots, lbs, csum == calc)

    def validate(self) -> None:
        if not self.checksum_ok:
            raise LpError("geometry checksum mismatch")
        if self.metadata_max_size == 0 or self.metadata_max_size % SECTOR_SIZE:
            raise LpError(f"metadata_max_size {self.metadata_max_size} is not a positive multiple of 512")
        if self.metadata_slot_count == 0:
            raise LpError("metadata_slot_count is 0")
        if self.logical_block_size == 0 or self.logical_block_size % SECTOR_SIZE:
            raise LpError(f"logical_block_size {self.logical_block_size} is not a positive multiple of 512")

    @property
    def metadata_region_end(self) -> int:
        """First byte after the backup slots in the normal (non super_empty) layout."""
        return RESERVED_BYTES + 2 * GEOMETRY_BLOCK_SIZE + 2 * self.metadata_slot_count * self.metadata_max_size

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Geometry":
        return cls(**{k: d[k] for k in cls.__dataclass_fields__ if k in d})


@dataclass
class TableDescriptor:
    offset: int
    num_entries: int
    entry_size: int

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "TableDescriptor":
        return cls(d["offset"], d["num_entries"], d["entry_size"])


@dataclass
class Header:
    """LpMetadataHeader (128 bytes for 10.0/10.1, 256 bytes for 10.2)."""
    magic: int = HEADER_MAGIC
    major_version: int = HEADER_MAJOR
    minor_version: int = 0
    header_size: int = HEADER_SIZE_V1_0
    header_checksum: str = ""
    tables_size: int = 0
    tables_checksum: str = ""
    descriptors: dict[str, TableDescriptor] = field(default_factory=dict)
    flags: int | None = None              # None when the header has no flags field (minor < 2)
    header_checksum_ok: bool = True
    tables_checksum_ok: bool = True

    @property
    def version(self) -> str:
        return f"{self.major_version}.{self.minor_version}"

    @property
    def flag_names(self) -> list[str]:
        return header_flag_names(self.flags)

    @property
    def metadata_size(self) -> int:
        """What lpdump prints as 'Metadata size' (header + tables)."""
        return self.header_size + self.tables_size

    @classmethod
    def unpack(cls, buf: bytes | memoryview, offset: int = 0) -> "Header":
        if len(buf) - offset < HEADER_SIZE_V1_0:
            raise LpError("buffer too small for LpMetadataHeader")
        magic, major, minor, hsize, hcsum, tsize, tcsum = struct.unpack_from(_HEADER_FMT, buf, offset)
        if magic != HEADER_MAGIC:
            raise LpError(f"bad metadata header magic 0x{magic:08x}")
        if major != HEADER_MAJOR:
            raise LpError(f"unsupported metadata major version {major} (expected {HEADER_MAJOR})")
        if hsize < HEADER_SIZE_V1_0 or len(buf) - offset < hsize:
            raise LpError(f"invalid header_size {hsize}")
        descriptors = {}
        for i, name in enumerate(_TABLE_NAMES):
            o, n, sz = struct.unpack_from(_DESCRIPTOR_FMT, buf, offset + 80 + 12 * i)
            descriptors[name] = TableDescriptor(o, n, sz)
        flags = struct.unpack_from("<I", buf, offset + 128)[0] if hsize >= 132 else None
        hdr = bytes(buf[offset:offset + hsize])
        hcalc = hashlib.sha256(hdr[:12] + b"\0" * 32 + hdr[44:]).digest()
        tables = bytes(buf[offset + hsize:offset + hsize + tsize])
        tables_ok = len(tables) == tsize and hashlib.sha256(tables).digest() == tcsum
        return cls(magic, major, minor, hsize, hcsum.hex(), tsize, tcsum.hex(), descriptors, flags,
                   hcsum == hcalc, tables_ok)

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["descriptors"] = {k: v.to_dict() for k, v in self.descriptors.items()}
        d["version"] = self.version
        d["flag_names"] = self.flag_names
        d["metadata_size"] = self.metadata_size
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Header":
        kw = {k: d[k] for k in cls.__dataclass_fields__ if k in d}
        kw["descriptors"] = {k: TableDescriptor.from_dict(v) for k, v in d.get("descriptors", {}).items()}
        return cls(**kw)


@dataclass
class Extent:
    """LpMetadataExtent (24 bytes). Sizes are in 512-byte sectors."""
    num_sectors: int
    target_type: int = TARGET_LINEAR
    target_data: int = 0                  # LINEAR: start sector on the block device; ZERO: 0
    target_source: int = 0                # index into block_devices (LINEAR only)

    @property
    def target_type_name(self) -> str:
        return _TARGET_NAMES.get(self.target_type, str(self.target_type))

    @property
    def is_linear(self) -> bool:
        return self.target_type == TARGET_LINEAR

    @property
    def num_bytes(self) -> int:
        return self.num_sectors * SECTOR_SIZE

    @property
    def start_byte(self) -> int:
        return self.target_data * SECTOR_SIZE

    @property
    def end_sector(self) -> int:
        return self.target_data + self.num_sectors

    @classmethod
    def unpack(cls, buf: bytes | memoryview, offset: int = 0) -> "Extent":
        return cls(*struct.unpack_from(_EXTENT_FMT, buf, offset))

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["target_type_name"] = self.target_type_name
        d["num_bytes"] = self.num_bytes
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Extent":
        return cls(d["num_sectors"], d.get("target_type", TARGET_LINEAR), d.get("target_data", 0),
                   d.get("target_source", 0))


@dataclass
class Partition:
    """LpMetadataPartition (52 bytes) with its extents and group resolved."""
    name: str
    attributes: int = 0
    attribute_names: set[str] = field(default_factory=set)
    extents: list[Extent] = field(default_factory=list)
    group: str = "default"
    first_extent_index: int = 0
    num_extents: int = 0
    group_index: int = 0

    def __post_init__(self) -> None:
        self.attribute_names = attribute_names(self.attributes)
        if not self.num_extents:
            self.num_extents = len(self.extents)

    @property
    def readonly(self) -> bool:
        return bool(self.attributes & ATTR_READONLY)

    @property
    def num_sectors(self) -> int:
        return sum(e.num_sectors for e in self.extents)

    @property
    def size(self) -> int:
        """Partition size in bytes (sum of extents)."""
        return self.num_sectors * SECTOR_SIZE

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "attributes": self.attributes,
            "attribute_names": sorted(self.attribute_names),
            "group": self.group,
            "group_index": self.group_index,
            "first_extent_index": self.first_extent_index,
            "num_extents": self.num_extents,
            "size": self.size,
            "extents": [e.to_dict() for e in self.extents],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Partition":
        return cls(d["name"], d.get("attributes", 0), set(), [Extent.from_dict(e) for e in d.get("extents", [])],
                   d.get("group", "default"), d.get("first_extent_index", 0), d.get("num_extents", 0),
                   d.get("group_index", 0))


@dataclass
class Group:
    """LpMetadataPartitionGroup (48 bytes)."""
    name: str
    flags: int = 0
    maximum_size: int = 0                 # 0 = unlimited

    @property
    def flag_names(self) -> list[str]:
        return group_flag_names(self.flags)

    @classmethod
    def unpack(cls, buf: bytes | memoryview, offset: int = 0) -> "Group":
        name, flags, mx = struct.unpack_from(_GROUP_FMT, buf, offset)
        return cls(_cstr(name), flags, mx)

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["flag_names"] = self.flag_names
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Group":
        return cls(d["name"], d.get("flags", 0), d.get("maximum_size", 0))


@dataclass
class BlockDevice:
    """LpMetadataBlockDevice (64 bytes)."""
    first_logical_sector: int
    alignment: int
    alignment_offset: int
    size: int
    partition_name: str
    flags: int = 0

    @property
    def flag_names(self) -> list[str]:
        return ["slot-suffixed"] if self.flags & BLOCK_DEVICE_FLAG_SLOT_SUFFIXED else []

    @classmethod
    def unpack(cls, buf: bytes | memoryview, offset: int = 0) -> "BlockDevice":
        fls, al, alo, sz, name, flags = struct.unpack_from(_BLOCK_DEVICE_FMT, buf, offset)
        return cls(fls, al, alo, sz, _cstr(name), flags)

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["flag_names"] = self.flag_names
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "BlockDevice":
        return cls(d["first_logical_sector"], d["alignment"], d["alignment_offset"], d["size"],
                   d["partition_name"], d.get("flags", 0))


@dataclass
class SlotInfo:
    """Result of parsing one metadata copy (primary or backup of one slot)."""
    index: int                  # slot number
    kind: str                   # "primary" | "backup"
    offset: int                 # file offset of the copy
    ok: bool = False
    error: str = ""
    metadata_sha256: str = ""   # SHA-256 of header + tables bytes (what matters for comparison)
    header: Header | None = None
    partitions: list[Partition] = field(default_factory=list)
    extents: list[Extent] = field(default_factory=list)
    groups: list[Group] = field(default_factory=list)
    block_devices: list[BlockDevice] = field(default_factory=list)

    def summary_dict(self) -> dict:
        return {"index": self.index, "kind": self.kind, "offset": self.offset, "ok": self.ok,
                "error": self.error, "metadata_sha256": self.metadata_sha256}


@dataclass
class CapacityRow:
    name: str
    size: int                   # requested size (bytes)
    aligned_size: int           # rounded up to logical_block_size (what lpmake stores)
    footprint: int              # space consumed in the layout: aligned_size + alignment gap after it
    group: str
    start_byte: int             # where lpmake would place it (sequential placement)

    def as_tuple(self) -> tuple[str, int, int]:
        return (self.name, self.size, self.aligned_size)


@dataclass
class CapacityReport:
    rows: list[CapacityRow]
    device_size: int
    device_used: int            # end byte of the last partition after placement
    free_bytes: int             # device_size - device_used
    group_used: dict[str, int]
    group_free: dict[str, int | None]   # None when the group has no maximum (unlimited)
    errors: list[str]

    @property
    def ok(self) -> bool:
        return not self.errors

    def table(self) -> list[tuple[str, int, int]]:
        return [r.as_tuple() for r in self.rows]

    def format(self) -> str:
        lines = [f"{'partition':<14}{'size':>14}{'aligned':>14}{'footprint':>14}{'start':>14}  group"]
        for r in self.rows:
            lines.append(f"{r.name:<14}{r.size:>14}{r.aligned_size:>14}{r.footprint:>14}{r.start_byte:>14}  {r.group}")
        lines.append(f"device {self.device_size} B, used {self.device_used} B, free {self.free_bytes} B")
        for g, used in self.group_used.items():
            free = self.group_free[g]
            lines.append(f"group {g}: used {used} B, free {'unlimited' if free is None else free} B")
        lines.extend("ERROR: " + e for e in self.errors)
        return "\n".join(lines)


# --- the image ------------------------------------------------------------------------------

class SuperImage:
    """Parsed LP metadata of a raw super image (or a lpmake super_empty image).

    Attributes: ``path``, ``size`` (file size), ``layout`` ("super" or "super_empty"),
    ``geometry``, ``header``, ``partitions``, ``extents``, ``groups``, ``block_devices``,
    ``slot`` (slot index whose metadata is exposed), ``slot_source`` ("primary"/"backup"),
    ``slots`` (every :class:`SlotInfo`, primary first), ``slots_agree``.
    """

    FORMAT = "superkit-lp-1"

    def __init__(self, path: str | os.PathLike, slot: int = 0) -> None:
        self.path = os.fspath(path)
        self.size = os.path.getsize(self.path)
        self.layout = "super"
        self.geometry_offset = RESERVED_BYTES
        self.slots: list[SlotInfo] = []
        with open(self.path, "rb") as f:
            self._parse(f, slot)

    # -- parsing -----------------------------------------------------------------------------

    def _parse(self, f, slot: int) -> None:
        head = f.read(RESERVED_BYTES + 2 * GEOMETRY_BLOCK_SIZE)
        if len(head) < 8:
            raise LpError(f"{self.path}: file too small to be a super image")
        magic0 = struct.unpack_from("<I", head, 0)[0]
        if magic0 == SPARSE_MAGIC:
            raise SparseImageError(
                f"{self.path} is an Android sparse image (magic 0xed26ff3a); convert it first with "
                f"'simg2img {self.path} super.raw' and pass the raw image")
        if magic0 == GEOMETRY_MAGIC:
            # lpmake super_empty layout: geometry at 0, single metadata copy at 4096.
            self.layout = "super_empty"
            self.geometry_offset = 0
            self.geometry = Geometry.unpack(head, 0)
            self.geometry.validate()
            self.geometry_backup_identical = None
            copies = [(0, "primary", GEOMETRY_BLOCK_SIZE)]
        else:
            if len(head) < RESERVED_BYTES + 2 * GEOMETRY_BLOCK_SIZE:
                raise LpError(f"{self.path}: file too small to hold LP geometry")
            try:
                self.geometry = Geometry.unpack(head, RESERVED_BYTES)
                self.geometry.validate()
            except LpError as primary_err:
                try:
                    self.geometry = Geometry.unpack(head, RESERVED_BYTES + GEOMETRY_BLOCK_SIZE)
                    self.geometry.validate()
                    self.geometry_offset = RESERVED_BYTES + GEOMETRY_BLOCK_SIZE
                except LpError:
                    raise LpError(f"{self.path}: no valid LP geometry at 4096 or 8192 "
                                  f"({primary_err}); not a raw super image?") from None
            self.geometry_backup_identical = (
                head[RESERVED_BYTES:RESERVED_BYTES + GEOMETRY_BLOCK_SIZE]
                == head[RESERVED_BYTES + GEOMETRY_BLOCK_SIZE:RESERVED_BYTES + 2 * GEOMETRY_BLOCK_SIZE])
            g = self.geometry
            base = RESERVED_BYTES + 2 * GEOMETRY_BLOCK_SIZE
            copies = []
            for s in range(g.metadata_slot_count):
                copies.append((s, "primary", base + s * g.metadata_max_size))
            for s in range(g.metadata_slot_count):
                copies.append((s, "backup", base + (g.metadata_slot_count + s) * g.metadata_max_size))

        for index, kind, offset in copies:
            info = SlotInfo(index, kind, offset)
            f.seek(offset)
            raw = f.read(self.geometry.metadata_max_size)
            try:
                self._parse_metadata(raw, info)
                info.ok = True
            except (LpError, struct.error) as e:
                info.ok = False
                info.error = str(e)
            self.slots.append(info)

        if slot < 0 or slot >= self.geometry.metadata_slot_count:
            raise LpError(f"slot {slot} out of range (slot count {self.geometry.metadata_slot_count})")
        chosen = None
        for info in self.slots:
            if info.index == slot and info.ok:
                chosen = info
                break
        if chosen is None:
            errs = "; ".join(f"{i.kind}@{i.offset}: {i.error}" for i in self.slots if i.index == slot)
            raise LpError(f"{self.path}: slot {slot} has no valid metadata copy ({errs})")
        self.slot = chosen.index
        self.slot_source = chosen.kind
        self.header = chosen.header
        self.partitions = chosen.partitions
        self.extents = chosen.extents
        self.groups = chosen.groups
        self.block_devices = chosen.block_devices

    def _parse_metadata(self, raw: bytes, info: SlotInfo) -> None:
        hdr = Header.unpack(raw, 0)
        if not hdr.header_checksum_ok:
            raise LpError("header checksum mismatch")
        if not hdr.tables_checksum_ok:
            raise LpError("tables checksum mismatch")
        if hdr.header_size + hdr.tables_size > len(raw):
            raise LpError("header + tables exceed metadata_max_size")
        tables = memoryview(raw)[hdr.header_size:hdr.header_size + hdr.tables_size]
        info.metadata_sha256 = hashlib.sha256(raw[:hdr.header_size + hdr.tables_size]).hexdigest()

        def entries(name: str, min_size: int) -> Iterator[int]:
            d = hdr.descriptors[name]
            if d.entry_size < min_size:
                raise LpError(f"{name} entry_size {d.entry_size} < {min_size}")
            end = d.offset + d.num_entries * d.entry_size
            if end > hdr.tables_size:
                raise LpError(f"{name} table [{d.offset}, {end}) exceeds tables_size {hdr.tables_size}")
            for i in range(d.num_entries):
                yield d.offset + i * d.entry_size

        extents = [Extent.unpack(tables, o) for o in entries("extents", EXTENT_ENTRY_SIZE)]
        groups = [Group.unpack(tables, o) for o in entries("groups", GROUP_ENTRY_SIZE)]
        bdevs = [BlockDevice.unpack(tables, o) for o in entries("block_devices", BLOCK_DEVICE_ENTRY_SIZE)]
        partitions = []
        for o in entries("partitions", PARTITION_ENTRY_SIZE):
            name, attrs, fei, ne, gi = struct.unpack_from(_PARTITION_FMT, tables, o)
            name = _cstr(name)
            if fei + ne > len(extents):
                raise LpError(f"partition {name}: extents [{fei}, {fei + ne}) out of range")
            if gi >= len(groups):
                raise LpError(f"partition {name}: group_index {gi} out of range")
            partitions.append(Partition(name, attrs, set(), extents[fei:fei + ne], groups[gi].name, fei, ne, gi))
        for e in extents:
            if e.is_linear and e.target_source >= len(bdevs):
                raise LpError(f"extent target_source {e.target_source} out of range")
        info.header, info.partitions, info.extents, info.groups, info.block_devices = \
            hdr, partitions, extents, groups, bdevs

    # -- slot agreement ------------------------------------------------------------------------

    @property
    def slots_agree(self) -> bool:
        """True when every metadata copy parsed successfully and all carry identical header+tables bytes."""
        if not self.slots or not all(s.ok for s in self.slots):
            return False
        return len({s.metadata_sha256 for s in self.slots}) == 1

    @property
    def slot_status(self) -> list[dict]:
        return [s.summary_dict() for s in self.slots]

    # -- lookups ---------------------------------------------------------------------------------

    @property
    def partition_names(self) -> list[str]:
        return [p.name for p in self.partitions]

    def partition(self, name: str) -> Partition:
        for p in self.partitions:
            if p.name == name:
                return p
        raise KeyError(f"no partition named {name!r} (have {self.partition_names})")

    def group(self, name: str) -> Group:
        for g in self.groups:
            if g.name == name:
                return g
        raise KeyError(f"no group named {name!r}")

    @property
    def block_device(self) -> BlockDevice:
        if not self.block_devices:
            raise LpError("metadata has no block device entry")
        return self.block_devices[0]

    @property
    def first_logical_sector(self) -> int:
        return self.block_device.first_logical_sector

    def partition_extent_ranges(self, name: str) -> list[tuple[int, int]]:
        """[(byte_offset, length)] of the partition's data inside the super image, in logical order.

        Only LINEAR extents on block device 0 (the super image itself) can be mapped; a ZERO
        extent or an extent on another block device raises :class:`LpError`.
        """
        p = self.partition(name)
        ranges = []
        for e in p.extents:
            if not e.is_linear:
                raise LpError(f"partition {name} has a {e.target_type_name} extent; cannot map to bytes")
            if e.target_source != 0:
                raise LpError(f"partition {name} has an extent on block device {e.target_source}, not super")
            ranges.append((e.start_byte, e.num_bytes))
        return ranges

    def partition_size(self, name: str) -> int:
        return self.partition(name).size

    def iter_partition(self, name: str, chunk_size: int = 8 << 20) -> Iterator[bytes]:
        """Yield the partition's bytes, streaming from the super image."""
        with open(self.path, "rb") as f:
            for offset, length in self.partition_extent_ranges(name):
                if offset + length > self.size:
                    raise LpError(f"partition {name}: extent [{offset}, {offset + length}) exceeds image size {self.size}")
                f.seek(offset)
                remaining = length
                while remaining:
                    buf = f.read(min(chunk_size, remaining))
                    if not buf:
                        raise LpError(f"short read while extracting {name}")
                    remaining -= len(buf)
                    yield buf

    def extract_partition(self, name: str, dest: str | os.PathLike, chunk_size: int = 8 << 20) -> int:
        """Streaming copy of a partition out of the super image into ``dest``. Returns bytes written."""
        written = 0
        with open(dest, "wb") as out:
            for buf in self.iter_partition(name, chunk_size):
                out.write(buf)
                written += len(buf)
        return written

    # -- serialisation ---------------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "format": self.FORMAT,
            "path": self.path,
            "size": self.size,
            "layout": self.layout,
            "geometry_offset": self.geometry_offset,
            "geometry_backup_identical": self.geometry_backup_identical,
            "geometry": self.geometry.to_dict(),
            "header": self.header.to_dict(),
            "slot": self.slot,
            "slot_source": self.slot_source,
            "slots_agree": self.slots_agree,
            "slots": self.slot_status,
            "partitions": [p.to_dict() for p in self.partitions],
            "extents": [e.to_dict() for e in self.extents],
            "groups": [g.to_dict() for g in self.groups],
            "block_devices": [b.to_dict() for b in self.block_devices],
        }

    def metadata_dict(self) -> dict:
        """The part of :meth:`to_dict` that describes the metadata itself (no path/size/slot bookkeeping)."""
        d = self.to_dict()
        for k in ("path", "size", "slot", "slot_source", "slots", "slots_agree", "geometry_offset",
                  "geometry_backup_identical", "layout"):
            d.pop(k, None)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "SuperImage":
        if d.get("format", cls.FORMAT) != cls.FORMAT:
            raise LpError(f"unknown super.json format {d.get('format')!r}")
        self = cls.__new__(cls)
        self.path = d.get("path", "")
        self.size = d.get("size", 0)
        self.layout = d.get("layout", "super")
        self.geometry_offset = d.get("geometry_offset", RESERVED_BYTES)
        self.geometry_backup_identical = d.get("geometry_backup_identical")
        self.geometry = Geometry.from_dict(d["geometry"])
        self.header = Header.from_dict(d["header"])
        self.slot = d.get("slot", 0)
        self.slot_source = d.get("slot_source", "primary")
        self.groups = [Group.from_dict(g) for g in d.get("groups", [])]
        self.block_devices = [BlockDevice.from_dict(b) for b in d.get("block_devices", [])]
        self.partitions = [Partition.from_dict(p) for p in d.get("partitions", [])]
        if "extents" in d:
            self.extents = [Extent.from_dict(e) for e in d["extents"]]
        else:
            self.extents = [e for p in self.partitions for e in p.extents]
        self.slots = []
        for s in d.get("slots", []):
            self.slots.append(SlotInfo(s["index"], s["kind"], s["offset"], s.get("ok", False),
                                       s.get("error", ""), s.get("metadata_sha256", "")))
        return self

    def save_json(self, path: str | os.PathLike) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, sort_keys=False)
            f.write("\n")

    @classmethod
    def load_json(cls, path: str | os.PathLike) -> "SuperImage":
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_dict(json.load(f))

    # -- lpmake ----------------------------------------------------------------------------------

    @staticmethod
    def _normalise_spec(spec: dict) -> dict:
        if "name" not in spec:
            raise LpError(f"partition spec without name: {spec!r}")
        size = int(spec.get("size", 0))
        if size < 0:
            raise LpError(f"partition {spec['name']}: negative size")
        return {
            "name": str(spec["name"]),
            "image_path": spec.get("image_path"),
            "size": size,
            "readonly": bool(spec.get("readonly", False)),
            "group": spec.get("group") or "default",
        }

    def lpmake_args(self, partitions_spec: list[dict], output: str | os.PathLike, sparse: bool = False,
                    lpmake: str = "lpmake", force_full_image: bool = False) -> list[str]:
        """Build the exact ``lpmake`` command line reproducing this image's geometry.

        ``partitions_spec`` is a list of ``{name, image_path, size, readonly, group}`` dicts in the
        order the partitions should be laid out (lpmake places extents in command-line order).
        ``image_path`` may be None (no ``--image``; the partition is then zero-filled).
        Groups come from the parsed metadata (``default`` is implicit and never passed); a spec
        may name a group that is not in the metadata only if ``groups`` are extended first.
        """
        g = self.geometry
        bd = self.block_device
        specs = [self._normalise_spec(s) for s in partitions_spec]
        known_groups = {grp.name for grp in self.groups} | {"default"}
        for s in specs:
            if s["group"] not in known_groups:
                raise LpError(f"partition {s['name']}: unknown group {s['group']!r} (have {sorted(known_groups)})")
            if not re.fullmatch(r"[A-Za-z0-9_]{1,35}", s["name"]):
                raise LpError(f"invalid partition name {s['name']!r}")
        args = [
            lpmake,
            "--metadata-size", str(g.metadata_max_size),
            "--metadata-slots", str(g.metadata_slot_count),
            "--super-name", bd.partition_name,
            "--block-size", str(g.logical_block_size),
            "--device", f"{bd.partition_name}:{bd.size}:{bd.alignment}:{bd.alignment_offset}",
        ]
        if self.header.flags and self.header.flags & HEADER_FLAG_VIRTUAL_AB:
            args.append("--virtual-ab")
        for grp in self.groups:
            if grp.name == "default":
                continue
            args += ["--group", f"{grp.name}:{grp.maximum_size}"]
        for s in specs:
            attrs = "readonly" if s["readonly"] else "none"
            args += ["--partition", f"{s['name']}:{attrs}:{s['size']}:{s['group']}"]
            if s["image_path"]:
                args += ["--image", f"{s['name']}={os.fspath(s['image_path'])}"]
        if sparse:
            args.append("--sparse")
        if force_full_image:
            args.append("--force-full-image")
        args += ["--output", os.fspath(output)]
        return args

    def stock_partitions_spec(self, image_dir: str | os.PathLike | None = None, suffix: str = ".img") -> list[dict]:
        """A partitions_spec reproducing this image's own layout (sizes, attributes, groups)."""
        spec = []
        for p in self.partitions:
            spec.append({
                "name": p.name,
                "image_path": os.path.join(os.fspath(image_dir), p.name + suffix) if image_dir else None,
                "size": p.size,
                "readonly": p.readonly,
                "group": p.group,
            })
        return spec

    def validate_capacity(self, partitions_spec: list[dict]) -> CapacityReport:
        """Check a partitions_spec against the group maxima and the block device size.

        Mirrors liblp: each size is rounded up to ``logical_block_size`` (that rounded size counts
        against the group maximum), extents are placed sequentially from ``first_logical_sector``
        with every start rounded up to the block device ``alignment``, and the last extent must end
        within the device. The report lists ``(name, size, aligned_size)`` rows plus free bytes.
        """
        g = self.geometry
        bd = self.block_device
        specs = [self._normalise_spec(s) for s in partitions_spec]
        groups = {grp.name: grp for grp in self.groups}
        if "default" not in groups:
            groups["default"] = Group("default")
        errors: list[str] = []
        names = [s["name"] for s in specs]
        for n in sorted(set(names)):
            if names.count(n) > 1:
                errors.append(f"partition {n} listed more than once")
        rows: list[CapacityRow] = []
        group_used: dict[str, int] = {name: 0 for name in groups}
        cursor = bd.first_logical_sector * SECTOR_SIZE
        for s in specs:
            aligned = align_up(s["size"], g.logical_block_size)
            start = align_up(cursor, bd.alignment)
            end = start + aligned
            footprint = align_up(end, bd.alignment) - start if aligned else 0
            rows.append(CapacityRow(s["name"], s["size"], aligned, footprint, s["group"], start))
            if s["group"] not in groups:
                errors.append(f"partition {s['name']}: unknown group {s['group']!r}")
            else:
                group_used[s["group"]] += aligned
            if aligned:
                cursor = end
            if end > bd.size:
                errors.append(f"partition {s['name']} ({aligned} B at {start}) ends at {end}, "
                              f"beyond device size {bd.size} (over by {end - bd.size} B)")
        group_free: dict[str, int | None] = {}
        for name, grp in groups.items():
            if grp.maximum_size == 0:
                group_free[name] = None
            else:
                group_free[name] = grp.maximum_size - group_used[name]
                if group_used[name] > grp.maximum_size:
                    errors.append(f"group {name}: {group_used[name]} B requested exceeds maximum "
                                  f"{grp.maximum_size} B by {group_used[name] - grp.maximum_size} B")
        used = cursor
        return CapacityReport(rows, bd.size, used, bd.size - used, group_used, group_free, errors)


# --- lpdump text oracle ---------------------------------------------------------------------

_LPDUMP_EXTENT_RE = re.compile(r"^\s*(\d+)\s+\.\.\s+(\d+)\s+(linear\s+(\S+)\s+(\d+)|zero)\s*$")


def parse_lpdump_text(text: str) -> list[dict]:
    """Parse ``lpdump`` text output (one or more ``Slot N:`` sections) into plain dicts.

    Each slot dict: version, metadata_size, metadata_max_size, metadata_slot_count, header_flags,
    partitions [{name, group, attributes (set of names), extents [{first, last, type, device, start}]}],
    block_devices [{partition_name, first_sector, size, flags}], groups [{name, maximum_size, flags}].
    """
    slots: list[dict] = []
    cur: dict | None = None
    section = None
    entry: dict | None = None

    def flush() -> None:
        nonlocal entry
        if entry is not None and cur is not None and section is not None:
            cur[section].append(entry)
        entry = None

    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"^Slot (\d+):$", s)
        if m:
            flush()
            cur = {"slot": int(m.group(1)), "partitions": [], "block_devices": [], "groups": []}
            slots.append(cur)
            section = None
            continue
        if cur is None:
            if s.startswith("Metadata version:"):
                # lpdump prints 'Slot N:' before this, but be lenient for super_empty dumps.
                cur = {"slot": 0, "partitions": [], "block_devices": [], "groups": []}
                slots.append(cur)
            else:
                continue
        if s.startswith("Metadata version:"):
            cur["version"] = s.split(":", 1)[1].strip()
        elif s.startswith("Metadata size:"):
            cur["metadata_size"] = int(s.split(":", 1)[1].split()[0])
        elif s.startswith("Metadata max size:"):
            cur["metadata_max_size"] = int(s.split(":", 1)[1].split()[0])
        elif s.startswith("Metadata slot count:"):
            cur["metadata_slot_count"] = int(s.split(":", 1)[1].strip())
        elif s.startswith("Header flags:"):
            v = s.split(":", 1)[1].strip()
            cur["header_flags"] = set() if v == "none" else set(v.split(","))
        elif s == "Partition table:":
            flush(); section = "partitions"
        elif s == "Super partition layout:":
            flush(); section = None
        elif s == "Block device table:":
            flush(); section = "block_devices"
        elif s == "Group table:":
            flush(); section = "groups"
        elif s.startswith("-----"):
            flush()
        elif section == "partitions":
            if s.startswith("Name:"):
                entry = {"name": s.split(":", 1)[1].strip(), "extents": []}
            elif s.startswith("Group:") and entry is not None:
                entry["group"] = s.split(":", 1)[1].strip()
            elif s.startswith("Attributes:") and entry is not None:
                v = s.split(":", 1)[1].strip()
                entry["attributes"] = set() if v == "none" else set(v.split(","))
            elif s == "Extents:":
                pass
            elif entry is not None:
                m = _LPDUMP_EXTENT_RE.match(s)
                if m:
                    ext = {"first": int(m.group(1)), "last": int(m.group(2)),
                           "type": "zero" if m.group(3) == "zero" else "linear"}
                    if ext["type"] == "linear":
                        ext["device"] = m.group(4)
                        ext["start"] = int(m.group(5))
                    entry["extents"].append(ext)
        elif section == "block_devices":
            if s.startswith("Partition name:"):
                entry = {"partition_name": s.split(":", 1)[1].strip()}
            elif s.startswith("First sector:") and entry is not None:
                entry["first_sector"] = int(s.split(":", 1)[1].strip())
            elif s.startswith("Size:") and entry is not None:
                entry["size"] = int(s.split(":", 1)[1].split()[0])
            elif s.startswith("Flags:") and entry is not None:
                v = s.split(":", 1)[1].strip()
                entry["flags"] = set() if v == "none" else set(v.split(","))
        elif section == "groups":
            if s.startswith("Name:"):
                entry = {"name": s.split(":", 1)[1].strip()}
            elif s.startswith("Maximum size:") and entry is not None:
                entry["maximum_size"] = int(s.split(":", 1)[1].split()[0])
            elif s.startswith("Flags:") and entry is not None:
                v = s.split(":", 1)[1].strip()
                entry["flags"] = set() if v == "none" else set(v.split(","))
    flush()
    return slots
