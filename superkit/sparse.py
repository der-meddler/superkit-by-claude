"""Android sparse image reader/writer in the style Samsung ships ``super.img``.

Samsung's stock sparse super uses only RAW and DONT_CARE chunks (zero runs stay RAW,
DONT_CARE only where the raw image has no data), whereas ``img2simg`` turns every zero run
into a FILL chunk.  ``raw_to_sparse`` reproduces the Samsung style: RAW chunks capped at
``max_raw`` bytes, DONT_CARE for filesystem holes (SEEK_HOLE) when ``holes_dont_care`` is
true, never FILL.  ``summary`` and ``sparse_to_raw`` exist for tests and inspection.
"""
from __future__ import annotations

import os
import struct

SPARSE_MAGIC = 0xED26FF3A
CHUNK_RAW = 0xCAC1
CHUNK_FILL = 0xCAC2
CHUNK_DONT_CARE = 0xCAC3
CHUNK_CRC32 = 0xCAC4
CHUNK_NAMES = {CHUNK_RAW: "RAW", CHUNK_FILL: "FILL", CHUNK_DONT_CARE: "DONT_CARE", CHUNK_CRC32: "CRC32"}
FILE_HDR = struct.Struct("<IHHHHIIII")   # magic, major, minor, file_hdr_sz, chunk_hdr_sz, blk_sz, total_blks, total_chunks, image_checksum
CHUNK_HDR = struct.Struct("<HHII")        # type, reserved, chunk_sz (blocks), total_sz (bytes incl. header)


class SparseError(Exception):
    pass


def is_sparse(path: str) -> bool:
    with open(path, "rb") as f:
        head = f.read(4)
    return len(head) == 4 and struct.unpack("<I", head)[0] == SPARSE_MAGIC


def summary(path: str) -> dict:
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        magic, major, minor, fhs, chs, blk, total_blks, total_chunks, csum = FILE_HDR.unpack(f.read(FILE_HDR.size))
        if magic != SPARSE_MAGIC:
            raise SparseError("%s is not a sparse image" % path)
        off = fhs
        types: dict[str, int] = {}
        blocks = 0
        for _ in range(total_chunks):
            f.seek(off)
            t, _r, csz, tsz = CHUNK_HDR.unpack(f.read(CHUNK_HDR.size))
            if tsz < chs:
                raise SparseError("chunk at %d has total_sz %d < header" % (off, tsz))
            name = CHUNK_NAMES.get(t, "0x%X" % t)
            types[name] = types.get(name, 0) + 1
            blocks += csz
            off += tsz
    if blocks != total_blks:
        raise SparseError("chunks cover %d blocks, header says %d" % (blocks, total_blks))
    return {"path": path, "size": size, "block_size": blk, "total_blocks": total_blks, "raw_size": blk * total_blks,
            "chunks": total_chunks, "types": types, "trailing_bytes": size - off, "version": "%d.%d" % (major, minor)}


def _data_ranges(fd: int, size: int, use_holes: bool):
    """Yield (offset, length) of regions that must be written (everything, or only data
    segments between filesystem holes)."""
    if not use_holes:
        yield 0, size
        return
    pos = 0
    while pos < size:
        try:
            data = os.lseek(fd, pos, os.SEEK_DATA)
        except OSError:
            return                      # no more data (ENXIO) -> trailing hole
        if data >= size:
            return
        try:
            hole = os.lseek(fd, data, os.SEEK_HOLE)
        except OSError:
            hole = size
        hole = min(hole, size)
        yield data, hole - data
        pos = hole


def raw_to_sparse(src: str, dst: str, block_size: int = 4096, max_raw: int = 64 << 20,
                  holes_dont_care: bool = True) -> dict:
    """Write ``dst`` as a sparse image of ``src`` using RAW (<= max_raw bytes each) and
    DONT_CARE chunks only.  Zero-filled data is kept RAW (Samsung style).  The raw size
    must be a multiple of ``block_size``; ``max_raw`` is rounded down to whole blocks."""
    size = os.path.getsize(src)
    if size % block_size:
        raise SparseError("%s: size %d is not a multiple of %d" % (src, size, block_size))
    max_raw -= max_raw % block_size
    if max_raw < block_size:
        raise SparseError("max_raw too small")
    total_blocks = size // block_size
    chunks = 0
    types = {"RAW": 0, "DONT_CARE": 0}
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        fout.write(FILE_HDR.pack(SPARSE_MAGIC, 1, 0, FILE_HDR.size, CHUNK_HDR.size, block_size, total_blocks, 0, 0))
        cur = 0  # raw offset covered so far
        for data_off, data_len in _data_ranges(fin.fileno(), size, holes_dont_care):
            # align the data range outwards to block boundaries
            start = data_off - data_off % block_size
            end = data_off + data_len
            end += (-end) % block_size
            if start > cur:
                gap_blocks = (start - cur) // block_size
                fout.write(CHUNK_HDR.pack(CHUNK_DONT_CARE, 0, gap_blocks, CHUNK_HDR.size))
                chunks += 1
                types["DONT_CARE"] += 1
                cur = start
            pos = max(start, cur)
            while pos < end:
                n = min(max_raw, end - pos)
                fout.write(CHUNK_HDR.pack(CHUNK_RAW, 0, n // block_size, CHUNK_HDR.size + n))
                fin.seek(pos)
                remaining = n
                while remaining:
                    buf = fin.read(min(remaining, 8 << 20))
                    if not buf:
                        raise SparseError("short read at %d" % pos)
                    fout.write(buf)
                    remaining -= len(buf)
                chunks += 1
                types["RAW"] += 1
                pos += n
            cur = end
        if cur < size:
            gap_blocks = (size - cur) // block_size
            fout.write(CHUNK_HDR.pack(CHUNK_DONT_CARE, 0, gap_blocks, CHUNK_HDR.size))
            chunks += 1
            types["DONT_CARE"] += 1
        fout.seek(0)
        fout.write(FILE_HDR.pack(SPARSE_MAGIC, 1, 0, FILE_HDR.size, CHUNK_HDR.size, block_size, total_blocks, chunks, 0))
    return {"path": dst, "size": os.path.getsize(dst), "chunks": chunks, "types": types, "raw_size": size}


def sparse_to_raw(src: str, dst: str) -> int:
    """Expand a sparse image (RAW/FILL/DONT_CARE/CRC32) to a raw file; DONT_CARE regions are
    left as holes.  Returns the raw size."""
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        magic, _maj, _min, fhs, chs, blk, total_blks, total_chunks, _c = FILE_HDR.unpack(fin.read(FILE_HDR.size))
        if magic != SPARSE_MAGIC:
            raise SparseError("%s is not a sparse image" % src)
        fin.seek(fhs)
        out_pos = 0
        for _ in range(total_chunks):
            t, _r, csz, tsz = CHUNK_HDR.unpack(fin.read(chs))
            nbytes = csz * blk
            payload = tsz - chs
            if t == CHUNK_RAW:
                if payload != nbytes:
                    raise SparseError("RAW chunk payload %d != %d" % (payload, nbytes))
                fout.seek(out_pos)
                remaining = nbytes
                while remaining:
                    buf = fin.read(min(remaining, 8 << 20))
                    fout.write(buf)
                    remaining -= len(buf)
            elif t == CHUNK_FILL:
                value = fin.read(4)
                if value != b"\0\0\0\0":
                    fout.seek(out_pos)
                    fout.write(value * (nbytes // 4))
            elif t == CHUNK_DONT_CARE:
                pass
            elif t == CHUNK_CRC32:
                fin.read(4)
            else:
                raise SparseError("unknown chunk type 0x%X" % t)
            out_pos += nbytes
        fout.truncate(total_blks * blk)
    return total_blks * blk
