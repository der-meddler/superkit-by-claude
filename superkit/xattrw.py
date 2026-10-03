"""In-place extended-attribute rewriting for f2fs images produced by ``sload_f2fs``.

``sload_f2fs`` (AOSP 1.16) writes only ``security.selinux``.  The stock Samsung images
also carry ``security.capability`` (``run-as``, ``simpleperf_app_runner``) and Samsung's
``user.pa`` process-authenticator certificates (about 400 bytes each).  This module
rewrites the xattr storage of an inode *in place*: the inline area (the last
``inline_xattr_addrs * 4`` bytes of ``i_addr``) and, when the inode owns one, the body of
its xattr node.  It never allocates blocks.  When the final entry set does not fit the
inline area, the build step must make sload allocate the xattr node up front by giving
the file a padded SELinux label (see :func:`pad_label` / :func:`needs_xattr_node`); the
padded label is then replaced by the real one here.

The on-disk layout (f2fs-tools ``include/xattr.h``): one ``f2fs_xattr_header`` (24 bytes:
magic 0xF2F52011, refcount, 16 reserved) at the start of the inline area, then entries
``{u8 index, u8 name_len, le16 value_size, name, value}`` each padded to 4 bytes, and a
4-byte zero terminator.  The entry list continues seamlessly from the inline area into
the xattr node body (``BLOCK_SIZE - 24`` usable bytes); the kernel and f2fs-tools both
read it as one concatenated buffer.
"""
from __future__ import annotations

import struct
from typing import Iterable

from .f2fs import (BLOCK_SIZE, F2FS_XATTR_MAGIC, I_NID_OFF, XATTR_HEADER_SIZE, F2FSError,
                   F2FSImage, Inode, UnsupportedError)
from .fsconfig import ManifestEntry, encode_capabilities

NODE_FOOTER_SIZE = 24
VALID_XATTR_BLOCK_SIZE = BLOCK_SIZE - NODE_FOOTER_SIZE
DEFAULT_INLINE_XATTR_ADDRS = 50

INDEX_USER = 1
INDEX_POSIX_ACL_ACCESS = 2
INDEX_POSIX_ACL_DEFAULT = 3
INDEX_TRUSTED = 4
INDEX_SECURITY = 6

_PREFIXES = (("security.", INDEX_SECURITY), ("trusted.", INDEX_TRUSTED), ("user.", INDEX_USER))

# A label at least this long cannot fit the 200-byte inline area together with the
# header and terminator, so sload_f2fs allocates an xattr node for the inode.
PAD_CHAR = "~"


class XattrError(F2FSError):
    pass


def split_xattr_name(full: str) -> tuple[int, bytes]:
    """``'user.pa'`` -> ``(1, b'pa')``; raises for namespaces f2fs cannot store."""
    if full == "system.posix_acl_access":
        return INDEX_POSIX_ACL_ACCESS, b""
    if full == "system.posix_acl_default":
        return INDEX_POSIX_ACL_DEFAULT, b""
    for prefix, idx in _PREFIXES:
        if full.startswith(prefix) and len(full) > len(prefix):
            return idx, full[len(prefix):].encode()
    raise UnsupportedError("cannot store xattr %r in an f2fs image" % full)


def entry_size(name_len: int, value_len: int) -> int:
    return (4 + name_len + value_len + 3) & ~3


def pack_xattrs(entries: Iterable[tuple[int, bytes, bytes]], header: bytes | None = None) -> bytes:
    """Serialise ``[(index, name, value)]`` as header + entries + terminator."""
    if header is None or len(header) != XATTR_HEADER_SIZE or \
            struct.unpack_from("<I", header)[0] != F2FS_XATTR_MAGIC:
        header = struct.pack("<II16x", F2FS_XATTR_MAGIC, 1)
    out = bytearray(header)
    for idx, name, value in entries:
        if not 0 < idx < 256:
            raise XattrError("bad xattr index %r" % idx)
        if len(name) > 255:
            raise XattrError("xattr name too long: %r" % name)
        if len(value) > 0xFFFF:
            raise XattrError("xattr value too long (%d bytes)" % len(value))
        out += struct.pack("<BBH", idx, len(name), len(value)) + name + value
        out += b"\0" * ((-len(out)) & 3)
    out += b"\0\0\0\0"
    return bytes(out)


def wanted_entries(e: ManifestEntry) -> list[tuple[int, bytes, bytes]]:
    """The complete xattr set a manifest entry describes, in on-disk order."""
    out: list[tuple[int, bytes, bytes]] = []
    if e.selinux is not None:
        out.append((INDEX_SECURITY, b"selinux", e.selinux.encode()))
    if e.caps:
        out.append((INDEX_SECURITY, b"capability", encode_capabilities(e.caps)))
    for name, value in e.xattrs.items():
        if name in ("security.selinux", "security.capability"):
            continue
        idx, short = split_xattr_name(name)
        out.append((idx, short, bytes(value)))
    return out


def inline_capacity(inline_xattr_addrs: int = DEFAULT_INLINE_XATTR_ADDRS) -> int:
    return 4 * inline_xattr_addrs


def needs_rewrite(e: ManifestEntry) -> bool:
    """True when sload alone cannot produce this entry's xattrs (caps or extra xattrs)."""
    return bool(e.caps) or any(n not in ("security.selinux",) for n in e.xattrs)


def needs_xattr_node(e: ManifestEntry, inline_xattr_addrs: int = DEFAULT_INLINE_XATTR_ADDRS) -> bool:
    return len(pack_xattrs(wanted_entries(e))) > inline_capacity(inline_xattr_addrs)


def pad_label(label: str, inline_xattr_addrs: int = DEFAULT_INLINE_XATTR_ADDRS) -> str:
    """A label long enough that ``sload_f2fs`` must allocate an xattr node for the file.

    header(24) + align4(4 + len('selinux') + L) + terminator(4) must exceed the inline
    capacity; with the default 200 bytes that is L >= 162.  A 16-byte margin is added.
    """
    cap = inline_capacity(inline_xattr_addrs)
    target = cap - XATTR_HEADER_SIZE - 4 - (4 + len(b"selinux")) + 1 + 16
    if len(label) >= target:
        return label
    return label + PAD_CHAR * (target - len(label))


def unpad_label(label: str) -> str:
    return label.rstrip(PAD_CHAR)


class XattrWriter:
    """Rewrite xattrs of inodes in an f2fs image file (not a super image slice unless
    ``offset`` is given).  Refuses images with inode checksums (the inline area is
    covered by ``i_inode_checksum``)."""

    def __init__(self, image_path, offset: int = 0, length: int | None = None):
        self.path = str(image_path)
        self.base = offset
        self.img = F2FSImage(self.path, offset, length)
        if "inode_checksum" in self.img.features:
            self.img.close()
            raise UnsupportedError("cannot rewrite xattrs on an image with the inode_checksum feature")
        self.fd = open(self.path, "r+b")

    def close(self) -> None:
        try:
            self.fd.flush()
            self.fd.close()
        finally:
            self.img.close()

    def __enter__(self) -> "XattrWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- primitives
    def capacity(self, inode: Inode) -> int:
        cap = 4 * inode.inline_xattr_addrs
        if inode.xattr_nid:
            cap += VALID_XATTR_BLOCK_SIZE
        return cap

    def set_xattrs(self, inode: Inode, entries: Iterable[tuple[int, bytes, bytes]]) -> int:
        """Replace the whole xattr set of ``inode``; returns the serialised size."""
        if not inode.inline_xattr_addrs:
            raise UnsupportedError("inode %d has no inline xattr area" % inode.nid)
        inline_size = 4 * inode.inline_xattr_addrs
        inline_off = self.base + inode.blkaddr * BLOCK_SIZE + I_NID_OFF - inline_size
        self.fd.seek(inline_off)
        header = self.fd.read(XATTR_HEADER_SIZE)
        buf = pack_xattrs(entries, header)
        cap = self.capacity(inode)
        if len(buf) > cap:
            raise XattrError("inode %d (%s): %d bytes of xattrs exceed the %d bytes available%s"
                             % (inode.nid, inode.name.decode(errors="replace"), len(buf), cap,
                                "" if inode.xattr_nid else " (no xattr node: the build must pad the label)"))
        self.fd.seek(inline_off)
        self.fd.write(buf[:inline_size].ljust(inline_size, b"\0"))
        if inode.xattr_nid:
            _ver, _ino, xblk = self.img.nat_lookup(inode.xattr_nid)
            if xblk == 0:
                raise XattrError("inode %d: xattr nid %d has no block" % (inode.nid, inode.xattr_nid))
            self.fd.seek(self.base + xblk * BLOCK_SIZE)
            self.fd.write(buf[inline_size:].ljust(VALID_XATTR_BLOCK_SIZE, b"\0"))
        self.fd.flush()
        return len(buf)

    # ---- manifest driven
    def apply_manifest(self, wanted: dict[str, ManifestEntry], only_paths: Iterable[str] | None = None) -> list[str]:
        """Bring every path in ``only_paths`` (default: every path of ``wanted`` whose
        current xattrs differ) to the xattr set its manifest entry describes.
        Returns the rewritten paths."""
        only = set(only_paths) if only_paths is not None else None
        done: list[str] = []
        for path, _cur, inode in self.img.walk():
            if only is not None and path not in only:
                continue
            want = wanted.get(path)
            if want is None:
                continue
            target = wanted_entries(want)
            if self.img.raw_xattrs(inode) == target:
                continue
            self.set_xattrs(inode, target)
            done.append(path)
        if only is not None:
            missing = only - set(done) - {p for p in only if p in wanted and wanted[p].type in ("chr", "blk", "fifo", "sock")}
            # paths already correct are not an error
            missing = {p for p in missing if p not in wanted or not self._already_ok(p, wanted[p])}
            if missing:
                raise XattrError("paths not found in the image: %s" % sorted(missing)[:10])
        return done

    def _already_ok(self, path: str, want: ManifestEntry) -> bool:
        for p, _e, inode in self.img.walk():
            if p == path:
                return self.img.raw_xattrs(inode) == wanted_entries(want)
        return False
