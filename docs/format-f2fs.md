# f2fs on-disk format for a userland reader

Scope: exactly what `superkit/f2fs.py` (DESIGN.md §5) needs to walk and extract an
f2fs image read-only. Derived from f2fs-tools 1.17 (`include/f2fs_fs.h`, `fsck/xattr.h`,
`lib/libf2fs.c`, `fsck/mount.c`, `fsck/xattr.c`, `fsck/dump.c`, `fsck/dir.c`,
`fsck/node.c`) and verified against `dump.f2fs` on the stock images and on a
`make_f2fs`/`sload_f2fs` test image (section 15). The kernel's
`include/linux/f2fs_fs.h` has the same layouts.

Conventions used throughout:

* All multi-byte integers are **little-endian**. Sizes/offsets are bytes unless said
  otherwise. `u8/le16/le32/le64` as in the C headers.
* Block size is 4096 (`log_blocksize == 12`). Every stock partition and everything
  `make_f2fs` produces here uses 4 KiB blocks; the reader may refuse other sizes
  (f2fs-tools 1.17 allows 4 K–16 K; the derived constants below are for 4 K only).
* A *block address* (`blkaddr`, `block_t`) is an absolute 4 KiB block index from the
  start of the image (block 0 contains the superblock). Valid data/node addresses are
  `main_blkaddr <= a < block_count`; also never read past the file (an AVB footer may
  follow the filesystem but it is beyond `block_count * 4096`).
* "Segment" = 512 blocks = 2 MiB (`log_blocks_per_seg == 9`, hard-coded in fsck).
* Pseudo code is Python-like; `u32(buf, off)` means `struct.unpack_from("<I", buf, off)[0]`.

Special block address values (`f2fs_fs.h`):

| name | value | meaning for a reader |
|---|---|---|
| `NULL_ADDR` | `0x00000000` | hole / not allocated: read as zeros |
| `NEW_ADDR` | `0xFFFFFFFF` | allocated but not yet written: read as zeros |
| `COMPRESS_ADDR` | `0xFFFFFFFE` | compressed-cluster marker: **error, unsupported** |

Derived constants for 4 KiB blocks (all used below):

| constant | formula | value |
|---|---|---|
| `DEF_ADDRS_PER_INODE` | `(4096 - 360 - 20 - 24) / 4` | 923 |
| `DEF_ADDRS_PER_BLOCK` = `NIDS_PER_BLOCK` | `(4096 - 24) / 4` | 1018 |
| `NAT_ENTRY_PER_BLOCK` | `4096 / 9` | 455 |
| `SIT_ENTRY_PER_BLOCK` | `4096 / 74` | 55 |
| `ENTRIES_IN_SUM` | `4096 / 8` | 512 |
| `SUM_ENTRIES_SIZE` | `7 * 512` | 3584 |
| `SUM_JOURNAL_SIZE` | `4096 - 5 - 3584` | 507 |
| `NAT_JOURNAL_ENTRIES` | `(507 - 2) / 13` | 38 (reserved 11) |
| `SIT_JOURNAL_ENTRIES` | `(507 - 2) / 78` | 6 (reserved 37) |
| `NR_DENTRY_IN_BLOCK` | `8*4096 / ((11+8)*8 + 1)` | 214 |
| `SIZE_OF_DENTRY_BITMAP` | `ceil(214 / 8)` | 27 |
| `SIZE_OF_RESERVED` | `4096 - (19*214 + 27)` | 3 |
| `DEFAULT_INLINE_XATTR_ADDRS` | fixed | 50 (= 200 bytes) |
| `DEF_INLINE_RESERVED_SIZE` | fixed | 1 (one `le32` slot) |
| `XATTR_NODE_OFFSET` | `0xFFFFFFFF >> 3` | `0x1FFFFFFF` (536870911) |
| `F2FS_NAME_LEN` | fixed | 255 |

## 1. CRC32 used everywhere

`f2fs_cal_crc32(seed, buf)` is the reflected CRC-32 (polynomial `0xEDB88320`) with
**initial register = seed and no final inversion**. Superblock and checkpoint use
`seed = F2FS_SUPER_MAGIC = 0xF2F52010`. In Python this is exactly

```python
def f2fs_crc32(data, seed=0xF2F52010):
    return zlib.crc32(data, seed ^ 0xFFFFFFFF) ^ 0xFFFFFFFF   # verified == the C loop
```

## 2. Superblock

Location: byte offset 1024 inside block 0 (`F2FS_SUPER_OFFSET`); an identical backup
at byte 1024 of block 1. Size 3072 (`sizeof(struct f2fs_super_block)`). Read block 0,
check `magic`; if it fails, try block 1.

| offset | size | field | notes |
|---|---|---|---|
| 0 | 4 | `magic` | `0xF2F52010` |
| 4 | 2 | `major_ver` | 1 |
| 6 | 2 | `minor_ver` | stock: 14 |
| 8 | 4 | `log_sectorsize` | 9 |
| 12 | 4 | `log_sectors_per_block` | 3 (`log_sectorsize + log_sectors_per_block == log_blocksize`) |
| 16 | 4 | `log_blocksize` | 12 |
| 20 | 4 | `log_blocks_per_seg` | 9 (fsck rejects anything else) |
| 24 | 4 | `segs_per_sec` | 1 |
| 28 | 4 | `secs_per_zone` | 1 |
| 32 | 4 | `checksum_offset` | 3068 when `sb_checksum` feature set, else 0 |
| 36 | 8 | `block_count` | total blocks incl. metadata = fs size / 4096 (packed, unaligned) |
| 44 | 4 | `section_count` | |
| 48 | 4 | `segment_count` | |
| 52 | 4 | `segment_count_ckpt` | 2 |
| 56 | 4 | `segment_count_sit` | 2 × SIT segments (both copies) |
| 60 | 4 | `segment_count_nat` | 2 × NAT segments (both copies) |
| 64 | 4 | `segment_count_ssa` | |
| 68 | 4 | `segment_count_main` | |
| 72 | 4 | `segment0_blkaddr` | |
| 76 | 4 | `cp_blkaddr` | start of checkpoint area (pack 1) |
| 80 | 4 | `sit_blkaddr` | |
| 84 | 4 | `nat_blkaddr` | |
| 88 | 4 | `ssa_blkaddr` | |
| 92 | 4 | `main_blkaddr` | first data/node block |
| 96 | 4 | `root_ino` | must be 3 |
| 100 | 4 | `node_ino` | must be 1 |
| 104 | 4 | `meta_ino` | must be 2 |
| 108 | 16 | `uuid` | |
| 124 | 1024 | `volume_name` | `le16[512]` UTF-16LE, NUL-terminated |
| 1148 | 4 | `extension_count` | cold extensions |
| 1152 | 512 | `extension_list[64][8]` | NUL-padded; cold first, then `hot_ext_count` hot ones |
| 1664 | 4 | `cp_payload` | extra checkpoint blocks holding bitmaps (section 3.3) |
| 1668 | 256 | `version` | kernel version string |
| 1924 | 256 | `init_version` | mkfs kernel version string |
| 2180 | 4 | `feature` | section 2.1 |
| 2184 | 1 | `encryption_level` | |
| 2185 | 16 | `encrypt_pw_salt` | |
| 2201 | 544 | `devs[8]` | each `{u8 path[64]; le32 total_segments}` (68 B); `devs[0].path[0] != 0` means multi-device: refuse |
| 2745 | 12 | `qf_ino[3]` | quota inode numbers (packed) |
| 2757 | 1 | `hot_ext_count` | |
| 2758 | 2 | `s_encoding` | casefold charset (0 = none) |
| 2760 | 2 | `s_encoding_flags` | |
| 2762 | 32 | `s_stop_reason[32]` | nonzero = kernel stopped checkpointing (treat as dirty) |
| 2794 | 16 | `s_errors[16]` | nonzero = kernel recorded corruption |
| 2810 | 258 | `reserved` | |
| 3068 | 4 | `crc` | `f2fs_crc32(sb[0:3068])` iff feature `SB_CHKSUM` |

Validation (`sanity_check_raw_super`): magic; if `feature & 0x800` then
`checksum_offset == 3068` and crc matches; `log_blocksize == 12`;
`log_blocks_per_seg == 9`; `node_ino,meta_ino,root_ino == 1,2,3`;
`cp_payload <= 510`; `main_blkaddr + segment_count_main*512 <= block_count` is the
useful upper bound for addresses.

### 2.1 Feature bits (`sb.feature`)

| bit | name (mkfs `-O`) | reader impact |
|---|---|---|
| `0x0001` | encrypt | per-file; refuse inodes with `i_advise & 0x04` |
| `0x0002` | blkzoned | none |
| `0x0004` | atomic_write | none |
| `0x0008` | extra_attr | inode has `i_extra_isize` area (section 7) |
| `0x0010` | project_quota | `i_projid` present in extra area |
| `0x0020` | inode_checksum | `i_inode_checksum` present (section 7.4) |
| `0x0040` | flexible_inline_xattr | inline xattr size comes from `i_inline_xattr_size` |
| `0x0080` | quota | quota inodes exist (`qf_ino`), they are regular hidden files |
| `0x0100` | inode_crtime | `i_crtime` present |
| `0x0200` | lost_found | `/lost+found` dir exists |
| `0x0400` | verity | reserved |
| `0x0800` | sb_checksum | sb crc at 3068 must verify |
| `0x1000` | casefold | names compared case-insensitively by kernel; bytes unchanged |
| `0x2000` | compression | **refuse** (DESIGN non-goal) |
| `0x4000` | **ro** | read-only image: SSA may be absent (`segment_count_ssa` can be 0, stock odm has 0), reserved/overprovision 0. No reader impact |
| `0x8000` | device_alias | `i_flags & 0x80000000` inodes alias a device: refuse |
| `0x10000` | packed_ssa | 16 KiB-block feature, summary blocks stay 4 KiB |

Stock: `feature == 0x4000`. Test image: `0x828` (extra_attr, inode_checksum,
sb_checksum).

## 3. Checkpoint

### 3.1 Checkpoint block (`struct f2fs_checkpoint`, 192 bytes + bitmaps, one block)

| offset | size | field |
|---|---|---|
| 0 | 8 | `checkpoint_ver` |
| 8 | 8 | `user_block_count` |
| 16 | 8 | `valid_block_count` |
| 24 | 4 | `rsvd_segment_count` |
| 28 | 4 | `overprov_segment_count` |
| 32 | 4 | `free_segment_count` |
| 36 | 32 | `cur_node_segno[8]` (le32 each; unused entries `0xFFFFFFFF`) |
| 68 | 16 | `cur_node_blkoff[8]` (le16) |
| 84 | 32 | `cur_data_segno[8]` |
| 116 | 16 | `cur_data_blkoff[8]` |
| 132 | 4 | `ckpt_flags` (section 3.2) |
| 136 | 4 | `cp_pack_total_block_count` |
| 140 | 4 | `cp_pack_start_sum` |
| 144 | 4 | `valid_node_count` |
| 148 | 4 | `valid_inode_count` |
| 152 | 4 | `next_free_nid` |
| 156 | 4 | `sit_ver_bitmap_bytesize` |
| 160 | 4 | `nat_ver_bitmap_bytesize` |
| 164 | 4 | `checksum_offset` (192 ≤ x ≤ 4092) |
| 168 | 8 | `elapsed_time` |
| 176 | 16 | `alloc_type[16]` (u8; 0 = LFS, 1 = SSR) |
| 192 | … | `sit_nat_version_bitmap[]` (section 3.3) |
| `checksum_offset` | 4 | crc |

Checkpoint CRC (`f2fs_checkpoint_chksum`):

```python
def cp_crc_ok(blk):
    off = u32(blk, 164)
    if off < 192 or off > 4092: return False
    crc = f2fs_crc32(blk[:off])
    if off < 4092:                      # crc sits before the bitmaps: skip it, hash the rest
        crc = f2fs_crc32(blk[off+4:], crc)
    return crc == u32(blk, off)
```

### 3.2 `ckpt_flags`

| bit | name | reader impact |
|---|---|---|
| `0x0001` | `CP_UMOUNT_FLAG` | clean unmount: node summaries are in the pack (section 4.1) |
| `0x0002` | `CP_ORPHAN_PRESENT_FLAG` | orphan-inode blocks in the pack (unlinked-but-open inodes); reader may warn |
| `0x0004` | `CP_COMPACT_SUM_FLAG` | data summaries compacted (section 4.2) |
| `0x0008` | `CP_ERROR_FLAG` | fs had errors |
| `0x0010` | `CP_FSCK_FLAG` | needs fsck |
| `0x0020` | `CP_FASTBOOT_FLAG` | |
| `0x0040` | `CP_CRC_RECOVERY_FLAG` | node-footer `cp_ver` carries crc in upper 32 bits (irrelevant to reader) |
| `0x0080` | `CP_NAT_BITS_FLAG` | nat_bits blocks exist at the end of the cp segment; ignore |
| `0x0100` | `CP_TRIMMED_FLAG` | |
| `0x0200` | `CP_NOCRC_RECOVERY_FLAG` | |
| `0x0400` | `CP_LARGE_NAT_BITMAP_FLAG` | bitmap order changes (section 3.3) |
| `0x0800` | `CP_QUOTA_NEED_FSCK_FLAG` | |
| `0x1000` | `CP_DISABLED_FLAG` | checkpointing disabled |
| `0x4000` | `CP_RESIZEFS_FLAG` | |

Stock: `0x81` (nat_bits + umount). Test image: `0x181` (+trimmed).

### 3.3 Pack layout and the valid checkpoint

There are two packs: pack 1 at `cp_blkaddr`, pack 2 at `cp_blkaddr + 512` (one
segment later). A pack is:

```
+0                     checkpoint block (copy A)
+1 .. +cp_payload      cp_payload blocks (bitmap overflow), only if sb.cp_payload > 0
                       orphan blocks, only if CP_ORPHAN_PRESENT_FLAG
cp_pack_start_sum      summary blocks: hot/warm/cold DATA (3, or 1-3 if compact),
                       then hot/warm/cold NODE (3) only if CP_UMOUNT_FLAG
+cp_pack_total_block_count-1   checkpoint block (copy B, must have the same version)
```

`cp_pack_start_sum == 1 + cp_payload + orphan_blocks`. Stock and test images:
`cp_pack_total_block_count = 8`, `cp_pack_start_sum = 1`, `cp_payload = 0`
(1 cp + 3 data sums + 3 node sums + 1 cp). nat_bits blocks (flag `0x80`) live in the
last blocks of the segment and are not counted.

Selection (`validate_checkpoint` / `get_valid_checkpoint`):

```python
def validate_pack(start):
    a = read_block(start)
    if not cp_crc_ok(a): return None
    total = u32(a, 136)
    if total > 512: return None
    b = read_block(start + total - 1)
    if not cp_crc_ok(b): return None
    if u64(a, 0) != u64(b, 0): return None          # both copies must agree
    return u64(a, 0), a                              # version, first block

p1 = validate_pack(sb.cp_blkaddr)
p2 = validate_pack(sb.cp_blkaddr + 512)
if p1 and p2:
    d = (p2.ver - p1.ver) % 2**64
    cur = 2 if 0 < d < 2**63 else 1                  # ver_after(): signed 64-bit difference > 0
elif p1: cur = 1
elif p2: cur = 2
else: raise Corrupt
cp_start = sb.cp_blkaddr + (512 if cur == 2 else 0)
ckpt = read_block(cp_start) + b"".join(read_block(cp_start + 1 + i) for i in range(sb.cp_payload))
```

`ckpt` is the checkpoint block with the payload blocks appended; bitmaps are
addressed inside this concatenated buffer.

Version bitmaps (`__bitmap_ptr`), sizes from fields 156/160:

```python
nat_sz, sit_sz = u32(ckpt,160), u32(ckpt,156)
if flags & 0x400:                                   # CP_LARGE_NAT_BITMAP: NAT first, then SIT
    base = 192 + (4 if u32(ckpt,164) == 192 else 0) # crc may sit right at 192
    nat_bitmap = ckpt[base : base+nat_sz]
    sit_bitmap = ckpt[base+nat_sz : base+nat_sz+sit_sz]
elif sb.cp_payload > 0:                             # NAT inline, SIT in the payload blocks
    nat_bitmap = ckpt[192 : 192+nat_sz]
    sit_bitmap = ckpt[4096 : 4096+sit_sz]
else:                                               # SIT first, then NAT, both inline
    sit_bitmap = ckpt[192 : 192+sit_sz]
    nat_bitmap = ckpt[192+sit_sz : 192+sit_sz+nat_sz]
```

Stock and test: `cp_payload = 0`, `sit_ver_bitmap_bytesize = nat_ver_bitmap_bytesize = 64`,
i.e. SIT bitmap at 192..256, NAT bitmap at 256..320, crc at 4092.

## 4. NAT (node address table)

### 4.1 NAT area and NAT entry

NAT entry (`struct f2fs_nat_entry`, 9 bytes, packed), 455 per block, last byte of the
block unused:

| offset | size | field |
|---|---|---|
| 0 | 1 | `version` |
| 1 | 4 | `ino` (owning inode; for an inode `ino == nid`) |
| 5 | 4 | `block_addr` (0 = free/unused nid, `NEW_ADDR` possible for not-yet-written) |

`nat_blocks = (segment_count_nat / 2) * 512`, `max_nid = nat_blocks * 455`. nid 0 is
never used; nid 1 (`node_ino`) and 2 (`meta_ino`) are virtual (NAT has
`block_addr = 1` for them in mkfs output) — skip nids < 3. Root is nid 3.

The NAT has two copies interleaved per segment: for segment pair `k`, copy 1 is at
`nat_blkaddr + 2k*512`, copy 2 at `nat_blkaddr + (2k+1)*512`. The NAT version bitmap
selects the copy per NAT block, and the bit order is **MSB-first within each byte**
(`f2fs_test_bit`: `mask = 1 << (7 - (nr & 7))`), unlike the dentry bitmaps:

```python
def current_nat_addr(nid):                           # fsck/mount.c
    block_off = nid // 455
    seg_off = block_off >> 9
    addr = sb.nat_blkaddr + (seg_off << 10) + (block_off & 511)
    if (nat_bitmap[block_off >> 3] >> (7 - (block_off & 7))) & 1:
        addr += 512                                  # copy 2
    return addr

def nat_lookup(nid):
    if nid in nat_journal: return nat_journal[nid]   # section 4.2 overrides the area
    blk = read_block(current_nat_addr(nid))
    off = (nid % 455) * 9
    return blk[off], u32(blk, off+1), u32(blk, off+5)    # version, ino, block_addr
```

### 4.2 NAT journal (hot-data summary block)

The current-segment summary blocks are inside the checkpoint pack. The **first**
summary block, at `cp_start + cp_pack_start_sum`, is the hot-data one, and its journal
area holds NAT entries that were newer than the NAT area at checkpoint time. They
**override** the NAT area and `n_nats` must be honoured (fsck rejects `n_nats > 38`).

Summary block layout (`struct f2fs_summary_block`, 4096):

| offset | size | content |
|---|---|---|
| 0 | 3584 | `entries[512]`, 7 bytes each: `le32 nid; u8 version; le16 ofs_in_node` (not needed by the reader) |
| 3584 | 507 | `journal`: `le16 n_nats` (or `n_sits`) at 3584, then entries at 3586 |
| 3586 | 38 × 13 | NAT journal entries: `le32 nid; u8 version; le32 ino; le32 block_addr` |
| 4080 | 11 | reserved |
| 4091 | 1 | `footer.entry_type` (0 = data, 1 = node) |
| 4092 | 4 | `footer.check_sum` |

(The SIT journal uses the same 507-byte area of the cold-data summary block, entries
`le32 segno + 74-byte sit entry`, 6 per block; not needed by the reader.)

Normal vs compact (`CP_COMPACT_SUM_FLAG 0x4`, `read_compacted_summaries`): with the flag
set, the block at `cp_pack_start_sum` is a packed block whose first 507 bytes are the
NAT journal (`n_nats` at 0, entries at 2), the next 507 bytes the SIT journal, followed
by the raw 7-byte summaries of the three data segments (spilling into following
blocks). Without the flag, the block is a full hot-data summary block and the journal is
at 3584. The node summaries (when `CP_UMOUNT_FLAG`) are the last 3 blocks before the
closing cp copy in both cases. Other summary-block addresses, if ever needed:
`cp_start + cp_pack_total_block_count - (base + 1) + type` with `base = 6` for data
types when unmounted (3 when not) and `base = 3` for node types (`sum_blk_addr`).

```python
sumblk = read_block(cp_start + cp_pack_start_sum)
j = sumblk[0:507] if flags & 0x4 else sumblk[3584:3584+507]
n_nats = u16(j, 0)
if n_nats > 38: raise Corrupt
nat_journal = {}
for i in range(n_nats):
    nid, ver, ino, blk = struct.unpack_from("<IBII", j, 2 + 13*i)
    nat_journal[nid] = (ver, ino, blk)
```

Stock odm, stock vendor and the test image all have `n_nats = 0` and an all-zero NAT
bitmap (freshly built, cleanly unmounted). A kernel-written image after use will have
both nonzero.

## 5. Node blocks and `node_footer`

Every node (inode, direct, indirect, xattr) is one 4 KiB block whose last 24 bytes are
the footer:

| offset in block | size | field | notes |
|---|---|---|---|
| 4072 | 4 | `nid` | must equal the nid looked up |
| 4076 | 4 | `ino` | owning inode; equals `nid` for an inode block |
| 4080 | 4 | `flag` | bit0 cold, bit1 fsync, bit2 dentry; `flag >> 3` = `ofs_in_node` |
| 4084 | 8 | `cp_ver` | checkpoint version at write time (unaligned) |
| 4092 | 4 | `next_blkaddr` | |

`ofs_in_node` is the node's position in the inode's index tree: 0 for the inode
itself, 1/2 for the direct nodes in `i_nid[0..1]`, `0x1FFFFFFF` (`XATTR_NODE_OFFSET`)
for the xattr node. Sanity (`dump_node`): `footer.nid == nid` and
`footer.ino == nat.ino`, else "invalid (i)node block".

```python
def read_node(nid, expect_ino=None):
    ver, ino, addr = nat_lookup(nid)
    if addr == 0 or addr == NEW_ADDR: raise Corrupt("unallocated node")
    if not (sb.main_blkaddr <= addr < sb.block_count): raise Corrupt
    blk = read_block(addr)
    if u32(blk, 4072) != nid or u32(blk, 4076) != ino: raise Corrupt("footer mismatch")
    if expect_ino is not None and ino != expect_ino: raise Corrupt
    return blk
```

Direct node: `le32 addr[1018]` at offset 0 (data block addresses). Indirect node:
`le32 nid[1018]` at offset 0 (nids of direct nodes; double-indirect holds nids of
indirect nodes). A zero entry means a hole for the whole subtree.

## 6. Inode (`struct f2fs_inode`, occupies the node block before the footer)

| offset | size | field | notes |
|---|---|---|---|
| 0 | 2 | `i_mode` | POSIX mode incl. S_IFMT (0o170000) |
| 2 | 1 | `i_advise` | bit `0x04` encrypted contents, `0x08` encrypted name → refuse |
| 3 | 1 | `i_inline` | section 6.1 |
| 4 | 4 | `i_uid` | |
| 8 | 4 | `i_gid` | |
| 12 | 4 | `i_links` | dirs ≥ 2; non-dir > 1 = hard link |
| 16 | 8 | `i_size` | bytes (symlink: target length; dir: bytes covered by dentry blocks) |
| 24 | 8 | `i_blocks` | blocks incl. inode, xattr node and index nodes |
| 32 | 8 | `i_atime` | seconds |
| 40 | 8 | `i_ctime` | |
| 48 | 8 | `i_mtime` | |
| 56 | 4 | `i_atime_nsec` | |
| 60 | 4 | `i_ctime_nsec` | |
| 64 | 4 | `i_mtime_nsec` | |
| 68 | 4 | `i_generation` | |
| 72 | 4 | `i_current_depth` | dir hash depth (union with `le16 i_gc_failures`) |
| 76 | 4 | `i_xattr_nid` | nid of the xattr node, 0 = none |
| 80 | 4 | `i_flags` | `0x4` `F2FS_COMPR_FL` → refuse; `0x10` immutable; `0x40` nodump; `0x80` noatime; `0x40000000` casefold; `0x80000000` device alias → refuse |
| 84 | 4 | `i_pino` | parent ino |
| 88 | 4 | `i_namelen` | |
| 92 | 255 | `i_name` | name as of creation (may be stale after rename: prefer the dentry name) |
| 347 | 1 | `i_dir_level` | |
| 348 | 12 | `i_ext` | `le32 fofs, blk_addr, len` extent cache hint; ignore |
| 360 | 4×923 | `i_addr[923]` **or** extra attrs + addrs (section 7) | |
| 4052 | 20 | `i_nid[5]` | direct, direct, indirect, indirect, double-indirect |
| 4072 | 24 | footer | section 5 |

`OFFSET_OF_END_OF_I_EXT = 360`, `SIZE_OF_I_NID = 20`. `i_addr[k]` is at
`360 + 4k`.

### 6.1 `i_inline` bits

| bit | name | meaning |
|---|---|---|
| `0x01` | `F2FS_INLINE_XATTR` | last 50 `i_addr` slots (200 B) hold inline xattrs (unless `flexible_inline_xattr`) |
| `0x02` | `F2FS_INLINE_DATA` | file/symlink data stored inside the inode (section 9) |
| `0x04` | `F2FS_INLINE_DENTRY` | directory entries stored inside the inode (section 10.2); also implies the 50-slot inline xattr area |
| `0x08` | `F2FS_DATA_EXIST` | inline data actually written (if clear, inline area is zeros) |
| `0x10` | `F2FS_INLINE_DOTS` | implicit `.`/`..` |
| `0x20` | `F2FS_EXTRA_ATTR` | extra attribute area present at offset 360 (section 7) |
| `0x40` | `F2FS_PIN_FILE` | |
| `0x80` | `F2FS_COMPRESS_RELEASED` | |

Observed: stock inodes are `0x00` (root only), `0x01` (most files/dirs), `0x0b`
(inline xattr + inline data + data exist: small files and all symlinks). Test image with
extra_attr: `0x20` (root), `0x21`, `0x2b`.

### 6.2 Special files

Device numbers (from the kernel's `__get_inode_rdev`, not in f2fs-tools; stock has no
device nodes, fifos or sockets): for chr/blk/fifo/sock, if `i_addr[base] != 0` it is
the old 16-bit encoding (`major = v >> 8 & 0xFF, minor = v & 0xFF`), else
`i_addr[base+1]` holds the new encoding (`major = (v >> 8) & 0xFFF`,
`minor = (v & 0xFF) | ((v >> 12) & 0xFFF00)`), where `base = extra_isize/4`. Report,
don't extract.

## 7. extra_attr and derived inode geometry

With `i_inline & F2FS_EXTRA_ATTR`, the first `i_extra_isize` bytes of the `i_addr`
area (starting at byte 360) are:

| offset | size | field | present when `i_extra_isize ≥` |
|---|---|---|---|
| 360 | 2 | `i_extra_isize` | 4 (always; multiple of 4, ≤ 36) |
| 362 | 2 | `i_inline_xattr_size` | 4 (used only with `flexible_inline_xattr`; unit = 4 bytes) |
| 364 | 4 | `i_projid` | 8 |
| 368 | 4 | `i_inode_checksum` | 12 |
| 372 | 8 | `i_crtime` | 24 |
| 380 | 4 | `i_crtime_nsec` | 24 |
| 384 | 8 | `i_compr_blocks` | 36 |
| 392 | 1 | `i_compress_algorithm` | 36 |
| 393 | 1 | `i_log_cluster_size` | 36 |
| 394 | 2 | `i_compress_flag` | 36 |
| 396 | | `i_extra_end` | (`F2FS_TOTAL_EXTRA_ATTR_SIZE = 36`) |

`calc_extra_isize()` (what mkfs/sload write): 4 by default and with
`flexible_inline_xattr`; 8 with `project_quota`; 12 with `inode_checksum`; 24 with
`inode_crtime`; 36 with `compression` (the largest enabled wins). Test image: 12.

Geometry (all in `le32` slots of `i_addr`, `extra = i_extra_isize/4` or 0):

```python
extra = u16(blk, 360) // 4 if blk[3] & 0x20 else 0
if sb.feature & 0x40:        inline_xattr = u16(blk, 362)             # flexible_inline_xattr
elif blk[3] & (0x01|0x04):   inline_xattr = 50
else:                        inline_xattr = 0
addrs_per_inode = 923 - extra - inline_xattr        # data pointers i_addr[extra .. extra+addrs_per_inode)
addr_base       = extra                             # first data pointer slot
inline_xattr_off = 360 + 4*(923 - inline_xattr)     # byte offset of the inline xattr area (…4052)
max_inline_data = 4*(923 - inline_xattr - extra - 1)   # MAX_INLINE_DATA
inline_data_off = 360 + 4*(extra + 1)               # i_addr[extra + DEF_INLINE_RESERVED_SIZE]
```

Worked values: no extra_attr + inline xattr: `addrs_per_inode 873`, inline xattr at
3852..4052, `max_inline_data 3488`, inline data at 364. extra_isize 12 + inline xattr:
870 / 3476 / 376. extra 36: 864 / 3452 / 400. Without inline xattr (stock root,
`i_inline = 0`): 923 data slots, `max_inline_data 3688`. The constant
`INLINE_DATA_OFFSET` in the header (= 364) is the no-extra case of `inline_data_off`.
`ADDRS_PER_BLOCK` is always 1018 (compression would round it down to the cluster size,
which we refuse).

### 7.4 Inode checksum (optional verification)

With feature `0x20`: `seed = crc(0xFFFFFFFF, sb.uuid)`; `c = crc(seed, le32 footer.ino)`;
`c = crc(c, le32 i_generation)`; `c = crc(c, inode[0:368])`; `c = crc(c, 4 zero bytes)`;
`c = crc(c, inode[372:4096])` (i.e. the whole node block with the checksum field zeroed);
compare with `i_inode_checksum` at 368.

## 8. Block index → address (direct, indirect, double indirect)

With `A = addrs_per_inode`, `D = 1018` (`ADDRS_PER_BLOCK`), `N = 1018` (`NIDS_PER_BLOCK`):

| file block index range | where |
|---|---|
| `[0, A)` | `i_addr[addr_base + i]` |
| `[A, A + D)` | direct node `i_nid[0]`, `addr[i - A]` |
| `[A + D, A + 2D)` | direct node `i_nid[1]` |
| `[A + 2D, A + 2D + N·D)` | indirect node `i_nid[2]` → direct node `nid[(i')/D]`, `addr[i' % D]` |
| next `N·D` | indirect node `i_nid[3]` |
| next `N·N·D` | double-indirect `i_nid[4]` → indirect `nid[i'/(N·D)]` → direct `nid[(i'/D) % N]` → `addr[i' % D]` |

For `A = 873`: ranges start at 0, 873, 1891, 2909, 1 039 233, 2 075 557 (end
1 057 053 389). Zero nid anywhere = hole for that whole subtree.
`get_node_path` in `fsck/node.c` is the reference. Address resolution:

```python
D = N = 1018
def data_block_addrs(inode_blk, ino, nblocks):     # yields addr for block index 0..nblocks-1
    A = addrs_per_inode
    for k in range(min(A, nblocks)):
        yield u32(inode_blk, 360 + 4*(addr_base + k))
    remaining = nblocks - A
    def node(nid, level, count):                   # level 0 = direct, 1 = indirect, 2 = double indirect
        span = D * N**level                        # blocks covered by this node
        if count <= 0: return
        if nid == 0:                               # hole for the whole subtree
            for _ in range(min(count, span)): yield 0
            return
        blk = read_node(nid, expect_ino=ino)       # footer.ino must be this inode
        if level == 0:
            for k in range(min(count, D)): yield u32(blk, 4*k)
        else:
            child_span = D * N**(level-1)
            for k in range(N):
                if count <= 0: return
                yield from node(u32(blk, 4*k), level-1, min(count, child_span))
                count -= child_span
    i_nid = struct.unpack_from("<5I", inode_blk, 4052)
    for nid, level in zip(i_nid, (0, 0, 1, 1, 2)):
        if remaining <= 0: break
        span = D * N**level
        yield from node(nid, level, min(remaining, span))
        remaining -= span
```

Stop at `ceil(i_size / 4096)` blocks; do not descend into nodes beyond that. Every
non-zero, non-`NEW_ADDR` address must satisfy `main_blkaddr <= a < block_count`;
`COMPRESS_ADDR` → error. Last block is truncated to `i_size % 4096`.

Observed in stock vendor: `i_nid[0]` used by 17 files, `i_nid[1]` by 10, `i_nid[2]`
(first indirect) by 7; stock system: 183/114/79; double indirect never (needs > 4 GiB).

## 9. Inline data and symlinks

`i_inline & INLINE_DATA`: the file content is `blk[inline_data_off : inline_data_off + i_size]`
with `i_size <= max_inline_data`. If `DATA_EXIST` is clear the content is zeros. The
inline region ends exactly where the inline xattr region starts (3852 in the common
case), so a file of 3488 bytes is inline and 3489 is not (with inline xattr, no extra).
f2fs-tools stores a symlink inline when `len + 1 <= max_inline_data`, a regular file
when `size <= max_inline_data` (kernel threshold identical for the reader's purpose:
trust the flag).

Symlink target: `i_size` bytes, either inline or in data block 0 (`i_addr[addr_base]`),
no NUL terminator on disk (`dump.f2fs` appends one in memory). All 186 stock vendor
symlinks and 264 system symlinks are inline.

## 10. Directories

### 10.1 Dentry block (data block of a directory, 4096 bytes)

| offset | size | field |
|---|---|---|
| 0 | 27 | `dentry_bitmap` (214 bits, **LSB-first** within each byte: `test_bit_le`) |
| 27 | 3 | reserved |
| 30 | 214 × 11 | `dentry[214]`: `le32 hash_code; le32 ino; le16 name_len; u8 file_type` |
| 2384 | 214 × 8 | `filename[214][8]` name slots |

A name of `name_len` bytes occupies `slots = (name_len + 7) // 8` consecutive dentries
starting at slot `i`: the name bytes are `filename[i] .. filename[i+slots-1]`
contiguous (`names_base + 8*i`, `name_len` bytes, no NUL), and **the bitmap bit is set
for every slot** the name covers (`test_and_set_bit_le(bit_pos + k)` for each slot).
Only the first slot's `dentry[i]` is meaningful. Walk:

```python
def walk_dentries(buf, bitmap_off, nr, dent_off, names_off):
    i = 0
    while i < nr:
        if not (buf[bitmap_off + (i >> 3)] >> (i & 7)) & 1:
            i += 1; continue
        h, ino, name_len, ftype = struct.unpack_from("<IIHB", buf, dent_off + 11*i)
        if name_len == 0 or name_len > 255: raise Corrupt
        name = buf[names_off + 8*i : names_off + 8*i + name_len]
        yield name, ino, ftype
        i += (name_len + 7) >> 3
# block:  walk_dentries(blk, 0, 214, 30, 2384)
```

`.` and `..` are real entries (slots 0 and 1 in the first block). Directories are hashed
into levels/buckets, so the directory's data-block map is sparse: iterate every block
index up to `ceil(i_size/4096)` (and through direct/indirect nodes exactly like a file),
skip `NULL_ADDR`, and parse each present block. Hash codes are not needed to enumerate.
Entry ordering is by slot, not by name.

`file_type` values: 0 unknown, 1 regular, 2 dir, 3 chrdev, 4 blkdev, 5 fifo, 6 sock,
7 symlink.

### 10.2 Inline dentries (`i_inline & INLINE_DENTRY`)

The inline data area (`inline_data_off`, `max_inline_data` bytes, see section 7) is laid
out like a dentry block with `NR_INLINE_DENTRY = max_inline_data*8 // 153`:

| region | offset from `inline_data_off` | size |
|---|---|---|
| bitmap | 0 | `ceil(NR/8)` |
| reserved | bitmap size | `max_inline_data - (19*NR + bitmap)` |
| dentries | bitmap + reserved | `11 * NR` |
| names | bitmap + reserved + 11·NR | `8 * NR` |

| `max_inline_data` | NR | bitmap | reserved | dentries @ | names @ |
|---|---|---|---|---|---|
| 3488 (no extra_attr) | 182 | 23 | 7 | 30 | 2032 |
| 3476 (extra_isize 12) | 181 | 23 | 14 | 37 | 2028 |
| 3452 (extra_isize 36) | 180 | 23 | 9 | 32 | 2012 |

`make_dentry_ptr(type=2)` in `fsck/dir.c` is the reference. Neither `make_f2fs`/`sload_f2fs`
nor the stock images produce inline dentries (0 found in stock; f2fs-tools only
*converts* them to blocks), so this layout is source-derived only — the kernel creates
them for new small directories on a rw mount.

## 11. Extended attributes

### 11.1 Where

`read_all_xattrs` builds one buffer = inline area (`inline_xattr_size = 4*inline_xattr`
bytes at `inline_xattr_off`, section 7) followed by the xattr node's first 4072 bytes
(`VALID_XATTR_BLOCK_SIZE = 4096 - 24`) if `i_xattr_nid != 0`. The xattr node is an
ordinary node (NAT lookup, footer `ino` = this inode, `ofs_in_node = 0x1FFFFFFF`).
There is exactly **one header at the start of the concatenated buffer** (so when the
inline area exists, the node block begins with entries, not a header; when the inline
area is absent, as for stock root inodes with `i_inline = 0`, the node block starts
with the header). An entry may straddle the inline/node boundary. The buffer length
`XATTR_SIZE = inline_xattr_size + (4072 if i_xattr_nid else 0)` bounds the walk.

### 11.2 Layout

Header `struct f2fs_xattr_header`, **24 bytes**:

| offset | size | field |
|---|---|---|
| 0 | 4 | `h_magic` = `0xF2F52011` (if different: no xattrs) |
| 4 | 4 | `h_refcount` (1) |
| 8 | 16 | `h_sloadd[4]` (zero) |

Entry `struct f2fs_xattr_entry`, 4-byte aligned:

| offset | size | field |
|---|---|---|
| 0 | 1 | `e_name_index` |
| 1 | 1 | `e_name_len` |
| 2 | 2 | `e_value_size` |
| 4 | `e_name_len` | `e_name` (no NUL) |
| 4 + name_len | `e_value_size` | value (no NUL; selinux context stored without terminator, `strlen` bytes) |

`ENTRY_SIZE = (4 + e_name_len + e_value_size + 3) & ~3`. The list ends at the first
entry whose first 4 bytes are all zero (`IS_XATTR_LAST_ENTRY`). Limits:
`MIN_OFFSET = 4068`, `MAX_VALUE_LEN = 4040`.

```python
def xattrs(inode_blk):
    buf = inode_blk[inline_xattr_off:4052] if inline_xattr else b""
    if i_xattr_nid: buf += read_node(i_xattr_nid, ino)[:4072]
    if len(buf) < 24 or u32(buf, 0) != 0xF2F52011: return []
    off, out = 24, []
    while off + 4 <= len(buf) and u32(buf, off) != 0:
        idx, nlen, vsize = struct.unpack_from("<BBH", buf, off)
        if off + 4 + nlen + vsize > len(buf): raise Corrupt("xattr entry crosses the end of xattr space")
        name = buf[off+4 : off+4+nlen]; value = buf[off+4+nlen : off+4+nlen+vsize]
        out.append((idx, name, value))
        off += (4 + nlen + vsize + 3) & ~3
    return out
```

### 11.3 Name index → prefix

| index | name | full name = prefix + `e_name` |
|---|---|---|
| 1 | `F2FS_XATTR_INDEX_USER` | `user.` |
| 2 | `F2FS_XATTR_INDEX_POSIX_ACL_ACCESS` | `system.posix_acl_access` (e_name empty; value `f2fs_acl_header` + entries) |
| 3 | `F2FS_XATTR_INDEX_POSIX_ACL_DEFAULT` | `system.posix_acl_default` |
| 4 | `F2FS_XATTR_INDEX_TRUSTED` | `trusted.` |
| 5 | `F2FS_XATTR_INDEX_LUSTRE` | `lustre.` |
| 6 | `F2FS_XATTR_INDEX_SECURITY` | `security.` (`selinux`, `capability`) |
| 9 | `F2FS_XATTR_INDEX_ENCRYPTION` | fscrypt context, e_name `"c"` → refuse file |
| 11 | `F2FS_XATTR_INDEX_VERITY` | fs-verity descriptor, e_name `"v"` |

Observed in stock: every inode has `security.selinux` (index 6, name `selinux`,
value = context string without NUL, e.g. 25 bytes `u:object_r:vendor_file:s0`);
`user.pa` on 6 vendor and 3 system files (index 1, name `pa`); `security.capability`
on 2 system files (`run-as`, `simpleperf_app_runner`).

### 11.4 `security.capability` value (`vfs_cap_data`, Linux `capability.h`)

| offset | size | field | notes |
|---|---|---|---|
| 0 | 4 | `magic_etc` | `(revision << 24) | flags`; `VFS_CAP_REVISION_MASK 0xFF000000`; `VFS_CAP_FLAGS_EFFECTIVE 0x1` |
| 4 | 4 | `data[0].permitted` | caps 0..31 |
| 8 | 4 | `data[0].inheritable` | |
| 12 | 4 | `data[1].permitted` | caps 32..63 (v2/v3 only) |
| 16 | 4 | `data[1].inheritable` | |
| 20 | 4 | `rootid` | v3 only (`vfs_ns_cap_data`) |

Sizes: v1 (`0x01000000`) 12 bytes, v2 (`0x02000000`) 20 bytes, v3 (`0x03000000`) 24 bytes.
`permitted = data[0].permitted | data[1].permitted << 32` is the 64-bit mask that the
canned fs_config `capabilities=0x...` expresses. Observed stock value (both files):
`01000002 c0000000 00000000 00000000 00000000` = v2, effective, permitted
`0xC0` (`CAP_SETGID|CAP_SETUID`), inheritable 0. AOSP's fs_config writes v2 with
`VFS_CAP_FLAGS_EFFECTIVE` set and inheritable = 0.

## 12. Compression markers (detect and refuse)

* `sb.feature & 0x2000` (`compression`) — warn at open; refuse extraction if any inode
  is compressed.
* `i_flags & 0x4` (`F2FS_COMPR_FL`) on a regular file — refuse the file (its
  `i_compr_blocks`, `i_compress_algorithm`, `i_log_cluster_size`, `i_compress_flag`
  live in the extra area; `ADDRS_PER_INODE/BLOCK` are rounded down to the cluster).
* any data address `== 0xFFFFFFFE` (`COMPRESS_ADDR`) — refuse (cluster head marker).

Stock: feature `0x4000`, all `i_flags == 0`, no `COMPRESS_ADDR` seen.

## 13. Reader walk (summary)

```python
fs = open_image(path)                         # sb (block 0, fallback block 1), features, checks
cp = valid_checkpoint(fs)                     # section 3.3; bitmaps; NAT journal (section 4.2)
root = read_node(sb.root_ino); assert S_ISDIR(root.i_mode)
seen = {}                                     # ino -> first path, for hard links (i_links > 1)
def visit(nid, path):
    blk = read_node(nid); ino = parse_inode(blk)
    if ino.i_advise & 0x04 or ino.i_flags & 0x80000004: raise Unsupported
    xattrs = xattrs(blk)                      # selinux, capability, others
    if S_ISDIR: for name, cino, ftype in dentries(blk, ino): if name not in (b".", b".."): visit(cino, path/name)
    elif S_ISREG: stream data_block_addrs(...) to disk, zeros for 0/NEW_ADDR, truncate to i_size
    elif S_ISLNK: target = inline or block 0, i_size bytes
    else: record (chr/blk/fifo/sock), rdev from i_addr[base]/[base+1]
visit(sb.root_ino, "/")
```

Node footer `ino` of every direct/indirect/xattr node must equal the visited inode.
`dump.f2fs -r` additionally skips files with `i_flags & F2FS_NODUMP_FL (0x40)` and
truncates with `le32(i_size)` (a 32-bit bug; irrelevant below 4 GiB).

## 14. Things the reader can ignore

SIT (segment validity bitmaps, 74-byte entries, two copies selected by the SIT version
bitmap with the same MSB-first rule as NAT), SSA (per-segment summaries at
`ssa_blkaddr`, absent on `ro` images), nat_bits, orphan blocks, quota inodes (`qf_ino`,
regular hidden files not linked in any directory), `lost+found`.

## 15. Empirical verification record

All decoding below was done with `work/tmp/spec-f2fs/verify.py` (stdlib Python using
the offsets in this document) and compared with `dump.f2fs -d 2 [-N -i NID] [-n a~b]`
(f2fs-tools 1.17). Outputs are kept next to the script (`*-dump.txt`, `*-root.txt`,
`*-verify.txt`, `*-dump_nat.txt`, `*-tally.txt`, `vendor-walk.txt`).

| item | stock `odm.img` | sloadtest `v.img` (`make_f2fs -O extra_attr,inode_checksum,sb_checksum`) |
|---|---|---|
| sb feature | `0x4000` ro | `0x828` |
| sb checksum_offset / crc | 0 / 0 | 3068 / verified |
| block_count, main_blkaddr | 5120, 3074 (`segment_count_ssa = 0`) | 16384, 4096 |
| cp_blkaddr, nat_blkaddr | 2, 2050 | 512, 2560 |
| cp_payload | 0 | 0 |
| cp version pack1 / pack2 → chosen | `0x4321` / `0x4321` → pack 1 | `0x24bd5239` / both → pack 1 |
| ckpt_flags | `0x81` | `0x181` |
| cp_pack_total_block_count / cp_pack_start_sum | 8 / 1 | 8 / 1 |
| sit / nat bitmap bytesize, location | 64 / 64, inline (SIT @192, NAT @256) | same |
| cp checksum_offset / crc | 4092 / `0xe9b8f5f0` (recomputed OK) | 4092 / `0x8b22d67e` (OK) |
| hot-data summary footer type / n_nats | 0 / **0** (dump.f2fs does not print n_nats) | 0 / 0 |
| NAT nid 3 | ver 0, ino 3, blkaddr 3074, pack 1 (matches `dump_nat`) | ver 0, ino 3, blkaddr 4096, pack 1 |
| root inode | mode `0x41ed`, uid 0, gid 0, links 3, size 4096, blocks 3, mtime 1770282379, `i_inline 0x00`, `i_xattr_nid 46`, `i_addr[0] = 0xe02` | mode `0x41ed`, uid 0, gid 2000, links 4, `i_inline 0x20`, `i_extra_isize 12`, `i_inode_checksum 0x8538bc92`, `i_xattr_nid 8`, `i_addr[3] = 0x1600` |
| root xattr | `security.selinux` = `u:object_r:vendor_file:s0` (25 B) in the xattr node (header at node offset 0) | same, xattr node nid 8 (`ofs_in_node 0x1FFFFFFF`) |
| root dentries | `.`, `..`, `etc` (slots 0,1,2) | `.`, `..`, `bin`, `etc` |

Further checks: `v.img` nid 6 (`hello`, `i_inline 0x2b`, extra 12) has inline data at
byte 376 (`#!/bin/sh\n`, `i_size 10`) and inline xattrs at 3852, as predicted. A copy of
`v.img` extended with `sload_f2fs` (`nat.img`): 9-char name `small.txt` occupies 2
slots with both bitmap bits set; 19-byte symlink inline; a 5 000 000-byte file uses 870
inode slots + direct node `i_nid[0]` (nid 16, footer ino 13, `ofs_in_node 1`, 351
addresses), `i_blocks 1223`. Whole-tree walk of stock `vendor.img` with the dentry
algorithm above yields exactly the 1988 paths (68 dirs, 1735 files, 186 symlinks,
longest name 68 bytes = 9 slots) of `work/stockdump/vendor` with identical types.
Tallies over every inode of all five stock partitions: `extra_isize 0` everywhere, no
inline dentries, no hard links, no special files, no symlink in a data block, xattr
nodes only on roots (7 in vendor incl. 6 `user.pa` carriers), caps only on 2 system
files.

## 16. Open questions

1. **`sload_f2fs` (AOSP 1.16) does not write `security.capability`.** With
   `capabilities=0x1000000` in the canned fs_config it logs
   `capabilities = 0x1000000` (`-d 2`) but the resulting inode carries only
   `security.selinux` (checked on both `sloadtest/v.img` and `nat.img`). Repacking stock
   `system` would silently drop the caps of `run-as` and `simpleperf_app_runner`
   (vendor/product/system_ext/odm have none). DESIGN §3 claims caps are applied —
   needs re-testing by the build.py owner, or a post-sload patch step (the reader side
   is fine).
2. NAT version bitmap bit order (MSB-first) and nonzero `n_nats` do not occur on any
   available image (all-zero bitmap, `n_nats = 0`: `sload_f2fs` rewrites NAT blocks in
   place and flushes the journal). Both are now exercised synthetically in
   `tests/test_f2fs.py` (`test_nat_version_bitmap_selects_pack2`,
   `test_nat_journal_overrides_nat_area`): a node block is relocated, the NAT copy 2 /
   the journal is patched by hand, and `dump.f2fs -n` (the oracle, see below) reports
   `pack:2` resp. the journal address — the reader agrees. Setting bit `7 - (block_off & 7)`
   of byte `block_off >> 3` is what makes `dump.f2fs` pick pack 2, confirming MSB-first.
   Note for using the oracle: `dump.f2fs -n A~B` is **end-exclusive** (`nid < B`) and
   writes its lines to a file named `dump_nat` in the current directory, not to stdout.
3. Inline dentry layout (section 10.2) is source-derived only; no tool here creates it.
4. Device-number encoding for special files (section 6.2) comes from the kernel, not
   from f2fs-tools, and is untested (stock has no special files).
5. `dump.f2fs -r` reference tree `work/stockdump/vendor` contains a nested
   `lost_found/` duplicate of the whole tree (3977 entries vs 1988 real); the
   byte-equality test in DESIGN §7.2 excludes it (`tests/test_f2fs.py`,
   `StockVendorTest`; our extraction equals the remaining 1988 entries byte for byte).
6. Both checkpoint packs of an `sload_f2fs`-built or stock image are valid and carry the
   **same** version (`validate_checkpoint` then picks pack 1); the "newer pack wins" rule
   only matters for kernel-written images and is covered by
   `test_newer_checkpoint_pack_wins` with a hand-built pack 2.
7. The inode checksum (section 7.4) was confirmed against `fsck.f2fs`: a corrupted
   `i_inode_checksum` makes fsck print the same "calculated" value that the reader
   computes (`test_inode_checksum`).
