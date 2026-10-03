# On-disk formats: LP metadata, lpmake, AVB, Odin packaging (SM-A137F stock A137FXXSCEZB1)

Implementation notes for `superkit/lp.py`, `superkit/avb.py`, `superkit/odin.py`.
Everything below was measured on 2026-10-02 against `stock/AP/super.raw`, `stock/super/*.img`,
`stock/BL/vbmeta.img`, `stock/AP/*.lz4` with the toolchain in DESIGN.md §3
(android-tools 37.0.0 lpdump/lpmake/img2simg, avbtool 1.4.0 source, lz4 1.10.0).
The throwaway oracle parser used for §1 is `work/tmp/spec-lp/lpparse.py`; its full output for the
stock image is `work/tmp/spec-lp/stock-parse.txt`. All integers are little-endian unless stated.

---

## 1. LP (dynamic partition) metadata in a super image

Authoritative header: `system/core/fs_mgr/liblp/include/liblp/metadata_format.h` (fetched from
AOSP main, 2026-10-02). All structs are `__attribute__((packed))`.

### 1.1 Layout of the start of the super partition

```
offset        size                    content
0             4096                    LP_PARTITION_RESERVED_BYTES. liblp never reads or writes it.
                                      (Samsung puts an Odin signature block here – see §1.8.)
4096          4096                    primary geometry block (LpMetadataGeometry, 52 B, rest zero)
8192          4096                    backup geometry block (byte-identical copy)
12288         slot_count * max_size   primary metadata slots: slot i at 12288 + i*max_size
12288 + N*M   slot_count * max_size   backup metadata slots:  slot i at 12288 + N*M + i*max_size
                                      (N = metadata_slot_count, M = metadata_max_size)
first_logical_sector*512              first usable byte for logical partitions
```

Stock values: N=2, M=65536 → slots at 12288, 77824 (primary 0,1) and 143360, 208896 (backup 0,1);
metadata region ends at 274432 (= sector 536); `first_logical_sector` is 2048 (1 MiB) because
liblp rounds the first usable sector up to the block-device `alignment`.

The only reader-side rule needed: parse geometry at 4096 (fall back to 8192 if the checksum fails),
then for slot `s` try primary, then backup. Samsung's stock image has **all four slots
byte-identical**, including the zero padding up to 65536 (verified with `lpparse.py`).

**`super_empty` layout**: `lpmake` without `--image`/`-F` writes a minimal file: geometry at
offset 0 (one copy, 4096 B) followed by a single metadata copy at 4096. `lpdump` accepts it.
Detect it by the geometry magic at offset 0. `superkit` should accept it in `inventory` but
never produce it (we always pass images or `-F`).

### 1.2 LpMetadataGeometry (52 bytes, at 4096 and 8192)

| off | size | field | stock |
|---|---|---|---|
| 0 | u32 | magic = `0x616c4467` ("gDla" in bytes `67 44 6c 61`) | ok |
| 4 | u32 | struct_size = 52 | 52 |
| 8 | 32 B | checksum: SHA-256 of bytes [0,struct_size) with this field zeroed | verifies |
| 40 | u32 | metadata_max_size (multiple of 512; lpmake rounds 1000 → 1024) | 65536 |
| 44 | u32 | metadata_slot_count | 2 |
| 48 | u32 | logical_block_size (= lpmake `--block-size`) | 4096 |

Bytes 52..4095 of each geometry block are zero.

### 1.3 LpMetadataHeader (at the start of each slot)

| off | size | field | notes / stock |
|---|---|---|---|
| 0 | u32 | magic = `0x414c5030` ("0PLA" bytes `30 50 4c 41`) | |
| 4 | u16 | major_version = 10 | 10 |
| 6 | u16 | minor_version 0..2 | **0** (lpmake also emits 0 unless `--virtual-ab`, which gives 10.2) |
| 8 | u32 | header_size | **128** for minor 0/1, 256 for minor 2 |
| 12 | 32 B | header_checksum: SHA-256 of bytes [0,header_size) with this field zeroed | verifies |
| 44 | u32 | tables_size: total bytes of the four tables that follow the header | 540 |
| 48 | 32 B | tables_checksum: SHA-256 of the `tables_size` bytes starting at `header_size` | verifies |
| 80 | 12 B | partitions descriptor {u32 offset, u32 num_entries, u32 entry_size} | {0, 5, 52} |
| 92 | 12 B | extents descriptor | {260, 5, 24} |
| 104 | 12 B | groups descriptor | {380, 2, 48} |
| 116 | 12 B | block_devices descriptor | {476, 1, 64} |
| 128 | u32 | flags (**only if header_size >= 132**, i.e. minor >= 2): 0x1 VIRTUAL_AB_DEVICE, 0x2 OVERLAYS_ACTIVE | absent in stock |
| 132 | 124 B | reserved (zero), pads v1.2 header to 256 | absent in stock |

Descriptor `offset` is relative to `header_start + header_size`. Tables are laid out back to back
in descriptor order: partitions, extents, groups, block_devices. `lpdump`'s "Metadata size"
= header_size + tables_size (stock 128 + 540 = 668). Everything after that up to
`metadata_max_size` is zero.

Writer rules (for building our own slot image or for verifying lpmake output): compute
tables_checksum first, then header_checksum over the finished header; write the identical blob
to every primary and backup slot.

### 1.4 LpMetadataPartition (52 bytes)

| off | size | field |
|---|---|---|
| 0 | char[36] | name, NUL-padded ASCII `[A-Za-z0-9_]` (max 36 incl. NUL in practice) |
| 36 | u32 | attributes: 0x1 READONLY, 0x2 SLOT_SUFFIXED, 0x4 UPDATED (v1.1+), 0x8 DISABLED (v1.1+) |
| 40 | u32 | first_extent_index (into extents table) |
| 44 | u32 | num_extents (contiguous run) |
| 48 | u32 | group_index (into groups table) |

Stock: 5 partitions in order system, odm, product, system_ext, vendor; attributes = 1
(readonly) on all; group_index = 1 (main); extents 0..4 one each. `lpmake` attribute keyword
`none` → 0, `readonly` → 1 (no CLI way to set other bits; not needed).

### 1.5 LpMetadataExtent (24 bytes)

| off | size | field |
|---|---|---|
| 0 | u64 | num_sectors (512-byte sectors) |
| 8 | u32 | target_type: 0 LINEAR, 1 ZERO |
| 12 | u64 | target_data: for LINEAR the start sector on the block device; 0 for ZERO |
| 20 | u32 | target_source: index into block_devices (LINEAR only) |

Stock extents (all LINEAR, source 0):

| partition | start sector | start byte | num_sectors | bytes | end sector |
|---|---|---|---|---|---|
| system | 2048 | 1048576 | 7520304 | 3850395648 | 7522352 |
| odm | 7524352 | 3852468224 | 41776 | 21389312 | 7566128 |
| product | 7567360 | 3874488320 | 2780160 | 1423441920 | 10347520 |
| system_ext | 10348544 | 5298454528 | 520384 | 266436608 | 10868928 |
| vendor | 10870784 | 5565841408 | 853312 | 436895744 | 11724096 |

Every start is 1 MiB-aligned (the gap after each partition is the round-up to the next 1 MiB
boundary); every size is a multiple of 4096 but not of 1 MiB. Partition image sizes in
`stock/super/*.img` equal the extent byte sizes exactly (they include the AVB hashtree/FEC/
vbmeta/footer padding, §3).

### 1.6 LpMetadataPartitionGroup (48 bytes)

| off | size | field |
|---|---|---|
| 0 | char[36] | name |
| 36 | u32 | flags: 0x1 SLOT_SUFFIXED |
| 40 | u64 | maximum_size (0 = unlimited) |

Stock: index 0 `default` (flags 0, max 0) – always present, always index 0, created implicitly by
liblp; index 1 `main` (flags 0, max 6413090816 = 6116 MiB). Sum of stock partitions
5998559232 → 414531584 B (≈395 MiB) headroom inside `main` before dropping hashtrees.

### 1.7 LpMetadataBlockDevice (64 bytes)

| off | size | field | stock |
|---|---|---|---|
| 0 | u64 | first_logical_sector | 2048 |
| 8 | u32 | alignment (bytes) | 1048576 |
| 12 | u32 | alignment_offset (bytes) | 0 |
| 16 | u64 | size (bytes) | 6417285120 |
| 24 | char[36] | partition_name (GPT name of the super partition) | `super` |
| 60 | u32 | flags: 0x1 SLOT_SUFFIXED | 0 |

`alignment_offset` is stored but current liblp (android-tools 37) does **not** use it when
placing extents (tested: `--device super:16777216:1048576:4096` still places partitions at
sectors 2048 and 4096). Stock has 0 anyway, so pass 0.

### 1.8 Stock-specific facts (measured)

* Geometry: max_size 65536, slot_count 2, logical_block_size 4096; both geometry copies
  byte-identical, checksums verify.
* Header 10.0, header_size 128 (no flags field), tables_size 540; header and tables checksums
  verify with SHA-256 as described; all 4 slots byte-identical; slot padding zero.
* `lpdump --json` is supported (android-tools 37): it reports per-partition `size` in bytes,
  `is_dynamic`, group `maximum_size`, block device `block_size`/`alignment` and
  `super_device.used_size`/`total_size`; it does **not** show first_logical_sector,
  alignment_offset, extents, attributes or header version – use the text output (`-a` dumps all
  slots, `-s N` one slot, `-d` prints the metadata reserved size = metadata_max_size) for those.
* **Reserved block 0..4095 is not zero in stock.** It holds Samsung's Odin signature record:
  `0x000..0x0FF` 256-byte RSA signature, `0x100..0x2FF` zero, `0x300` `"SignerVer02"`,
  `0x310` `"106288421R"`, `0x320` build `"A137FXXSCEZB1"`, `0x340` timestamp
  `"20260205213726"`, `0x350` `"SM-A137F_MEA_MEA_MKEY0"`, `0x370`/`0x380` `"SRPVD04A012"`,
  `0x390` `"usr\0frp\0mrk\0super.img"`, `0x3AC` `"106288457R"`, `0x3BC` `"106279844R"`,
  `0x400` u32 `11724096` (= end sector of the last partition, i.e. the signed extent),
  rest zero. The same 512-byte record (strings at +0x000, signature at +0x100) is *appended*
  to `vbmeta.img` (8384 = 7872 + 512) and `vbmeta_system.img` (3648 = 3136 + 512); it is not
  present in `boot.img`. liblp/lpmake ignore the block; `lpmake` writes it as zeros (a FILL-0
  sparse chunk). We cannot re-sign, so a rebuilt super has a zero reserved block.
  The sparse `stock/AP/super.img` ships the block as a 1-block RAW chunk followed by a
  66-block RAW chunk (geometry + slots), then DONT_CARE up to 1 MiB.

### 1.9 Minimal parser (what `lp.py` must do)

```python
g = Geometry.unpack(buf[4096:4096+52])          # verify sha256; else try 8192
for s in range(g.slot_count):
    for base in (12288 + s*g.max_size, 12288 + (g.slot_count + s)*g.max_size):
        hdr = Header.unpack(buf[base:base+128]); if hdr.header_size > 128: read flags at base+128
        tables = buf[base+hdr.header_size : base+hdr.header_size+hdr.tables_size]
        # verify both checksums; parse 4 tables by descriptor (entry_size may be larger than ours: step by entry_size)
```
Always step by the descriptor's `entry_size`, never by `sizeof(struct)`, and read only the
leading known bytes of each entry.

---

## 2. lpmake: reproducing the stock geometry

Help text of android-tools 37 lpmake is reproduced in `lpmake --help`. Flags that matter:

| flag | meaning | stock value |
|---|---|---|
| `-m, --metadata-size=N` | geometry.metadata_max_size (rounded up to 512) | `65536` |
| `-s, --metadata-slots=N` | geometry.metadata_slot_count | `2` |
| `-n, --super-name=NAME` | name of the block device entry; **must equal** the name in `--device` ("Invalid metadata parameters" otherwise); default `super` | `super` |
| `-b, --block-size=N` | geometry.logical_block_size; also the unit partition sizes are rounded up to | `4096` |
| `-D, --device=NAME:SIZE[:ALIGN:OFFSET]` | block device table entry; with `-D`, `-d/-a/-O` must not be given (`-a` is even ambiguous on this build). ALIGN defaults to 1048576, OFFSET to 0 | `super:6417285120:1048576:0` |
| `-d, --device-size=SIZE\|auto` | alternative to `-D` (single device named by `--super-name`); `auto` = sum + metadata | not used |
| `-g, --group=NAME:MAX` | partition group with maximum_size MAX (0 = unlimited) | `main:6413090816` |
| `-p, --partition=NAME:ATTRS:SIZE[:GROUP]` | ATTRS is `none` or `readonly`; SIZE in bytes, rounded **up** to `--block-size` (1000→4096 at bs 4096, 1000→1024 at bs 512; 4097→8192); GROUP defaults to `default` | `system:readonly:3850395648:main` … |
| `-i, --image=NAME=FILE` | content for partition NAME (raw or sparse; raw prints the harmless "Invalid sparse file format at header magic"); FILE larger than SIZE → error `Image for partition … is greater than its size`; smaller → zero-padded, partition keeps SIZE | one per partition |
| `-S, --sparse` | write an Android sparse image (header: magic 0xed26ff3a, v1.0, 28/12, blk 4096) instead of raw | for Odin |
| `-F, --force-full-image` | write a full-size raw/sparse image even with no `--image` | |
| `-o, --output=FILE` | output | |
| `-x, --auto-slot-suffixing`, `--virtual-ab` | A/B only; `--virtual-ab` bumps the header to 10.2 (header_size 256, flags=1). **Never** for this device | |

Behaviour verified with a synthetic super (`work/tmp/spec-lp/synth.img`, device 16 MiB,
`alpha:readonly:1048576:main`, `beta:none:1052672:main`, images attached):

* Group `default` (index 0, max 0) is always emitted even if no partition uses it; named
  groups follow in command-line order; partitions are assigned by index. A partition with no
  `:group` lands in `default`.
* Extents are placed in `--partition` order, each start rounded up to `alignment`; the first
  starts at `first_logical_sector` = metadata end rounded up to alignment (2048 with stock
  numbers). Partition size is rounded up to `--block-size` and that rounded size is the extent
  length (sectors = size/512). So the stock layout is reproduced exactly by listing the
  partitions in stock order with their exact byte sizes.
* Group overflow fails hard: `Not enough space on device for partition …`.
* Output header is 10.0 / header_size 128 (same as stock) unless `--virtual-ab`.
* Our parser (`lpparse.py`) on the lpmake output shows identical geometry/header/table
  encodings to stock (same checksum algorithm, same `default` group, same block device entry).

Exact stock reproduction command (sizes from super.json; attrs `none` for rw partitions):

```
lpmake --metadata-size 65536 --metadata-slots 2 --super-name super --block-size 4096 \
  --device super:6417285120:1048576:0 --group main:6413090816 \
  --partition system:readonly:3850395648:main     --image system=system.img \
  --partition odm:readonly:21389312:main          --image odm=odm.img \
  --partition product:readonly:1423441920:main    --image product=product.img \
  --partition system_ext:readonly:266436608:main  --image system_ext=system_ext.img \
  --partition vendor:readonly:436895744:main      --image vendor=vendor.img \
  [--sparse] --output super.img
```

Sparse output of lpmake vs stock: lpmake `--sparse` emits the reserved block as FILL(0),
geometry+slots as RAW, gaps as DONT_CARE, and any 4 KiB run that repeats one 4-byte pattern
(zeros or otherwise) inside partition images as FILL; the stock
sparse image uses only RAW (max 64 MiB per chunk) and DONT_CARE (36 of 157 chunks). Both are
valid for Odin/`simg2img`. If we build raw and convert with `img2simg` (default block 4096,
RAW chunks also capped at 64 MiB): plain `img2simg` turns every all-zero 4 KiB run into FILL(0),
`img2simg -s` turns file *holes* into DONT_CARE. FILL(0) actually writes zeros to flash while
DONT_CARE leaves old data – harmless for us because every logical partition is fully rewritten
and the gaps are never read.

---

## 3. AVB structures (avbtool 1.4.0 source, `/usr/bin/avbtool`)

All AVB structs are **big-endian** (`struct` format `!`).

### 3.1 AvbFooter (64 bytes, in the last 64 bytes of the image)

`FORMAT_STRING = '!4s2LQQQ' + 28x`

| off | size | field | odm.img | vendor.img |
|---|---|---|---|---|
| 0 | 4s | magic `AVBf` | ok | ok |
| 4 | u32 | version_major = 1 | 1 | 1 |
| 8 | u32 | version_minor = 0 | 0 | 0 |
| 12 | u64 | original_image_size (= f2fs size) | 20971520 | 429916160 |
| 20 | u64 | vbmeta_offset | 21311488 | 436740096 |
| 28 | u64 | vbmeta_size | 2112 | 2176 |
| 36 | 28 B | reserved, zero | zero | zero |

Image layout (odm, partition size 21389312 = LP extent size):
`[0, 20971520)` filesystem · `[20971520, 21139456)` hashtree (167936) · `[21139456, 21311488)`
FEC (172032) · `[21311488, 21313600)` vbmeta blob (AVB0 header + auth + aux) · zero padding ·
`[21385216, 21389312)` last 4096-byte block: 4032 zero bytes then the 64-byte footer.
Detection: read the last 64 bytes, check `AVBf`. Strip = truncate to `original_image_size`
(for Odin we then re-pad to the LP partition size inside super anyway). `avbtool info_image`
agrees on every number above (and on boot.img, which has the footer at 33554432-64).

### 3.2 AvbVBMetaImageHeader (256 bytes, at `vbmeta_offset` in a footered image, or at 0 in `vbmeta*.img`)

`FORMAT_STRING = '!4s2L2QL2Q2Q2Q2Q2QQLL47sx80x'` (calcsize 256, asserted by avbtool).

| off | size | field | BL/AP vbmeta.img | odm vbmeta |
|---|---|---|---|---|
| 0 | 4s | magic `AVB0` | | |
| 4 | u32 | required_libavb_version_major | 1 | 1 |
| 8 | u32 | required_libavb_version_minor | 0 | 0 |
| 12 | u64 | authentication_data_block_size | 576 | 576 |
| 20 | u64 | auxiliary_data_block_size | 7040 | 1280 |
| 28 | u32 | algorithm_type (0 NONE, 1 SHA256_RSA2048, 2 SHA256_RSA4096, 3 SHA256_RSA8192, 4–6 SHA512_*) | 2 | 2 |
| 32 | u64 | hash_offset (into auth block) | 0 | 0 |
| 40 | u64 | hash_size | 32 | 32 |
| 48 | u64 | signature_offset | 32 | 32 |
| 56 | u64 | signature_size | 512 | 512 |
| 64 | u64 | public_key_offset (into aux block) | 5968 | 248 |
| 72 | u64 | public_key_size | 1032 | 1032 |
| 80 | u64 | public_key_metadata_offset | 7000 | 1280 |
| 88 | u64 | public_key_metadata_size | 0 | 0 |
| 96 | u64 | descriptors_offset | 0 | 0 |
| 104 | u64 | descriptors_size | 5968 | 248 |
| **112** | u64 | rollback_index | 0 | 0 |
| **120** | u32 | flags: 1 = HASHTREE_DISABLED, 2 = VERIFICATION_DISABLED | 0 | 0 |
| 124 | u32 | rollback_index_location | 0 | 0 |
| 128 | 47s+1 | release_string, NUL-terminated | `avbtool 1.2.0` | same |
| 176 | 80 B | reserved | zero | zero |

Blob layout: header (256) → authentication block (starts at 256, `auth_size` bytes: hash then
signature) → auxiliary block (starts at 256+auth_size: descriptors, public key, key metadata).
The signature covers header + auxiliary block, so patching `flags` at offset 120 invalidates
it; that is intended – libavb with VERIFICATION_DISABLED skips signature checks (bootloader
must be OEM-unlocked). Verified: writing `!I` 2 at offset 120 of a copy of `stock/BL/vbmeta.img`
makes `avbtool info_image` print `Flags: 2` and `avbtool verify_image` fail the signature
check, as expected. `stock/BL/vbmeta.img` and `stock/AP/vbmeta.img` are byte-identical.

Alternative accepted by many Samsung devices: `avbtool make_vbmeta_image --flags 2
--padding_size 4096 --output vbmeta_disabled.img` (4096 B, algorithm NONE, no descriptors).
The patched stock copy keeps the chain/hash descriptors and the Samsung 512-byte
"SignerVer02" trailer at 7872..8383 (§1.8); patching in place is the lower-risk default, with
the empty image as a config option.

---

## 4. Odin packaging

### 4.1 lz4 frame parameters (stock `*.img.lz4`)

Decoded from the frame headers (`work/tmp/spec-lp` python decode; `lz4 --list` agrees):

| file | FLG | BD | block | content size | content checksum | block checksum | dict |
|---|---|---|---|---|---|---|---|
| AP/super.img.lz4 | 0x6c | 0x60 | B6 = 1 MiB, independent | yes, 5941163896 | yes | no | no |
| AP/boot.img.lz4 | 0x6c | 0x60 | B6 1 MiB indep | yes, 33554432 | yes | no | no |
| AP/vbmeta.img.lz4, BL/vbmeta.img.lz4 | 0x6c | 0x40 | B4 (64 KiB) | yes, 8384 | yes | no | no |
| BL/lk-verified, preloader, up_param | | | B6 | yes | yes | no | no |
| BL/param.bin.lz4 / efuse.img.lz4 | | | B5 / B4 | yes | yes | no | no |

Frame header is 15 bytes (magic 4 + FLG 1 + BD 1 + content size 8 + HC 1); the first block
of boot.img.lz4 is stored uncompressed (`0x80100000` = 1 MiB, high bit set), i.e. the
encoder is plain lz4 level 1 with 1 MiB independent blocks and the content size recorded; the
smaller B4/B5 ids are lz4frame's automatic choice when the content is smaller than the block.
**Reproduction**: `lz4 -B6 --content-size <in> <out>` (lz4 1.10.0; `-BI` is the default,
level 1 default) produced **byte-identical** output to stock `boot.img.lz4` and
`vbmeta.img.lz4`. For `superkit.odin` use exactly:
`lz4 -f -B6 --content-size super.img super.img.lz4` (stock super.img.lz4 is 3755283913 B for a
5941163896 B sparse input; single frame; 4-byte content checksum at the end).
The lz4 CLI copies the input mtime to the output (stock lz4s carry 2026-02-05 10:06/13:37 timestamps).

### 4.2 Android sparse image (`super.img` inside the lz4)

Header (28 B, LE): magic 0xed26ff3a, major 1, minor 0, file_hdr_sz 28, chunk_hdr_sz 12,
blk_sz 4096, total_blks 1566720 (= 6417285120/4096), total_chunks 157, image_checksum 0.
Chunk header (12 B): u16 type (0xCAC1 RAW, 0xCAC2 FILL, 0xCAC3 DONT_CARE, 0xCAC4 CRC32),
u16 reserved, u32 chunk_sz (blocks), u32 total_sz (bytes incl. header). Stock: 121 RAW
(max 64 MiB each) + 36 DONT_CARE, no FILL, no CRC chunk. `img2simg super.raw super.img`
(block 4096) yields RAW/FILL(0) chunks capped at 64 MiB; lpmake `--sparse` yields RAW/FILL/
DONT_CARE. Both round-trip through `simg2img`. `superkit inventory` must detect the sparse
magic and either `simg2img` to a temp file or read chunk-wise.

### 4.3 AP tar layout — **PENDING: zip not present yet**

`~/Downloads/firmware/` currently holds only `super.img.lz4` (identical to
`stock/AP/super.img.lz4`); `SM-A137F_3_20260207175611_l3zl6dvpxu_fac.zip` has not landed and
no samloader process is running. Fill this section with:

```
unzip -l ~/Downloads/firmware/SM-A137F_3_20260207175611_l3zl6dvpxu_fac.zip
unzip -p ~/Downloads/firmware/SM-A137F_*_fac.zip 'AP_*' | tar tv | head -30
unzip -p ~/Downloads/firmware/SM-A137F_*_fac.zip 'AP_*' | head -c 512 | xxd | sed -n '16,18p'   # bytes 257..264: "ustar\0""00" (POSIX) vs "ustar  \0" (GNU)
unzip -p ~/Downloads/firmware/SM-A137F_*_fac.zip 'AP_*' | tail -c 64 | xxd                   # .tar.md5 trailer: "<md5>  <name>\n"
```

What is already known from the extracted `stock/AP` tree (member mtimes preserved by tar):
members `boot.img.lz4` (2026-02-05 10:06:44), `super.img.lz4` (13:37:31), `vbmeta.img.lz4`
(13:37:34), `vbmeta_system.img.lz4` (13:37:36) and the directory `meta-data/` with
`fota.zip` (13:38:04, 1069560797 B); no `recovery`/`userdata`/`dtbo` members were extracted,
so whether the stock AP tar contains more members must be read from the zip. Working
assumptions for `pack-odin` until confirmed: POSIX ustar format (what Samsung's tools and most
Odin guides use; GNU tar 1.35 default is `gnu`, Python `tarfile` default is PAX – pass
`format=tarfile.USTAR_FORMAT` explicitly), uid/gid 0, mode 0644, member order as above with
`meta-data/fota.zip` last, file name `AP_<build>_..._fac.tar.md5` = tar bytes + the text line
`md5sum` of the tar (`<32 hex>  <tarname>\n`) appended. `meta-data/fota.zip` is optional for
flashing (it is only used by Samsung's FOTA update checker); a minimal AP tar with
`super.img.lz4` + `vbmeta.img.lz4` + `boot.img.lz4` flashes.

---

## 5. Summary of stock constants for `superkit`

```
LP:   reserved 4096 | geometry @4096 & @8192 (52 B, sha256 zero-field) | slots @12288: 2 primary + 2 backup x 65536
      header 10.0 size 128 (no flags) | tables 540 B | logical_block_size 4096 | first_logical_sector 2048
      block device super: size 6417285120, alignment 1048576, alignment_offset 0, flags 0
      groups: default(0,max 0), main(0,max 6413090816) | 5 partitions readonly, 1 linear extent each, 1 MiB-aligned
AVB:  footer: last 64 B, '!4s2LQQQ28x', AVBf v1.0 | vbmeta header 256 B '!4s2L2QL2Q2Q2Q2Q2QQLL47sx80x'
      rollback_index @112 (u64 BE), flags @120 (u32 BE): 1 hashtree-disabled, 2 verification-disabled
      stock vbmeta.img 8384 B = 7872 B AVB blob + 512 B Samsung SignerVer02 trailer
Odin: lz4 -B6 --content-size (frame FLG 0x6c BD 0x60, byte-identical to stock) | sparse blk 4096, RAW<=64 MiB
```

## 6. Open questions

1. AP tar member list, order, tar format (ustar vs gnu), owner/mode fields and the exact
   `.tar.md5` trailer – blocked on the firmware zip (§4.3).
2. Samsung "SignerVer02" block in super's reserved first 4096 bytes and appended to
   vbmeta*.img: unsigned/zero reserved block and a flag-patched (signature-invalid) vbmeta
   are only accepted on an OEM-unlocked bootloader. Should `pack-odin` copy the stock reserved
   block verbatim (keeps the strings, signature stays wrong anyway) or write zeros (lpmake
   default)? Default proposal: zeros.
3. Whether Odin (or the a13ve LK) requires the sparse super to use DONT_CARE instead of FILL
   for gaps (stock has no FILL chunks). `img2simg -s` on a raw image written with real holes
   gives DONT_CARE for holes; lpmake `--sparse` mixes FILL and DONT_CARE. Needs a flash test.
4. vbmeta_disabled: patched stock copy (keeps chain descriptors + Samsung trailer) vs
   `avbtool make_vbmeta_image --flags 2` empty image – both documented; pick in config.
