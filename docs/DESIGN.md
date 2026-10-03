# superkit — manual, root-free super.img kitchen for SM-A137F (a13ve)

Owner: der-meddler. Device: Samsung Galaxy A13 4G SM-A137F, codename a13ve, MediaTek MT6768
(Helio G80), Samsung 4.14 kernel, boot header v2, non-A/B, dynamic partitions ("super").
Stock firmware used for development: A137FXXSCEZB1 (Android 14 / One UI 6), extracted
under `stock/` (gitignored). Host: CachyOS, Python 3.14, NO sudo available to the tool.

## 1. Goals

1. Unpack `super.img` fully in userland (no loop mounts, no root): LP metadata + every
   partition's file tree, ownership, modes, SELinux contexts, file capabilities, symlinks,
   mtimes — everything needed to rebuild a bootable image byte-for-byte equivalent in the
   ways Android cares about.
2. Apply declarative modifications: remove AVB and dm-verity flags from fstabs, remove
   userdata encryption flags, edit/add/remove build properties, add/remove files.
3. Repack every partition as f2fs WITHOUT the f2fs `ro` feature (so it can be mounted rw),
   drop the AVB hashtree/FEC/footer, drop the LP `readonly` attribute, rebuild the LP
   metadata with the exact stock geometry, and package for Odin (sparse + lz4 + tar) plus a
   verification-disabled vbmeta.
4. Verify: re-extract the rebuilt image with the same reader and diff manifests against the
   unpacked tree, so the only differences are the intended modifications.

Non-goals (for now): ext4/erofs partitions (this firmware has none), A/B, virtual A/B,
f2fs compression (stock has none; detect and refuse rather than silently corrupt),
Odin flashing itself (user flashes with odin4/heimdall).

## 2. Facts about the stock image (measured 2026-10-02)

```
super.raw: 6,417,285,120 bytes (sparse super.img.lz4 in AP tar, lz4 -> simg2img)
LP metadata: version 10.0, max size 65536, slot count 2, header flags none,
  block device "super" first sector 2048, groups: default (0), main (6,413,090,816)
Partitions (all group main, all attribute readonly, one linear extent each):
  system      7520304 sectors @2048      fs 3789553664 B  volume name "/"
  odm           41776 sectors @7524352   fs   20971520 B  volume name "odm"
  product     2780160 sectors @7567360   fs 1400897536 B  volume name "product"
  system_ext   520384 sectors @10348544  fs  262144000 B  volume name "system_ext"
  vendor       853312 sectors @10870784  fs  429916160 B  volume name "vendor"
Every partition: f2fs, superblock feature bits = 0x4000 (only `ro`): no extra_attr,
  no inode/sb checksums, no compression, no casefold, no quota. Checkpoint state 0x81
  (nat_bits, unmount). An AVB footer (v1.0) with hashtree + FEC is appended after
  "Original image size" (= fs size). Per-partition rollback index 0, flags 0.
Stock vendor root inode: mode 0755, uid 0, gid 0, selinux u:object_r:vendor_file:s0.
Stock vendor tree via dump.f2fs -r: 1735 files, 68 dirs, 186 symlinks (reference copy in
  work/stockdump/vendor, log in work/stockdump/vendor-dump.log).
vbmeta (BL and AP identical): SHA256_RSA4096, rollback index 0, flags 0, chains
  recovery/prism/optics, hash descriptor for boot, chained vbmeta_system covers
  system/system_ext/vendor/product/odm hashtrees. Flags field is at byte offset 120.
boot.img ramdisk (gzip cpio) holds first-stage init and fstab.mt6768/fstab.mt6769t.
Second-stage fstab: /vendor/etc/fstab.mt6768 (+ .mt6769t) — same content.
Relevant fstab lines (both copies):
  system  /system f2fs ro wait,,avb=vbmeta_system,logical,first_stage_mount,avb_keys=...
  vendor  /vendor f2fs ro wait,,avb,logical,first_stage_mount   (same for product, odm)
  userdata /data f2fs ...,inlinecrypt  wait,check,,quota,latemount,,reservedsize=128M,
     checkpoint=fs,fileencryption=aes-256-xts:aes-256-cts:v2,
     keydirectory=/metadata/vold/metadata_encryption,fscompress
Props: system/system/build.prop; vendor/build.prop, vendor/ro.prop, vendor/rw.prop;
  product/etc/build.prop; system_ext/etc/build.prop; odm/etc/build.prop.
Free space in super: 6,417,285,120 - 1 MiB header - sum(partitions) ≈ 418 MiB, plus
  ≈ 95 MiB reclaimed by dropping the AVB hashtrees. rw f2fs needs overprovision, so
  per-partition growth must be budgeted and checked against the group maximum.
```

## 3. Host toolchain (verified)

| Tool | Package | Notes |
|---|---|---|
| `lpdump`, `lpunpack`, `lpmake`, `lpadd` | android-tools 37 | LP metadata; we parse the binary ourselves and use lpdump only as an oracle |
| `make_f2fs` (1.16 AOSP) | android-tools | formatter; `-R uid:gid` for root owner (defaults to the invoking uid!) |
| `sload_f2fs` (1.16 AOSP) | android-tools | **the only sload with SELinux**: `-C fs_config -s file_contexts -t <mount point> -f <dir> -T <ts>`; applies uid/gid/mode/capabilities + labels unprivileged (tested) |
| `sload.f2fs`, `dump.f2fs`, `fsck.f2fs` (1.17) | f2fs-tools | `sload.f2fs` has NO selinux — never use it. `dump.f2fs -r -o DIR -f -N -L` extracts a tree unprivileged (xattr/chown restore fails with EPERM, harmless) — used as a cross-check oracle only |
| `avbtool` | android-tools | Python; `info_image` oracle for footers |
| `simg2img`, `img2simg`, `lz4` | android-tools, lz4 | sparse + lz4 for Odin |
| f2fs-tools 1.17 source | scratchpad clone | on-disk format reference (see §5) |

Python: 3.14 stdlib only (no lz4/zstd/pytest modules installed). Tests use `unittest`.

## 4. Package layout and CLI

```
superkit/
  __init__.py
  __main__.py      argparse CLI (python3 -m superkit <cmd>)
  lp.py            LP metadata: parse geometry/header/tables from a super image,
                   dataclasses, to_json/from_json, lpmake argument builder
  f2fs.py          userland f2fs reader: superblock, checkpoint, NAT (+journal), nodes,
                   data block map, directories (block + inline), inline data, symlinks,
                   xattrs (inline + xattr node), walk(), extract(), Manifest builder
  avb.py           AVB footer detect/parse/strip; vbmeta flag patch (offset 120)
  fsconfig.py      sidecar formats: canned fs_config, exact-path file_contexts,
                   manifest.tsv read/write/diff, security.capability (vfs_cap_data v2/v3)
                   encode/decode, regex escaping for file_contexts
  build.py         repack one partition: size estimation, make_f2fs + sload_f2fs with
                   retry-on-ENOSPC growth loop, feature selection; whole-super assembly
                   with lpmake from lp.py; capacity checks
  odin.py          img2simg + lz4 (match stock frame params) + tar, patched vbmeta
  mods/__init__.py mods.toml loader and dispatcher (tomllib)
  mods/fstab.py    remove/add mount flags per entry, keeps both fstab copies in sync
  mods/props.py    set/remove keys in *.prop files, preserving order and comments
  mods/files.py    add/delete files and dirs with metadata inheritance into sidecars
tests/             unittest suites; synthetic images built with make_f2fs/sload_f2fs
docs/              this file, format notes written by implementers
```

CLI (all paths explicit, nothing implicit; idempotent; never needs root):

```
superkit inventory  <super.raw|super.img>            # LP + per-partition facts (sparse auto-detected)
superkit unpack     <super.raw> <workdir>            # everything from §4.1
superkit mod        <workdir> <mods.toml>            # apply modifications, resync sidecars
superkit repack     <workdir> <outdir> [--config repack.toml]
superkit verify     <outdir/super.img> <workdir>     # manifest diff report, exit 1 on unexpected diffs
superkit pack-odin  <outdir/super.img> <outdir>      # super.img.lz4 (sparse), AP_super.tar, vbmeta_disabled.img
```

### 4.1 Workdir layout produced by `unpack`

```
<workdir>/super.json              full LP metadata (geometry, header, partitions, extents, groups, block devices)
<workdir>/<part>/root/            file tree (regular files, dirs, symlinks; host mtime = inode mtime)
<workdir>/<part>/fs_config        canned fs_config: "<mnt>/path uid gid mode capabilities=0x..." (root entry too)
<workdir>/<part>/file_contexts    one exact, regex-escaped, anchored line per path: "/vendor/bin/foo  u:object_r:...:s0"
<workdir>/<part>/manifest.tsv     per path: path type mode uid gid nlink size mtime selinux caps(hex) xattrs(other) target sha256
<workdir>/<part>/meta.json        f2fs sb facts: uuid, label, features, fs_size, block/sector sizes, root uid/gid/mode/mtime,
                                  sload timestamp hint, avb footer facts, mount point, counts
```
Mount point per partition: system → `/` (its tree contains `system/`), others → `/<name>`.
Paths in fs_config have no leading slash (AOSP canned format); in file_contexts they are
absolute. Both must be derived from the manifest, never from host stat.

## 5. f2fs reader — format references and required behaviour

Reference implementation to read (absolute path of the f2fs-tools clone is given by the
coordinator): `include/f2fs_fs.h`, `include/xattr.h`, `lib/libf2fs.c`, `fsck/mount.c`
(`get_valid_checkpoint`, `init_node_manager`, `get_node_info`, `current_nat_addr`,
`lookup_nat_in_journal`, `print_inode_info`), `fsck/xattr.c` (`read_all_xattrs`),
`fsck/dump.c` (`dump_folder_contents`, `dump_data_blk`, `dump_node_blk`, `dump_xattr`),
`fsck/node.c`, `fsck/dir.c`, `fsck/sload.c`. The kernel's `include/linux/f2fs_fs.h` is
the same layout.

Must handle, with and without `extra_attr`: superblock (offset 1024 in block 0, backup in
block 1) and its feature bits; both checkpoint packs and choosing the valid newer one
(crc, version); NAT area with the per-block version bitmap from the checkpoint (bitmap
location differs when cp_payload > 0); NAT journal entries in the hot-data summary block
(override the NAT area; nonzero n_nats must be honoured); node footer sanity (nid/ino);
inode flags `i_inline` (INLINE_XATTR, INLINE_DATA, INLINE_DENTRY, EXTRA_ATTR, DATA_EXIST);
addressing through i_addr, direct, indirect and double-indirect nodes, holes (NULL_ADDR=0)
and NEW_ADDR (0xFFFFFFFF) as zero-filled; i_size truncation of the last block; inline
data; symlink targets (inline or in a data block, length = i_size); directory dentry
blocks (bitmap, 214 slots, 8-byte name slots, multi-slot names) and inline dentries
(182 slots layout computed from MAX_INLINE_DATA); xattrs from the inline area and/or the
xattr node (header only at the start of the concatenated buffer), name index → prefix
mapping (user/trusted/security/…), terminating entry; `security.capability` decoding;
hard links (i_links > 1) reported in the manifest; special files (device nodes, fifos,
sockets) reported, not extracted. Compression (`i_flags` COMPR or sb feature) must be
detected and cause a clear error. Must never read past the device size; every block
address must be validated against main_blkaddr..block_count.

Performance target: system.img (3.8 GB) walk + extract in minutes, not hours — read
whole 4 KiB blocks, use `struct.unpack_from`/`memoryview`, avoid per-byte Python loops,
stream file data to disk in block runs.

## 6. Repack rules

* Features for rebuilt images = stock features minus `ro` (so, none). Keep the stock
  UUID and volume label. Root owner/mode/label from meta.json (`-R uid:gid`, `-l`).
* Timestamp: sload `-T` = stock root mtime, so timestamps are reproducible; per-file
  mtimes from the manifest are applied to the host tree so sload copies them when `-T`
  is omitted (config option `fixed_timestamp = true|false`).
* Size: start at `max(fs_size_stock, data+metadata estimate) * (1 + slack_percent/100)
  + slack_min`; on sload ENOSPC grow by 10% and retry (max 6). Final sizes must be a
  multiple of the LP logical block size, and the sum must fit the group maximum —
  otherwise fail with a per-partition size table and a hint which partition to keep `ro`.
* Per-partition `ro = true` in repack.toml keeps `-O ro` and the LP readonly attribute
  (useful for odm/product/system_ext when space is tight).
* LP rebuild: `lpmake --metadata-size <max> --metadata-slots <n> --super-name super
  --block-size <logical> --device super:<size>[:alignment:offset] --group main:<max>
  --partition <name>:<none|readonly>:<size>:main --image <name>=<img> ... --output`.
  No `--virtual-ab` / `--auto-slot-suffixing` unless header flags say so. Verify the
  rebuilt metadata by re-parsing it and comparing with super.json (only sizes/attributes
  may differ).
* xattrs beyond the SELinux label: `sload_f2fs` never writes `security.capability` and
  cannot write Samsung's `user.pa` process-authenticator certificates (6 files in vendor,
  3 in system, ~400 B each; 2 files in system carry caps 0xc0). `build.py` therefore
  (1) gives files whose final xattr set does not fit the 200-byte inline area a padded
  SELinux label so sload allocates an xattr node, (2) after sload rewrites the xattr
  storage of those inodes in place with `xattrw.py` (real label, capability v2, user.*),
  without allocating anything, and (3) re-reads the image to prove every entry matches
  the manifest before `fsck.f2fs --dry-run`.
* Samsung download mode checks a firmware revision stored in the first 4 KiB of super
  (Samsung's SignerVer02 record: RSA signature, build string `A137FXXSCEZB1` whose letter
  `C` encodes revision 12, end sector at 0x400). `lpmake` zero-fills that block, and the
  bootloader then refuses the image before writing ("SW REV CHECK FAIL |super| Fused 12 <
  Binary 0"). `pack-odin --stock-super` copies the stock record into the rebuilt super and
  updates the end-sector field; the signature cannot be valid but an OEM-unlocked
  bootloader only enforces the revision (verified: the flag-patched vbmeta with its
  record flashes, the record-less super does not, 2026-10-03).
* The download-mode sparse parser of this bootloader does not support FILL chunks (it
  stalls, 66 % with stock content re-encoded by img2simg), so `pack-odin` writes the
  sparse image itself with RAW and DONT_CARE chunks only (`superkit/sparse.py`), which is
  also how Samsung's own `super.img` is laid out (121 RAW + 36 DONT_CARE, no FILL).
* Never write into `stock/`.

## 7. Verification strategy (tests must exist for all of these)

1. Synthetic f2fs images built with `make_f2fs` + `sload_f2fs` from generated trees with
   known fs_config/file_contexts: long names (> 8 and > 200 chars), > 214 entries per
   dir (several dentry blocks), deep nesting, empty files, inline-sized files
   (3487/3488/3489 bytes), 4096-byte files, files needing direct nodes (> 3.4 MiB) and
   indirect nodes (> 12 MiB), many symlinks incl. long targets, capabilities, with and
   without `-O extra_attr,inode_checksum,sb_checksum`, with and without `-O ro`.
   Oracles: original bytes (sha256), original sidecars (semantic equality after
   regeneration), `dump.f2fs -r` output (byte equality), `dump.f2fs -i` xattr hex.
2. Stock oracle: `work/stockdump/vendor` (dump.f2fs -r output) must equal our extraction
   of `stock/super/vendor.img` byte for byte, same counts (1735/68/186).
3. LP: parse `stock/AP/super.raw` and compare every field with `lpdump` text; build a
   synthetic super with lpmake (2 partitions, known sizes) and round-trip.
4. Round trip: unpack stock vendor → repack unmodified (non-ro) → unpack again → manifests
   identical (modes, owners, labels, caps, targets, sha256), fsck.f2fs clean.
5. Mods: fstab/prop editors tested on copies of the stock files; idempotent.

## 8. Flashing (verified on the device, 2026-10-03)

* **Download mode refuses any modified super**, with or without the copied signature record
  ("SW REV CHECK FAIL |super| Fused 12 < Binary 0"): the revision check is bound to Samsung's
  RSA signature over the image. Only the stock sparse `super.img` passes. Download mode is
  still the way to clear the "failed download" state after a rejected attempt (flash the stock
  sparse super with Heimdall: `heimdall flash --super stock/AP/super.img --no-reboot`).
  Heimdall must be given the *sparse* file: a raw stream is rejected immediately.
* **One-step alternative**: `superkit pack-twrp out/v1/super.img out/v1/twrp --vbmeta out/v1/odin/vbmeta.img`
  builds a TWRP-flashable zip (gzip-compressed raw super streamed into the partition with
  `unzip -p | gzip -dc | dd`, size check against the block device, sha256 read-back
  verification, optional vbmeta). `adb sideload` it or install it from storage.
* **The manual way (first boot used this)**: Format Data, `adb push out/v1/super.img
  /data/super.img`, `dd if=/data/super.img of=/dev/block/by-name/super bs=4M conv=fsync`,
  compare sha256 of file and partition (`count=1530` 4 MiB blocks), remove the copy, then
  `adb sideload` the AnyKernel3 zip (patched first-stage fstab), reboot.
* vbmeta (flags 3, stock record kept) flashes fine through download mode.
* Result on A137FXXSCEZB1: all five partitions mounted f2fs without dm-verity, LP attributes
  none, `ro.crypto.state=unsupported` (no encryption), `mount -o remount,rw /vendor` works,
  run-as keeps its capability, Samsung `user.pa` xattrs preserved, debloat applied.
* Free space after the first build: / 556 MiB, product 582 MiB, vendor 22 MiB, system_ext
  24 MiB, odm 8 MiB. Raise `slack_percent` per partition in repack.toml before adding files
  to vendor or system_ext.
