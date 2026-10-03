# Tooling notes: make_f2fs, sload_f2fs, dump.f2fs, lpmake (measured 2026-10-02)

Everything below was measured on this host, unprivileged, with small images under
`work/tmp/spec-tooling/` (scripts `mkfs_exp*.sh`, `sload_exp*.py`, `space_exp.py`,
helpers `sbinfo.py` (superblock/checkpoint fields) and `inodes.py` (inode table via
`dump.f2fs -N -i`); logs `*.log` next to them).

Versions: `make_f2fs` / `sload_f2fs` **1.16.0 (2023-04-11)**, AOSP build from
android-tools 37.0.0-5.1 (statically linked AOSP libselinux + pcre2 and libcutils
canned fs_config; `sload_f2fs` is the only sload with SELinux support).
`dump.f2fs` / `fsck.f2fs` **1.17.0** (upstream f2fs-tools, no SELinux, no fs_config).

Summary of the things that bite:

* `make_f2fs -R` defaults to the **invoking uid:gid**, not 0:0. Always pass `-R 0:0`.
* `make_f2fs` without `-O` gives **feature = 0** (good: that is exactly "stock minus ro").
* Non-`ro` images need ≥ 46 MiB and lose 10–55 % to overprovision; `ro` images need
  ≥ 27 MiB and ~0 % (6 segments). See §1.4 and §2.9.
* `sload_f2fs -C` is a **strict** loader: single spaces only, no comments, no blank
  lines, every created path must have an entry, missing entry = fatal.
* `sload_f2fs` parses `capabilities=` but **never writes `security.capability`**.
* The root inode's label is looked up as `<mount><mount>` (`/vendor/vendor` for
  `-t /vendor`), not as `/vendor`. An exact file_contexts must contain that key.
* On ENOSPC an `ro` image is **silently truncated with exit status 0**; the only
  signal is `Not enough space` on stderr. Non-`ro` images abort with an ASSERT.
* Files ≤ 3344 bytes are stored inline; directories are never inline; symlink targets
  ≥ 3488 bytes trigger an sload bug (irrelevant for stock: longest target is 31).

## 1. make_f2fs

```
make_f2fs [options] device [sectors]
  -O feature1[,feature2,...]   -R uid:gid   -l label   -U uuid   -T timestamp
  -o overprovision%   -f   -b blocksize(4096)   -w sector size   -S sparse   ...
```

### 1.1 device and the `sectors` argument

* `device` must exist; a regular file is fine. Nonexistent file → `stat failed errno:2`
  / `Not available on mounted device!`, rc 255. A zero-length file → **SIGFPE crash**
  (rc 136). It never creates or grows the file.
* Sector size for a regular file is always 512 (`-w 4096` only changes the unit in
  which the `sectors` argument is interpreted; the superblock keeps
  `log_sectorsize=9`). `total sectors = floor(size / 512)`, `block_count =
  floor(sectors / 8)`; a 65 000 000 byte file gives 126 953 sectors → 15 869 blocks.
* `sectors` (optional 2nd positional) limits the filesystem to that many 512-byte
  sectors: larger than the file → clamped to the file size (`Info: wanted sectors =
  N`); not a multiple of 8 → rounded down to whole blocks; 131 073 → 16 384 blocks,
  131 080 → 16 385 blocks. The file itself is left as is (not truncated).
* `-f` has no effect for regular files: make_f2fs never prompts and silently
  overwrites an existing f2fs (with or without `-f`, stdin open or closed).

### 1.2 options

| option | behaviour (measured) |
|---|---|
| `-O list` | comma- or space-separated (`"ro,extra_attr"`, `"ro, extra_attr"`, `"ro extra_attr"` all work). Accepted names and bits: encrypt 0x1, extra_attr 0x8, project_quota 0x10, inode_checksum 0x20, flexible_inline_xattr 0x40, quota 0x80, inode_crtime 0x100, lost_found 0x200, verity 0x400, sb_checksum 0x800, casefold 0x1000, compression 0x2000, **ro 0x4000**, packed_ssa (accepted, then "disabled for 4k block", no bit). Rejected (`Error: Wrong features X`, rc 1): blkzoned, device_alias, anything else. inode_checksum, flexible_inline_xattr, inode_crtime, project_quota and compression **require extra_attr in the same list** (otherwise an `Info: ... should always be enabled with extra attr feature` and rc 1). |
| no `-O` | superblock `feature = 0x0` — no features at all. This is what repack wants (stock = 0x4000 = only ro). `-g android` would add encrypt,extra_attr,project_quota,quota,verity (0x499): never use it. |
| `-R uid:gid` | **default is the invoking user** (1000:1000 here), the usage text ("default: 0:0") is wrong. Parsed with strtoul: `root:root` → 0:0 silently, `:1000` → 0:1000, `-1:-1` → 0xffffffff:0xffffffff, `70000:70000` kept (32-bit), `1000:` → rc 1. Sets uid/gid of the root inode only; root mode is always 0755, i_links 2, ino 3, no xattrs. |
| `-l label` | stored UTF-16LE in `volume_name` (max 512 chars, longer → rc 1); spaces and non-ASCII fine. Stock labels: `/` for system, else the partition name. |
| `-U uuid` | canonical 36-char form, case-insensitive; invalid → `supplied string is not a valid UUID`, rc 255 (image left unformatted). |
| `-T ts` | strtoul base 0: decimal or `0x` hex; non-numeric → 0; `-1` means "unset" (= now). Sets atime/ctime/mtime (nsec 0) of the root inode; default `time(NULL)`. Stock root mtime is in meta.json; use it. |
| `-o pct` | forces the overprovision ratio; `-o 0` = auto; at 64 MiB `-o 1`/`-o 5` → `Device size is not sufficient` (rc 255) while 10/20/50/95/100 work. Auto is cheaper at small sizes than any manual value except 20–50 at 64 MiB — leave it on auto. |
| `-S` | sparse output; untested, we always write raw images. |

Exit codes: 0 ok, 1 option/feature error, 255 format error, 136 SIGFPE (image < 14 MiB).
The superblock `version`/`init_version` strings are the host kernel version
(`7.2.8-2-cachyos`; stock has `6.8.0-52-generic`). Only `make_f2fs` sets them.

### 1.3 minimum size

* Without `ro`: **46 MiB** (45 MiB and below → `Error: Device size is not sufficient
  for F2FS volume`, rc 255; 13 MiB and below → SIGFPE, rc 136).
* With `-O ro`: **27 MiB** (26 and below → not sufficient).
* Size need not be a MiB multiple; it is rounded down to whole 4 KiB blocks (and
  segments of 2 MiB for the main area).

### 1.4 auto overprovision and usable space (`ckpt.user_block_count`)

Auto overprovision (`get_best_overprovision`): `ro` images always get ratio 0 % and 6
overprovision segments (12 MiB) with 0 reserved; non-`ro` images get a ratio chosen
from {55, 35, 30, 25, 20, 15, 10, 5.27, 3.58, 2.57, 2.39 …}% depending on the main area
size plus the GC reserve. Measured:

| image size | rw ovp % (ovp/rsvd segs) | rw usable | ro usable |
|---|---|---|---|
| 46 MiB | 55 % (14/8) | 2 MiB | – |
| 52 MiB | 55 % (14/8) | 8 MiB | – |
| 64 MiB | 55 % (14/8) | 20 MiB | 38 MiB (ro at 64 MiB) |
| 104 MiB | 30 % (16/10) | 56 MiB | – |
| 128 MiB | 25 % (17/11) | 78 MiB | 102 MiB |
| 256 MiB | 15 % (22/13) | 196 MiB | 230 MiB |
| 410 MiB (stock vendor) | 10 % (24/17) | 346 MiB | 384 MiB |
| 472 MiB | 10 % (27/17) | 402 MiB | – |
| 512 MiB | 10 % (29/17) | 438 MiB | 486 MiB |
| 1024 MiB | 5.27 % (31/25) | 942 MiB | 994 MiB |
| 2048 MiB | 3.58 % (40/34) | 1942 MiB | 2014 MiB |
| 3614 MiB (stock system) | 2.57 % (51/45) | 3478 MiB | 3576 MiB |
| 4096 MiB | 2.39 % (54/48) | 3950 MiB | 4054 MiB |

Fixed metadata (sb + 2 cp + sit + nat + ssa) costs 7 segments ≈ 14 MiB for images up
to a few GiB (the NAT grows slowly). Rule of thumb for a non-`ro` image:
`usable ≈ (size − 14 MiB) × (1 − ovp%) − 12 MiB`; for `ro`: `usable ≈ size − 26 MiB`.
sload needs usable ≥ data blocks + node blocks (1 per inode, +1 per 3.4 MiB of a big
file, +1 per 1 GiB) + 1 dentry block per directory, and in practice a few free
segments on top (see §2.9 for measured minima).

## 2. sload_f2fs

```
sload_f2fs [-C fs_config] [-s file_contexts] [-t mount_point] [-T timestamp] [-P] [-d lvl] -f source_dir device
```

The image must already be formatted (`make_f2fs`); an unformatted file → rc 255 with no
message. `-f` accepts absolute or relative paths, trailing slash ok; nonexistent source
→ rc 255. An empty source directory is fine. Running sload twice on the same image is
harmless (`Skip the existing "name"`, rc 0, nothing changed).

Entries are created per directory in `scandir` + `alphasort` order (strcoll — run
sload with `LC_ALL=C` for byte order: observed `C`, `_x`, `a`, `aa`, `b`), all entries
of a directory first (dirs, files, symlinks get consecutive inode numbers starting at
4), then recursion into each subdirectory in that order. Inode numbers are therefore a
deterministic function of the tree.

### 2.1 `-C fs_config` (canned fs_config, libcutils `load_canned_fs_config`)

Lexical rules (each verified, log `sload_fsconfig*.log`):

* one entry per line: `<path> <uid> <gid> <mode> [capabilities=<n>] [ignored tokens...]`
* separator is a **single space run** — tabs are a parse error (`Ill-formed line`, rc 255);
  multiple spaces, trailing spaces, CRLF and a missing final newline are fine
* **no comments, no blank lines** (either → `Ill-formed line`, rc 255); fewer than 4
  fields → rc 255
* `path` is the canned key = **mount point without leading slash + "/" + path**
  (`vendor/bin/hello` for `-t /vendor`; `system/bin/sh` and `init` for `-t /`). A
  leading `/` is tolerated (stripped by the loader); `./x`, `x//y`, a trailing `/` on a
  directory, or a leading space make the entry unfindable. Paths with spaces cannot be
  expressed (the loader splits at spaces) → such files make sload fail.
* `uid`, `gid`: decimal (`atoi`: `root` → 0, `-1` → 65535 after masking); **sload keeps
  only the low 16 bits** (65536 → 0, 70000 → 4464). `mode`: octal (`strtol(…, 8)`:
  `0755`, `755`, `0100755` all give 0755; `0x1a4` → 0). Type bits are masked away
  (`de->mode = (stat type) | (mode & 0xffff)`), suid/sgid/sticky are kept (04755 → 104755).
* `capabilities=`: `strtoll(…, 0)` → `0x1000000`, `16777216` and octal `010` all work;
  it may be followed by other tokens; unknown tokens before it are skipped.
* Lookup is a bsearch after qsort: **order is irrelevant**; duplicates are undefined
  (observed: the later line won) — never emit duplicates.
* **Every path sload creates (dirs, regular files, symlinks) must have an entry**;
  otherwise sload dies with `failed to find <key> in canned fs_config` (rc 1) leaving a
  half-built image. Entries for paths that do not exist in the source are ignored, as
  are entries for special files (which sload skips anyway).
* A root entry (`vendor 0 0 0755` or, for `/`, impossible) is accepted and **ignored**:
  the root inode keeps `make_f2fs -R` owner and mode 0755. An entry `vendor` is also
  what a real file named `vendor` in the vendor root would use (no collision in stock).
* `capabilities` are parsed (visible with `-d 2`: `… capabilities = 0x1000000`) but this
  build **never writes the `security.capability` xattr** — checked with
  `dump.f2fs -N -i` on files given caps (only `security.selinux` is present) and on the
  sample image; the upstream 1.17 source has no capability-writing code either. The
  stock images carry exactly 2 capability xattrs (both in system.img, v2
  `01000002 c0000000 …` = CAP_SETUID|CAP_SETGID effective, i.e. `run-as`); vendor,
  product, system_ext, odm have none. Restoring them needs a post-sload xattr write
  (f2fs.py/build.py concern); fsconfig.py keeps the values in fs_config/manifest.
* Without `-C`, libcutils' built-in `android_dirs`/`android_files` table applies
  (`vendor/bin` 0751 root:shell, `vendor/bin/*` 0755 root:shell, `vendor/etc/*` 0644
  root:root, `system/bin/run-as` 0750 + caps 0xc0, symlinks 0644 …) — never rely on it.
  `-P` ("preserve owner") is overridden by either table, so it is useless.

### 2.2 `-s file_contexts` (AOSP libselinux, pcre2)

* Format: `<regex> [-<type>] <label>`, whitespace separated (spaces or tabs); `#`
  comments, blank lines, CRLF and a missing final newline are fine. The file must be
  **pure ASCII** (`line N error due to: Non-ASCII characters found`, rc 234).
* Regexes are anchored (`^…$`): `/vendor/bin` does **not** match `/vendor/bin/hello`.
* Unescaped metacharacters are live regex: `/vendor/a.b` matches `axb`, `/vendor/c++`
  matches `c`, `d(1)` matches `d1`, `e[2]` matches `e2`, `f*` matches `ff`. A line
  that is not a valid pcre2 regex (`d(`, `l\m`) poisons every lookup that reaches it
  (`cannot lookup security context`, rc 234).
* Exact matching: escape `. + ( ) [ ] { } * ? $ ^ | \` with a backslash and write any
  other byte outside `[A-Za-z0-9/_-]` as `\xHH` — verified for every byte 0x21–0x7e
  (except `/`) and for UTF-8 bytes (`\xc3\xbc` = `ü`; `\x{c3}` also works). A literal
  space cannot be written (`\ ` is rejected) but `\x20` and `\s` match it. `-`, `_`,
  `,`, `:`, `@`, `~`, `=`, `%`, `#` (not at line start) need no escaping.
* Precedence: a line without metacharacters (after escape removal) beats regex lines
  regardless of order; among exact lines **the last one wins**; among regex lines the
  last matching line wins (no prefix-length ranking). So an exact-only file is
  order-independent.
* `-<type>` specifiers work (`-l` only symlinks, `--` only regular files, `-d` dirs): the
  lookup passes the entry's S_IFMT.
* Symlinks are labelled by their own path (no target resolution).
* **No match for a created path → fatal** `cannot lookup security context for <path>`,
  rc 234 (image half-labelled). `<<none>>` behaves like no match. An invalid label
  string (`notacontext`) is written verbatim. Labels up to at least 300 chars work (an
  xattr node is allocated when the inline area overflows).
* Lookup key = mount point + sload's internal path (which starts with `/`): `-t /vendor`
  → `/vendor/bin/hello`; `-t /` → `//bin/hello` (libselinux collapses `//`).
* **Root inode**: sload looks it up as `mount_point + mount_point`: `-t /` → `//` → `/`
  (a `/` line labels it); `-t /vendor` → **`/vendor/vendor`**. A plain `/vendor` line
  does **not** label the root (rc 234 "cannot lookup … /vendor/vendor"); the regex
  `/vendor(/.*)?` covers it. `fsconfig.write_file_contexts` emits the root label under
  both `/vendor` and `/vendor/vendor`.
* Without `-s` no `security.selinux` xattr is written at all.

### 2.3 `-t mount point`

Must be `/` (default) or `/<name>` — absolute, no trailing slash. `-t /vendor/` makes
the fs_config key `vendor//a` (not found, fatal); `-t vendor` makes the contexts key
`vendor/a` (no match, fatal). The mount point is purely a prefix for the two sidecar
lookups; it is not stored in the image.

### 2.4 timestamps (`-T`) and host mtimes

* With `-T ts` (strtoul base 0, `0` and hex allowed): every created inode gets
  `atime = ctime = mtime = ts`, all `_nsec = 0`.
* Without `-T`: each inode gets its **source's `st_mtime` seconds** (lstat, so symlinks
  use their own mtime, directories theirs) copied into atime, ctime and mtime;
  nanoseconds are **dropped** (0). Host atime/ctime are never used.
* The root inode's times come from `make_f2fs -T` and are never touched by sload (nor
  does sload bump directory mtimes when adding entries). So for reproducible images:
  `make_f2fs -T <stock root mtime>` and either `sload -T <same>` or per-file host mtimes
  from the manifest with `-T` omitted (DESIGN §6 `fixed_timestamp`). Stock images have
  `_nsec = 0` everywhere that was checked.

### 2.5 inline data, inline dentries, symlinks

* Regular files: **≤ 3344 bytes are inline** (`i_inline = INLINE_XATTR|INLINE_DATA|
  DATA_EXIST = 0xb`, `i_blocks = 1`), 3345 bytes and more get a data block
  (`i_blocks = 2`). The threshold is 3344 with and without `extra_attr` (sload's
  `DEF_MAX_INLINE_DATA` already reserves the extra-attr space). 0-byte files are inline
  with `DATA_EXIST` set and `i_size 0`. Note: this is not the kernel's 3488/3452 limit;
  the reader must honour the flags, not guess from the size.
* Directories are **never** inline-dentry: every directory gets ≥ 1 dentry block
  (`i_inline = 0x1`, `i_size = 4096 × blocks`, `i_blocks = 2`), 215 entries → 2 blocks.
* Symlinks: target stored inline when `len + 1 ≤ 3488 − extra_isize` (3487 bytes without
  extra_attr; 3475 with `extra_attr,inode_checksum,sb_checksum`, extra_isize 12),
  `i_size = len`, `i_blocks = 1`. Longer targets go into a data block, but sload leaves
  `i_blocks = 1` → its final fsck asserts (`has i_blocks: 1, but has 2 blocks`, rc 1).
  Stock vendor's longest target is 31 bytes, max name 68, depth 5.
* Symlink mode comes from fs_config like any file (`0777` normally; sload happily stores
  `120644`); the built-in table (no `-C`) gives symlinks 0644.
* `i_name` holds the file name (≤ 255 bytes), `i_pino` the parent.

### 2.6 hard links, special files, odd sources

* Hard links (same `st_dev:st_ino`, `st_nlink > 1`) become one inode with `i_links`
  incremented and several dentries, also across directories. The **first name created**
  (alphasort/DFS order) fixes uid/gid/mode (later names' fs_config entries are ignored)
  and the label (later `setxattr` creates fail silently). Stock vendor has none.
* fifo / socket / char / block sources are **skipped silently** (`Error unknown file
  type` only at `-d 1`), rc 0; their fs_config/file_contexts lines are harmless.
* An unreadable source file (mode 000) is created as an empty 0-byte inode (`Skip: Fail
  to open …`), **rc 0**.
* With `-O ro` images sload behaves the same (plus `update_largest_extent`).

### 2.7 exit codes and messages

0 ok · 1 fs_config lookup failure (`failed to find … in canned fs_config`) or final fsck
assertion · 234 (= −22, EINVAL) file_contexts lookup failure · 255 everything else
(cannot open image/source, `Ill-formed line`, ENOSPC assertions). Images are **not**
cleaned up on failure.

### 2.8 ENOSPC behaviour (important)

* Non-`ro` image too small: sload aborts with `[reserve_new_block:73] Can't find free
  block [ASSERT] (reserve_new_block: 74) 0` (rc 255) or `[ASSERT]
  (move_one_curseg_info:3194) ret == 0` (rc 255), or prints `[reserve_new_block:47] Not
  enough space` and fails its final fsck (rc 1).
* **`ro` image too small: sload prints `[reserve_new_block:47] Not enough space` once per
  missing block and then exits 0, and `fsck.f2fs` is clean** — but the later files have
  their `i_size` and no data blocks (`i_blocks = 1`); `dump.f2fs -r` produces files full
  of holes. build.py must treat `Not enough space` or `ASSERT` anywhere in the sload
  output as failure regardless of the exit status, and verify by re-reading.

### 2.9 image size needed vs content (measured with random data, `space_exp.py`)

| content | rw: minimum image that sload accepts | ro: minimum |
|---|---|---|
| 1 MiB (4 × 256 KiB) | 52 MiB (46 MiB mkfs minimum gives only 2 MiB usable) | 27 MiB (= mkfs minimum) |
| 50 MiB (50 × 1 MiB) | 104 MiB (30 % ovp) | 77 MiB |
| 100 MiB (100 × 1 MiB) | 158 MiB (25 % ovp) | 127 MiB |
| 400 MiB (100 × 4 MiB) | 472 MiB (10 % ovp; usable 402 MiB for 400.8 MiB of data+nodes) | 427 MiB |

(`ro` minima were re-measured with "`Not enough space` in the output counts as
failure", see §2.8; `space_exp2.log`.) `ro` therefore costs content + 27 MiB.

So for the stock sizes (vendor 410 MiB, fs ≈ 396 MiB used): rw needs about
content / 0.9 + 14 MiB at the 10 % tier; at 1 GiB+ the tier drops to 5.3 % / 3.6 % /
2.6 %, i.e. system (3.8 GB, 2.57 %) needs ≈ +115 MiB. The 10 % → 5.27 % step happens
between 512 MiB and 1 GiB (check `make_f2fs` output: `Overprovision ratio`).
DESIGN §6's grow-by-10 %-and-retry loop is adequate; start at
`content × 1.12 + 16 MiB` for images < 1 GiB and `content × 1.04 + 16 MiB` above.

## 3. dump.f2fs (1.17) usage notes

* `dump.f2fs -N -i <nid> img` prints the inode (`i_mode … i_name`, `i_addr[]`,
  `i_nid[]`) **and its xattrs** (`xattr: e_name_index:6 e_name:selinux … e_value:` +
  hex) and, thanks to `-N` ("answer no"), dumps nothing to disk. `-i` takes decimal or
  `0x` hex. Without `-N` (`-f -i`) it also extracts the inode's contents into
  `./lost_found/` **of the current directory** — run it in a scratch cwd.
* `e_name_index`: 1 user, 2 posix_acl_access, 3 posix_acl_default, 4 trusted, 5 lustre,
  **6 security** (`selinux`, `capability`), 7 advise, 9 encryption, 11 verity. The
  selinux value has no trailing NUL (31 bytes for `u:object_r:vendor_hello_exec:s0`).
* `-d 1` prefixes the superblock/checkpoint dump. `-r -o DIR -f -N -L` extracts the
  tree (chown/xattr restore fail with EPERM unprivileged, harmless; `-P` not needed).
* `fsck.f2fs -f --dry-run img` returns 0 even for the silently truncated ro image
  above; it only checks metadata consistency.

## 4. lpmake — exact argument syntax (`lpmake --help`, android-tools 37)

```
lpmake [options]
Required:
  -d,--device-size=[SIZE|auto]   size of the super block device (auto = sum of partitions + metadata)
  -m,--metadata-size=SIZE        max bytes reserved for partition metadata (stock: 65536)
  -s,--metadata-slots=COUNT      number of metadata slot copies (stock: 2)
  -p,--partition=DATA            <name>:<attributes>:<size>[:group]   attributes = none | readonly
  -o,--output=FILE
Optional:
  -b,--block-size=SIZE           physical block size, default 4096
  -a,--alignment=N               partition alignment in bytes
  -O,--alignment-offset=N        alignment offset to the device parent
  -S,--sparse                    sparse output (fastboot)
  -i,--image=PARTITION=FILE      initial data for a partition (file or sparse file)
  -g,--group=GROUP:SIZE          named group with maximum size
  -D,--device=DATA               <partition_name>:<size>[:<alignment>:<alignment_offset>]; with -D,
                                 -d/--device-size and -a/-O must NOT be given
  -n,--super-name=NAME           name of the block device housing super (stock: super)
  -x,--auto-slot-suffixing       mark names as needing slot suffixes (A/B only — not for a13ve)
  -F,--force-full-image          write a full (flashable) image even without --image
  --virtual-ab                   set VIRTUAL_AB_DEVICE header flag (v1.2 header) — not for a13ve
```

Short options take the value either attached (`-m65536`) or as the next word; long
options use `=` or the next word. The stock geometry (DESIGN §2, §6) maps to
`--metadata-size 65536 --metadata-slots 2 --super-name super --block-size 4096
--device super:6417285120[:alignment:offset] --group main:6413090816
--partition <name>:readonly|none:<size>:main --image <name>=<img> … --output super.img`;
lp.py's `lpmake_args` builder and `tests/test_lp.py` are the authority on the exact
alignment/offset values that reproduce the stock block-device entry.
