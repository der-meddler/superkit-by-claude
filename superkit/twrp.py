"""TWRP-flashable zip that writes the rebuilt super (and optionally vbmeta).

Download mode on the SM-A137F refuses any super that is not Samsung-signed, so the
rebuilt image has to be written from recovery.  This packer turns the push-and-dd
procedure into one zip:

* ``super.img.gz``  the raw super, gzip-compressed (gzip is in every TWRP busybox/toybox;
                     ~6.4 GB raw -> ~2.8 GB, below the 4 GB zip64 threshold)
* ``vbmeta.img``    optional, written as-is
* ``update-binary`` a POSIX sh script: checks the super block device size against the
                     image, unmounts anything mounted from super, streams
                     ``unzip -p | gzip -dc | dd`` into the partition, then reads the
                     partition back and compares its sha256 with the one recorded at
                     pack time.  Nothing is staged on /data.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time
import zipfile

BLOCK = 4 << 20  # dd block size used by the script

UPDATE_BINARY = r'''#!/sbin/sh
# superkit TWRP installer (generated) - writes the rebuilt super partition.
# Arguments from recovery: <api> <outfd> <zip>
OUTFD=$2
ZIP=$3
EXPECTED_SIZE=@SIZE@
EXPECTED_SHA=@SHA@
DD_COUNT=@COUNT@
DD_BS=@BS@
BUILD_INFO="@INFO@"

ui_print() { echo "ui_print $1" > /proc/self/fd/$OUTFD; echo "ui_print" > /proc/self/fd/$OUTFD; }
abort() { ui_print "ERROR: $1"; ui_print "Nothing else was changed. Reboot to recovery and retry, or restore the stock super."; exit 1; }

ui_print " "
ui_print "superkit super installer"
ui_print "$BUILD_INFO"
ui_print " "

for t in unzip gzip dd sha256sum blockdev; do
  command -v $t >/dev/null 2>&1 || abort "missing tool in recovery: $t"
done

BLK=/dev/block/by-name/super
if [ ! -e "$BLK" ]; then
  BLK=$(ls /dev/block/platform/*/by-name/super /dev/block/platform/*/*/by-name/super 2>/dev/null | head -n1)
fi
[ -n "$BLK" ] && [ -e "$BLK" ] || abort "super partition not found"
DEVSIZE=$(blockdev --getsize64 "$BLK" 2>/dev/null)
[ "$DEVSIZE" = "$EXPECTED_SIZE" ] || abort "super is $DEVSIZE bytes, this image is for $EXPECTED_SIZE bytes (wrong device?)"

DEVICE=$(getprop ro.product.device 2>/dev/null)
[ -n "$DEVICE" ] && ui_print "Device: $DEVICE"
ui_print "Target: $BLK ($DEVSIZE bytes)"

# nothing from super may stay mounted while it is rewritten
for m in /system_root /system /vendor /product /odm /system_ext; do umount "$m" 2>/dev/null; done
awk '$1 ~ /^\/dev\/block\/dm-/ {print $2}' /proc/mounts 2>/dev/null | while read -r m; do umount "$m" 2>/dev/null; done
if grep -q '^/dev/block/dm-' /proc/mounts 2>/dev/null; then
  abort "a dynamic partition is still mounted; unmount System/Vendor/Product in TWRP's Mount menu and retry"
fi

ui_print "Writing super ($((EXPECTED_SIZE / 1048576)) MiB, several minutes, no progress shown)..."
unzip -p "$ZIP" super.img.gz | gzip -dc | dd of="$BLK" bs=$DD_BS conv=fsync 2>/tmp/superkit-dd.log
RC=$?
sync
if [ $RC -ne 0 ]; then
  ui_print "$(tail -n 3 /tmp/superkit-dd.log 2>/dev/null)"
  abort "write failed (dd exit $RC)"
fi

ui_print "Verifying the written partition..."
GOT=$(dd if="$BLK" bs=$DD_BS count=$DD_COUNT 2>/dev/null | sha256sum | cut -d' ' -f1)
if [ "$GOT" != "$EXPECTED_SHA" ]; then
  ui_print "expected $EXPECTED_SHA"
  ui_print "got      $GOT"
  abort "verification FAILED - do not boot; flash again or restore the stock super"
fi
ui_print "super verified OK"

if unzip -l "$ZIP" 2>/dev/null | grep -q ' vbmeta.img$'; then
  VB=/dev/block/by-name/vbmeta
  if [ -e "$VB" ]; then
    unzip -p "$ZIP" vbmeta.img | dd of="$VB" conv=fsync 2>/dev/null && ui_print "vbmeta written" || ui_print "WARNING: vbmeta write failed"
  else
    ui_print "WARNING: vbmeta partition not found, skipped"
  fi
fi

ui_print " "
ui_print "Done. Reboot to system now; TWRP's old super mappings are stale until then."
exit 0
'''

UPDATER_SCRIPT = "#MAGIC\n"


class TwrpError(Exception):
    pass


def sha256_file(path: str, progress=None) -> str:
    h = hashlib.sha256()
    done = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8 << 20), b""):
            h.update(chunk)
            done += len(chunk)
            if progress and done % (512 << 20) == 0:
                progress("hashing %d MiB" % (done >> 20))
    return h.hexdigest()


def gzip_file(src: str, dst: str, level: int = 6) -> str:
    """gzip ``src`` to ``dst`` with pigz when available (parallel), else gzip."""
    tool = shutil.which("pigz") or shutil.which("gzip")
    if not tool:
        raise TwrpError("neither pigz nor gzip found")
    with open(dst, "wb") as out:
        p = subprocess.run([tool, "-%d" % level, "-n", "-c", src], stdout=out, stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise TwrpError("%s failed: %s" % (tool, p.stderr.decode(errors="replace")[-500:]))
    return dst


def pack_twrp(super_img: str, outdir: str, vbmeta: str | None = None, name: str | None = None,
              level: int = 6, progress=None, keep_gz: bool = False) -> dict:
    size = os.path.getsize(super_img)
    if size % 4096:
        raise TwrpError("%s: size %d is not a multiple of 4096" % (super_img, size))
    bs = BLOCK if size % BLOCK == 0 else 4096
    count = size // bs
    os.makedirs(outdir, exist_ok=True)
    stamp = name or time.strftime("%Y%m%d-%H%M%S")
    if progress:
        progress("sha256 of %s" % super_img)
    sha = sha256_file(super_img, progress)
    gz = os.path.join(outdir, "super.img.gz")
    if progress:
        progress("gzip -> %s (this takes a few minutes)" % gz)
    gzip_file(super_img, gz, level)
    gz_size = os.path.getsize(gz)
    if gz_size >= (4 << 30) - (1 << 20):
        raise TwrpError("compressed super is %d bytes; TWRP's unzip needs entries below 4 GiB" % gz_size)
    info = "image %s, %d MiB, sha256 %s..." % (os.path.basename(super_img), size >> 20, sha[:16])
    script = (UPDATE_BINARY.replace("@SIZE@", str(size)).replace("@SHA@", sha)
              .replace("@COUNT@", str(count)).replace("@BS@", str(bs)).replace("@INFO@", info))
    zip_path = os.path.join(outdir, "TWRP_super_%s.zip" % stamp)
    if progress:
        progress("zip -> %s" % zip_path)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as zf:
        zf.writestr("META-INF/com/google/android/update-binary", script)
        zf.writestr("META-INF/com/google/android/updater-script", UPDATER_SCRIPT)
        zf.writestr("super.sha256", "%s  super.img\n%d bytes\n" % (sha, size))
        zf.write(gz, "super.img.gz")
        if vbmeta:
            zf.write(vbmeta, "vbmeta.img")
    if not keep_gz:
        os.remove(gz)
    return {"zip": zip_path, "zip_size": os.path.getsize(zip_path), "super_size": size, "sha256": sha,
            "gz_size": gz_size, "vbmeta": bool(vbmeta), "dd": "bs=%d count=%d" % (bs, count)}
