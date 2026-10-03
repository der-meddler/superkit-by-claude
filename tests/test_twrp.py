"""pack-twrp: zip layout, script syntax, payload round trip."""
import gzip, hashlib, os, shutil, subprocess, sys, tempfile, unittest, zipfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from superkit import twrp  # noqa: E402

PROJ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP_ROOT = os.path.join(PROJ, "work", "tmp", "twrp-tests")


class PackTwrpTests(unittest.TestCase):
    def setUp(self):
        os.makedirs(TMP_ROOT, exist_ok=True)
        self.tmp = tempfile.mkdtemp(prefix="t-", dir=TMP_ROOT)

    def tearDown(self):
        if not os.environ.get("SUPERKIT_KEEP_TMP"):
            shutil.rmtree(self.tmp, ignore_errors=True)

    def test_zip_round_trip(self):
        img = os.path.join(self.tmp, "super.img")
        data = (bytes(range(256)) * 16) + b"\0" * (12 << 20) + os.urandom(1 << 20) + b"\0" * ((4 << 20) - 4096)
        with open(img, "wb") as f:
            f.write(data)
        self.assertEqual(len(data) % 4096, 0)
        vb = os.path.join(self.tmp, "vbmeta.img")
        with open(vb, "wb") as f:
            f.write(b"AVB0" + b"\1" * 8380)
        res = twrp.pack_twrp(img, self.tmp, vbmeta=vb, name="test", level=1)
        self.assertTrue(os.path.exists(res["zip"]))
        self.assertEqual(res["sha256"], hashlib.sha256(data).hexdigest())
        with zipfile.ZipFile(res["zip"]) as zf:
            names = set(zf.namelist())
            self.assertEqual(names, {"META-INF/com/google/android/update-binary",
                                     "META-INF/com/google/android/updater-script",
                                     "super.sha256", "super.img.gz", "vbmeta.img"})
            self.assertEqual(gzip.decompress(zf.read("super.img.gz")), data)
            self.assertEqual(zf.read("vbmeta.img")[:4], b"AVB0")
            script = zf.read("META-INF/com/google/android/update-binary").decode()
            self.assertIn("EXPECTED_SIZE=%d" % len(data), script)
            self.assertIn("EXPECTED_SHA=%s" % res["sha256"], script)
            self.assertNotIn("@SIZE@", script)
            self.assertIn("DD_COUNT=%d" % (len(data) // (4 << 20)), script)
            for e in zf.infolist():
                self.assertEqual(e.compress_type, zipfile.ZIP_STORED)
            sp = os.path.join(self.tmp, "update-binary")
            with open(sp, "w") as f:
                f.write(script)
        rc = subprocess.run(["sh", "-n", sp], stderr=subprocess.PIPE)
        self.assertEqual(rc.returncode, 0, rc.stderr.decode())
        # a size that is not a 4 MiB multiple falls back to 4 KiB blocks
        img2 = os.path.join(self.tmp, "odd.img")
        with open(img2, "wb") as f:
            f.write(b"x" * (4096 * 3))
        res2 = twrp.pack_twrp(img2, self.tmp, name="odd", level=1)
        self.assertEqual(res2["dd"], "bs=4096 count=3")

    def test_rejects_unaligned(self):
        img = os.path.join(self.tmp, "bad.img")
        with open(img, "wb") as f:
            f.write(b"x" * 5000)
        with self.assertRaises(twrp.TwrpError):
            twrp.pack_twrp(img, self.tmp, name="bad")


if __name__ == "__main__":
    unittest.main()
