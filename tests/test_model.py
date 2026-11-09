import subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"src"))
from authlibjws.model import CASES, evaluate_case, deserialize_json_pre, deserialize_json_post

class T(unittest.TestCase):
    def test_all(self):
        for c in CASES:
            with self.subTest(c.id):
                self.assertTrue(evaluate_case(c)["ok"], evaluate_case(c))
    def test_pos_flip(self):
        flips = [evaluate_case(c) for c in CASES if c.kind=="pos"]
        self.assertEqual(len(flips), 2)
        for r in flips: self.assertTrue(r["flips"], r)
    def test_oracle(self):
        out = subprocess.check_output([sys.executable, str(ROOT/"scripts"/"derive_expected.py")], text=True)
        lines = [ln for ln in out.splitlines() if ln and not ln.startswith("id")]
        by = {c.id:c for c in CASES}
        for ln in lines:
            cid, kind, pre, post = ln.split("\t")
            c = by[cid]
            self.assertEqual((pre, post), (c.pre, c.post))
    def test_vacuous_comment(self):
        # The all-quantifier over an empty list is vacuously true.
        self.assertEqual(deserialize_json_pre({"payload":"YQ","signatures":[]}), "VALID")
        with self.assertRaises(Exception):
            deserialize_json_post({"payload":"YQ","signatures":[]})
    def test_regen(self):
        from authlibjws.cli import _write_results
        with tempfile.TemporaryDirectory() as tmp:
            _write_results(Path(tmp))
            for name in ("cases.csv","summary.csv","SHA256SUMS"):
                self.assertEqual((ROOT/"results"/name).read_bytes(), (Path(tmp)/name).read_bytes())
if __name__ == "__main__":
    unittest.main()
