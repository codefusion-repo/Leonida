"""Synthetic MSVC verbose trace parsing; no compiler or executable invocation."""
from pathlib import Path
import runpy
import unittest

p = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/native_link_evidence.py"))


class LinkEvidenceTests(unittest.TestCase):
    def test_references(self):
        records = p["parse_trace"](
            " Searching kernel32.lib:\n"
            "   Found __imp_Example\n"
            "     Referenced in libcmt.lib(example.obj)\n"
            "     Loaded kernel32.lib(KERNEL32.dll)\n"
            "   Found Other\n"
            "     Loaded kernel32.lib(KERNEL32.dll)\n")
        rows = p["attribute"]([("kernel32.dll", "Example"), ("kernel32.dll", "Other")], records)
        self.assertEqual(rows[0]["matches"][0]["references"], ["libcmt.lib(example.obj)"])
        self.assertEqual(rows[1]["matches"], [])

    def test_difference(self):
        self.assertEqual(p["additional_imports"]({"a.dll": ["X"]}, {"a.dll": ["X", "Y"], "b.dll": ["X"]}),
                         [("a.dll", "Y"), ("b.dll", "X")])

    def test_no_cross_group_attribution(self):
        records = p["parse_trace"]("Found __imp_X\nReferenced in a.obj\nSearching b.lib:\nLoaded b.lib(b.obj)\n")
        self.assertEqual(p["attribute"]([("b.dll", "X")], records)[0]["matches"], [])

    def test_no_cross_blank_attribution(self):
        records = p["parse_trace"]("Found __imp_X\nReferenced in a.obj\n\nLoaded b.lib(b.obj)\n")
        self.assertEqual(p["attribute"]([("b.dll", "X")], records)[0]["matches"], [])


if __name__ == "__main__":
    unittest.main()
