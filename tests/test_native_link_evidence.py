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


    def test_map_and_trace_provider(self):
        text = (" Address Publics by Value Rva+Base Lib:Object\n"
                " 0002:00000010 __imp_Example 0000000140002010 kernel32:KERNEL32.dll\n"
                " entry point at 0001:00000000\n")
        records = p["parse_trace"]("Found __imp_Example\nReferenced in crt.lib(example.obj)\nLoaded kernel32.lib(KERNEL32.dll)\n")
        maps = p["parse_map"](text)
        row = p["corroborate"](p["attribute"]([("kernel32.dll", "Example")], records), maps)[0]
        self.assertTrue(row["provider_verified"])
        self.assertTrue(row["trace_provider_verified"])
        wrong = p["corroborate"](p["attribute"]([("other.dll", "Example")], records), maps)[0]
        self.assertFalse(wrong["provider_verified"])
        self.assertFalse(wrong["trace_provider_verified"])

    def test_map_does_not_replace_reference(self):
        maps = p["parse_map"](" Address Publics by Value Rva+Base Lib:Object\n"
                              " 0002:00000010 __imp_Example 0000000140002010 kernel32:KERNEL32.dll\n")
        row = p["corroborate"](p["attribute"]([("kernel32.dll", "Example")], {}), maps)[0]
        self.assertTrue(row["provider_verified"])
        self.assertFalse(row["trace_provider_verified"])

    def test_ambiguous_map_and_substring(self):
        text = (" Address Publics by Value Rva+Base Lib:Object\n"
                " 0002:00000010 __imp_X 0000000140002010 lib:kernel32.dll\n"
                " 0002:00000018 __imp_X 0000000140002018 lib:kernel32.dll\n"
                " 0002:00000020 __imp_Y 0000000140002020 lib:fakekernel32.dll\n")
        rows = p["corroborate"](p["attribute"]([("kernel32.dll", "X"), ("kernel32.dll", "Y")], {}), p["parse_map"](text))
        self.assertTrue(all(not row["provider_verified"] for row in rows))


if __name__ == "__main__":
    unittest.main()
