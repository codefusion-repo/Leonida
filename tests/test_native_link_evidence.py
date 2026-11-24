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


    def test_observed_decorated_cpp_imports(self):
        cases = [
            ('struct _Cvtvec __cdecl std::_Locinfo::_Getcvt(void)const ',
             '?_Getcvt@_Locinfo@std@@QEBA?AU_Cvtvec@@XZ'),
            ('unsigned short const * __cdecl std::_Locinfo::_W_Getdays(void)const ',
             '?_W_Getdays@_Locinfo@std@@QEBAPEBGXZ'),
            ('unsigned short const * __cdecl std::_Locinfo::_W_Getmonths(void)const ',
             '?_W_Getmonths@_Locinfo@std@@QEBAPEBGXZ'),
        ]
        for description, symbol in cases:
            with self.subTest(symbol=symbol):
                found = f'Found "__declspec(dllimport) public: {description}" (__imp_{symbol})\n'
                trace = found + "Referenced in main.obj\nReferenced in pe_loader.obj\nLoaded msvcprt.lib(MSVCP140.dll)\n"
                # Repeated Found without references must not be sufficient by itself.
                records = p["parse_trace"](found + "Loaded msvcprt.lib(MSVCP140.dll)\n" + trace)
                maps = p["parse_map"](" Address Publics by Value Rva+Base Lib:Object\n"
                                      f" 0005:000003a8 __imp_{symbol} 000000014009b3a8 msvcprt:MSVCP140.dll\n")
                row = p["corroborate"](p["attribute"]([("msvcp140.dll", symbol)], records), maps)[0]
                self.assertTrue(row["provider_verified"])
                self.assertTrue(row["trace_provider_verified"])
                self.assertEqual(len(row["matches"]), 1)
                self.assertEqual(row["matches"][0]["references"], ["main.obj", "pe_loader.obj"])

    def test_decorated_format_fail_closed(self):
        symbol = "?Example@@YAXXZ"
        for found in (f'Found "description" (__imp_{symbol}) extra',
                      f'Found "description" (__imp_{symbol}',
                      f'Found "description" (__imp_{symbol}) (__imp_{symbol})',
                      f'Found "description __imp_{symbol}"'):
            with self.subTest(found=found):
                trace = found + "\nReferenced in a.obj\nLoaded example.lib(example.dll)\n"
                row = p["attribute"]([("example.dll", symbol)], p["parse_trace"](trace))[0]
                self.assertEqual(row["matches"], [])

    def test_no_cross_unrelated_line(self):
        records = p["parse_trace"]("Found __imp_X\nReferenced in a.obj\nUnrelated linker line\nLoaded b.lib(b.dll)\n")
        self.assertEqual(p["attribute"]([("b.dll", "X")], records)[0]["matches"], [])


if __name__ == "__main__":
    unittest.main()
