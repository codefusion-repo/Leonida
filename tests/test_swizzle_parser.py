"""Synthetic regression tests for the swizzle expression parser (no game data)."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

# The parser itself does not use NumPy. Stub only that optional dependency
# during module loading; these tests do not exercise texture operations.
path = Path(__file__).resolve().parents[1] / "tools" / "amd_swizzle.py"
spec = importlib.util.spec_from_file_location("amd_swizzle", path)
swizzle = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"numpy": types.ModuleType("numpy")}):
    spec.loader.exec_module(swizzle)


class SwizzleParserTests(unittest.TestCase):
    def test_zero_and_symbols(self):
        symbols = swizzle._symbols()
        self.assertEqual(swizzle._parse_mask("0", symbols), 0)
        for name, value in symbols.items():
            self.assertEqual(swizzle._parse_mask(name, symbols), value)

    def test_xor_and_whitespace(self):
        symbols = swizzle._symbols()
        self.assertEqual(swizzle._parse_mask(" X0 ^ Y2 ^ Z3 ^ S1 ", symbols),
                         1 ^ (1 << 18) ^ (1 << 35) ^ (1 << 49))
        self.assertEqual(swizzle._parse_mask("X0^X0", symbols), 0)

    def test_reject_non_grammar(self):
        for expression in ("", "X16", "X0+Y1", "X0|Y0", "X0^^Y0",
                           "X0^", "len([])", "X0.real", "X0[0]",
                           "(X0)", "1", "X0; Y1", "X0" * 600):
            with self.subTest(expression=expression):
                with self.assertRaises(ValueError):
                    swizzle._parse_mask(expression, swizzle._symbols())

    def test_load_synthetic_header(self):
        names = ("NIBBLE01", "NIBBLE2", "NIBBLE3", "NIBBLE4")
        header = "\n".join(
            f"const UINT_64 GFX10_SW_PATTERN_{name}[][2] =\n"
            "{\n{X0^Y1, 0, },\n};" for name in names)
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "fixture.h"
            file.write_text(header, encoding="utf-8")
            nibbles, tables = swizzle.load(file)
            self.assertEqual(nibbles, {name: [[1 ^ (1 << 17), 0]] for name in names})
            self.assertEqual(tables, {})
            file.write_text(header.replace("X0^Y1", "len([])"), encoding="utf-8")
            with self.assertRaises(ValueError):
                swizzle.load(file)
            file.write_text("", encoding="utf-8")
            with self.assertRaises(ValueError):
                swizzle.load(file)


if __name__ == "__main__":
    unittest.main()
