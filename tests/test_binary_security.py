"""Non-executable byte fixtures for the static native build policy."""
from pathlib import Path
import runpy
import struct
import unittest

p = runpy.run_path(str(Path(__file__).resolve().parents[1]/"scripts/binary_security.py"))
analyze = p["analyze"]


def fixture():
    b = bytearray(0xc00)
    def put(fmt, off, *values):
        struct.pack_into("<"+fmt,b,off,*values)
    b[:2] = b"MZ"
    put("I",0x3c,0x80)
    b[0x80:0x84] = b"PE\0\0"
    put("HHIIIHH",0x84,0x8664,3,0,0,0,240,0x22)
    o = 0x98
    put("H",o,0x20b)
    put("I",o+16,0x1000)
    put("Q",o+24,0x140000000)
    put("II",o+32,0x1000,0x200)
    put("II",o+56,0x4000,0x200)
    put("H",o+70,0x4160)
    put("I",o+108,16)
    for index,rva,size in ((1,0x2100,40),(5,0x3000,20),(10,0x2200,148),(12,0x2180,16)):
        put("II",o+112+index*8,rva,size)
    for i,(name,vs,va,rs,rp,flags) in enumerate((
        (b".text",0x200,0x1000,0x200,0x200,0x60000020),
        (b".rdata",0x600,0x2000,0x600,0x400,0x40000040),
        (b".reloc",0x200,0x3000,0x200,0xa00,0x42000040))):
        s=o+240+i*40
        b[s:s+len(name)]=name
        put("IIII",s+8,vs,va,rs,rp)
        put("I",s+36,flags)
    put("IIIII",0x500,0x2160,0,0,0x2150,0x2180)
    b[0x550:0x55d]=b"kernel32.dll\0"
    put("QQ",0x560,0x21a0,0)
    put("QQ",0x580,0x21a0,0)
    b[0x5a2:0x5ae]=b"VirtualFree\0"
    put("I",0x600,148)
    put("QQQQI",0x670,0x140002300,0x140002308,0x140002320,1,0x500)
    put("QQ",0x700,0x140001000,0x140001010)
    put("I",0x720,0x1000)
    put("IIHHHHHH",0xa00,0x2000,20,0xa270,0xa278,0xa280,0xa300,0xa308,0)
    return b


class BinaryPolicyTests(unittest.TestCase):
    def test_positive(self):
        b=fixture()
        r=analyze(b)
        self.assertEqual(r["direct_imports"],{"kernel32.dll":["VirtualFree"]})
        self.assertEqual(r["cfg"]["function_count"],1)
        self.assertEqual(r["sha256"],p["digest"](b))
        bom=p["make_sbom"](r,"a"*40,"cmake")
        self.assertEqual(bom["components"],[{"type":"library","name":"kernel32.dll","bom-ref":"pe-import:kernel32.dll"}])
        self.assertEqual(bom["metadata"]["component"]["hashes"][0]["content"],r["sha256"])

    def bad(self,fmt,off,*values):
        b=fixture()
        struct.pack_into("<"+fmt,b,off,*values)
        with self.assertRaises(ValueError):
            analyze(b)

    def test_header(self):
        self.bad("I",0x3c,0xffffffff)
        self.bad("H",0x84,0x14c)
        self.bad("H",0x98,0x10b)
        self.bad("H",0x86,0xffff)
        with self.assertRaises(ValueError): analyze(fixture()[:100])

    def test_mitigations(self):
        for bit in (0x20,0x40,0x100,0x4000):
            # NXCOMPAT is 0x100; the full required mask is 0x4160.
            self.bad("H",0x98+70,0x4160 & ~bit)
        self.bad("H",0x96,0x23)

    def test_sections(self):
        self.bad("I",0x98+240+36,0xe0000020)
        self.bad("I",0x98+240+40+12,0x1000)
        self.bad("I",0x98+240+40+20,0x200)
        self.bad("I",0x98+240+40+16,0xffffffff)
        self.bad("I",0x98+16,0x2000)

    def test_cfg(self):
        self.bad("I",0x600,144)
        self.bad("I",0x690,0x100)
        self.bad("Q",0x688,0)
        self.bad("Q",0x680,0xffffffffffffffff)
        self.bad("I",0x720,0x2000)
        self.bad("Q",0x688,262145)
        self.bad("I",0x98+240+40+36,0xc0000040)
        self.bad("Q",0x678,0x140002300)
        self.bad("Q",0x700,0)
        self.bad("Q",0x708,0x140002000)
        self.bad("I",0x690,0x10000500)
        self.bad("H",0xa0c,0)

    def test_imports(self):
        b=fixture()
        b[0x550:0x55d]=b"unknownx.dll\0"
        with self.assertRaises(ValueError): analyze(b)
        b=fixture()
        b[0x5a2:0x5b5]=b"WriteProcessMemory\0"
        with self.assertRaises(ValueError): analyze(b)
        self.bad("Q",0x560,0x8000000000000001)
        self.bad("I",0x500,0x4000)
        self.bad("II",0x98+112+13*8,0x2100,40)
        self.bad("I",0x514,1)
        self.bad("Q",0x580,0)
        self.bad("II",0x98+112+12*8,0,0)
        self.bad("II",0x98+112+12*8,0x2188,16)
        self.bad("I",0x510,0x2160)
        b=fixture()
        struct.pack_into("<QQ",b,0x560,0x8000000000000001,0)
        struct.pack_into("<QQ",b,0x580,0x8000000000000001,0)
        with self.assertRaisesRegex(ValueError,"ordinal"): analyze(b)

    def test_reloc(self):
        self.bad("I",0x98+112+5*8+4,0)
        self.bad("I",0xa04,0xffffffff)
        self.bad("H",0xa08,0x3270)
        self.bad("HH",0xa08,0,0)
        self.bad("H",0xa0a,0xa270)
        self.bad("H",0xa0a,0xa274)


if __name__ == "__main__":
    unittest.main()
