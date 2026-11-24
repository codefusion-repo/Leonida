"""Data-only lifecycle integration; never execute the fixture."""
import pathlib
import runpy
import subprocess
import sys
import tempfile
import struct

def main():
    fixture = runpy.run_path(str(pathlib.Path(__file__).with_name("dll_dry_run_test.py")))["fixture"]
    exe = pathlib.Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        good, bad = root / "good.exe", root / "bad.exe"
        data = bytearray(fixture())
        # Add a distinct section requesting executable PE characteristics.
        # It contains zeros, never instructions, and is never called.
        nt = struct.unpack_from("<I", data, 0x3c)[0]
        opt = nt + 24
        sections = opt + struct.unpack_from("<H", data, nt + 20)[0]
        count = struct.unpack_from("<H", data, nt + 6)[0]
        assert count == 1
        section = sections + 40
        assert section + 40 <= struct.unpack_from("<I", data, opt + 60)[0]
        raw = len(data)
        assert raw % 0x200 == 0
        data.extend(bytes(0x200))
        struct.pack_into("<H", data, nt + 6, 2)
        struct.pack_into("<I", data, opt + 56, 0x3000)
        struct.pack_into("<8sIIIIIIHHI", data, section, b".text", 0x200,
                         0x2000, 0x200, raw, 0, 0, 0, 0, 0x60000020)
        good.write_bytes(data)
        bad.write_bytes(fixture(b"CON.dll"))
        subprocess.run([str(exe), str(good), str(bad)], check=True, timeout=30)

if __name__ == "__main__":
    main()
