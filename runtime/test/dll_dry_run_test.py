"""Generate a data-only PE and verify dry-run ignores neighboring DLL files."""
import pathlib
import struct
import subprocess
import sys
import tempfile

def fixture():
    b = bytearray(0x600)
    def put(offset, value, fmt="I"):
        struct.pack_into("<" + fmt, b, offset, value)
    nt = 0x80
    opt = nt + 24
    sec = opt + 240
    put(0, 0x5a4d, "H")
    put(0x3c, nt)
    put(nt, 0x4550)
    put(nt + 4, 0x8664, "H")
    put(nt + 6, 1, "H")
    put(nt + 20, 240, "H")
    put(nt + 22, 2, "H")
    put(opt, 0x20b, "H")
    put(opt + 24, 0x140000000, "Q")
    put(opt + 32, 0x1000)
    put(opt + 36, 0x200)
    put(opt + 56, 0x2000)
    put(opt + 60, 0x200)
    put(opt + 108, 16)
    put(sec + 8, 0x400)
    put(sec + 12, 0x1000)
    put(sec + 16, 0x400)
    put(sec + 20, 0x200)
    put(sec + 36, 0xc0000040)
    put(opt + 120, 0x1000)
    put(opt + 124, 40)
    put(0x200, 0x1080)
    put(0x20c, 0x1040)
    put(0x210, 0x10a0)
    b[0x240:0x24c] = b"fixture.dll\0"
    put(0x280, 0x10c0, "Q")
    put(0x2a0, 0x10c0, "Q")
    b[0x2c2:0x2ca] = b"Example\0"
    return b

def main():
    exe = pathlib.Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        image = root / "fixture.exe"
        image.write_bytes(fixture())
        # Deliberately invalid neighbor: any recursive mapping would fail.
        (root / "fixture.dll").write_bytes(b"not a PE")
        result = subprocess.run(
            [str(exe), "--dry-run", str(image), "--game-dir", str(root)],
            cwd=root, capture_output=True, text=True, timeout=20, check=False)
        print(result.stdout)
        print(result.stderr)
        if result.returncode != 3 or "fixture.dll!Example" not in result.stdout or \
                "1 module(s) mapped, 1 unimplemented import(s)" not in result.stdout or \
                "--game-dir is ignored" not in result.stderr:
            raise SystemExit("diagnostic-only integration failed")
        print("DLL dry-run integration PASS")

if __name__ == "__main__":
    main()
