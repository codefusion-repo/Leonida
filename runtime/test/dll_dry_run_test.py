"""Generate a data-only PE and verify dry-run ignores neighboring DLL files."""
import pathlib
import struct
import subprocess
import sys
import tempfile

def fixture(dll=b"fixture.dll", symbol=b"Example"):
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
    b[0x240:0x240 + len(dll) + 1] = dll + b"\0"
    put(0x280, 0x10c0, "Q")
    put(0x2a0, 0x10c0, "Q")
    b[0x2c2:0x2c2 + len(symbol) + 1] = symbol + b"\0"
    return b

def main():
    exe = pathlib.Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        image = root / "fixture.exe"
        image.write_bytes(fixture())
        # Deliberately invalid neighbor: any recursive mapping would fail.
        (root / "fixture.dll").write_bytes(b"not a PE")
        def run(args, code, stdout="", stderr=""):
            result = subprocess.run([str(exe), *map(str, args)], cwd=root,
                                    capture_output=True, text=True, timeout=20, check=False)
            if result.returncode != code or stdout not in result.stdout or stderr not in result.stderr:
                raise AssertionError(f"expected exit {code}: {args!r}\n{result.returncode}\n{result.stdout}\n{result.stderr}")
            if code in (0, 3) and "diagnostic dynamic-code mitigation active" not in result.stderr:
                raise AssertionError("diagnostic process mitigation not confirmed")
            return result

        run(["--dry-run", image, "--game-dir", root], 3,
            "1 module(s) mapped, 1 unimplemented import(s)", "--game-dir is ignored")
        # A valid neighboring PE must also be ignored, not merely rejected.
        (root / "fixture.dll").write_bytes(fixture(b"xmem.dll", b"XMemAlloc"))
        run(["--dry-run", image], 3, "fixture.dll!Example")
        image.write_bytes(fixture(b"XMEM.DLL", b"XMemAlloc"))
        run(["--dry-run", image], 0, "xmem.dll!XMemAlloc")
        image.write_bytes(fixture(b"d3d12_xs.dll", b"D3D12SerializeVersionedRootSignature"))
        run(["--dry-run", image], 0, "d3d12_xs.dll!D3D12SerializeVersionedRootSignature")
        image.write_bytes(fixture(b"kernel32.dll", b"GetCurrentProcess"))
        run(["--dry-run", image], 3, "kernel32.dll!GetCurrentProcess")
        image.write_bytes(fixture(b"CON.dll", b"Example"))
        run(["--dry-run", image], 1, stderr="reserved Windows device basename")
        image.write_bytes(b"invalid")
        run(["--dry-run", image], 1)
        for args in ([image], ["--dry-run"], ["--dry-run", "--dry-run", image],
                     ["--dry-run", "--unknown"], ["--dry-run", image, "--game-dir"],
                     ["--dry-run", image, "--game-dir", "--dry-run"],
                     ["--dry-run", image, "--game-dir", root, "--game-dir", root],
                     ["--dry-run", image, image]):
            run(args, 2)
        dash = root / "-fixture.exe"
        dash.write_bytes(fixture())
        run(["--dry-run", "--", "-fixture.exe"], 3, "fixture.dll!Example")
        print("DLL dry-run integration PASS: registered, unresolved, invalid, CLI and neighboring PE cases")

if __name__ == "__main__":
    main()
