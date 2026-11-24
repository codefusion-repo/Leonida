"""Data-only lifecycle integration; never execute the fixture."""
import pathlib
import runpy
import subprocess
import sys
import tempfile

def main():
    fixture = runpy.run_path(str(pathlib.Path(__file__).with_name("dll_dry_run_test.py")))["fixture"]
    exe = pathlib.Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        good, bad = root / "good.exe", root / "bad.exe"
        good.write_bytes(fixture())
        bad.write_bytes(fixture(b"CON.dll"))
        subprocess.run([str(exe), str(good), str(bad)], check=True, timeout=30)

if __name__ == "__main__":
    main()
