"""Exercise the real PowerShell wrapper against synthetic data on a disposable runner."""
import hashlib
import pathlib
import runpy
import subprocess
import tempfile

def main():
    repo = pathlib.Path(__file__).resolve().parents[2]
    fixture = runpy.run_path(str(pathlib.Path(__file__).with_name("dll_dry_run_test.py")))["fixture"]
    wrapper = repo / "scripts" / "first_look.ps1"
    runtime = repo / "runtime" / "build" / "gta6rt.exe"
    # A stale non-executable sentinel must be replaced by the explicit build.
    runtime.parent.mkdir(parents=True, exist_ok=True)
    runtime.write_bytes(b"stale diagnostic sentinel")
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        image = root / "s3-wrapper-unknown.exe"
        data = fixture()
        image.write_bytes(data)
        (root / "fixture.dll").write_bytes(fixture(b"xmem.dll", b"XMemAlloc"))
        def run(expected, needle):
            result = subprocess.run(
                ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(wrapper),
                 "-Exe", str(image), "-GameDir", str(root)],
                cwd=root, capture_output=True, text=True, timeout=180, check=False)
            output = result.stdout + result.stderr
            print(output)
            if result.returncode != expected or needle not in output:
                raise AssertionError(f"wrapper exit {result.returncode}, expected {expected}")
        run(3, "Unimplemented imports")
        reports = repo / "reports" / "exe" / image.stem
        if hashlib.sha256(data).hexdigest() not in (reports / "hash.txt").read_text(encoding="utf-8-sig"):
            raise AssertionError("hash report mismatch")
        if "fixture.dll!Example" not in (reports / "dryrun.txt").read_text(encoding="utf-8-sig"):
            raise AssertionError("diagnostic report mismatch")
        if runtime.read_bytes()[:2] != b"MZ":
            raise AssertionError("direct build did not replace stale output")
        image = root / "s3-wrapper-known.exe"
        image.write_bytes(fixture(b"XMEM.DLL", b"XMemAlloc"))
        run(0, "xmem.dll!XMemAlloc")
        image = root / "s3-wrapper-invalid.exe"
        image.write_bytes(b"MZ" + bytes(62))
        run(1, "runtime dry-run failed (1)")
        print("PowerShell wrapper PASS: fresh direct build, exit 0/1/3, synthetic reports")

if __name__ == "__main__":
    main()
