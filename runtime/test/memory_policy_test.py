"""Regression guard for native source memory policy (not a general security scanner)."""
import pathlib
import re

def main():
    root = pathlib.Path(__file__).resolve().parents[1]
    forbidden = re.compile(r"\b(?:PAGE_EXECUTE(?:_READ|_READWRITE|_WRITECOPY)?|make_unimplemented_thunk|FlushInstructionCache)\b")
    for path in sorted(root.rglob("*")):
        if path.suffix not in (".cpp", ".h"):
            continue
        if forbidden.search(path.read_text(encoding="utf-8")):
            raise SystemExit(f"Executable-memory policy regression: {path.relative_to(root)}")
    print("Native source memory policy PASS")

if __name__ == "__main__":
    main()
