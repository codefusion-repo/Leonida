"""Verify the parser against a pinned public Mesa 25.0.0 header (data only)."""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import tempfile

HEADER_BYTES = 504619
HEADER_SHA256 = "5029e548dd641742d4ef8fe6485f4433f9e3e44342c547daacb9e902c8aaebc3"
RESULT_SHA256 = "989f81aea66ccf17ea5cc7fa4b500b855372f9728d8a61e90ec02108d95e9b0f"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("header", type=Path)
    args = parser.parse_args()
    with args.header.open("rb") as stream:
        data = stream.read(HEADER_BYTES + 1)
    if len(data) != HEADER_BYTES or hashlib.sha256(data).hexdigest() != HEADER_SHA256:
        raise SystemExit("Mesa reference size or SHA-256 mismatch")

    # Reuse the parser-only loader; no NumPy installation or game assets.
    swizzle = runpy.run_path(str(Path(__file__).with_name("test_swizzle_parser.py")))["swizzle"]
    with tempfile.TemporaryDirectory() as folder:
        verified = Path(folder) / "reference.h"
        verified.write_bytes(data)
        nibbles, tables = swizzle.load(verified)
    rows = [len(nibbles[name]) for name in swizzle.NIBBLE_WIDTHS]
    masks = sum(len(row) for table in nibbles.values() for row in table)
    entries = sum(map(len, tables.values()))
    if (rows, masks, len(tables), entries) != ([40, 510, 842, 239], 6684, 60, 3460):
        raise SystemExit("Mesa reference table counts mismatch")

    # Preserve order and compare every decoded 64-bit mask and pattern entry,
    # including the original labels, against the independently computed digest.
    canonical = [[(name, [[str(mask) for mask in row] for row in table])
                  for name, table in nibbles.items()], list(tables.items())]
    result = hashlib.sha256(json.dumps(canonical, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
    if result != RESULT_SHA256:
        raise SystemExit("Mesa reference decoded data mismatch")
    print(f"Mesa reference PASS: {masks} masks, {len(tables)} pattern tables, {entries} entries")
    print(f"header_sha256={HEADER_SHA256}\nresult_sha256={result}")


if __name__ == "__main__":
    main()
