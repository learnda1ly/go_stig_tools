#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file.cklb>")
        sys.exit(1)

    path = Path(sys.argv[1])
    if not path.suffix == ".cklb":
        print("Error: input file must have .cklb extension", file=sys.stderr)
        sys.exit(1)

    data = json.loads(path.read_text())

    out_path = path.parent / f"formatted_{path.name}"
    out_path.write_text(json.dumps(data, indent=2) + "\n")
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
