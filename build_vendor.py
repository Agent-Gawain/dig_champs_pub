#!/usr/bin/env python3
"""
build_vendor.py — Pre-download dig_champs dependencies for air-gapped deployment.

Run this ONCE on an internet-connected machine:
    python3 build_vendor.py

This creates a _vendor/ directory alongside this script containing the full
requests, rich, and anthropic packages. Transfer the entire folder to any
air-gapped target alongside dig_champs(1).py — no pip required on the target.

Optionally also builds a single-file dig_champs.pyz zipapp (pass --pyz).
"""

import argparse
import os
import subprocess
import sys
import zipapp
import zipfile
from pathlib import Path

HERE   = Path(__file__).parent.resolve()
VENDOR = HERE / "_vendor"
MAIN   = HERE / "dig_champs(1).py"
PYZ    = HERE / "dig_champs.pyz"

PACKAGES = ["requests", "rich", "anthropic"]


def build_vendor():
    print(f"[*] Installing packages into {VENDOR} ...")
    VENDOR.mkdir(exist_ok=True)
    subprocess.run(
        [sys.executable, "-m", "pip", "install",
         "--target", str(VENDOR),
         "--no-user",
         "--quiet",
         *PACKAGES],
        check=True,
    )
    print(f"[+] _vendor/ populated with: {', '.join(PACKAGES)}")


def build_pyz():
    """Bundle dig_champs(1).py + _vendor/ + stub files into a single .pyz."""
    if not MAIN.exists():
        print(f"[!] {MAIN} not found — cannot build .pyz")
        return

    STUB_FILES = [HERE / "_dc_http.py", HERE / "_dc_rich.py"]

    # A zipapp needs a __main__.py entry point
    main_source = MAIN.read_text(encoding="utf-8")

    # Replace the shebang line if present so __main__.py is valid
    lines = main_source.splitlines(keepends=True)
    if lines and lines[0].startswith("#!"):
        lines[0] = "# (shebang removed for zipapp)\n"
    main_source = "".join(lines)

    import io, tempfile
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        # Write __main__.py
        (tmp / "__main__.py").write_text(main_source, encoding="utf-8")

        # Copy stub files
        for stub in STUB_FILES:
            if stub.exists():
                (tmp / stub.name).write_bytes(stub.read_bytes())

        # Copy _vendor/ tree if present
        if VENDOR.is_dir():
            import shutil
            shutil.copytree(str(VENDOR), str(tmp / "_vendor"))

        zipapp.create_archive(str(tmp), str(PYZ), interpreter="/usr/bin/env python3")

    print(f"[+] Single-file archive → {PYZ}")
    print(f"    Usage: python3 dig_champs.pyz -t <target>")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pyz", action="store_true",
                        help="Also build a single-file dig_champs.pyz zipapp after vendoring")
    parser.add_argument("--pyz-only", action="store_true",
                        help="Only build the .pyz (assumes _vendor/ already populated)")
    args = parser.parse_args()

    if not args.pyz_only:
        build_vendor()

    if args.pyz or args.pyz_only:
        build_pyz()

    if not args.pyz and not args.pyz_only:
        print()
        print("Transfer these files/folders to your air-gapped target:")
        print(f"  {MAIN.name}")
        print(f"  _vendor/")
        print(f"  _dc_http.py")
        print(f"  _dc_rich.py")
        print()
        print("Or re-run with --pyz for a single-file bundle instead.")


if __name__ == "__main__":
    main()
