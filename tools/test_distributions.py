#!/usr/bin/env python3
"""Run the offline suite and consumer golden check from built distributions."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from build_reproducible import SDIST_FILENAME, SDIST_ROOT, VERSION, WHEEL_FILENAME


def run(command: list[str], *, cwd: Path, extra_env: dict[str, str] | None = None) -> None:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    if extra_env:
        environment.update(extra_env)
    subprocess.run(command, cwd=cwd, env=environment, check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    directory = args.directory.resolve()
    sdist = directory / SDIST_FILENAME
    wheel = directory / WHEEL_FILENAME
    with tempfile.TemporaryDirectory(prefix="technocore-dist-test-") as temporary:
        root = Path(temporary)
        with tarfile.open(sdist, "r:gz") as archive:
            archive.extractall(root, filter="data")
        source = root / SDIST_ROOT
        run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=source)
        smoke = (
            "import sys; sys.path.insert(0, sys.argv[1]); "
            "import technocore_workflow_bridge as package; "
            f"assert package.__version__ == '{VERSION}'; "
            "assert 'sanitize_records' in package.__all__"
        )
        run([sys.executable, "-B", "-c", smoke, str(wheel)], cwd=root)
        golden = (
            "import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
            "from technocore_workflow_bridge.consumer import decode_jsonl, sanitized_jsonl; "
            "base=Path(sys.argv[2]); "
            "actual=sanitized_jsonl(decode_jsonl((base/'examples/golden/bridge-records.jsonl').read_bytes())); "
            "expected=(base/'examples/golden/sanitized-records.jsonl').read_bytes(); "
            "assert actual == expected"
        )
        run([sys.executable, "-B", "-c", golden, str(wheel), str(source)], cwd=root)
    print("sdist_tests=PASS")
    print("wheel_import_and_golden=PASS")


if __name__ == "__main__":
    main()
