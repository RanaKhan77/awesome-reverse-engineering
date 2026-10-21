"""Compile fixture.py for CPython 3.11-3.13, decompile it with PyLingual, and check behavior against the original."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parent
VERSIONS = ("3.11", "3.12", "3.13")
ORACLE = """
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("m", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
print(json.dumps({
    "classify": [m.classify(v) for v in (-3, 0, 4, 7)],
    "checksum": [m.checksum(b"trace"), m.checksum(bytes([0, 1, 0, 2])), m.checksum(b"")],
    "parse_port": [m.parse_port(v) for v in ("8080", "x", "0", "70000")],
    "squares": m.squares(8),
    "label": m.label("trace", 7),
}, sort_keys=True))
"""
COMPILE = "import py_compile, sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True, invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH)"


def python(version, *args):
    command = ["uv", "run", "--quiet", "--no-project", "--python", version, "python", *args]
    return subprocess.run(command, text=True, capture_output=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pylingual", required=True, help="pylingual executable from the pinned checkout")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="pylingual-", dir=args.output))
    expected = json.loads(python("3.12", "-c", ORACLE, str(SOURCE / "fixture.py")).stdout)
    assert expected["parse_port"] == [8080, -1, -2, -2], expected
    results = []
    for version in VERSIONS:
        pyc, out = work / f"fixture.{version}.pyc", work / f"out-{version}"
        assert python(version, "-c", COMPILE, str(SOURCE / "fixture.py"), str(pyc)).returncode == 0
        subprocess.run([args.pylingual, "-q", "-c", str(SOURCE / "pinned_config.yaml"), "-o", str(out), str(pyc)], check=True, capture_output=True)
        decompiled = out / f"decompiled_fixture.{version}.py"
        failures = re.findall(r"# \*\*\*<module>\.(\w+): Failure: (.+)", decompiled.read_text())
        observed = python(version, "-c", ORACLE, str(decompiled))
        behavior = json.loads(observed.stdout) if observed.returncode == 0 else None
        if version == "3.11":
            assert failures == [("parse_port", "Compilation Error")], failures
            assert behavior is None and "SyntaxError" in observed.stderr
        else:
            assert failures == [("parse_port", "Different control flow")], failures
            assert {k: v for k, v in behavior.items() if k != "parse_port"} == {k: v for k, v in expected.items() if k != "parse_port"}
            assert behavior["parse_port"] == [-2, -1, -2, -2], behavior["parse_port"]
        results.append({"version": version, "pyc_sha256": hashlib.sha256(pyc.read_bytes()).hexdigest(),
                        "flagged_failures": failures, "behavior": behavior})
    report = {"host": {"platform": platform.platform()}, "expected": expected, "results": results}
    (args.output / "pylingual-results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
