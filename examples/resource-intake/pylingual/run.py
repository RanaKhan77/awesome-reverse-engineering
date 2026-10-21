"""Compile fixture.py for CPython 3.11-3.13, decompile it with PyLingual, and check behavior against the original."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parent
VERSIONS = ("3.11", "3.12", "3.13")
# Load each top-level function on its own, so a function that does not compile cannot hide the others.
ORACLE = """
import json, sys
source = open(sys.argv[1]).read()
chunks = {}
for chunk in source.split("\\ndef ")[1:]:
    chunks[chunk.split("(", 1)[0]] = "def " + chunk
calls = {
    "classify": lambda f: [f(v) for v in (-3, 0, 4, 7)],
    "checksum": lambda f: [f(b"trace"), f(bytes([0, 1, 0, 2])), f(b"")],
    "parse_port": lambda f: [f(v) for v in ("8080", "x", "0", "70000")],
    "squares": lambda f: f(8),
    "label": lambda f: f("trace", 7),
}
behavior, syntax_errors = {}, []
for name, call in calls.items():
    namespace = {}
    try:
        exec(compile(chunks[name], name, "exec"), namespace)
    except SyntaxError:
        syntax_errors.append(name)
        continue
    behavior[name] = call(namespace[name])
print(json.dumps({"behavior": behavior, "syntax_errors": syntax_errors}, sort_keys=True))
"""
COMPILE = "import py_compile, sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True, invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH)"
INPUTS = ("fixture.py", "pinned_config.yaml", "run.py")


def python(version, *args):
    command = ["uv", "run", "--quiet", "--no-project", "--python", version, "python", *args]
    return subprocess.run(command, text=True, capture_output=True)


def observe(version, path):
    observed = python(version, "-c", ORACLE, str(path))
    observed.check_returncode()
    return json.loads(observed.stdout)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pylingual_environment(executable):
    """Record the checkout commit and package versions of the PyLingual install that ran."""
    checkout = Path(executable).resolve().parents[2]
    commit = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True, capture_output=True, check=True).stdout.strip()
    probe = """
import importlib.metadata as m, json, sys
xdis = m.distribution("xdis")
vcs = json.loads(xdis.read_text("direct_url.json") or "{}").get("vcs_info", {})
print(json.dumps({"python": sys.version.split()[0], "torch": m.version("torch"), "transformers": m.version("transformers"),
                  "xdis": xdis.version + (f" (git {vcs['commit_id']})" if "commit_id" in vcs else "")}))
"""
    versions = subprocess.run([str(Path(executable).parent / "python"), "-c", probe], text=True, capture_output=True, check=True).stdout
    return {"repository": "https://github.com/syssec-utd/pylingual", "commit": commit, "install": "uv sync --frozen", **json.loads(versions)}


def tokenizer_revisions():
    """Tokenizers follow their default branch, so record the revision the Hugging Face cache resolved."""
    hub = Path(os.environ.get("HF_HUB_CACHE") or Path(os.environ.get("HF_HOME") or Path.home() / ".cache/huggingface") / "hub")
    revisions = {}
    for repo in re.findall(r"^\s*TOKENIZER:\s*(\S+)", (SOURCE / "pinned_config.yaml").read_text(), re.M):
        ref = hub / f"models--{repo.replace('/', '--')}" / "refs" / "main"
        revisions[repo] = ref.read_text().strip() if ref.exists() else None
    return revisions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pylingual", required=True, help="pylingual executable from the pinned checkout")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="pylingual-", dir=args.output))
    expected = observe("3.12", SOURCE / "fixture.py")["behavior"]
    if expected["parse_port"] != [8080, -1, -2, -2]:
        raise SystemExit(f"Unexpected fixture behavior: {expected}")
    others = {name: value for name, value in expected.items() if name != "parse_port"}
    results = []
    for version in VERSIONS:
        pyc, out = work / f"fixture.{version}.pyc", work / f"out-{version}"
        python(version, "-c", COMPILE, str(SOURCE / "fixture.py"), str(pyc)).check_returncode()
        subprocess.run([args.pylingual, "-q", "-c", str(SOURCE / "pinned_config.yaml"), "-o", str(out), str(pyc)], check=True, capture_output=True)
        decompiled = out / f"decompiled_fixture.{version}.py"
        failures = [list(failure) for failure in re.findall(r"# \*\*\*<module>\.(\w+): Failure: (.+)", decompiled.read_text())]
        observed = observe(version, decompiled)
        behavior = observed["behavior"]
        if {name: value for name, value in behavior.items() if name != "parse_port"} != others:
            raise SystemExit(f"{version}: unflagged functions changed behavior: {behavior}")
        if version == "3.11":
            checks = failures == [["parse_port", "Compilation Error"]] and observed["syntax_errors"] == ["parse_port"]
        else:
            checks = failures == [["parse_port", "Different control flow"]] and not observed["syntax_errors"] and behavior["parse_port"] == [-2, -1, -2, -2]
        if not checks:
            raise SystemExit(f"{version}: unexpected flagged failures {failures} or parse_port result {observed}")
        results.append({"version": version, "pyc_sha256": sha256(pyc), "flagged_failures": failures,
                        "syntax_errors": observed["syntax_errors"], "behavior": behavior})
    report = {
        "checked_at": datetime.now(timezone.utc).date().isoformat(),
        "host": {"platform": platform.platform()},
        "pylingual": pylingual_environment(args.pylingual),
        "models": "pinned_config.yaml (tokenizers resolved from their default branch; see README)",
        "tokenizer_revisions_observed": tokenizer_revisions(),
        "expected": expected,
        "results": results,
        "inputs": [{"path": name, "sha256": sha256(SOURCE / name)} for name in INPUTS],
    }
    (args.output / "pylingual-results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
