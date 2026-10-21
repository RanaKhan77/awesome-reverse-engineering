"""Prerequisite diagnostics must work without third-party Python packages."""
import importlib.util
import hashlib
import io
import platform
import re
from importlib.metadata import PackageNotFoundError
from pathlib import Path
import subprocess
import sys
import tempfile
import tarfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "examples/resource-intake/verify.py"
spec = importlib.util.spec_from_file_location("resource_verify", SCRIPT)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


# Independent of the verifier: (sys_platform, platform_machine) -> packages pip should install beyond the
# always-required pins. MemProcFS is exercised only on Linux x86-64.
HOST_MATRIX = {
    ("linux", "x86_64"): {"memprocfs", "leechcorepyc"},
    ("linux", "aarch64"): set(),
    ("darwin", "arm64"): set(),
    ("darwin", "x86_64"): set(),
    ("win32", "AMD64"): set(),
}
PLATFORM_SYSTEM = {"linux": "Linux", "darwin": "Darwin", "win32": "Windows"}


def requirements():
    """Yield (name, version, marker) from requirements.txt without third-party packages."""
    for line in (SCRIPT.parent / "requirements.txt").read_text().splitlines():
        if line and not line.startswith("#"):
            requirement, _, marker = line.partition(";")
            name, pinned = requirement.strip().split("==", 1)
            yield name, pinned, marker.strip()


def marker_selects(marker, sys_platform, machine):
    """Evaluate the `name == "value"` clauses joined by `and` that requirements.txt uses."""
    if not marker:
        return True
    values = {"sys_platform": sys_platform, "platform_machine": machine}
    selected = True
    for clause in marker.split(" and "):
        match = re.fullmatch(r'\s*(sys_platform|platform_machine)\s*==\s*"([^"]*)"\s*', clause)
        if not match:
            raise AssertionError(f"Unsupported requirement marker: {marker}")
        selected = selected and values[match[1]] == match[2]
    return selected


class Prerequisites(unittest.TestCase):
    def test_missing_dependencies_print_install_command_without_traceback(self):
        with tempfile.TemporaryDirectory() as output:
            result = subprocess.run([sys.executable, "-S", str(SCRIPT), "--output", output], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Missing Python dependency: construct", result.stderr)
        self.assertIn("requirements.txt", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_help_does_not_need_dependencies(self):
        result = subprocess.run([sys.executable, "-S", str(SCRIPT), "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)

    def test_all_missing_pinned_packages_are_reported(self):
        packages = {name: pinned for name, pinned, marker in requirements() if marker_selects(marker, sys.platform, platform.machine())}
        for missing in packages:
            def installed(name):
                if name == missing:
                    raise PackageNotFoundError(name)
                return packages[name]
            with self.subTest(package=missing), patch.object(verifier, "version", side_effect=installed):
                with self.assertRaisesRegex(SystemExit, f"Missing Python dependency: {missing}"):
                    verifier.verify(Path("unused"), None)

    def test_wrong_pinned_version_is_actionable(self):
        with patch.object(verifier, "version", return_value="0.0"), self.assertRaisesRegex(SystemExit, "Expected construct==2.10.70"):
            verifier.verify(Path("unused"), None)

    def test_requirement_markers_match_verifier_on_each_host(self):
        always = {name for name, _, marker in requirements() if not marker}
        for (sys_platform, machine), extra in HOST_MATRIX.items():
            installed = {name for name, _, marker in requirements() if marker_selects(marker, sys_platform, machine)}
            with self.subTest(host=(sys_platform, machine)), patch.object(verifier.platform, "system", return_value=PLATFORM_SYSTEM[sys_platform]), patch.object(verifier.platform, "machine", return_value=machine):
                self.assertEqual(installed, always | extra)
                self.assertEqual(set(verifier.required_packages()), installed)

    def test_leechcore_path_keeps_existing_library_path(self):
        with patch.dict(verifier.os.environ, {"LD_LIBRARY_PATH": "/opt/existing/lib"}):
            env = verifier.memprocfs_env(Path("/wheel/leechcorepyc"))
        self.assertEqual(env["LD_LIBRARY_PATH"].split(verifier.os.pathsep), ["/wheel/leechcorepyc", "/opt/existing/lib"])
        with patch.dict(verifier.os.environ, clear=True):
            self.assertEqual(verifier.memprocfs_env(Path("/wheel/leechcorepyc"))["LD_LIBRARY_PATH"], "/wheel/leechcorepyc")

    def test_memprocfs_pins_are_required_only_on_its_host(self):
        installed = dict(verifier.MEMPROCFS_PACKAGES, **{"construct": "2.10.70", "scapy": "2.8.0", "yara-x": "1.21.0", "hermes-dec": "0.1.8", "malduck": "4.4.1"})
        for host, expected in [(("Darwin", "arm64"), "javac"), (("Linux", "x86_64"), "Missing Python dependency: memprocfs")]:
            def version(name):
                if name == "memprocfs":
                    raise PackageNotFoundError(name)
                return installed[name]
            with self.subTest(host=host), patch.object(verifier.platform, "system", return_value=host[0]), patch.object(verifier.platform, "machine", return_value=host[1]), patch.object(verifier, "version", side_effect=version), patch.object(verifier, "require_java", side_effect=SystemExit("javac")):
                with self.assertRaisesRegex(SystemExit, expected):
                    verifier.verify(Path("unused"), None)

    def test_missing_libusb_is_actionable(self):
        with patch.object(verifier.ctypes.util, "find_library", return_value=None), self.assertRaisesRegex(SystemExit, "libusb-1.0"):
            verifier.verify_memprocfs(Path("unused"))

    def test_java_versions_on_either_output_stream(self):
        for executable, stdout, stderr in [
            ("javac", "javac 17.0.1", ""),
            ("java", "", 'openjdk version "17.0.1"'),
            ("java", 'openjdk 21.0.1 2023-10-17', ""),
        ]:
            with self.subTest(output=stdout + stderr), patch.object(verifier.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout, stderr)):
                verifier.require_java(executable)

    def test_old_or_unknown_java_is_rejected(self):
        for output in ['javac 11.0.2', 'java version "1.8.0_442"', 'unrecognized version']:
            with self.subTest(output=output), patch.object(verifier.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "")):
                with self.assertRaisesRegex(SystemExit, "requires JDK 17"):
                    verifier.require_java("java")

    def test_missing_or_broken_java_has_no_raw_exception(self):
        for failure in [FileNotFoundError(), subprocess.CalledProcessError(1, ["java", "-version"])]:
            with self.subTest(failure=type(failure).__name__), patch.object(verifier.subprocess, "run", side_effect=failure):
                with self.assertRaisesRegex(SystemExit, "Install JDK 17"):
                    verifier.require_java("java")

    def test_windows_hermes_compiler_keeps_required_runtime_dlls(self):
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as tar:
            for name, data in [("hermesc.exe", b"compiler"), ("icuuc64.dll", b"runtime")]:
                member = tarfile.TarInfo("package/hermesc/win64-bin/" + name)
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
        data = archive.getvalue()
        with tempfile.TemporaryDirectory() as output, patch.object(verifier.platform, "system", return_value="Windows"), patch.object(verifier.platform, "machine", return_value="AMD64"), patch.object(verifier, "urlopen", return_value=io.BytesIO(data)), patch.object(verifier, "HERMESC", {98: ("https://example.test/compiler", hashlib.sha256(data).hexdigest())}):
            compiler = verifier.hermesc(Path(output), 98)
            self.assertEqual(compiler.name, "hermesc.exe")
            self.assertEqual(compiler.read_bytes(), b"compiler")
            self.assertEqual((compiler.parent / "icuuc64.dll").read_bytes(), b"runtime")

    def test_unsupported_hermes_host_exits_before_downloading(self):
        with patch.object(verifier.platform, "system", return_value="Linux"), patch.object(verifier.platform, "machine", return_value="aarch64"), patch.object(verifier, "urlopen") as download:
            with self.assertRaisesRegex(SystemExit, "pinned Hermes compilers require"):
                verifier.hermesc(Path("unused"), 98)
            download.assert_not_called()


if __name__ == "__main__":
    unittest.main()
