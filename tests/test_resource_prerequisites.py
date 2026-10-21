"""Prerequisite diagnostics must work without third-party Python packages."""
import importlib.util
import hashlib
import io
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
        packages = {}
        for line in (SCRIPT.parent / "requirements.txt").read_text().splitlines():
            if line and not line.startswith("#"):
                requirement, _, marker = line.partition(";")
                name, pinned = requirement.strip().split("==", 1)
                # Platform-limited pins are only required on the host the marker selects.
                if not marker or name not in verifier.MEMPROCFS_PACKAGES or verifier.memprocfs_host():
                    packages[name] = pinned
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
