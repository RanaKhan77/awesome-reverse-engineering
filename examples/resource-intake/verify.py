"""Reproduce seven narrow resource examples with independent expected outputs."""
import argparse
import ctypes.util
from datetime import datetime, timezone
import hashlib
from importlib.metadata import PackageNotFoundError, version
import io
import json
import os
from pathlib import Path
import platform
import re
import struct
import subprocess
import sys
import tarfile
import tempfile
from urllib.request import urlopen


SOURCE = Path(__file__).resolve().parent
JAR_URL = "https://github.com/Vineflower/vineflower/releases/download/1.12.0/vineflower-1.12.0.jar"
JAR_SHA256 = "1dfcfe974395734fa467ce620661c7623d05ba83670de0529b1fbd63ff548b9d"
GOLDEN = bytes.fromhex("534d4b310500017472616365")
EXPECTED_BRANCHES = "-1:-1\n0:11\n1:22\n2:22\n9:-1"
HERMESC = {
    98: ("https://registry.npmjs.org/hermes-compiler/-/hermes-compiler-250829098.0.19.tgz",
         "839af099f0926b5ebbd738ba54764a3f40e35dfc3aac91babf56f8eb7c69280e"),
    99: ("https://registry.npmjs.org/hermes-compiler/-/hermes-compiler-260318099.0.4.tgz",
         "613b6230cf796bd1b6a8248e2cf8fb2799a5be92d23d49e96ee0b68dc2bfdcf2"),
}
HBC_ORIGINAL_OUTPUT = "even:negative:25"
HBC_PSEUDOCODE_OUTPUT = "even:negative:21"


DUCK_KEY = b"duck-key"
DUCK_PLAIN = b"c2=http://192.0.2.10/gate;c2=http://198.51.100.7/gate;campaign=trace-7;sleep=300"
DUCK_CONFIG = {"family": "duckcfg", "urls": ["http://192.0.2.10/gate", "http://198.51.100.7/gate"], "campaign": "trace-7", "sleep": 300}
MEMPROCFS_PACKAGES = {"memprocfs": "5.19.0", "leechcorepyc": "2.23.3"}
PML4, PDPT, PD, PT, PAGE = 0x10000, 0x11000, 0x12000, 0x13000, 0x345000
FIXTURE_VA = 0x140001678

def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checksum(data):
    """Independent RFC 1071-style checksum for the small packet fixture."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def run(*args, env=None):
    completed = subprocess.run(args, text=True, capture_output=True, check=True, env=env)
    return completed.stdout.strip()


def hermesc(work, bytecode_version):
    hosts = {"Linux": "linux64-bin", "Darwin": "osx-bin", "Windows": "win64-bin"}
    system = platform.system()
    if system not in hosts or (system != "Darwin" and platform.machine().lower() not in ("x86_64", "amd64")):
        raise SystemExit("The pinned Hermes compilers require Linux/Windows x86-64 or macOS x86-64/arm64.")
    url, digest = HERMESC[bytecode_version]
    with urlopen(url, timeout=120) as response:
        archive = response.read()
    assert hashlib.sha256(archive).hexdigest() == digest, f"hermes-compiler {bytecode_version} digest mismatch"
    prefix = Path("package/hermesc") / hosts[system]
    directory = work / f"hermesc-{bytecode_version}"
    directory.mkdir()
    target = directory / ("hermesc.exe" if system == "Windows" else "hermesc")
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        # Windows needs the runtime DLLs beside hermesc.exe, not just the executable.
        for member in tar.getmembers():
            if member.isfile() and Path(member.name).parent == prefix:
                (directory / Path(member.name).name).write_bytes(tar.extractfile(member).read())
    target.chmod(0o755)
    return target


def verify_hermes_dec(work):
    tools = Path(sys.executable).parent
    suffix = ".exe" if platform.system() == "Windows" else ""
    shim = "globalThis.print = console.log; new Function(require('fs').readFileSync(process.argv[1], 'utf8'))();"
    assert run("node", "-e", shim, str(SOURCE / "hbc_fixture.js")) == HBC_ORIGINAL_OUTPUT
    digests = {}
    for bytecode_version in HERMESC:
        compiler = hermesc(work, bytecode_version)
        bare, hbc = [work / f"fixture-{bytecode_version}-{level}.hbc" for level in ("g0", "g1")]
        for level, output in (("-g0", bare), ("-g1", hbc)):
            run(str(compiler), "-emit-binary", level, "-out", str(output), str(SOURCE / "hbc_fixture.js"))
            assert output.read_bytes()[8] == bytecode_version, "Unexpected HBC header version"
        parsed = subprocess.run([str(tools / ("hbc-file-parser" + suffix)), str(bare)], text=True, capture_output=True, check=True)
        assert f"| Version                      | {bytecode_version}" in parsed.stdout
        assert "not formally supported" in parsed.stderr
        # With backtrace location info (-g1), the header prints but debug-info parsing raises a TypeError.
        parsed = subprocess.run([str(tools / ("hbc-file-parser" + suffix)), str(hbc)], text=True, capture_output=True)
        assert parsed.returncode == 1 and f"| Version                      | {bytecode_version}" in parsed.stdout
        assert "debug_info_parser.py" in parsed.stderr and "TypeError" in parsed.stderr
        for binary in (bare, hbc):
            hasm, pseudo = binary.with_suffix(".hasm"), binary.with_suffix(".js")
            run(str(tools / ("hbc-disassembler" + suffix)), str(binary), str(hasm))
            run(str(tools / ("hbc-decompiler" + suffix)), str(binary), str(pseudo))
            listing, code = hasm.read_text(), pseudo.read_text()
            for needle in ('Function #1 "classify"', 'Function #2 "scaled"', "<Mod>", "'hbc-fixture-marker'"):
                assert needle in listing, (binary.name, needle)
            for needle in ("// Original name: classify", "// Original name: scaled", "'negative'", "'zero'", "'even'", "'odd'", "r0 = 7;"):
                assert needle in code, (binary.name, needle)
            # The pseudo-code shares register variables across functions, so running it does not reproduce the original.
            assert run("node", "-e", shim, str(pseudo)) == HBC_PSEUDOCODE_OUTPUT, binary.name
        digests[bytecode_version] = {"g0": sha256(bare), "g1": sha256(hbc)}
    return digests


def require_java(executable):
    try:
        completed = subprocess.run([executable, "-version"], text=True, capture_output=True, check=True)
    except FileNotFoundError as exc:
        raise SystemExit(
            f"{executable} was not found. Install JDK 17 or newer and retry."
        ) from exc
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"Cannot query {executable} version. Install JDK 17 or newer and retry.") from exc
    output = completed.stdout + completed.stderr
    match = re.search(r'\b(?:javac|(?:openjdk|java)(?:\s+version)?)\s+"?(\d+)(?:\.(\d+))?', output)
    major = int(match[2] if match and match[1] == "1" and match[2] else match[1]) if match else 0
    if major < 17:
        raise SystemExit(f"{executable} requires JDK 17 or newer; found {output.strip() or 'an unknown version'}.")

def rc4(key, data):
    """Independent RC4 used only to build the Malduck fixture."""
    state, j = list(range(256)), 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        out.append(byte ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(out)

def duck_sample(key=DUCK_KEY, marker=b"DKCFG1"):
    return b"\x00" * 64 + marker + DUCK_KEY + struct.pack("<H", len(DUCK_PLAIN)) + rc4(key, DUCK_PLAIN) + b"\x00" * 32

def verify_malduck(work):
    from malduck.extractor import ExtractManager, ExtractorModules

    modules = ExtractorModules(str(SOURCE / "malduck_modules"))
    results = {}
    for name, data in {"good": duck_sample(), "wrong-key": duck_sample(key=b"bad-key!"), "no-marker": duck_sample(marker=b"XXXXXX")}.items():
        path = work / f"duckcfg-{name}.bin"
        path.write_bytes(data)
        manager = ExtractManager(modules)
        results[name] = (manager.push_file(str(path)), manager.config)
    assert results["good"] == ("duckcfg", [DUCK_CONFIG]), results["good"]
    assert results["wrong-key"] == (None, []) and results["no-marker"] == (None, [])
    return sha256(work / "duckcfg-good.bin")

def memprocfs_host():
    # The pinned wheels are Linux x86-64 and Windows x64; only Linux x86-64 is exercised here.
    return platform.system() == "Linux" and platform.machine() == "x86_64"


def memprocfs_image(path):
    image = bytearray(16 * 1024 * 1024)
    indexes = [(FIXTURE_VA >> shift) & 0x1FF for shift in (39, 30, 21, 12)]
    for table, entry, index in zip((PML4, PDPT, PD, PT), (PDPT, PD, PT, PAGE), indexes):
        image[table + index * 8:table + index * 8 + 8] = struct.pack("<Q", entry | 0x7)
    image[0x1000:0x1010] = b"MPFS-PHYS-MARK-1"
    image[PAGE + 0x678:PAGE + 0x688] = b"MPFS-VIRT-MARK-2"
    path.write_bytes(image)


def verify_memprocfs(work):
    if not ctypes.util.find_library("usb-1.0"):
        raise SystemExit("MemProcFS needs the libusb-1.0 system library; install it (for example `sudo apt-get install libusb-1.0-0`) and retry.")
    import leechcorepyc

    image = work / "memprocfs.raw"
    memprocfs_image(image)
    # The memprocfs wheel does not bundle leechcore.so; leechcorepyc provides it.
    env = dict(os.environ, LD_LIBRARY_PATH=str(Path(leechcorepyc.__file__).parent))
    output = run(sys.executable, str(SOURCE / "memprocfs_probe.py"), str(image), hex(PML4), hex(FIXTURE_VA), env=env)
    observed = json.loads(output.splitlines()[-1])
    assert bytes.fromhex(observed["physical"]) == b"MPFS-PHYS-MARK-1" == bytes.fromhex(observed["pmem_file"])
    assert observed["processes"] == [[1, "unknown_process", PML4]], observed["processes"]
    assert bytes.fromhex(observed["virtual"]) == b"MPFS-VIRT-MARK-2" and observed["virt2phys"] == PAGE + 0x678
    assert "memory.pmem" in observed["root"]
    return sha256(image)


def verify(work, jar):
    expected_versions = {"construct": "2.10.70", "scapy": "2.8.0", "yara-x": "1.21.0", "hermes-dec": "0.1.8", "malduck": "4.4.1"}
    if memprocfs_host():
        expected_versions.update(MEMPROCFS_PACKAGES)
    for package, expected in expected_versions.items():
        try:
            installed = version(package)
        except PackageNotFoundError as exc:
            raise SystemExit(
                f'Missing Python dependency: {package}. Install with `"{sys.executable}" -m pip install -r "{SOURCE / "requirements.txt"}"`.'
            ) from exc
        if installed != expected:
            raise SystemExit(f"Expected {package}=={expected}, found {installed}. Install the pinned requirements from {SOURCE / 'requirements.txt'}.")

    require_java("javac")
    require_java("java")
    try:
        run("node", "--version")
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise SystemExit("Node.js is required for the Hermes fixture; install Node.js 22 LTS and retry.") from exc

    from construct import Byte, Bytes, Const, ConstructError, Int16ul, Struct, Terminated
    from scapy.all import Ether, IP, Raw, UDP, rdpcap, wrpcap
    import yara_x

    schema = Struct(
        "magic" / Const(b"SMK1"), "length" / Int16ul, "kind" / Byte,
        "payload" / Bytes(lambda ctx: ctx.length), Terminated,
    )
    parsed = schema.parse(GOLDEN)
    assert parsed.length == 5 and parsed.kind == 1 and parsed.payload == b"trace"
    assert schema.build(dict(length=5, kind=1, payload=b"trace")) == GOLDEN
    for bad in (GOLDEN[:-1], GOLDEN + b"\x00", b"WRNG" + GOLDEN[4:]):
        try:
            schema.parse(bad)
        except ConstructError:
            continue
        raise AssertionError("Malformed fixture accepted")

    packet = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.1", dst="192.0.2.2")
        / UDP(sport=1234, dport=4321) / Raw(b"trace")
    )
    wire = bytes(packet)
    assert len(wire) == 47 and wire[:14] == bytes.fromhex("0200000000020200000000010800")
    assert checksum(wire[14:34]) == 0
    pseudo_header = bytes.fromhex("c0000201c0000202") + struct.pack("!BBH", 0, 17, 13)
    assert checksum(pseudo_header + wire[34:]) == 0
    assert Ether(wire)[UDP].dport == 4321 and bytes(Ether(wire)[Raw]) == b"trace"
    pcap = work / "trace.pcap"
    wrpcap(str(pcap), [packet])
    packets = rdpcap(str(pcap))
    assert len(packets) == 1 and packets[0][IP].src == "192.0.2.1"
    assert bytes(packets[0][Raw]) == b"trace"

    compiler = yara_x.Compiler()
    compiler.add_source('rule Fixture { strings: $a = "trace" condition: $a and uint16(0) == 0x4d53 }')
    scanner = yara_x.Scanner(compiler.build())
    assert [r.identifier for r in scanner.scan(GOLDEN).matching_rules] == ["Fixture"]
    assert list(scanner.scan(b"negative sample").matching_rules) == []
    bad_compiler = yara_x.Compiler()
    try:
        bad_compiler.add_source("rule Bad { strings: $a = /abc{/ condition: $a }")
    except Exception as exc:
        assert type(exc).__name__ == "CompileError", type(exc).__name__
    else:
        raise AssertionError("Unescaped brace unexpectedly compiled")

    if jar is None:
        jar = work / "vineflower-1.12.0.jar"
        with urlopen(JAR_URL, timeout=60) as response:
            jar.write_bytes(response.read())
    assert sha256(jar) == JAR_SHA256, "Vineflower artifact digest mismatch"
    original, decompiled, rebuilt = [work / name for name in ("original", "decompiled", "rebuilt")]
    for directory in (original, decompiled, rebuilt):
        directory.mkdir()
    run("javac", "--release", "17", "-d", str(original), str(SOURCE / "BranchDemo.java"), str(SOURCE / "Probe.java"))
    run("java", "-jar", str(jar), str(original), str(decompiled))
    run("javac", "--release", "17", "-d", str(rebuilt), str(decompiled / "BranchDemo.java"), str(SOURCE / "Probe.java"))
    for classes in (original, rebuilt):
        assert run("java", "-cp", str(classes), "BranchDemo") == "25"
        assert run("java", "-cp", str(classes), "Probe") == EXPECTED_BRANCHES

    duck_digest = verify_malduck(work)
    hbc_digests = verify_hermes_dec(work)
    memprocfs = {"name": "MemProcFS", "version": "5.19.0", "result": "skipped", "scope": "This check runs on Linux x86-64 only"}
    image_digest = None
    if memprocfs_host():
        image_digest = verify_memprocfs(work)
        memprocfs.update(result="passed", scope="Self-authored raw image: physical read, user-supplied DTB fallback process, virtual read, virt2phys, /memory.pmem; no Windows OS analysis")

    return {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "host": {"platform": platform.platform(), "python": platform.python_version(), "javac": run("javac", "-version"), "node": run("node", "--version")},
        "results": [
            {"name": "Construct", "version": "2.10.70", "result": "passed", "scope": "Golden bytes, parse/build, wrong magic, truncation, trailing-data rejection"},
            {"name": "Scapy", "version": "2.8.0", "result": "passed", "scope": "Offline packet/PCAP round trip and independent IP/UDP checksums; no traffic sent"},
            {"name": "YARA-X", "version": "1.21.0", "result": "passed", "scope": "Python API positive/negative matching and strict-regex CompileError"},
            {"name": "Vineflower", "version": "1.12.0", "result": "passed", "scope": "Java 17 record/switch expression, rebuild, main output and five branch vectors"},
            {"name": "Malduck", "version": "4.4.1", "result": "passed", "scope": "Self-authored YARA-triggered extractor and RC4 config; wrong-key and no-marker samples yield no config"},
            {"name": "hermes-dec", "version": "0.1.8", "result": "passed", "scope": "HBC 98/99 at -g0/-g1: header, disassembly and pseudo-code landmarks; -g1 debug-info parsing raises TypeError; executing the pseudo-code prints 21, not 25"},
            memprocfs,
        ],
        "inputs": [{"path": name, "sha256": sha256(SOURCE / name)} for name in ("BranchDemo.java", "Probe.java", "hbc_fixture.js", "malduck_modules/duckcfg/__init__.py", "malduck_modules/duckcfg/duckcfg.yar", "memprocfs_probe.py", "verify.py", "requirements.txt")],
        "golden_hex": GOLDEN.hex(),
        "vineflower_artifact": {"url": JAR_URL, "sha256": JAR_SHA256},
        "expected_main": "25", "expected_branches": EXPECTED_BRANCHES.splitlines(),
        "malduck": {"sample_sha256": duck_digest, "expected_config": DUCK_CONFIG},
        "hermes_dec": {"compilers": {str(v): {"url": u, "sha256": d} for v, (u, d) in HERMESC.items()},
                       "hbc_sha256": {str(v): d for v, d in hbc_digests.items()},
                       "original_output": HBC_ORIGINAL_OUTPUT, "pseudocode_output": HBC_PSEUDOCODE_OUTPUT},
        "memprocfs": {"image_sha256": image_digest, "dtb": hex(PML4), "virtual_address": hex(FIXTURE_VA), "physical_address": hex(PAGE + 0x678)},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="Directory for results and generated example artifacts")
    parser.add_argument("--vineflower-jar", type=Path, help="Optional existing 1.12.0 JAR; its digest is still checked")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    jar = args.vineflower_jar.resolve() if args.vineflower_jar else None
    work = Path(tempfile.mkdtemp(prefix="run-", dir=args.output))
    report = verify(work, jar)
    (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
