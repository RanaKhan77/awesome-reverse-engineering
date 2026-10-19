"""Reproduce five narrow resource examples with independent expected outputs."""
import argparse
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import io
import json
from pathlib import Path
import platform
import struct
import subprocess
import sys
import tarfile
import tempfile
from urllib.request import urlopen

from construct import Byte, Bytes, Const, ConstructError, Int16ul, Struct, Terminated
from scapy.all import Ether, IP, Raw, UDP, rdpcap, wrpcap
import yara_x

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


def run(*args):
    completed = subprocess.run(args, text=True, capture_output=True, check=True)
    return completed.stdout.strip()


def hermesc(work, bytecode_version):
    url, digest = HERMESC[bytecode_version]
    with urlopen(url, timeout=120) as response:
        archive = response.read()
    assert hashlib.sha256(archive).hexdigest() == digest, f"hermes-compiler {bytecode_version} digest mismatch"
    member = {"Linux": "package/hermesc/linux64-bin/hermesc", "Darwin": "package/hermesc/osx-bin/hermesc"}[platform.system()]
    target = work / f"hermesc-{bytecode_version}"
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        target.write_bytes(tar.extractfile(member).read())
    target.chmod(0o755)
    return target


def verify_hermes_dec(work):
    tools = Path(sys.executable).parent
    shim = "globalThis.print = console.log; new Function(require('fs').readFileSync(process.argv[1], 'utf8'))();"
    assert run("node", "-e", shim, str(SOURCE / "hbc_fixture.js")) == HBC_ORIGINAL_OUTPUT
    digests = {}
    for bytecode_version in HERMESC:
        compiler = hermesc(work, bytecode_version)
        bare, hbc = [work / f"fixture-{bytecode_version}-{level}.hbc" for level in ("g0", "g1")]
        for level, output in (("-g0", bare), ("-g1", hbc)):
            run(str(compiler), "-emit-binary", level, "-out", str(output), str(SOURCE / "hbc_fixture.js"))
            assert output.read_bytes()[8] == bytecode_version, "Unexpected HBC header version"
        parsed = subprocess.run([str(tools / "hbc-file-parser"), str(bare)], text=True, capture_output=True, check=True)
        assert f"| Version                      | {bytecode_version}" in parsed.stdout
        assert "not formally supported" in parsed.stderr
        # With backtrace location info (-g1), the header prints but debug-info parsing raises a TypeError.
        parsed = subprocess.run([str(tools / "hbc-file-parser"), str(hbc)], text=True, capture_output=True)
        assert parsed.returncode == 1 and f"| Version                      | {bytecode_version}" in parsed.stdout
        assert "debug_info_parser.py" in parsed.stderr and "TypeError" in parsed.stderr
        for binary in (bare, hbc):
            hasm, pseudo = binary.with_suffix(".hasm"), binary.with_suffix(".js")
            run(str(tools / "hbc-disassembler"), str(binary), str(hasm))
            run(str(tools / "hbc-decompiler"), str(binary), str(pseudo))
            listing, code = hasm.read_text(), pseudo.read_text()
            for needle in ('Function #1 "classify"', 'Function #2 "scaled"', "<Mod>", "'hbc-fixture-marker'"):
                assert needle in listing, (binary.name, needle)
            for needle in ("// Original name: classify", "// Original name: scaled", "'negative'", "'zero'", "'even'", "'odd'", "r0 = 7;"):
                assert needle in code, (binary.name, needle)
            # The pseudo-code shares register variables across functions, so running it does not reproduce the original.
            assert run("node", "-e", shim, str(pseudo)) == HBC_PSEUDOCODE_OUTPUT, binary.name
        digests[bytecode_version] = {"g0": sha256(bare), "g1": sha256(hbc)}
    return digests


def verify(work, jar):
    for package, expected in {"construct": "2.10.70", "scapy": "2.8.0", "yara-x": "1.21.0", "hermes-dec": "0.1.8"}.items():
        assert version(package) == expected, f"Unexpected {package} version"

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

    hbc_digests = verify_hermes_dec(work)

    return {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "host": {"platform": platform.platform(), "python": platform.python_version(), "javac": run("javac", "-version"), "node": run("node", "--version")},
        "results": [
            {"name": "Construct", "version": "2.10.70", "result": "passed", "scope": "Golden bytes, parse/build, wrong magic, truncation, trailing-data rejection"},
            {"name": "Scapy", "version": "2.8.0", "result": "passed", "scope": "Offline packet/PCAP round trip and independent IP/UDP checksums; no traffic sent"},
            {"name": "YARA-X", "version": "1.21.0", "result": "passed", "scope": "Python API positive/negative matching and strict-regex CompileError"},
            {"name": "Vineflower", "version": "1.12.0", "result": "passed", "scope": "Java 17 record/switch expression, rebuild, main output and five branch vectors"},
            {"name": "hermes-dec", "version": "0.1.8", "result": "passed", "scope": "HBC 98/99 at -g0/-g1: header, disassembly and pseudo-code landmarks; -g1 debug-info parsing raises TypeError; executing the pseudo-code prints 21, not 25"},
        ],
        "inputs": [{"path": name, "sha256": sha256(SOURCE / name)} for name in ("BranchDemo.java", "Probe.java", "hbc_fixture.js", "verify.py", "requirements.txt")],
        "golden_hex": GOLDEN.hex(),
        "vineflower_artifact": {"url": JAR_URL, "sha256": JAR_SHA256},
        "expected_main": "25", "expected_branches": EXPECTED_BRANCHES.splitlines(),
        "hermes_dec": {"compilers": {str(v): {"url": u, "sha256": d} for v, (u, d) in HERMESC.items()},
                       "hbc_sha256": {str(v): d for v, d in hbc_digests.items()},
                       "original_output": HBC_ORIGINAL_OUTPUT, "pseudocode_output": HBC_PSEUDOCODE_OUTPUT},
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
