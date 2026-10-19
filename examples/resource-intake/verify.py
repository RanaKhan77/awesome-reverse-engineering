"""Reproduce five narrow resource examples with independent expected outputs."""
import argparse
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import platform
import struct
import subprocess
import tempfile
from urllib.request import urlopen

from construct import Byte, Bytes, Const, ConstructError, Int16ul, Struct, Terminated
from scapy.all import Ether, IP, Raw, UDP, rdpcap, wrpcap
import yara_x
from malduck.extractor import ExtractManager, ExtractorModules

SOURCE = Path(__file__).resolve().parent
JAR_URL = "https://github.com/Vineflower/vineflower/releases/download/1.12.0/vineflower-1.12.0.jar"
JAR_SHA256 = "1dfcfe974395734fa467ce620661c7623d05ba83670de0529b1fbd63ff548b9d"
GOLDEN = bytes.fromhex("534d4b310500017472616365")
EXPECTED_BRANCHES = "-1:-1\n0:11\n1:22\n2:22\n9:-1"
DUCK_KEY = b"duck-key"
DUCK_PLAIN = b"c2=http://192.0.2.10/gate;c2=http://198.51.100.7/gate;campaign=trace-7;sleep=300"
DUCK_CONFIG = {"family": "duckcfg", "urls": ["http://192.0.2.10/gate", "http://198.51.100.7/gate"], "campaign": "trace-7", "sleep": 300}


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


def verify(work, jar):
    for package, expected in {"construct": "2.10.70", "scapy": "2.8.0", "yara-x": "1.21.0", "malduck": "4.4.1"}.items():
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

    duck_digest = verify_malduck(work)

    return {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "host": {"platform": platform.platform(), "python": platform.python_version(), "javac": run("javac", "-version")},
        "results": [
            {"name": "Construct", "version": "2.10.70", "result": "passed", "scope": "Golden bytes, parse/build, wrong magic, truncation, trailing-data rejection"},
            {"name": "Scapy", "version": "2.8.0", "result": "passed", "scope": "Offline packet/PCAP round trip and independent IP/UDP checksums; no traffic sent"},
            {"name": "YARA-X", "version": "1.21.0", "result": "passed", "scope": "Python API positive/negative matching and strict-regex CompileError"},
            {"name": "Vineflower", "version": "1.12.0", "result": "passed", "scope": "Java 17 record/switch expression, rebuild, main output and five branch vectors"},
            {"name": "Malduck", "version": "4.4.1", "result": "passed", "scope": "Self-authored YARA-triggered extractor and RC4 config; wrong-key and no-marker samples yield no config"},
        ],
        "inputs": [{"path": name, "sha256": sha256(SOURCE / name)} for name in (
            "BranchDemo.java", "Probe.java", "malduck_modules/duckcfg/__init__.py",
            "malduck_modules/duckcfg/duckcfg.yar", "verify.py", "requirements.txt")],
        "golden_hex": GOLDEN.hex(),
        "vineflower_artifact": {"url": JAR_URL, "sha256": JAR_SHA256},
        "expected_main": "25", "expected_branches": EXPECTED_BRANCHES.splitlines(),
        "malduck": {"sample_sha256": duck_digest, "expected_config": DUCK_CONFIG},
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
