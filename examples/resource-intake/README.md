# Seven bounded resource examples

These self-authored fixtures demonstrate Construct, Scapy, YARA-X, Vineflower, Malduck, hermes-dec, and boofuzz. They are small selection examples, not upstream test suites or evidence of full platform/version support.

Use Python 3.11 with `venv`/`pip` support, JDK 17, Node.js, and an Internet connection for the pinned packages, JAR, and Hermes compilers. From the repository root:

```bash
resource_examples_dir="$(mktemp -d)"
python3.11 -m venv "$resource_examples_dir/venv"
"$resource_examples_dir/venv/bin/python" -m pip install -r examples/resource-intake/requirements.txt
"$resource_examples_dir/venv/bin/python" examples/resource-intake/verify.py --output "$resource_examples_dir/results"
```

The runner downloads [Vineflower 1.12.0](https://github.com/Vineflower/vineflower/releases/tag/1.12.0) and two `hermes-compiler` npm tarballs, and checks each SHA-256 before executing anything from them. An existing JAR can be supplied with `--vineflower-jar /path/to/vineflower-1.12.0.jar`; the same digest check still applies. Failed assertions or commands fail the run; a successful run writes `results.json` and retains generated artifacts in a unique directory under the selected output path.

The Hermes fixture additionally needs Node.js (CI uses Node.js 22). Its pinned compilers provide Linux x86-64, universal macOS, and Windows x86-64 binaries; native Windows/macOS execution is not part of this repository's verification.

On Windows, use this PowerShell block with Python 3.11 and JDK 17 or newer (`java` and `javac` on `PATH`). The verifier checks both Java versions before running the fixtures. Use `python` in place of `py -3.11` if that is your Python 3.11 launcher.

```powershell
$resourceExamplesDir = Join-Path ([System.IO.Path]::GetTempPath()) ("resource-examples-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $resourceExamplesDir | Out-Null
py -3.11 -m venv (Join-Path $resourceExamplesDir "venv")
$resourcePython = Join-Path $resourceExamplesDir "venv\Scripts\python.exe"
& $resourcePython -m pip install -r examples/resource-intake/requirements.txt
& $resourcePython examples/resource-intake/verify.py --output $resourceExamplesDir
```

| Resource / pinned version | Input and independent expected result | Scope |
| --- | --- | --- |
| Construct 2.10.70 | Golden bytes `534d4b310500017472616365`: `SMK1`, little-endian length 5, type 1, payload `trace`; parse/build and reject bad magic, truncation, or trailing bytes | One binary schema on this Python host |
| Scapy 2.8.0 | Known Ethernet/IP/UDP fields and `trace` payload; independent IP/UDP checksum checks; PCAP write/read | Offline packets only, no transmission or live capture |
| YARA-X 1.21.0 | Self-authored rule matches the golden bytes and not `negative sample`; unescaped `{` in a regex produces `CompileError` | Python API and this documented regex difference, not all YARA rules/modules |
| Vineflower 1.12.0 | Java 17 record and switch expression; compile → decompile → rebuild; main prints `25`, five branch vectors match explicit expected values | This fixture only, no obfuscation or other Java target versions |
| Malduck 4.4.1 | A [self-authored extractor](malduck_modules/duckcfg/__init__.py) and [YARA rule](malduck_modules/duckcfg/duckcfg.yar); a sample with marker `DKCFG1`, an 8-byte key, and a config encrypted by an independent RC4 implementation yields two C2 URLs, campaign `trace-7`, and sleep `300`; wrong-key and no-marker samples yield no config | Extractor framework, procmem reads, and RC4 only; no real malware family |
| hermes-dec 0.1.8 | [`hbc_fixture.js`](hbc_fixture.js) compiled by `hermes-compiler` 250829098.0.19 (HBC 98) and 260318099.0.4 (HBC 99) at `-g0` and `-g1`; header version, disassembly, and pseudo-code landmarks (function names, strings, `<Mod>`, constant `7`) | See the limits below |
| boofuzz 0.4.2 | A made-up TRC1 protocol (`TRC1`, kind, big-endian length, payload, big-endian CRC-32) described with `Size` and `Checksum` blocks; the default frame matches bytes built with `struct` and `zlib`, and a localhost server receives all 575 payload mutations with a correct length and CRC, replying to each | One-field-at-a-time fuzzing (`max_depth=1`) against a localhost server only; see the limits below |

The branch oracle for `Probe.java` is:

```text
-1:-1
0:11
1:22
2:22
9:-1
```

The hermes-dec check also records three limits:

- `hbc-file-parser` warns that HBC 98 and 99 are not formally supported.
- With `-g1` location info, `hbc-file-parser` prints the header and then raises a `TypeError` in `debug_info_parser.py`; `-g0` files parse cleanly. The disassembler and decompiler succeed at both levels.
- The original fixture prints `even:negative:25` under Node.js; executing the pseudo-code prints `even:negative:21`, because register variables are shared across functions instead of being local to each call.

The boofuzz check also records three limits:

- Replies to fuzzed messages are read only with `receive_data_after_fuzz=True`; by default `last_recv` stays empty.
- `String` mutations are text: byte patterns such as `\xde\xad\xbe\xef` are sent UTF-8 encoded, and `max_len` counts characters, so a 48-character limit produced a 96-byte payload.
- Without a process monitor or restart callback, a target that stops listening ends the run after 17 of 575 cases with only an info message ("Ending fuzzing"); no test case is marked failed and `fuzz()` returns normally.

The [dated local result](verified.json) records host/tool versions, input hashes, artifact digests, and the tested scope; it was produced in a Linux x86_64 container. CI repeats the examples and uploads current results through the [resource-example workflow](../../.github/workflows/resource-examples.yml). The current job uses Linux, Python 3.11, Java 17, and Node.js 22; it makes no Windows, macOS, hardware, or other-version claim.

See the [candidate review](../../docs/priority-candidates.md) for primary sources, documented requirements, and the nineteen entries without execution verification.
