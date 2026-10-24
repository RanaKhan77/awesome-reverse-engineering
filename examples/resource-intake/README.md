# Five bounded resource examples

These self-authored fixtures demonstrate Construct, Scapy, YARA-X, Vineflower, Malduck, and hermes-dec in CI, plus a local PyLingual check. They are small selection examples, not upstream test suites or evidence of full platform/version support.

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

The [dated local result](verified.json) records host/tool versions, input hashes, artifact digests, and the tested scope; it was produced in a Linux x86_64 container. CI repeats the examples and uploads current results through the [resource-example workflow](../../.github/workflows/resource-examples.yml). The current job uses Linux, Python 3.11, Java 17, and Node.js 22; it makes no Windows, macOS, hardware, or other-version claim.

## Local check: PyLingual

PyLingual needs about 1.2 GB of models per target Python version, so it is not part of the CI job. [`pylingual/fixture.py`](pylingual/fixture.py) is compiled with checked-hash invalidation for CPython 3.11.15, 3.12.13, and 3.13.14 (through exact-version `uv` requests), decompiled with PyLingual v0.1.0 (commit `11a1516`), and its functions are loaded one at a time and compared with the original, so a function that does not compile cannot hide the others. [`pinned_config.yaml`](pylingual/pinned_config.yaml) pins the segmentation and statement models to the Hugging Face revisions observed on 2026-10-19 and still current on 2026-10-21. PyLingual loads tokenizers without a revision argument, so the config cannot pin them; [the report](pylingual/verified.json), which the runner generates, records the tokenizer revisions the Hugging Face cache resolved, the PyLingual commit and package versions, and input hashes.

```bash
git clone https://github.com/syssec-utd/pylingual && git -C pylingual checkout 11a1516d84a6c2aa71ec23fbd11e4b99dc8c4a86
(cd pylingual && uv sync --frozen)
python3 examples/resource-intake/pylingual/run.py --pylingual pylingual/.venv/bin/pylingual --output "$(mktemp -d)"
```

The runner records the resolved compiler versions, disables the optional shared Redis translation cache, and saves per-target stdout/stderr logs for model-download or decompilation failures. PyLingual itself needs Python 3.12 or newer. Hosts using a SOCKS proxy may also need the optional `socksio` transport in the PyLingual environment; this is a transport requirement, not a model or decompiler result. On all three target versions, `classify`, `checksum`, `squares`, and `label` behave like the original. `parse_port` (a `try`/`except` followed by a chained comparison) fails on every version, and PyLingual flags it in both its report and the output file: on 3.11 it does not compile (`Compilation Error`), so the decompiled file as a whole cannot be imported; on 3.12 and 3.13 the file imports, but `parse_port` returns `-2` for `"8080"` instead of `8080` (`Different control flow`). The same results were produced at commit `509ea92` on 2026-10-19, and repeated runs produced identical output.

See the [candidate review](../../docs/priority-candidates.md) for primary sources, documented requirements, and the nineteen entries without execution verification.
