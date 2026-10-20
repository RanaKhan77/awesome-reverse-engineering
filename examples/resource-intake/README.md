# Four bounded resource examples

These self-authored fixtures demonstrate Construct, Scapy, YARA-X, and Vineflower. They are small selection examples, not upstream test suites or evidence of full platform/version support.

Use Python 3.11 with `venv`/`pip` support, JDK 17, and an Internet connection for the pinned packages and JAR. From the repository root:

```bash
resource_examples_dir="$(mktemp -d)"
python3.11 -m venv "$resource_examples_dir/venv"
"$resource_examples_dir/venv/bin/python" -m pip install -r examples/resource-intake/requirements.txt
"$resource_examples_dir/venv/bin/python" examples/resource-intake/verify.py --output "$resource_examples_dir/results"
```

The runner downloads [Vineflower 1.12.0](https://github.com/Vineflower/vineflower/releases/tag/1.12.0) and checks the JAR SHA-256 before executing it. An existing JAR can be supplied with `--vineflower-jar /path/to/vineflower-1.12.0.jar`; the same digest check still applies. Failed assertions or commands fail the run; a successful run writes `results.json` and retains generated artifacts in a unique directory under the selected output path.

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

The branch oracle for `Probe.java` is:

```text
-1:-1
0:11
1:22
2:22
9:-1
```

The [dated local result](verified.json) records host/tool versions, input hashes, artifact digest, and the tested scope. CI repeats the examples and uploads current results through the [resource-example workflow](../../.github/workflows/resource-examples.yml). The current job uses Linux, Python 3.11, and Java 17; it makes no Windows, macOS, hardware, or other-version claim.

See the [candidate review](../../docs/priority-candidates.md) for primary sources, documented requirements, and the nineteen entries without execution verification.
