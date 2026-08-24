# CAPE Artifact

## 1. Overview

This repository is a standalone Open Science artifact for six PIR experiment implementations. It provides clean
builds, real Client/Server protocol execution, configuration-specific correctness checks, and reproducible performance
measurements. The release-gate evidence is summarized in [docs/CORRECTNESS_STATUS.md](docs/CORRECTNESS_STATUS.md).

## 2. Included Schemes

- MMK
- BKPIR
- FusePIR
- FusePIR-C
- CAPE
- CAPE-C

No other MPC4J PIR protocol is included as a public experiment entry.

## 3. Repository Structure

- `mpc4j-s2pc-pir/`: Java Client/Server protocols and the artifact runner.
- `mpc4j-native-fhe/`: JNI implementation and FHE primitives.
- `mpc4j-common-*`: minimal reachable MPC4J support modules.
- `configs/quick/`: small deterministic execution configuration.
- `configs/paper/`: explicit paper experiment matrix.
- `scripts/`: build, execution, and CSV collection helpers.
- `results/`: locally generated CSV files and detailed logs.

## 4. System Requirements

Validated on Ubuntu 22.04 with OpenJDK 17.0.19, Maven 3.9.9, GCC/G++ 11.4, CMake 3.22.1, and Microsoft SEAL 4.0.0.
The native build requires an installed Microsoft SEAL CMake package compatible with the source. At least 8 GB RAM is recommended; complete paper
experiments need substantially more time and may benefit from additional memory.

Runtime depends on CPU, memory bandwidth, compiler, and system load. The evaluator does not need the authors' CPU.

## 5. Build

```bash
./build.sh
```

The script checks required tools, builds `libmpc4j-native-fhe.so`, and packages the standalone Java runner. It does not
run the long experiment suite.

The equivalent component commands are:

```bash
./scripts/build_native.sh
mvn -pl mpc4j-s2pc-pir -am -DskipTests package
```

## 6. Quick Start

```bash
git clone <artifact-repository>
cd CAPE
./build.sh
./run.sh
```

`run.sh` invokes all six real Client/Server implementations and creates `results/quick_results.csv`. Detailed output
is kept in `results/logs/`. A per-scheme exception or timeout is retained as a `FAIL` row and makes `run.sh` return a
nonzero exit code after all six schemes have been attempted.

The deterministic synthetic dataset uses seed 2026. Schemes in the same single-keyword or conjunctive group receive
the same logical workload. Quick mode reduces database and query counts only; it does not select RAW correctness
parameters or lower the schemes' cryptographic parameter sets.

Run one single-keyword or conjunctive scheme directly when a full sweep is unnecessary:

```bash
./scripts/run_experiment.sh --scheme FusePIR --keyword-num 4 --values-per-keyword 3 --value-bit-length 128 --q 1
./scripts/run_experiment.sh --scheme CAPE --keyword-num 4 --values-per-keyword 3 --value-bit-length 128 --q 3
```

## 7. Fixed Cryptographic Parameters

The four contributed schemes use the following release parameters in both Java and JNI/native context creation:

```text
polyModulusDegree = 16384
plainModulus = 65537
coeffModulusBits = [60,60,60,60,60,60,60]
```

The quick workload reduces only the database dimensions and number of queries. It does not replace these parameters
with `BFVDefault`, RAW/toy parameters, or a lower-modulus configuration.

## 8. Reproducing the Paper Experiments

Run selected configurations explicitly:

```bash
./scripts/run_paper.sh --scheme FusePIR
./scripts/run_paper.sh --scheme FusePIR-C
./scripts/run_paper.sh --scheme CAPE
./scripts/run_paper.sh --scheme CAPE-C
./scripts/run_paper.sh --scheme MMK
./scripts/run_paper.sh --scheme BKPIR
```

To run the complete recorded matrix:

```bash
./scripts/run_paper.sh --all
```

This can require many hours or days. It is never started by `build.sh` or the default quick command.

## 9. Output Format

CSV columns are:

```text
scheme,keyword_num,values_per_keyword,value_bit_length,conjunctive_keyword_num,
preprocessing_ms,query_time_ms,query_size_bytes,response_size_bytes,
execution_status,correctness_status
```

- `preprocessing_ms`: database preprocessing plus evaluation/setup key work and offline setup exchange.
- `query_time_ms`: server online query-to-response wall-clock time.
- `query_size_bytes`: online client-to-server RPC bytes after setup counters are reset.
- `response_size_bytes`: online server-to-client RPC bytes.
- `execution_status`: `PASS` or `FAIL`.
- `correctness_status`: `VERIFIED`, `UNVERIFIED`, or `FAILED`.

Setup material such as public, relinearization, Galois, LWE-to-RGSW, and circuit-bootstrap keys is excluded from online
query size. Metrics are measured from the current run and are not copied from a paper spreadsheet or reference log.

## 10. Correctness Gate

For FusePIR, FusePIR-C, CAPE, and CAPE-C, the release gate exercises `init`, query generation, server answer,
decryption, decode/filter, and deterministic expected-result comparison with the fixed parameters above. A CSV row is
`VERIFIED` only after that comparison passes. The runner preserves exceptions and mismatches as failures.

## 11. Expected Trends

The compressed schemes trade server computation for communication. In successful comparable runs, FusePIR-C and
CAPE-C are expected to send smaller online queries than their uncompressed counterparts. CAPE/CAPE-C use packed
candidate-oriented responses rather than returning the complete global value universe. Scripts do not enforce a fixed
ratio and never rewrite measured results to manufacture these trends.

## 12. Hardware Notes

Timing values are hardware-dependent. Compare communication sizes directly and treat runtime comparisons as trends
unless runs use the same machine, load, compiler, and configuration.

## 13. Troubleshooting

- `SEALConfig.cmake` not found: install Microsoft SEAL and make its CMake package visible through the normal CMake
  search path or `CMAKE_PREFIX_PATH`.
- `UnsatisfiedLinkError`: rerun `./build.sh`; execution scripts discover the artifact's own native build directory and
  set `LD_LIBRARY_PATH` automatically.
- A scheme reports `FAIL`: inspect its file in `results/logs/` and consult `docs/CORRECTNESS_STATUS.md`. The runner does
  not suppress noise-budget, decode, JNI, or protocol exceptions.
- To reproduce from a clean state: `./clean.sh && ./build.sh && ./run.sh`.
