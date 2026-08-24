# Correctness Status

This document records the configuration-specific correctness evidence used by the artifact release gate.

## FusePIR

- The CRT decomposition carry-truncation correctness bug has been fixed.
- Dense multi-column selection, multiple packed blocks, three-share aggregation, multi-value payloads, and padding passed.
- The full Client/Server E2E passed with N=16384, t=65537, and coefficient-modulus bits `[60,60,60,60,60,60,60]`.

## FusePIR-C

- The compressed LWE-to-RGSW query, recursive CMUX selector, candidate retrieval, and decode path passed a full E2E run.
- RAW N=16 development tests are not part of the release gate and are not used by this artifact.

## CAPE

- Anchor retrieval, Bloom scoring, packed response generation, false-candidate rejection, and Client decode passed a full E2E run.

## CAPE-C

- Compressed anchor recovery, recursive CMUX selection, candidate value/Bloom retrieval, scoring, packed response, and decode passed a full E2E run.

## Baselines

MMK and BKPIR retain their existing baseline E2E checks. A runner row is marked `VERIFIED` only when its decoded
result is checked against the deterministic expected result. `UNVERIFIED` never means that an incorrect result passed.

The release evidence applies to the fixed artifact parameters and deterministic workloads documented in the README. It
is not a blanket claim about historical toy/development parameter sets that are excluded from this repository.
