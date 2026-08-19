# Correctness Status

This document separates execution/measurement availability from formal correctness validation.

## FusePIR

- The CRT decomposition carry-truncation correctness bug has been fixed.
- N=8192 row 0/1/2 selection, packed response, packed/unpacked consistency, and a small E2E run passed.
- The `DEFAULT_PARAMS` N=16384 E2E run has not completed because LWE-to-RGSW setup is lengthy.
- The artifact therefore does not claim that every FusePIR parameter configuration is formally verified.

## FusePIR-C

- RAW N=16 development tests are incompatible with SEAL's standard polynomial degrees and are not an execution gate.
- Secure `DEFAULT_PARAMS` formal E2E verification remains deferred to the correctness repair track.

## CAPE and CAPE-C

- The artifact contains the real experimental Client/Server implementations and records their actual outcomes.
- Formal correctness repair and validation remain ongoing; no blanket formal-correctness claim is made.

## Baselines

MMK and BKPIR retain their existing baseline E2E checks. A runner row is marked `VERIFIED` only when its decoded
result is checked against the deterministic expected result. `UNVERIFIED` never means that an incorrect result passed.

Correctness Repair Track R2-R5 remains deferred and is not part of the current artifact packaging step.
