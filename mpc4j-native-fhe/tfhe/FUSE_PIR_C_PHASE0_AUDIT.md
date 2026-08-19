# FUSE_PIR_C Phase 0 Audit

This note records the current MPC4J native FHE components that FUSE_PIR_C may reuse and the boundaries that FUSE_PIR_C must not cross.

## RGSW Type And Layout

- `RLWECipher` is an alias of `seal::Ciphertext`.
- `RGSWCipher` is `std::vector<RLWECipher>`.
- The current RGSW layout is body component digits first, key component digits second:
  - components `0 .. targetP::l_ - 1` correspond to ciphertext body component `data(0)`;
  - components `targetP::l_ .. 2 * targetP::l_ - 1` correspond to key component `data(1)`.
- The current gadget parameters are defined in `tfhe/params.h`:
  - `targetP::digits = 124`;
  - `targetP::Bgbit = 16`;
  - `targetP::Bg = 2^16`;
  - `targetP::l_ = ceil(124 / 16) = 7`.
- Therefore every RGSW ciphertext consumed by `ExternalProduct` must contain `2 * targetP::l_ = 14` RLWE ciphertext components.

Evidence:
- `tfhe.h` defines the aliases.
- `tfhe.cpp::TFHEcipher::encrypt` allocates `2 * targetP::l_` RLWE encryptions of zero and adds gadget-scaled plaintext into `cipher[i + k * targetP::l_].data(k)`.
- `tfhe.cpp::TFHEcipher::ExternalProduct` decomposes `src.data(k)` and multiplies by `operand[i + k * targetP::l_]`.

## ExternalProduct And CMUX Contract

- `ExternalProduct(dst, src, operand)` expects:
  - `src` as an RLWE ciphertext with two polynomial components;
  - `operand` as the body-first RGSW layout above;
  - operand components in NTT form.
- The only FUSE_PIR_C CMUX formula is:
  - `CMUX(RGSW(bit), C1, C0) = C0 + ExternalProduct(C1 - C0, RGSW(bit))`.
- Required semantics:
  - bit 0 selects `C0`;
  - bit 1 selects `C1`.

The FUSE_PIR_C wrapper files `rgsw_layout.{h,cpp}` and `cmux.{h,cpp}` fix this contract for later FUSE_PIR_C code. FUSE_PIR_C must not introduce a second RGSW layout or another CMUX formula.

## Serialization And Existing FUSE_PIR Flow

- Existing native serialization helpers in `serialize.{h,cpp}` can serialize BFV parameters, keys, ciphertexts, plaintexts, and RGSW vectors.
- Existing FUSE_PIR native code contains useful matrix/BFF mechanics:
  - matrix column selection via BFV column queries;
  - row packing with `mul_by_monomial` / `multiply_power_of_X`;
  - BlindRotate using CMUX;
  - response packing.
- FUSE_PIR_C must not reuse FUSE_PIR's compressed row-bit conversion:
  - `generateLweToRgswKey`;
  - `convertCompressedRowBitsToRgsw`.
- Those FUSE_PIR helpers implement a linear pseudo conversion over encrypted key material, not Wang-style secure circuit bootstrapping. They are out of scope for FUSE_PIR_C.

## Raw Access And Missing Primitive

- SEAL BFV `Ciphertext` exposes raw polynomial/RNS buffers through `data(poly_index)`, and the current TFHE layer already uses RNS iterators, NTT tables, and polynomial arithmetic directly.
- This is enough to support the current ExternalProduct/CMUX layout.
- It is not enough to obtain Wang 2024 secure circuit bootstrapping from SEAL high-level BFV APIs. FUSE_PIR_C needs a raw LWE/RLWE/circuit-bootstrapping layer with explicit bootstrapping keys and gadget operations.
- FUSE_PIR_C therefore adds a raw LWE layer in `tfhe/lwe.{h,cpp}` and a fail-closed `secure_lwe_to_rgsw` entry point in `tfhe/circuit_bootstrap.{h,cpp}`.
- The `secure_lwe_to_rgsw` entry point explicitly takes `CircuitBootstrapParams` and `CircuitBootstrapKey`; the current key is deliberately empty because the real Wang-style bootstrapping key material and algorithm are not implemented yet.
- Until that entry point contains a real Wang-style circuit bootstrapping implementation, FUSE_PIR_C must fail with:
  - `secure circuit bootstrapping is not implemented yet`.

## Query Compression Reuse Boundary

- Existing FUSE_PIR Java query compression (`FusePirLwePrgUtils`, `FusePirCompressedLweBitQuery`) sends one seed plus `b` components for row bits only.
- FUSE_PIR_C needs a separate compressed query format because it must encode both column and row bits for all three BFF hash positions:
  - for `a = 0..2`: column bits of `h_a(K)`, then row bits of `h_a(K)`.
- FUSE_PIR_C must use fresh query seeds and domain separation over:
  - hash position;
  - selector type `COL` or `ROW`;
  - bit index.

## Reusable Files

- Reusable without changing existing FUSE_PIR/MMK/BKPIR/CAPE logic:
  - `mpc4j-native-fhe/tfhe/tfhe.{h,cpp}` for current RGSW encryption and ExternalProduct layout;
  - `mpc4j-native-fhe/tfhe/rns.h` and `tfhe/util.*` for current decomposition and polynomial helpers;
  - `mpc4j-native-fhe/serialize.*` for native serialization;
  - FUSE_PIR BFF/matrix ideas may be copied into FUSE_PIR_C-owned files only.

## Files Added For FUSE_PIR_C

- `tfhe/lwe.{h,cpp}`: raw LWE keygen, bit encryption, PRG expansion, compressed-query recovery, and local primitive checks.
- `tfhe/rgsw_layout.{h,cpp}`: single ExternalProduct-compatible RGSW layout.
- `tfhe/cmux.{h,cpp}`: single CMUX contract.
- `tfhe/circuit_bootstrap.{h,cpp}`: fail-closed `secure_lwe_to_rgsw` boundary for the missing Wang circuit bootstrapping primitive.
- `pir/std/..._fusepirc_FusePirCStdKwPirNativeUtils.{h,cpp}` and Java `kw/fusepirc` package: FUSE_PIR_C-owned protocol skeleton and query compression.

## Phase 0 Conclusion

The RGSW layout is confirmed as body-first, key-second. ExternalProduct and CMUX contracts are known and fixed. SEAL BFV exposes enough low-level buffers for the current RGSW/CMUX path but does not provide the secure LWE-to-RGSW circuit bootstrapping primitive. FUSE_PIR_C may proceed only through an FUSE_PIR_C-owned raw primitive layer; it must not reuse the existing FUSE_PIR linear LWE-to-RGSW conversion.
