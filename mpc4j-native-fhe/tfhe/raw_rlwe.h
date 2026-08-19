#pragma once

#include "raw_poly.h"

#include <cstdint>
#include <vector>

namespace seal {
    namespace fusepirc {
        struct RawRlweParams {
            std::uint32_t degree;
            std::uint64_t modulus;
            std::uint32_t logModulus;
            bool useRns;
            std::vector<std::uint64_t> rnsPrimes;
        };

        struct RawRlweSecretKey {
            TorusPoly s;
        };

        struct RawRlweCipher {
            TorusPoly a;
            TorusPoly b;
            RawRlweParams params;
            bool isNttForm;
            std::uint32_t level;
        };

        void validate_raw_rlwe_params(const RawRlweParams &params);

        RawRlweSecretKey raw_rlwe_keygen(const RawRlweParams &params);

        RawRlweCipher raw_rlwe_encrypt_zero(
            const RawRlweSecretKey &sk, const RawRlweParams &params, double sigma);

        RawRlweCipher raw_rlwe_encrypt_poly(
            const TorusPoly &message, const RawRlweSecretKey &sk, const RawRlweParams &params, double sigma);

        TorusPoly raw_rlwe_decrypt_phase(const RawRlweCipher &ct, const RawRlweSecretKey &sk);

        RawRlweCipher raw_rlwe_add(const RawRlweCipher &ct_a, const RawRlweCipher &ct_b);

        RawRlweCipher raw_rlwe_sub(const RawRlweCipher &ct_a, const RawRlweCipher &ct_b);

        RawRlweCipher raw_rlwe_scalar_mul(const RawRlweCipher &ct, std::uint64_t scalar);

        RawRlweCipher raw_rlwe_mul_monomial(const RawRlweCipher &ct, std::int64_t exponent);

        RawRlweCipher raw_rlwe_automorphism(const RawRlweCipher &ct, std::uint32_t k);
    }
}
