#pragma once

#include "raw_external_product.h"

#include <cstdint>
#include <vector>

namespace seal {
    namespace fusepirc {
        struct RawRlwePrimeCipher {
            std::vector<RawRlweCipher> digits;
            RawRlweParams params;
            GadgetParams gadgetParams;
        };

        void validate_raw_rlwe_prime_cipher(const RawRlwePrimeCipher &ct);

        RawRlwePrimeCipher raw_rlwe_prime_zero(
            const RawRlweParams &rlwe_params, const GadgetParams &gadget_params);

        RawRlwePrimeCipher trivial_raw_rlwe_prime_constant(
            std::uint64_t value, const RawRlweParams &rlwe_params, const GadgetParams &gadget_params);

        RawRlwePrimeCipher raw_rlwe_prime_add(
            const RawRlwePrimeCipher &a, const RawRlwePrimeCipher &b);

        RawRlwePrimeCipher raw_rlwe_prime_sub(
            const RawRlwePrimeCipher &a, const RawRlwePrimeCipher &b);

        RawRlwePrimeCipher raw_rlwe_prime_mul_plain_poly(
            const RawRlwePrimeCipher &ct, const TorusPoly &plain);

        RawRlwePrimeCipher raw_rgsw_mul_rlwe_prime(
            const RawRgswCipher &rgsw_bit, const RawRlwePrimeCipher &node,
            const RawExternalProductParams &ep_params, const RgswLayout &rgsw_layout);
    }
}
