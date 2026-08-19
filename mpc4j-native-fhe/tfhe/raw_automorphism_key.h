#pragma once

#include "gadget.h"

namespace seal {
    namespace fusepirc {
        struct RawAutomorphismKey {
            std::uint32_t automorphismExponent;
            RawRlweParams params;
            GadgetParams gadgetParams;
            std::vector<RawRlweCipher> keySwitchComponents;
        };

        RawRlweCipher apply_raw_rlwe_automorphism(const RawRlweCipher &ct, std::uint32_t k);

        RawAutomorphismKey generate_raw_automorphism_key(
            const RawRlweSecretKey &sk, std::uint32_t automorphism_exponent, const RawRlweParams &params,
            const GadgetParams &gadget_params, double sigma);

        RawRlweCipher raw_automorphism_key_switch(
            const RawRlweCipher &ct_under_auto_sk, const RawAutomorphismKey &aut_key);
    }
}
