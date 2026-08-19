#pragma once

#include "hom_trace.h"
#include "raw_cmux.h"

namespace seal {
    namespace fusepirc {
        struct SchemeSwitchParams {
            RawRlweParams inputParams;
            RawRlweParams outputParams;
            GadgetParams gadgetParams;
            RgswLayout rgswLayout;
            std::uint32_t gadgetLength;
            std::uint64_t gadgetBase;
            std::uint64_t modulus;
            std::uint32_t degree;
            bool outputBodyFirst;
        };

        struct SchemeSwitchKey {
            RawRlweParams params;
            GadgetParams gadgetParams;
            RgswLayout rgswLayout;
            RawRlweCipher encryptedSkSquare;
            std::vector<RawRlweCipher> keySwitchComponents;
        };

        void validate_scheme_switch_params(const SchemeSwitchParams &params);

        void validate_raw_rgsw_layout_for_external_product(
            const RawRgswCipher &rgsw, const RgswLayout &layout);

        SchemeSwitchKey generate_scheme_switch_key(
            const RawRlweSecretKey &rlwe_sk, const SchemeSwitchParams &params, double sigma);

        RawRlweCipher scheme_switch_digit_to_secret_part(
            const RawRlweCipher &msg_digit, const SchemeSwitchKey &key, const SchemeSwitchParams &params);

        RawRgswCipher scheme_switch_to_raw_rgsw(
            const std::vector<RawRlweCipher> &traced_digits, const SchemeSwitchKey &key,
            const SchemeSwitchParams &params);
    }
}
