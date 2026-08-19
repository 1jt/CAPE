#pragma once

#include "gadget.h"
#include "rgsw_layout.h"

namespace seal {
    namespace fusepirc {
        struct RawExternalProductParams {
            RawRlweParams rlweParams;
            GadgetParams gadgetParams;
            RgswLayout layout;
        };

        struct RawRgswCipher {
            std::vector<RawRlweCipher> components;
            RgswLayout layout;
            RawRlweParams params;
        };

        void validate_raw_external_product_params(const RawExternalProductParams &params);

        void validate_raw_rgsw_cipher(const RawRgswCipher &cipher, const RawExternalProductParams &params);

        RawRgswCipher raw_rgsw_encrypt_bit(
            std::uint64_t bit, const RawRlweSecretKey &sk, const RawExternalProductParams &params, double sigma);

        RawRgswCipher raw_rgsw_encrypt_zero(
            const RawRlweSecretKey &sk, const RawExternalProductParams &params, double sigma);

        RawRgswCipher raw_rgsw_encrypt_one(
            const RawRlweSecretKey &sk, const RawExternalProductParams &params, double sigma);
    }
}
