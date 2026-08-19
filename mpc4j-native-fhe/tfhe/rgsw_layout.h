#pragma once

#include "tfhe.h"

#include <cstdint>

namespace seal {
    namespace fusepirc {
        enum class ComponentOrder {
            BODY_FIRST = 0,
            KEY_FIRST = 1
        };

        struct RgswLayout {
            std::uint32_t gadgetLength;
            std::uint64_t gadgetBase;
            ComponentOrder componentOrder;
        };

        RgswLayout current_rgsw_layout();

        RgswLayout current_rgsw_layout(const SEALContext &context);

        void validate_rgsw_layout(const RgswLayout &layout, const RGSWCipher &cipher);

        RGSWCipher normalize_rgsw_for_external_product(const RgswLayout &layout, const RGSWCipher &cipher);

        RGSWCipher encrypt_rgsw_zero(SEALContext &context, PublicKey &public_key);

        RGSWCipher encrypt_rgsw_one(SEALContext &context, PublicKey &public_key);

        RGSWCipher encrypt_rgsw_bit(SEALContext &context, PublicKey &public_key, std::uint64_t bit);
    }
}
