#pragma once

#include "raw_ntt.h"
#include "raw_rgsw.h"

namespace seal {
    namespace fusepirc {
        struct RawRlweCipherNtt {
            std::vector<std::uint64_t> aNtt;
            std::vector<std::uint64_t> bNtt;
            RawRlweParams params;
        };

        struct CachedRawRgswCipherNtt {
            std::vector<RawRlweCipherNtt> components;
            RgswLayout layout;
            RawRlweParams params;
        };

        struct RawNttWorkspace {
            std::vector<std::uint64_t> digitNtt;
            std::vector<std::uint64_t> accANtt;
            std::vector<std::uint64_t> accBNtt;
        };

        CachedRawRgswCipherNtt make_cached_raw_rgsw_ntt(
            const RawRgswCipher &rgsw, const RawNttParams &ntt_params);

        std::vector<TorusPoly> raw_decompose_rlwe_for_external_product(
            const RawRlweCipher &ct, const GadgetParams &gadget_params, const RgswLayout &layout);

        RawRlweCipher raw_external_product(
            const RawRlweCipher &ct, const RawRgswCipher &rgsw, const RawExternalProductParams &params);

        RawRlweCipher raw_external_product_cached_ntt(
            const RawRlweCipher &ct, const CachedRawRgswCipherNtt &cached_rgsw,
            const RawExternalProductParams &params, RawNttWorkspace &workspace);
    }
}
