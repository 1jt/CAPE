#pragma once

#include "raw_external_product.h"

namespace seal {
    namespace fusepirc {
        RawRlweCipher raw_cmux(
            const RawRgswCipher &rgsw_bit, const RawRlweCipher &ct1, const RawRlweCipher &ct0,
            const RawExternalProductParams &params);

        RawRlweCipher raw_cmux_cached_ntt(
            const CachedRawRgswCipherNtt &rgsw_bit_ntt, const RawRlweCipher &ct1, const RawRlweCipher &ct0,
            const RawExternalProductParams &params, RawNttWorkspace &workspace);
    }
}
