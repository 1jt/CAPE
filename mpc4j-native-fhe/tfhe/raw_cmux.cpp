#include "raw_cmux.h"

namespace seal {
    namespace fusepirc {
        RawRlweCipher raw_cmux(
            const RawRgswCipher &rgsw_bit, const RawRlweCipher &ct1, const RawRlweCipher &ct0,
            const RawExternalProductParams &params) {
            RawRlweCipher diff = raw_rlwe_sub(ct1, ct0);
            RawRlweCipher product = raw_external_product(diff, rgsw_bit, params);
            return raw_rlwe_add(ct0, product);
        }

        RawRlweCipher raw_cmux_cached_ntt(
            const CachedRawRgswCipherNtt &rgsw_bit_ntt, const RawRlweCipher &ct1, const RawRlweCipher &ct0,
            const RawExternalProductParams &params, RawNttWorkspace &workspace) {
            RawRlweCipher diff = raw_rlwe_sub(ct1, ct0);
            RawRlweCipher product = raw_external_product_cached_ntt(diff, rgsw_bit_ntt, params, workspace);
            return raw_rlwe_add(ct0, product);
        }
    }
}
