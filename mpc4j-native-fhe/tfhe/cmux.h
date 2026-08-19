#pragma once

#include "rgsw_layout.h"

namespace seal {
    namespace fusepirc {
        Ciphertext cmux(
            const RGSWCipher &gsw_bit, const Ciphertext &ct1, const Ciphertext &ct0, SEALContext &context,
            PublicKey &public_key);
    }
}
