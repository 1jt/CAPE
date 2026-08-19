#include "rgsw_layout.h"

#include "params.h"
#include "seal/util/iterator.h"
#include "seal/util/polyarithsmallmod.h"

#include <algorithm>
#include <stdexcept>

using namespace std;

namespace seal {
    namespace fusepirc {
        namespace {
            Plaintext rns_bit_plaintext(const SEALContext &context, uint64_t bit) {
                auto &parms = context.first_context_data()->parms();
                uint32_t coeff_count = parms.poly_modulus_degree();
                uint32_t coeff_mod_count = parms.coeff_modulus().size();
                Plaintext plain(coeff_count * coeff_mod_count);
                plain.resize(coeff_count * coeff_mod_count);
                fill(plain.data(), plain.data() + coeff_count * coeff_mod_count, 0);
                for (uint32_t i = 0; i < coeff_mod_count; i++) {
                    plain[i * coeff_count] = bit;
                }
                auto plain_iter = util::RNSIter(plain.data(), coeff_count);
                util::ntt_negacyclic_harvey(
                    plain_iter, coeff_mod_count, context.first_context_data()->small_ntt_tables()
                );
                return plain;
            }
        }

        RgswLayout current_rgsw_layout() {
            return RgswLayout{
                static_cast<uint32_t>(targetP::l_),
                targetP::Bg,
                ComponentOrder::BODY_FIRST
            };
        }

        RgswLayout current_rgsw_layout(const SEALContext &context) {
            size_t total_bits = static_cast<size_t>(context.first_context_data()->total_coeff_modulus_bit_count());
            return RgswLayout{
                static_cast<uint32_t>((total_bits + targetP::Bgbit - 1) / targetP::Bgbit),
                targetP::Bg,
                ComponentOrder::BODY_FIRST
            };
        }

        void validate_rgsw_layout(const RgswLayout &layout, const RGSWCipher &cipher) {
            if (layout.componentOrder != ComponentOrder::BODY_FIRST) {
                throw invalid_argument("FUSE_PIR_C ExternalProduct requires body-first RGSW layout");
            }
            if (layout.gadgetBase != targetP::Bg) {
                throw invalid_argument("FUSE_PIR_C RGSW gadget base mismatch");
            }
            if (cipher.size() != 2 * layout.gadgetLength) {
                throw invalid_argument("FUSE_PIR_C RGSW size must be 2 * gadgetLength");
            }
            for (const auto &component : cipher) {
                if (component.size() != 2) {
                    throw invalid_argument("FUSE_PIR_C RGSW component must be an RLWE ciphertext");
                }
                if (!component.is_ntt_form()) {
                    throw invalid_argument("FUSE_PIR_C RGSW component must be in NTT form");
                }
            }
        }

        RGSWCipher normalize_rgsw_for_external_product(const RgswLayout &layout, const RGSWCipher &cipher) {
            validate_rgsw_layout(layout, cipher);
            return cipher;
        }

        RGSWCipher encrypt_rgsw_bit(SEALContext &context, PublicKey &public_key, uint64_t bit) {
            if (bit > 1) {
                throw invalid_argument("FUSE_PIR_C RGSW plaintext bit must be 0 or 1");
            }
            TFHEcipher tfhe(context, public_key);
            Plaintext plain = rns_bit_plaintext(context, bit);
            RGSWCipher cipher;
            tfhe.encrypt(plain, cipher);
            validate_rgsw_layout(current_rgsw_layout(context), cipher);
            return cipher;
        }

        RGSWCipher encrypt_rgsw_zero(SEALContext &context, PublicKey &public_key) {
            return encrypt_rgsw_bit(context, public_key, 0);
        }

        RGSWCipher encrypt_rgsw_one(SEALContext &context, PublicKey &public_key) {
            return encrypt_rgsw_bit(context, public_key, 1);
        }
    }
}
