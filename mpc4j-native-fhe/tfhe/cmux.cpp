#include "cmux.h"

#include <algorithm>
#include <stdexcept>

using namespace std;

namespace seal {
    namespace fusepirc {
        Ciphertext cmux(
            const RGSWCipher &gsw_bit, const Ciphertext &ct1, const Ciphertext &ct0, SEALContext &context,
            PublicKey &public_key) {
            RGSWCipher normalized_gsw = normalize_rgsw_for_external_product(current_rgsw_layout(context), gsw_bit);
            Evaluator evaluator(context);
            Ciphertext diff = ct1;
            try {
                evaluator.sub_inplace(diff, ct0);
            } catch (const logic_error &e) {
                if (string(e.what()).find("transparent") != string::npos) {
                    return ct0;
                }
                throw;
            }
            if (diff.is_transparent()) {
                return ct0;
            }
            if (diff.is_ntt_form()) {
                evaluator.transform_from_ntt_inplace(diff);
            }
            Ciphertext selected(context);
            selected.resize(context, context.first_context_data()->parms_id(), 2);
            auto &parms = context.first_context_data()->parms();
            size_t coeff_count = parms.poly_modulus_degree();
            size_t coeff_mod_count = parms.coeff_modulus().size();
            for (size_t poly = 0; poly < selected.size(); poly++) {
                fill(selected.data(poly), selected.data(poly) + coeff_count * coeff_mod_count, 0);
            }
            selected.is_ntt_form() = true;
            TFHEcipher tfhe(context, public_key);
            tfhe.ExternalProduct(selected, diff, normalized_gsw);
            if (selected.is_transparent()) {
                return ct0;
            }
            if (ct0.is_ntt_form()) {
                evaluator.add_inplace(selected, ct0);
                return selected;
            }
            evaluator.transform_from_ntt_inplace(selected);
            evaluator.add_inplace(selected, ct0);
            return selected;
        }
    }
}
