#pragma once
#include "params.h"
#include "seal/seal.h"
#include "seal/util/common.h"
#include "seal/util/ntt.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/scalingvariant.h"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>
using namespace std;
namespace seal
{

    class TFHERNS
    {
    public:
        explicit TFHERNS(SEALContext &context) : context_(context)
        {
            auto &context_data = *context_.first_context_data();
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeff_modulus();
            auto Mcnt = coeff_modulus.size();
            // CRTDecPoly accumulates one lifted CRT term per coefficient modulus. The unreduced
            // integer sum is smaller than M * Q, so its gadget representation must retain the
            // carry bits above bitlen(Q); truncating them corrupts reconstruction modulo q_i.
            size_t crt_carry_bits = 0;
            for (size_t bound = 1; bound < Mcnt; bound <<= 1) {
                crt_carry_bits++;
            }
            Qlen = static_cast<size_t>(context_data.total_coeff_modulus_bit_count()) + crt_carry_bits;
            Qword = (Qlen + targetP::Bgbit - 1) / targetP::Bgbit;
            coeff_modulus_size = Mcnt;
            poly_degree = parms.poly_modulus_degree();
            auto punctured_prod_array = context_data.rns_tool()->base_q()->punctured_prod_array();
            auto inv_punctured_prod = context_data.rns_tool()->base_q()->inv_punctured_prod_mod_base_array();
            auto base_prod = context_data.rns_tool()->base_q()->base_prod();
            size_t Qsize = context_data.rns_tool()->base_q()->size();
            Qrst.resize(Mcnt);
            Qinv.resize(Mcnt);
            Qtot.resize(Qword);
            basered(base_prod, Qtot, Qsize, 0);
            for (size_t i = 0; i < Mcnt; i++)
                Qinv[i] = inv_punctured_prod[i].operand;
            for (size_t i = 0; i < Mcnt; i++) {
                Qrst[i].resize(Qword);
                basered(punctured_prod_array + Qsize * i, Qrst[i], Qsize, 0);
            }
        }
        void CRTDecPoly(Ciphertext::ct_coeff_type *poly, vector<vector<uint64_t>> &crtdec)
        {
            size_t Wlen = targetP::Bgbit;
            uint64_t mask = targetP::Bg - 1;
            auto &coeff_modulus = context_.first_context_data()->parms().coeff_modulus();
            for (size_t i = 0; i < coeff_modulus_size; i++)
                for (size_t j = 0; j < poly_degree; j++)
                    poly[j + i * poly_degree] = util::multiply_uint_mod(poly[j + i * poly_degree], Qinv[i], coeff_modulus[i]);
            crtdec.resize(Qword);
            for (size_t k = 0; k < Qword; k++)
                crtdec[k].resize(poly_degree);
            for (size_t j = 0; j < poly_degree; j++)
                for (size_t i = 0; i < coeff_modulus_size; i++) {
                    __uint128_t prod = 0;
                    for (size_t k = 0; k < Qword; k++) {
                        uint64_t val = Qrst[i][Qword - 1 - k];
                        prod += static_cast<__uint128_t>(poly[j + i * poly_degree]) * val + crtdec[Qword - 1 - k][j];
                        crtdec[Qword - 1 - k][j] = prod & mask;
                        prod >>= Wlen;
                    }
                }
        }

        inline void basered(const uint64_t *vec_in, vector<uint64_t> &vec_out, size_t in_cnt, const size_t sft) const
        {
            for (size_t i = 0; i < Qword; i++) {
                // CRTDecPoly consumes little-endian base-Bg digits and stores them in reverse
                // order. Align to the padded gadget width, not to the exact bit length of Q:
                // otherwise a short least-significant digit is shifted into the high bits of
                // one limb and no longer matches the RGSW gadget powers.
                int64_t source_start = static_cast<int64_t>((Qword - 1 - i) * targetP::Bgbit);
                uint64_t digit = 0;
                for (size_t bit = 0; bit < targetP::Bgbit; bit++) {
                    int64_t shifted_source = source_start + static_cast<int64_t>(bit);
                    if (shifted_source < static_cast<int64_t>(sft)) {
                        continue;
                    }
                    size_t source = static_cast<size_t>(shifted_source - static_cast<int64_t>(sft));
                    size_t word = source / 64;
                    size_t offset = source % 64;
                    if (word < in_cnt && ((vec_in[word] >> offset) & 1ULL) != 0) {
                        digit |= 1ULL << bit;
                    }
                }
                vec_out[i] = digit;
            }
        }
        vector<vector<uint64_t>> Qrst;
        vector<uint64_t> Qtot;
        vector<uint64_t> Qinv;
        SEALContext context_;
        size_t coeff_modulus_size;
        size_t poly_degree;
        size_t Qword;
        size_t Qlen;
    };
} // namespace seal
