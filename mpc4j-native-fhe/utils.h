//
// Created by pengliqiang on 2022/9/8.
//

#ifndef MPC4J_NATIVE_FHE_UTILS_H
#define MPC4J_NATIVE_FHE_UTILS_H

#include <iomanip>
#include <memory>
#include "seal/seal.h"

using namespace seal;
using namespace std;


parms_id_type get_parms_id_for_chain_idx(const SEALContext& seal_context, uint32_t chain_idx);

Serializable<GaloisKeys> generate_galois_keys(const SEALContext& context, KeyGenerator &keygen);

uint64_t invert_mod(uint64_t m, const seal::Modulus &mod);

void try_clear_irrelevant_bits(const EncryptionParameters &parms, Ciphertext &ciphertext);

void sample_poly_uniform(size_t bit_width, const EncryptionParameters &parms, uint64_t *destination);

vector<Modulus> create_default_bfv_coeff_modulus_128(size_t poly_modulus_degree);

EncryptionParameters create_default_bfv_parameters_128(size_t poly_modulus_degree, uint64_t plain_modulus);

SEALContext create_context_128(const EncryptionParameters &parms, const string &scheme_name,
                               const char *location);

void log_bfv_parameter_summary(const string &prefix, const string &scheme_name, const SEALContext &context,
                               bool include_non_seal_note);

void multiply_acum(uint64_t op1, uint64_t op2, __uint128_t& product_acum);

void multiply_poly_acum(const uint64_t *ct_ptr, const uint64_t *pt_ptr, size_t size, __uint128_t *result);

#endif //MPC4J_NATIVE_FHE_UTILS_H
