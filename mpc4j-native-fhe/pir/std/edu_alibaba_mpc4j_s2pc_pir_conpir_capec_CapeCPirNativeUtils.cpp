#include "edu_alibaba_mpc4j_s2pc_pir_conpir_capec_CapeCPirNativeUtils.h"
#include "seal/seal.h"
#include "../../serialize.h"
#include "../../index_pir.h"
#include "../../tfhe/tfhe.h"
#include "../../utils.h"
#include "seal/util/polyarithsmallmod.h"
#include <algorithm>
#include <iostream>
#include <sstream>
#include <stdexcept>

using namespace seal;
using namespace std;

namespace {
    vector<int> jint_array_to_vector(JNIEnv *env, jintArray array) {
        jsize length = env->GetArrayLength(array);
        jint *elements = env->GetIntArrayElements(array, nullptr);
        vector<int> result(elements, elements + length);
        env->ReleaseIntArrayElements(array, elements, JNI_ABORT);
        return result;
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_capec_CapeCPirNativeUtils_generateEncryptionParams
    (JNIEnv *env, jclass, jint poly_modulus_degree, jlong plain_modulus, jintArray coeff_modulus_bits) {
    try {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(static_cast<size_t>(poly_modulus_degree));
        parms.set_plain_modulus(static_cast<uint64_t>(plain_modulus));
        parms.set_coeff_modulus(CoeffModulus::Create(
            static_cast<size_t>(poly_modulus_degree), jint_array_to_vector(env, coeff_modulus_bits)
        ));
        SEALContext context = create_context_128(parms, "CAPE_C", __func__);
        log_bfv_parameter_summary("[CAPE-C-PARAM]", "CAPE-C", context, true);
        return serialize_encryption_parms(env, parms);
    } catch (const exception &e) {
        jclass exception = env->FindClass("java/lang/RuntimeException");
        if (exception != nullptr) {
            env->ThrowNew(exception, e.what());
            env->DeleteLocalRef(exception);
        }
        return nullptr;
    }
}

namespace {
    void throw_runtime(JNIEnv *env, const char *message) {
        jclass exception = env->FindClass("java/lang/RuntimeException");
        if (exception != nullptr) {
            env->ThrowNew(exception, message);
            env->DeleteLocalRef(exception);
        }
    }

    void require_non_null(jobject object, const char *name) {
        if (object == nullptr) {
            throw invalid_argument(string(name) + " must not be null");
        }
    }

    string string_from_bytes(JNIEnv *env, jbyteArray bytes) {
        require_non_null(bytes, "byte array");
        jbyte *data = env->GetByteArrayElements(bytes, nullptr);
        if (data == nullptr) {
            throw invalid_argument("GetByteArrayElements returned null");
        }
        string result(reinterpret_cast<char *>(data), env->GetArrayLength(bytes));
        env->ReleaseByteArrayElements(bytes, data, JNI_ABORT);
        return result;
    }

    jobject list_get(JNIEnv *env, jobject list, jint index) {
        require_non_null(list, "list");
        jclass list_class = env->FindClass("java/util/List");
        jmethodID get = env->GetMethodID(list_class, "get", "(I)Ljava/lang/Object;");
        jobject item = env->CallObjectMethod(list, get, index);
        env->DeleteLocalRef(list_class);
        return item;
    }

    jint list_size(JNIEnv *env, jobject list) {
        require_non_null(list, "list");
        jclass list_class = env->FindClass("java/util/List");
        jmethodID size = env->GetMethodID(list_class, "size", "()I");
        jint result = env->CallIntMethod(list, size);
        env->DeleteLocalRef(list_class);
        return result;
    }

    Plaintext deserialize_plaintext_from_list(JNIEnv *env, jobject list, jint index, const SEALContext &context) {
        auto item = reinterpret_cast<jbyteArray>(list_get(env, list, index));
        string data = string_from_bytes(env, item);
        env->DeleteLocalRef(item);
        Plaintext result;
        istringstream input(data);
        result.load(context, input);
        return result;
    }

    jobject new_array_list(JNIEnv *env) {
        jclass array_list_class = env->FindClass("java/util/ArrayList");
        jmethodID init = env->GetMethodID(array_list_class, "<init>", "()V");
        jobject list = env->NewObject(array_list_class, init);
        env->DeleteLocalRef(array_list_class);
        return list;
    }

    void list_add(JNIEnv *env, jobject list, jobject item) {
        jclass list_class = env->FindClass("java/util/List");
        jmethodID add = env->GetMethodID(list_class, "add", "(Ljava/lang/Object;)Z");
        env->CallBooleanMethod(list, add, item);
        env->DeleteLocalRef(list_class);
    }

    RGSWCipher deserialize_rgsw(JNIEnv *env, jbyteArray bytes, const SEALContext &context) {
        string data = string_from_bytes(env, bytes);
        istringstream input(data);
        uint32_t size;
        input.read(reinterpret_cast<char *>(&size), sizeof(size));
        RGSWCipher result;
        result.reserve(size);
        for (uint32_t i = 0; i < size; i++) {
            uint32_t ct_size;
            input.read(reinterpret_cast<char *>(&ct_size), sizeof(ct_size));
            string ct_bytes(ct_size, '\0');
            input.read(ct_bytes.data(), static_cast<streamsize>(ct_size));
            istringstream ct_input(ct_bytes);
            Ciphertext ct;
            ct.load(context, ct_input);
            result.emplace_back(std::move(ct));
        }
        return result;
    }

    vector<vector<RGSWCipher>> deserialize_flat_rgsw_bits(JNIEnv *env, jobject flattened_bits,
                                                         jint hash_num, jint bit_num,
                                                         const SEALContext &context, const char *name) {
        if (list_size(env, flattened_bits) != hash_num * bit_num) {
            throw invalid_argument(string(name) + " flattened bit count mismatch");
        }
        vector<vector<RGSWCipher>> bits(static_cast<size_t>(hash_num));
        for (jint h = 0; h < hash_num; h++) {
            bits[static_cast<size_t>(h)].reserve(static_cast<size_t>(bit_num));
            for (jint b = 0; b < bit_num; b++) {
                auto bit_bytes = reinterpret_cast<jbyteArray>(list_get(env, flattened_bits, h * bit_num + b));
                bits[static_cast<size_t>(h)].push_back(deserialize_rgsw(env, bit_bytes, context));
                env->DeleteLocalRef(bit_bytes);
            }
        }
        return bits;
    }

    uint32_t ceil_log2(uint32_t n) {
        uint32_t log = 0;
        uint32_t pow = 1;
        while (pow < n) {
            pow <<= 1;
            log++;
        }
        return log;
    }

    Ciphertext mul_by_monomial(const Ciphertext &ct, int exponent, const SEALContext &context) {
        auto n = static_cast<int>(context.first_context_data()->parms().poly_modulus_degree());
        int modulus = 2 * n;
        int normalized = exponent % modulus;
        if (normalized < 0) {
            normalized += modulus;
        }
        Ciphertext out;
        multiply_power_of_X(ct, out, static_cast<uint32_t>(normalized), context);
        return out;
    }

    Ciphertext cmux(const RGSWCipher &gsw_bit, const Ciphertext &ct1, const Ciphertext &ct0,
                    TFHEcipher &tfhe, Evaluator &evaluator, const SEALContext &context) {
        Ciphertext diff = ct1;
        evaluator.sub_inplace(diff, ct0);
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
        tfhe.ExternalProduct(selected, diff, gsw_bit);
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

    Ciphertext build_private_column_selector(const vector<RGSWCipher> &col_bits, int col_num,
                                             int blocks_per_packed_matrix, const SEALContext &context,
                                             Encryptor &encryptor, TFHEcipher &tfhe, Evaluator &evaluator) {
        uint32_t bit_num = ceil_log2(static_cast<uint32_t>(col_num));
        if (col_bits.size() < bit_num) {
            throw invalid_argument("not enough encrypted column bits");
        }
        Plaintext one(context.first_context_data()->parms().poly_modulus_degree());
        one.set_zero();
        one[0] = 1;
        Ciphertext current;
        encryptor.encrypt(one, current);
        for (uint32_t j = 0; j < bit_num; j++) {
            Ciphertext shifted = mul_by_monomial(
                current, static_cast<int>((1U << j) * blocks_per_packed_matrix), context
            );
            current = cmux(col_bits[j], shifted, current, tfhe, evaluator, context);
        }
        return current;
    }

    Ciphertext blind_rotate_to_zero(const Ciphertext &packed_column, const vector<RGSWCipher> &encrypted_row_bits,
                                    int row_num, int row_stride, const SEALContext &context, TFHEcipher &tfhe,
                                    Evaluator &evaluator) {
        Ciphertext current = packed_column;
        uint32_t bit_num = ceil_log2(static_cast<uint32_t>(row_num));
        if (encrypted_row_bits.size() < bit_num) {
            throw invalid_argument("not enough encrypted row bits");
        }
        for (uint32_t j = 0; j < bit_num; j++) {
            Ciphertext shifted = mul_by_monomial(current, -static_cast<int>((1U << j) * row_stride), context);
            current = cmux(encrypted_row_bits[j], shifted, current, tfhe, evaluator, context);
        }
        return current;
    }

    void keep_constant_coefficient_inplace(Evaluator &evaluator, Ciphertext &ciphertext,
                                           const GaloisKeys &galois_keys, const SEALContext &context) {
        const auto &parms = context.first_context_data()->parms();
        size_t coeff_count = parms.poly_modulus_degree();
        for (size_t stride = coeff_count / 2; stride >= 1; stride >>= 1) {
            Ciphertext folded;
            evaluator.apply_galois(ciphertext, static_cast<uint32_t>(2 * stride + 1), galois_keys, folded);
            evaluator.add_inplace(ciphertext, folded);
            if (stride == 1) {
                break;
            }
        }
    }

    Plaintext build_shifted_matrix_row(const Plaintext &raw_row, const EncryptionParameters &parms,
                                       int col_num, int blocks_per_packed_matrix) {
        uint32_t coeff_count = parms.poly_modulus_degree();
        Plaintext plain(coeff_count);
        plain.set_zero();
        for (jint col = 0; col < col_num; col++) {
            for (jint block_offset = 0; block_offset < blocks_per_packed_matrix; block_offset++) {
                size_t raw_index = static_cast<size_t>(col * blocks_per_packed_matrix + block_offset);
                if (raw_index >= raw_row.coeff_count()) {
                    continue;
                }
                uint64_t raw = raw_row[raw_index];
                if (raw == 0) {
                    continue;
                }
                uint64_t value = raw % parms.plain_modulus().value();
                int exponent = block_offset - col * blocks_per_packed_matrix;
                if (exponent >= 0) {
                    plain[static_cast<size_t>(exponent)] = value;
                } else {
                    plain[static_cast<size_t>(static_cast<int>(coeff_count) + exponent)]
                        = (parms.plain_modulus().value() - value) % parms.plain_modulus().value();
                }
            }
        }
        return plain;
    }

    Plaintext build_shifted_matrix_row_with_query_stride(const Plaintext &raw_row,
                                                         const EncryptionParameters &parms,
                                                         int col_num,
                                                         int matrix_col_offset,
                                                         int matrix_blocks_per_packed_matrix,
                                                         int query_blocks_per_packed_matrix) {
        uint32_t coeff_count = parms.poly_modulus_degree();
        Plaintext plain(coeff_count);
        plain.set_zero();
        for (jint col = 0; col < col_num; col++) {
            for (jint block_offset = 0; block_offset < matrix_blocks_per_packed_matrix; block_offset++) {
                size_t raw_index = static_cast<size_t>(col * matrix_blocks_per_packed_matrix + block_offset);
                if (raw_index >= raw_row.coeff_count()) {
                    continue;
                }
                uint64_t raw = raw_row[raw_index];
                if (raw == 0) {
                    continue;
                }
                uint64_t value = raw % parms.plain_modulus().value();
                int exponent = block_offset - (matrix_col_offset + col) * query_blocks_per_packed_matrix;
                exponent %= static_cast<int>(coeff_count);
                if (exponent < 0) {
                    exponent += static_cast<int>(coeff_count);
                    value = (parms.plain_modulus().value() - value) % parms.plain_modulus().value();
                }
                plain[static_cast<size_t>(exponent)] = value;
            }
        }
        return plain;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_capec_CapeCPirNativeUtils_generateCapeCCandidateReply
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jobject col_rgsw_bits,
     jobject row_rgsw_bits, jobject encoded_matrices, jint payload_block_num, jint row_num, jint col_num,
     jint blocks_per_packed_matrix) {
    try {
        if (payload_block_num <= 0 || row_num <= 0 || col_num <= 0 || blocks_per_packed_matrix <= 0) {
            throw invalid_argument("invalid CAPE_C candidate retrieval shape");
        }
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE_C", __func__);
        Evaluator evaluator(context);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        vector<Plaintext> raw_matrix_rows = deserialize_plaintexts(env, encoded_matrices, context);
        uint32_t coeff_count = parms.poly_modulus_degree();
        jint packed_matrix_group_num = (payload_block_num + blocks_per_packed_matrix - 1)
            / blocks_per_packed_matrix;
        jint row_stride = col_num * blocks_per_packed_matrix;
        if (static_cast<uint64_t>(row_num) * static_cast<uint64_t>(row_stride) > coeff_count) {
            throw invalid_argument("CAPE_C packed matrix requires rowNum * rowStride <= polyModulusDegree");
        }
        if (raw_matrix_rows.size() != static_cast<size_t>(packed_matrix_group_num * row_num)) {
            throw invalid_argument("CAPE_C encoded matrix size mismatch");
        }
        constexpr jint hash_num = 3;
        jint row_bit_num = static_cast<jint>(ceil_log2(static_cast<uint32_t>(row_num)));
        jint col_bit_num = static_cast<jint>(ceil_log2(static_cast<uint32_t>(col_num)));
        vector<vector<RGSWCipher>> row_bits = deserialize_flat_rgsw_bits(
            env, row_rgsw_bits, hash_num, row_bit_num, context, "CAPE_C row RGSW bits"
        );
        vector<vector<RGSWCipher>> col_bits = deserialize_flat_rgsw_bits(
            env, col_rgsw_bits, hash_num, col_bit_num, context, "CAPE_C column RGSW bits"
        );
        TFHEcipher tfhe(context, public_key);
        Encryptor encryptor(context, public_key);
        vector<Ciphertext> column_selectors(hash_num);
        for (jint a = 0; a < hash_num; a++) {
            column_selectors[static_cast<size_t>(a)] = build_private_column_selector(
                col_bits[static_cast<size_t>(a)], col_num, blocks_per_packed_matrix, context, encryptor,
                tfhe, evaluator
            );
        }
        size_t result_count = static_cast<size_t>(
            (static_cast<uint64_t>(payload_block_num) + coeff_count - 1) / coeff_count
        );
        vector<Ciphertext> replies(result_count);
        vector<bool> reply_initialized(result_count, false);
        for (jint group = 0; group < packed_matrix_group_num; group++) {
            Ciphertext group_reply;
            bool initialized = false;
            for (jint a = 0; a < hash_num; a++) {
                const Ciphertext &column_selector = column_selectors[static_cast<size_t>(a)];
                Ciphertext packed_col;
                bool packed_initialized = false;
                for (jint row = 0; row < row_num; row++) {
                    const Plaintext &raw_row = raw_matrix_rows[group * row_num + row];
                    if (raw_row.is_zero()) {
                        continue;
                    }
                    Plaintext matrix_row = build_shifted_matrix_row(
                        raw_row, parms, col_num, blocks_per_packed_matrix
                    );
                    if (matrix_row.is_zero()) {
                        continue;
                    }
                    Ciphertext selected;
                    evaluator.multiply_plain(column_selector, matrix_row, selected);
                    if (selected.is_transparent()) {
                        continue;
                    }
                    Ciphertext coeff_selected = selected;
                    if (row > 0) {
                        coeff_selected = mul_by_monomial(coeff_selected, row * row_stride, context);
                    }
                    if (!packed_initialized) {
                        packed_col = coeff_selected;
                        packed_initialized = true;
                    } else if (!coeff_selected.is_transparent()) {
                        evaluator.add_inplace(packed_col, coeff_selected);
                    }
                }
                if (!packed_initialized) {
                    continue;
                }
                Ciphertext rotated = blind_rotate_to_zero(
                    packed_col, row_bits[static_cast<size_t>(a)], row_num, row_stride, context, tfhe, evaluator
                );
                if (!initialized) {
                    group_reply = rotated;
                    initialized = true;
                } else if (!rotated.is_transparent()) {
                    evaluator.add_inplace(group_reply, rotated);
                }
            }
            if (!initialized) {
                encryptor.encrypt_zero(group_reply);
            }
            if (group_reply.is_ntt_form()) {
                evaluator.transform_from_ntt_inplace(group_reply);
            }
            uint64_t global_offset = static_cast<uint64_t>(group) * blocks_per_packed_matrix;
            if (global_offset >= static_cast<uint64_t>(payload_block_num)) {
                break;
            }
            uint64_t active_block_num = min<uint64_t>(
                static_cast<uint64_t>(blocks_per_packed_matrix),
                static_cast<uint64_t>(payload_block_num) - global_offset
            );
            size_t result_index = static_cast<size_t>(global_offset / coeff_count);
            int local_offset = static_cast<int>(global_offset % coeff_count);
            if (static_cast<uint64_t>(local_offset) + active_block_num > coeff_count) {
                throw invalid_argument("CAPE_C packed value group crosses BFV ciphertext boundary");
            }
            Ciphertext shifted_reply = local_offset == 0
                ? group_reply
                : mul_by_monomial(group_reply, local_offset, context);
            if (!reply_initialized[result_index]) {
                replies[result_index] = shifted_reply;
                reply_initialized[result_index] = true;
            } else if (!shifted_reply.is_transparent()) {
                evaluator.add_inplace(replies[result_index], shifted_reply);
            }
        }
        for (size_t result_index = 0; result_index < replies.size(); result_index++) {
            if (!reply_initialized[result_index]) {
                encryptor.encrypt_zero(replies[result_index]);
            }
        }
        return serialize_ciphertexts(env, replies);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_capec_CapeCPirNativeUtils_generateCapeCFusedPackedCoeffCtCtBloomScoresPackedBloom
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jbyteArray relin_keys_bytes,
     jbyteArray galois_keys_bytes, jobject col_rgsw_bits, jobject row_rgsw_bits, jobject encoded_matrices,
     jobject encrypted_packed_bloom_queries, jint payload_block_num, jint row_num, jint col_num,
     jint bloom_matrix_column_capacity, jint query_blocks_per_packed_matrix, jint blocks_per_packed_matrix,
     jint max_value_num_per_keyword, jint bloom_bit_length) {
    GaloisKeys *galois_keys = nullptr;
    try {
        if (max_value_num_per_keyword <= 0 || payload_block_num <= 0 || row_num <= 0 || col_num <= 0
            || bloom_matrix_column_capacity <= 0 || query_blocks_per_packed_matrix <= 0
            || blocks_per_packed_matrix <= 0 || bloom_bit_length <= 0) {
            throw invalid_argument("invalid CAPE_C packed Bloom fused packed score parameters");
        }
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "CAPE_C", __func__);
        Evaluator evaluator(context);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        RelinKeys relin_keys = deserialize_relin_keys(env, relin_keys_bytes, context);
        galois_keys = deserialize_galois_keys(env, galois_keys_bytes, context);
        vector<Ciphertext> packed_bloom_queries = deserialize_ciphertexts(env, encrypted_packed_bloom_queries, context);
        uint32_t coeff_count = parms.poly_modulus_degree();
        if (static_cast<size_t>(max_value_num_per_keyword) > coeff_count) {
            throw invalid_argument("maxValueNumPerKeyword exceeds score packing capacity");
        }
        if (bloom_bit_length > static_cast<jint>(coeff_count)) {
            throw invalid_argument("CAPE_C packed Bloom payload requires bloomBitLength <= polyModulusDegree");
        }
        if (blocks_per_packed_matrix % bloom_bit_length != 0) {
            throw invalid_argument("CAPE_C packed Bloom coefficient stride must be a multiple of bloomBitLength");
        }
        jint bloom_per_packed_block = blocks_per_packed_matrix / bloom_bit_length;
        if (bloom_per_packed_block <= 0) {
            throw invalid_argument("CAPE_C packed Bloom coefficient stride cannot hold one Bloom filter");
        }
        jint expected_packed_payload_block_num = (max_value_num_per_keyword + bloom_per_packed_block - 1)
            / bloom_per_packed_block;
        if (payload_block_num != expected_packed_payload_block_num) {
            throw invalid_argument("CAPE_C packed Bloom payload block count mismatch");
        }
        jint packed_query_bloom_num = (bloom_bit_length + static_cast<jint>(coeff_count) - 1)
            / static_cast<jint>(coeff_count);
        if (packed_bloom_queries.size() != static_cast<size_t>(packed_query_bloom_num)) {
            throw invalid_argument("CAPE_C packed Bloom formal query ciphertext count mismatch");
        }
        if (packed_bloom_queries.empty()) {
            throw invalid_argument("CAPE_C packed Bloom query is empty");
        }
        if (static_cast<uint64_t>(col_num) * static_cast<uint64_t>(query_blocks_per_packed_matrix) > coeff_count) {
            throw invalid_argument("CAPE_C packed Bloom query column stride exceeds polyModulusDegree");
        }
        jint column_tile_num = (col_num + bloom_matrix_column_capacity - 1) / bloom_matrix_column_capacity;
        if (static_cast<uint64_t>(bloom_matrix_column_capacity) * static_cast<uint64_t>(blocks_per_packed_matrix)
            > coeff_count) {
            throw invalid_argument("CAPE_C packed Bloom matrix column tile exceeds polyModulusDegree");
        }
        jint row_stride = blocks_per_packed_matrix;
        if (static_cast<uint64_t>(row_num) * static_cast<uint64_t>(row_stride) > coeff_count) {
            throw invalid_argument("CAPE_C packed Bloom matrix requires rowNum * rowStride <= polyModulusDegree");
        }
        constexpr jint hash_num = 3;
        jint row_bit_num = static_cast<jint>(ceil_log2(static_cast<uint32_t>(row_num)));
        jint col_bit_num = static_cast<jint>(ceil_log2(static_cast<uint32_t>(col_num)));
        vector<vector<RGSWCipher>> row_bits = deserialize_flat_rgsw_bits(
            env, row_rgsw_bits, hash_num, row_bit_num, context, "CAPE_C packed Bloom row RGSW bits"
        );
        vector<vector<RGSWCipher>> col_bits = deserialize_flat_rgsw_bits(
            env, col_rgsw_bits, hash_num, col_bit_num, context, "CAPE_C packed Bloom column RGSW bits"
        );
        jint encoded_matrix_size = list_size(env, encoded_matrices);
        if (encoded_matrix_size != payload_block_num * column_tile_num * row_num) {
            throw invalid_argument("encoded matrix size mismatch in CAPE_C packed Bloom fused score");
        }
        cerr << "[CAPE_C-CHECKPOINT] native packed Bloom score begin: packedMatrixGroupNum="
             << payload_block_num << ", rowNum=" << row_num << ", encodedMatrixRows="
             << encoded_matrix_size << ", maxValueNumPerKeyword=" << max_value_num_per_keyword
             << ", bloomBitLength=" << bloom_bit_length << ", bloomPerPackedBlock=" << bloom_per_packed_block
             << ", bloomMatrixColumnCapacity=" << bloom_matrix_column_capacity
             << ", bloomMatrixColumnTileNum=" << column_tile_num
             << ", queryBlocksPerPackedMatrix=" << query_blocks_per_packed_matrix
             << ", bloomBlocksPerPackedMatrix=" << blocks_per_packed_matrix
             << ", scoreExtractionLoopBound=maxValueNumPerKeyword" << endl;
        TFHEcipher tfhe(context, public_key);
        Encryptor encryptor(context, public_key);
        vector<Ciphertext> column_selectors(hash_num);
        for (jint a = 0; a < hash_num; a++) {
            column_selectors[static_cast<size_t>(a)] = build_private_column_selector(
                col_bits[static_cast<size_t>(a)], col_num, query_blocks_per_packed_matrix, context, encryptor,
                tfhe, evaluator
            );
        }
        Ciphertext packed_score;
        bool packed_score_initialized = false;
        for (jint group = 0; group < payload_block_num; group++) {
            if (group == 0 || group + 1 == payload_block_num || group % 16 == 0) {
                cerr << "[CAPE_C-CHECKPOINT] native packed Bloom score group "
                     << (group + 1) << "/" << payload_block_num << endl;
            }
            Ciphertext group_reply;
            bool group_initialized = false;
            for (jint a = 0; a < hash_num; a++) {
                const Ciphertext &column_selector = column_selectors[static_cast<size_t>(a)];
                Ciphertext packed_col;
                bool packed_col_initialized = false;
                for (jint column_tile = 0; column_tile < column_tile_num; column_tile++) {
                    jint tile_start_col = column_tile * bloom_matrix_column_capacity;
                    jint tile_col_num = min(bloom_matrix_column_capacity, col_num - tile_start_col);
                    for (jint row = 0; row < row_num; row++) {
                        Plaintext raw_row = deserialize_plaintext_from_list(
                            env, encoded_matrices,
                            (group * column_tile_num + column_tile) * row_num + row, context
                        );
                        if (raw_row.is_zero()) {
                            continue;
                        }
                        Plaintext matrix_row = build_shifted_matrix_row_with_query_stride(
                            raw_row, parms, tile_col_num, tile_start_col, blocks_per_packed_matrix,
                            query_blocks_per_packed_matrix
                        );
                        if (matrix_row.is_zero()) {
                            continue;
                        }
                        Ciphertext selected;
                        evaluator.multiply_plain(column_selector, matrix_row, selected);
                        if (selected.is_transparent()) {
                            continue;
                        }
                        Ciphertext coeff_selected = selected;
                        if (row > 0) {
                            coeff_selected = mul_by_monomial(coeff_selected, row * row_stride, context);
                        }
                        if (!packed_col_initialized) {
                            packed_col = coeff_selected;
                            packed_col_initialized = true;
                        } else if (!coeff_selected.is_transparent()) {
                            evaluator.add_inplace(packed_col, coeff_selected);
                        }
                    }
                }
                if (!packed_col_initialized) {
                    continue;
                }
                Ciphertext rotated = blind_rotate_to_zero(
                    packed_col, row_bits[static_cast<size_t>(a)], row_num, row_stride, context, tfhe, evaluator
                );
                if (!group_initialized) {
                    group_reply = rotated;
                    group_initialized = true;
                } else if (!rotated.is_transparent()) {
                    evaluator.add_inplace(group_reply, rotated);
                }
            }
            if (!group_initialized) {
                encryptor.encrypt_zero(group_reply);
            }
            if (group_reply.is_ntt_form()) {
                evaluator.transform_from_ntt_inplace(group_reply);
            }
            Ciphertext product;
            evaluator.multiply(group_reply, packed_bloom_queries[0], product);
            evaluator.relinearize_inplace(product, relin_keys);
            if (product.is_transparent()) {
                continue;
            }
            jint valid_candidate_windows = min(
                bloom_per_packed_block, max_value_num_per_keyword - group * bloom_per_packed_block
            );
            cerr << "[CAPE_C-CHECKPOINT] native packed Bloom block " << (group + 1) << "/"
                 << payload_block_num << ": validCandidateWindows=" << valid_candidate_windows
                 << ", ignoredPaddingCoefficients=" << (coeff_count - valid_candidate_windows * bloom_bit_length)
                 << ", scoreExtractionLoopBound=" << valid_candidate_windows << endl;
            for (jint local_candidate = 0; local_candidate < valid_candidate_windows; local_candidate++) {
                jint global_candidate = group * bloom_per_packed_block + local_candidate;
                jint dot_coeff = local_candidate * bloom_bit_length;
                Ciphertext candidate_score = dot_coeff == 0
                    ? product
                    : mul_by_monomial(product, -dot_coeff, context);
                keep_constant_coefficient_inplace(evaluator, candidate_score, *galois_keys, context);
                Ciphertext shifted_score = global_candidate == 0
                    ? candidate_score
                    : mul_by_monomial(candidate_score, global_candidate, context);
                if (!packed_score_initialized) {
                    packed_score = shifted_score;
                    packed_score_initialized = true;
                } else if (!shifted_score.is_transparent()) {
                    evaluator.add_inplace(packed_score, shifted_score);
                }
            }
        }
        cerr << "[CAPE_C-CHECKPOINT] native packed Bloom score packing end" << endl;
        if (!packed_score_initialized) {
            encryptor.encrypt_zero(packed_score);
        }
        jobject scores = new_array_list(env);
        jbyteArray score_bytes = serialize_ciphertext(env, packed_score);
        list_add(env, scores, score_bytes);
        env->DeleteLocalRef(score_bytes);
        cerr << "[CAPE_C-CHECKPOINT] native packed Bloom score end" << endl;
        delete galois_keys;
        return scores;
    } catch (const exception &e) {
        if (galois_keys != nullptr) {
            delete galois_keys;
        }
        throw_runtime(env, e.what());
        return nullptr;
    }
}
