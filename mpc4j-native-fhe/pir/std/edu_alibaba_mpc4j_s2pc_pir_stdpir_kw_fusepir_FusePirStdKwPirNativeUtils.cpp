#include "edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepir_FusePirStdKwPirNativeUtils.h"
#include "../../serialize.h"
#include "../../index_pir.h"
#include "../../tfhe/tfhe.h"
#include "../../utils.h"
#include "seal/seal.h"
#include "seal/util/iterator.h"
#include "seal/util/polyarithsmallmod.h"
#include <cmath>
#include <cstring>

using namespace seal;
using namespace std;

namespace {
    void throw_unsupported(JNIEnv *env, const char *message) {
        jclass exception = env->FindClass("java/lang/UnsupportedOperationException");
        if (exception != nullptr) {
            env->ThrowNew(exception, message);
        }
    }

    vector<int> jint_array_to_vector(JNIEnv *env, jintArray array) {
        jsize length = env->GetArrayLength(array);
        jint *elements = env->GetIntArrayElements(array, nullptr);
        vector<int> result(elements, elements + length);
        env->ReleaseIntArrayElements(array, elements, JNI_ABORT);
        return result;
    }

    void throw_runtime(JNIEnv *env, const char *message) {
        jclass exception = env->FindClass("java/lang/RuntimeException");
        if (exception != nullptr) {
            env->ThrowNew(exception, message);
        }
    }

    jobject new_array_list(JNIEnv *env) {
        jclass list_cls = env->FindClass("java/util/ArrayList");
        jmethodID list_init = env->GetMethodID(list_cls, "<init>", "()V");
        jobject list = env->NewObject(list_cls, list_init);
        env->DeleteLocalRef(list_cls);
        return list;
    }

    void list_add(JNIEnv *env, jobject list, jobject item) {
        jclass list_cls = env->FindClass("java/util/List");
        jmethodID add_method = env->GetMethodID(list_cls, "add", "(Ljava/lang/Object;)Z");
        env->CallBooleanMethod(list, add_method, item);
        env->DeleteLocalRef(list_cls);
    }

    jobject list_get(JNIEnv *env, jobject list, jint index) {
        jclass list_cls = env->FindClass("java/util/List");
        jmethodID get_method = env->GetMethodID(list_cls, "get", "(I)Ljava/lang/Object;");
        jobject item = env->CallObjectMethod(list, get_method, index);
        env->DeleteLocalRef(list_cls);
        return item;
    }

    jint list_size(JNIEnv *env, jobject list) {
        jclass list_cls = env->FindClass("java/util/List");
        jmethodID size_method = env->GetMethodID(list_cls, "size", "()I");
        jint size = env->CallIntMethod(list, size_method);
        env->DeleteLocalRef(list_cls);
        return size;
    }

    jbyteArray bytes_from_string(JNIEnv *env, const string &data) {
        auto out = env->NewByteArray(static_cast<jsize>(data.size()));
        env->SetByteArrayRegion(out, 0, static_cast<jsize>(data.size()),
                                reinterpret_cast<const jbyte *>(data.data()));
        return out;
    }

    string string_from_bytes(JNIEnv *env, jbyteArray bytes) {
        jbyte *data = env->GetByteArrayElements(bytes, nullptr);
        string result(reinterpret_cast<char *>(data), env->GetArrayLength(bytes));
        env->ReleaseByteArrayElements(bytes, data, JNI_ABORT);
        return result;
    }

    jbyteArray serialize_rgsw(JNIEnv *env, const RGSWCipher &cipher) {
        ostringstream output;
        uint32_t size = static_cast<uint32_t>(cipher.size());
        output.write(reinterpret_cast<const char *>(&size), sizeof(size));
        for (const auto &ct : cipher) {
            ostringstream ct_output;
            ct.save(ct_output, Serialization::compr_mode_default);
            string ct_bytes = ct_output.str();
            uint32_t ct_size = static_cast<uint32_t>(ct_bytes.size());
            output.write(reinterpret_cast<const char *>(&ct_size), sizeof(ct_size));
            output.write(ct_bytes.data(), static_cast<streamsize>(ct_bytes.size()));
        }
        return bytes_from_string(env, output.str());
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
        util::ntt_negacyclic_harvey(plain_iter, coeff_mod_count, context.first_context_data()->small_ntt_tables());
        return plain;
    }

    void scalar_multiply_ciphertext_inplace(Ciphertext &ct, uint64_t scalar, const SEALContext &context) {
        auto &parms = context.first_context_data()->parms();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = parms.coeff_modulus().size();
        const auto &coeff_modulus = parms.coeff_modulus();
        for (size_t poly = 0; poly < ct.size(); poly++) {
            for (size_t mod_index = 0; mod_index < coeff_mod_count; mod_index++) {
                uint64_t reduced_scalar = util::barrett_reduce_64(scalar, coeff_modulus[mod_index]);
                util::multiply_poly_scalar_coeffmod(
                    ct.data(poly) + mod_index * coeff_count, coeff_count, reduced_scalar,
                    coeff_modulus[mod_index], ct.data(poly) + mod_index * coeff_count
                );
            }
        }
    }

    RGSWCipher scalar_multiply_rgsw(const RGSWCipher &cipher, uint64_t scalar, const SEALContext &context) {
        RGSWCipher result = cipher;
        for (auto &ct : result) {
            scalar_multiply_ciphertext_inplace(ct, scalar, context);
        }
        return result;
    }

    void sub_rgsw_inplace(RGSWCipher &left, const RGSWCipher &right, Evaluator &evaluator) {
        if (left.size() != right.size()) {
            throw invalid_argument("RGSW size mismatch");
        }
        for (size_t i = 0; i < left.size(); i++) {
            evaluator.sub_inplace(left[i], right[i]);
        }
    }

    vector<vector<uint64_t>> deserialize_long_matrix(JNIEnv *env, jobjectArray matrix) {
        jsize row_num = env->GetArrayLength(matrix);
        vector<vector<uint64_t>> result(static_cast<size_t>(row_num));
        for (jsize row = 0; row < row_num; row++) {
            auto row_array = reinterpret_cast<jlongArray>(env->GetObjectArrayElement(matrix, row));
            jsize col_num = env->GetArrayLength(row_array);
            jlong *data = env->GetLongArrayElements(row_array, nullptr);
            result[static_cast<size_t>(row)].resize(static_cast<size_t>(col_num));
            for (jsize col = 0; col < col_num; col++) {
                result[static_cast<size_t>(row)][static_cast<size_t>(col)] = static_cast<uint64_t>(data[col]);
            }
            env->ReleaseLongArrayElements(row_array, data, JNI_ABORT);
            env->DeleteLocalRef(row_array);
        }
        return result;
    }

    vector<uint64_t> jlong_array_to_u64_vector(JNIEnv *env, jlongArray array) {
        jsize length = env->GetArrayLength(array);
        jlong *data = env->GetLongArrayElements(array, nullptr);
        vector<uint64_t> result(static_cast<size_t>(length));
        for (jsize i = 0; i < length; i++) {
            result[static_cast<size_t>(i)] = static_cast<uint64_t>(data[i]);
        }
        env->ReleaseLongArrayElements(array, data, JNI_ABORT);
        return result;
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
        try {
            tfhe.ExternalProduct(selected, diff, gsw_bit);
        } catch (const exception &e) {
            throw runtime_error(string("FUSE_PIR CMUX ExternalProduct failed: ") + e.what());
        }
        if (selected.is_transparent()) {
            return ct0;
        }
        if (ct0.is_ntt_form()) {
            evaluator.add_inplace(selected, ct0);
            return selected;
        } else {
            evaluator.transform_from_ntt_inplace(selected);
            evaluator.add_inplace(selected, ct0);
            return selected;
        }
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
            Ciphertext shifted;
            try {
                shifted = mul_by_monomial(current, -static_cast<int>((1U << j) * row_stride), context);
            } catch (const exception &e) {
                throw runtime_error(string("FUSE_PIR BlindRotate monomial shift failed: ") + e.what());
            }
            try {
                current = cmux(encrypted_row_bits[j], shifted, current, tfhe, evaluator, context);
            } catch (const exception &e) {
                throw runtime_error(string("FUSE_PIR BlindRotate CMUX failed: ") + e.what());
            }
        }
        return current;
    }

    vector<vector<vector<uint64_t>>> deserialize_matrices(JNIEnv *env, jobjectArray matrices) {
        jsize payload_block_num = env->GetArrayLength(matrices);
        vector<vector<vector<uint64_t>>> result(payload_block_num);
        for (jsize b = 0; b < payload_block_num; b++) {
            auto rows = reinterpret_cast<jobjectArray>(env->GetObjectArrayElement(matrices, b));
            jsize row_num = env->GetArrayLength(rows);
            result[b].resize(row_num);
            for (jsize r = 0; r < row_num; r++) {
                auto cols = reinterpret_cast<jlongArray>(env->GetObjectArrayElement(rows, r));
                jsize col_num = env->GetArrayLength(cols);
                jlong *col_data = env->GetLongArrayElements(cols, nullptr);
                result[b][r].resize(col_num);
                for (jsize c = 0; c < col_num; c++) {
                    result[b][r][c] = static_cast<uint64_t>(col_data[c]);
                }
                env->ReleaseLongArrayElements(cols, col_data, JNI_ABORT);
                env->DeleteLocalRef(cols);
            }
            env->DeleteLocalRef(rows);
        }
        return result;
    }
}

JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepir_FusePirStdKwPirNativeUtils_generateEncryptionParams
    (JNIEnv *env, jclass, jint poly_modulus_degree, jlong plain_modulus, jintArray coeff_modulus_bits) {
    try {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(static_cast<size_t>(poly_modulus_degree));
        parms.set_plain_modulus(static_cast<uint64_t>(plain_modulus));
        parms.set_coeff_modulus(CoeffModulus::Create(
            static_cast<size_t>(poly_modulus_degree), jint_array_to_vector(env, coeff_modulus_bits)
        ));
        SEALContext context = create_context_128(parms, "FUSE_PIR", __func__);
        log_bfv_parameter_summary("[FusePIR-PARAM]", "FusePIR", context, false);
        return serialize_encryption_parms(env, parms);
    } catch (const exception &e) {
        jclass exception = env->FindClass("java/lang/RuntimeException");
        if (exception != nullptr) {
            env->ThrowNew(exception, e.what());
        }
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepir_FusePirStdKwPirNativeUtils_keyGen
    (JNIEnv *env, jclass, jbyteArray parms_bytes) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "FUSE_PIR", __func__);
        KeyGenerator key_gen(context);
        const SecretKey &secret_key = key_gen.secret_key();
        Serializable<PublicKey> public_key = key_gen.create_public_key();
        jobject list = new_array_list(env);
        jbyteArray sk_bytes = serialize_secret_key(env, secret_key);
        jbyteArray pk_bytes = serialize_public_key(env, public_key);
        list_add(env, list, sk_bytes);
        list_add(env, list, pk_bytes);
        env->DeleteLocalRef(sk_bytes);
        env->DeleteLocalRef(pk_bytes);
        return list;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepir_FusePirStdKwPirNativeUtils_generateColumnQuery
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray, jbyteArray sk_bytes, jint column_index, jint column_num) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "FUSE_PIR", __func__);
        SecretKey secret_key = deserialize_secret_key(env, sk_bytes, context);
        if (column_index < 0 || column_index >= column_num ||
            static_cast<size_t>(column_num) > parms.poly_modulus_degree()) {
            throw invalid_argument("invalid FUSE_PIR column index / column num");
        }
        Plaintext plain(parms.poly_modulus_degree());
        plain.set_zero();
        plain[static_cast<size_t>(column_index)] = 1;
        Encryptor encryptor(context, secret_key);
        Serializable<Ciphertext> query_cipher = encryptor.encrypt_symmetric(plain);
        return serialize_ciphertext(env, query_cipher);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepir_FusePirStdKwPirNativeUtils_generateEncryptedRowBits
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jbyteArray, jint row_index, jint row_num) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "FUSE_PIR", __func__);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        if (row_index < 0 || row_index >= row_num) {
            throw invalid_argument("invalid FUSE_PIR row index / row num");
        }
        TFHEcipher tfhe(context, public_key);
        jobject list = new_array_list(env);
        uint32_t bit_num = ceil_log2(static_cast<uint32_t>(row_num));
        for (uint32_t j = 0; j < bit_num; j++) {
            uint64_t bit = (static_cast<uint32_t>(row_index) >> j) & 1U;
            Plaintext bit_plain = rns_bit_plaintext(context, bit);
            RGSWCipher gsw_bit;
            tfhe.encrypt(bit_plain, gsw_bit);
            jbyteArray bit_bytes = serialize_rgsw(env, gsw_bit);
            list_add(env, list, bit_bytes);
            env->DeleteLocalRef(bit_bytes);
        }
        return list;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepir_FusePirStdKwPirNativeUtils_generateLweToRgswKey
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jlongArray lwe_secret_key) {
    try {
        // Reclaim the large RGSW key-generation scratch pool when this JNI call returns.
        MMProfGuard temporary_pool_guard(make_unique<MMProfNew>());
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "FUSE_PIR", __func__);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        vector<uint64_t> secret_key = jlong_array_to_u64_vector(env, lwe_secret_key);
        TFHEcipher tfhe(context, public_key);
        jobject list = new_array_list(env);
        for (uint64_t secret_bit : secret_key) {
            if (secret_bit != 0 && secret_bit != 1) {
                throw invalid_argument("FUSE_PIR LWE secret key must be binary");
            }
            Plaintext bit_plain = rns_bit_plaintext(context, secret_bit);
            RGSWCipher gsw_bit;
            tfhe.encrypt(bit_plain, gsw_bit);
            jbyteArray bit_bytes = serialize_rgsw(env, gsw_bit);
            list_add(env, list, bit_bytes);
            env->DeleteLocalRef(bit_bytes);
        }
        return list;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepir_FusePirStdKwPirNativeUtils_convertCompressedRowBitsToRgsw
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jobject lwe_to_rgsw_key,
     jobjectArray a_array, jlongArray b_array) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "FUSE_PIR", __func__);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        Evaluator evaluator(context);
        TFHEcipher tfhe(context, public_key);
        vector<vector<uint64_t>> a_vectors = deserialize_long_matrix(env, a_array);
        vector<uint64_t> b_values = jlong_array_to_u64_vector(env, b_array);
        if (a_vectors.size() != b_values.size()) {
            throw invalid_argument("FUSE_PIR compressed row-bit a/b size mismatch");
        }
        jint key_size = list_size(env, lwe_to_rgsw_key);
        if (key_size <= 0) {
            throw invalid_argument("empty FUSE_PIR LWE-to-RGSW key");
        }
        vector<RGSWCipher> key;
        key.reserve(static_cast<size_t>(key_size));
        for (jint i = 0; i < key_size; i++) {
            auto key_bytes = reinterpret_cast<jbyteArray>(list_get(env, lwe_to_rgsw_key, i));
            key.push_back(deserialize_rgsw(env, key_bytes, context));
            env->DeleteLocalRef(key_bytes);
        }
        jobject list = new_array_list(env);
        for (size_t bit_index = 0; bit_index < a_vectors.size(); bit_index++) {
            if (a_vectors[bit_index].size() != key.size()) {
                throw invalid_argument("FUSE_PIR compressed row-bit LWE dimension mismatch");
            }
            Plaintext b_plain = rns_bit_plaintext(context, b_values[bit_index]);
            RGSWCipher result;
            tfhe.encrypt(b_plain, result);
            for (size_t i = 0; i < key.size(); i++) {
                uint64_t scalar = a_vectors[bit_index][i];
                if (scalar == 0) {
                    continue;
                }
                RGSWCipher scaled = scalar_multiply_rgsw(key[i], scalar, context);
                sub_rgsw_inplace(result, scaled, evaluator);
            }
            jbyteArray bit_bytes = serialize_rgsw(env, result);
            list_add(env, list, bit_bytes);
            env->DeleteLocalRef(bit_bytes);
        }
        return list;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepir_FusePirStdKwPirNativeUtils_preprocessDatabase
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jobjectArray matrices, jint col_num,
     jint blocks_per_packed_matrix) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "FUSE_PIR", __func__);
        auto matrix_data = deserialize_matrices(env, matrices);
        uint32_t coeff_count = parms.poly_modulus_degree();
        if (col_num <= 0 || blocks_per_packed_matrix <= 0) {
            throw invalid_argument("invalid FUSE_PIR packed matrix shape");
        }
        jobject list = new_array_list(env);
        for (const auto &block : matrix_data) {
            for (const auto &row : block) {
                if (row.size() != static_cast<size_t>(col_num * blocks_per_packed_matrix)) {
                    throw invalid_argument("FUSE_PIR packed matrix row size mismatch");
                }
                Plaintext plain(coeff_count);
                plain.set_zero();
                for (jint col = 0; col < col_num; col++) {
                    for (jint block_offset = 0; block_offset < blocks_per_packed_matrix; block_offset++) {
                        uint64_t raw = row[col * blocks_per_packed_matrix + block_offset];
                        if (raw == 0) {
                            continue;
                        }
                        uint64_t value = raw % parms.plain_modulus().value();
                        int column_coefficient = col * blocks_per_packed_matrix;
                        int exponent = block_offset - column_coefficient;
                        if (exponent >= 0) {
                            plain[static_cast<size_t>(exponent)] = value;
                        } else {
                            plain[static_cast<size_t>(static_cast<int>(coeff_count) + exponent)]
                                = (parms.plain_modulus().value() - value) % parms.plain_modulus().value();
                        }
                    }
                }
                jbyteArray plain_bytes = serialize_plaintext(env, plain);
                list_add(env, list, plain_bytes);
                env->DeleteLocalRef(plain_bytes);
            }
        }
        return list;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepir_FusePirStdKwPirNativeUtils_generateReply
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jobject column_queries,
     jobject encrypted_row_bits, jobject encoded_matrices, jint payload_block_num, jint row_num, jint col_num,
     jint blocks_per_packed_matrix) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "FUSE_PIR", __func__);
        Evaluator evaluator(context);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        vector<Ciphertext> queries = deserialize_ciphertexts(env, column_queries, context);
        vector<Plaintext> matrix_rows = deserialize_plaintexts(env, encoded_matrices, context);
        uint32_t coeff_count = parms.poly_modulus_degree();
        if (queries.size() != 3) {
            throw invalid_argument("FUSE_PIR needs exactly three BFF position queries");
        }
        if (blocks_per_packed_matrix <= 0) {
            throw invalid_argument("blocksPerPackedMatrix must be positive");
        }
        jint packed_matrix_group_num = (payload_block_num + blocks_per_packed_matrix - 1)
            / blocks_per_packed_matrix;
        jint row_stride = col_num * blocks_per_packed_matrix;
        if (matrix_rows.size() != static_cast<size_t>(packed_matrix_group_num * row_num)) {
            throw invalid_argument("encoded matrix size mismatch");
        }
        if (static_cast<uint64_t>(row_num) * static_cast<uint64_t>(row_stride) > coeff_count) {
            throw invalid_argument("FUSE_PIR packed matrix requires rowNum * rowStride <= polyModulusDegree");
        }
        jint row_bit_num = static_cast<jint>(ceil_log2(static_cast<uint32_t>(row_num)));
        if (list_size(env, encrypted_row_bits) != static_cast<jint>(3 * row_bit_num)) {
            throw invalid_argument("FUSE_PIR flattened encrypted row bits size mismatch");
        }
        vector<vector<RGSWCipher>> row_bits(3);
        for (jint a = 0; a < 3; a++) {
            row_bits[a].reserve(row_bit_num);
            for (jint b = 0; b < row_bit_num; b++) {
                auto bit_bytes = reinterpret_cast<jbyteArray>(list_get(env, encrypted_row_bits, a * row_bit_num + b));
                row_bits[a].push_back(deserialize_rgsw(env, bit_bytes, context));
                env->DeleteLocalRef(bit_bytes);
            }
        }
        TFHEcipher tfhe(context, public_key);
        Encryptor encryptor(context, public_key);
        jint groups_per_reply = static_cast<jint>(coeff_count / blocks_per_packed_matrix);
        if (groups_per_reply <= 0) {
            throw invalid_argument("blocksPerPackedMatrix exceeds response packing capacity");
        }
        jint reply_num = (packed_matrix_group_num + groups_per_reply - 1) / groups_per_reply;
        vector<Ciphertext> replies(static_cast<size_t>(reply_num));
        vector<bool> reply_initialized(static_cast<size_t>(reply_num), false);
        for (jint group = 0; group < packed_matrix_group_num; group++) {
            Ciphertext group_reply;
            bool initialized = false;
            for (jint a = 0; a < 3; a++) {
                Ciphertext packed_col;
                bool packed_initialized = false;
                for (jint row = 0; row < row_num; row++) {
                    const Plaintext &matrix_row = matrix_rows[group * row_num + row];
                    if (matrix_row.is_zero()) {
                        continue;
                    }
                    Ciphertext selected;
                    evaluator.multiply_plain(queries[a], matrix_row, selected);
                    if (selected.is_transparent()) {
                        continue;
                    }
                    Ciphertext coeff_selected = selected;
                    if (row > 0) {
                        try {
                            coeff_selected = mul_by_monomial(coeff_selected, row * row_stride, context);
                        } catch (const exception &e) {
                            throw runtime_error(string("FUSE_PIR row packing monomial shift failed: ") + e.what());
                        }
                    }
                    if (!packed_initialized) {
                        packed_col = coeff_selected;
                        packed_initialized = true;
                    } else {
                        if (!coeff_selected.is_transparent()) {
                            evaluator.add_inplace(packed_col, coeff_selected);
                        }
                    }
                }
                if (!packed_initialized) {
                    continue;
                }
                Ciphertext rotated = blind_rotate_to_zero(
                    packed_col, row_bits[a], row_num, row_stride, context, tfhe, evaluator
                );
                if (!initialized) {
                    group_reply = rotated;
                    initialized = true;
                } else {
                    if (!rotated.is_transparent()) {
                        evaluator.add_inplace(group_reply, rotated);
                    }
                }
            }
            if (!initialized) {
                encryptor.encrypt_zero(group_reply);
            }
            if (group_reply.is_ntt_form()) {
                evaluator.transform_from_ntt_inplace(group_reply);
            }
            jint reply_index = group / groups_per_reply;
            int local_offset = (group % groups_per_reply) * blocks_per_packed_matrix;
            Ciphertext shifted_reply = local_offset == 0
                ? group_reply
                : mul_by_monomial(group_reply, local_offset, context);
            if (!reply_initialized[static_cast<size_t>(reply_index)]) {
                replies[static_cast<size_t>(reply_index)] = shifted_reply;
                reply_initialized[static_cast<size_t>(reply_index)] = true;
            } else if (!shifted_reply.is_transparent()) {
                evaluator.add_inplace(replies[static_cast<size_t>(reply_index)], shifted_reply);
            }
        }
        for (jint reply_index = 0; reply_index < reply_num; reply_index++) {
            if (!reply_initialized[static_cast<size_t>(reply_index)]) {
                encryptor.encrypt_zero(replies[static_cast<size_t>(reply_index)]);
            }
        }
        return serialize_ciphertexts(env, replies);
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}

JNIEXPORT jobjectArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_fusepir_FusePirStdKwPirNativeUtils_decryptReply
    (JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray sk_bytes, jobject response) {
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "FUSE_PIR", __func__);
        SecretKey secret_key = deserialize_secret_key(env, sk_bytes, context);
        vector<Ciphertext> replies = deserialize_ciphertexts(env, response, context);
        Decryptor decryptor(context, secret_key);
        uint32_t coeff_count = parms.poly_modulus_degree();
        jclass long_array_cls = env->FindClass("[J");
        jobjectArray result = env->NewObjectArray(static_cast<jsize>(replies.size()), long_array_cls, nullptr);
        env->DeleteLocalRef(long_array_cls);
        for (jsize i = 0; i < static_cast<jsize>(replies.size()); i++) {
            if (replies[i].is_ntt_form()) {
                Evaluator evaluator(context);
                evaluator.transform_from_ntt_inplace(replies[i]);
            }
            Plaintext plain(coeff_count);
            decryptor.decrypt(replies[i], plain);
            jlongArray row = env->NewLongArray(static_cast<jsize>(coeff_count));
            vector<jlong> coeffs(coeff_count);
            for (uint32_t j = 0; j < coeff_count; j++) {
                coeffs[j] = j < plain.coeff_count() ? static_cast<jlong>(plain[j]) : 0L;
            }
            env->SetLongArrayRegion(row, 0, static_cast<jsize>(coeff_count), coeffs.data());
            env->SetObjectArrayElement(result, i, row);
            env->DeleteLocalRef(row);
        }
        return result;
    } catch (const exception &e) {
        throw_runtime(env, e.what());
        return nullptr;
    }
}
