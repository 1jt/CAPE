#include "edu_alibaba_mpc4j_s2pc_pir_conpir_bkpir_BkPirNativeUtils.h"
#include "seal/seal.h"
#include "../../serialize.h"
#include "../../index_pir.h"
#include "../../utils.h"
#include <stdexcept>

using namespace seal;
using namespace std;

static void throw_java_runtime_exception(JNIEnv *env, const char *message) {
    jclass exception = env->FindClass("java/lang/RuntimeException");
    env->ThrowNew(exception, message);
    env->DeleteLocalRef(exception);
}

static void throw_java_unsupported_exception(JNIEnv *env, const char *message) {
    jclass exception = env->FindClass("java/lang/UnsupportedOperationException");
    env->ThrowNew(exception, message);
    env->DeleteLocalRef(exception);
}

static Plaintext encode_constant_plaintext(const SEALContext &context, uint64_t value) {
    BatchEncoder encoder(context);
    vector<uint64_t> slots(encoder.slot_count(), value);
    Plaintext plaintext;
    encoder.encode(slots, plaintext);
    return plaintext;
}

static uint64_t factorial_mod(uint32_t k, const Modulus &modulus) {
    uint64_t result = 1;
    for (uint32_t i = 2; i <= k; i++) {
        result = (result * i) % modulus.value();
    }
    return result;
}

static void add_all_slots_inplace(Evaluator &evaluator, Ciphertext &ciphertext, const GaloisKeys &galois_keys,
                                  size_t slot_count) {
    size_t row_size = slot_count / 2;
    for (size_t l = 1; l < row_size; l <<= 1) {
        Ciphertext rotated;
        evaluator.rotate_rows(ciphertext, static_cast<int>(l), galois_keys, rotated);
        evaluator.add_inplace(ciphertext, rotated);
    }
    Ciphertext rotated_columns;
    evaluator.rotate_columns(ciphertext, galois_keys, rotated_columns);
    evaluator.add_inplace(ciphertext, rotated_columns);
}

static Ciphertext multiply_many_balanced(Evaluator &evaluator, const RelinKeys &relin_keys,
                                         vector<Ciphertext> ciphertexts) {
    if (ciphertexts.empty()) {
        throw invalid_argument("ciphertexts must not be empty");
    }
    while (ciphertexts.size() > 1) {
        vector<Ciphertext> next;
        next.reserve((ciphertexts.size() + 1) / 2);
        for (size_t i = 0; i < ciphertexts.size(); i += 2) {
            if (i + 1 == ciphertexts.size()) {
                next.push_back(ciphertexts[i]);
            } else {
                Ciphertext product;
                evaluator.multiply(ciphertexts[i], ciphertexts[i + 1], product);
                evaluator.relinearize_inplace(product, relin_keys);
                next.push_back(product);
            }
        }
        ciphertexts = std::move(next);
    }
    return ciphertexts[0];
}

static Ciphertext compute_equality(Evaluator &evaluator, const SEALContext &context, const EncryptionParameters &parms,
                                   const RelinKeys &relin_keys, Ciphertext inner_product, int cw_weight) {
    if (cw_weight <= 0) {
        throw invalid_argument("cwWeight must be positive");
    }
    uint64_t inv_factorial = invert_mod(factorial_mod(static_cast<uint32_t>(cw_weight), parms.plain_modulus()),
                                        parms.plain_modulus());
    Plaintext inv_factorial_pt = encode_constant_plaintext(context, inv_factorial);
    vector<Ciphertext> factors;
    factors.reserve(static_cast<size_t>(cw_weight));
    for (int j = 0; j < cw_weight; j++) {
        Ciphertext factor = inner_product;
        if (j > 0) {
            Plaintext scalar_pt = encode_constant_plaintext(context, static_cast<uint64_t>(j));
            evaluator.sub_plain_inplace(factor, scalar_pt);
        }
        factors.push_back(factor);
    }
    Ciphertext eq = multiply_many_balanced(evaluator, relin_keys, factors);
    evaluator.multiply_plain_inplace(eq, inv_factorial_pt);
    return eq;
}

static Ciphertext compute_encrypted_value_map(Evaluator &evaluator, Encryptor &encryptor, const SEALContext &context,
                                              const EncryptionParameters &parms, const RelinKeys &relin_keys,
                                              const GaloisKeys &galois_keys, const Ciphertext &query,
                                              const vector<Plaintext> &keyword_codewords,
                                              const vector<Plaintext> &value_maps, int cw_weight) {
    if (keyword_codewords.size() != value_maps.size()) {
        throw invalid_argument("encodedKeywordCodewords and encodedValueMaps must have the same size");
    }
    BatchEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    Ciphertext result;
    bool has_result = false;
    for (size_t i = 0; i < keyword_codewords.size(); i++) {
        Ciphertext inner_product;
        evaluator.multiply_plain(query, keyword_codewords[i], inner_product);
        add_all_slots_inplace(evaluator, inner_product, galois_keys, slot_count);
        Ciphertext eq = compute_equality(evaluator, context, parms, relin_keys, inner_product, cw_weight);
        Ciphertext selected_map;
        evaluator.multiply_plain(eq, value_maps[i], selected_map);
        if (has_result) {
            evaluator.add_inplace(result, selected_map);
        } else {
            result = selected_map;
            has_result = true;
        }
    }
    if (!has_result) {
        Plaintext zero_pt(parms.poly_modulus_degree());
        zero_pt.set_zero();
        Ciphertext zero_ct;
        encryptor.encrypt(zero_pt, zero_ct);
        return zero_ct;
    }
    return result;
}

[[maybe_unused]] JNIEXPORT
jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_bkpir_BkPirNativeUtils_generateEncryptionParams(
        JNIEnv *env, jclass, jint poly_modulus_degree, jlong plain_modulus, jintArray) {
    // BKPIR setup: generate BFV encryption parameters.
    try {
        EncryptionParameters parms = create_default_bfv_parameters_128(
            static_cast<size_t>(poly_modulus_degree), static_cast<uint64_t>(plain_modulus)
        );
        SEALContext context = create_context_128(parms, "BKPIR", __func__);
        log_bfv_parameter_summary("[BK-PARAM]", "BKPIR", context, false);
        return serialize_encryption_parms(env, parms);
    } catch (const exception &e) {
        throw_java_runtime_exception(env, e.what());
        return nullptr;
    }
}

[[maybe_unused]] JNIEXPORT
jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_bkpir_BkPirNativeUtils_keyGen(
        JNIEnv *env, jclass, jbyteArray parms_bytes) {
    // BKPIR query setup: return [0] sk, [1] pk, [2] relin keys, [3] galois keys.
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "BKPIR", __func__);
        KeyGenerator key_gen(context);
        const SecretKey &secret_key = key_gen.secret_key();
        Serializable<PublicKey> public_key = key_gen.create_public_key();
        Serializable<RelinKeys> relin_keys = key_gen.create_relin_keys();
        Serializable<GaloisKeys> galois_keys = key_gen.create_galois_keys();
        jclass list_jcs = env->FindClass("java/util/ArrayList");
        jmethodID list_init = env->GetMethodID(list_jcs, "<init>", "()V");
        jobject list_obj = env->NewObject(list_jcs, list_init, "");
        jmethodID list_add = env->GetMethodID(list_jcs, "add", "(Ljava/lang/Object;)Z");
        jbyteArray sk = serialize_secret_key(env, secret_key);
        jbyteArray pk = serialize_public_key(env, public_key);
        jbyteArray rlk = serialize_relin_keys(env, relin_keys);
        jbyteArray gk = serialize_galois_keys(env, galois_keys);
        env->CallBooleanMethod(list_obj, list_add, sk);
        env->CallBooleanMethod(list_obj, list_add, pk);
        env->CallBooleanMethod(list_obj, list_add, rlk);
        env->CallBooleanMethod(list_obj, list_add, gk);
        env->DeleteLocalRef(sk);
        env->DeleteLocalRef(pk);
        env->DeleteLocalRef(rlk);
        env->DeleteLocalRef(gk);
        env->DeleteLocalRef(list_jcs);
        return list_obj;
    } catch (const exception &e) {
        throw_java_runtime_exception(env, e.what());
        return nullptr;
    }
}

[[maybe_unused]] JNIEXPORT
jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_bkpir_BkPirNativeUtils_generateQuery(
        JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jbyteArray sk_bytes,
        jlongArray query_codeword) {
    // BKPIR query generation: encode one constant-weight keyword query and symmetrically encrypt it.
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "BKPIR", __func__);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        SecretKey secret_key = deserialize_secret_key(env, sk_bytes, context);
        Encryptor encryptor(context, public_key);
        encryptor.set_secret_key(secret_key);
        Plaintext query_pt = deserialize_plaintext_from_coeff(env, query_codeword, context);
        Serializable<Ciphertext> query_ct = encryptor.encrypt_symmetric(query_pt);
        return serialize_ciphertext(env, query_ct);
    } catch (const exception &e) {
        throw_java_runtime_exception(env, e.what());
        return nullptr;
    }
}

[[maybe_unused]] JNIEXPORT
jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_bkpir_BkPirNativeUtils_preprocessDatabase(
        JNIEnv *env, jclass, jbyteArray parms_bytes, jobjectArray keyword_codewords,
        jobjectArray value_maps, jobjectArray value_payloads) {
    // BKPIR setup: encode DB = {(y_i, VM_i)} plus real value payload blocks.
    // Return order: first n keyword codewords, next n value maps, final payload plaintext blocks.
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "BKPIR", __func__);
        vector<Plaintext> plaintexts = deserialize_plaintexts_from_coeff(env, keyword_codewords, context);
        vector<Plaintext> maps = deserialize_plaintexts_from_coeff(env, value_maps, context);
        vector<Plaintext> payloads = deserialize_plaintexts_from_coeff(env, value_payloads, context);
        if (plaintexts.size() != maps.size()) {
            throw invalid_argument("keywordCodewords and valueMaps must have the same size");
        }
        if (payloads.empty()) {
            throw invalid_argument("valuePayloads must not be empty");
        }
        plaintexts.insert(plaintexts.end(), maps.begin(), maps.end());
        plaintexts.insert(plaintexts.end(), payloads.begin(), payloads.end());
        return serialize_plaintexts(env, plaintexts);
    } catch (const exception &e) {
        throw_java_runtime_exception(env, e.what());
        return nullptr;
    }
}

[[maybe_unused]] JNIEXPORT
jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_bkpir_BkPirNativeUtils_generateAndReply(
        JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jbyteArray relin_keys_bytes,
        jbyteArray galois_keys_bytes, jobject query_list, jobject encoded_keyword_codewords,
        jobject encoded_value_maps, jobject encoded_value_payloads, jint cw_weight) {
    // BKPIR AND response: recover encrypted value maps for all query keywords, multiply them, then select every real
    // payload block.
    GaloisKeys *galois_keys = nullptr;
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "BKPIR", __func__);
        PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
        Encryptor encryptor(context, public_key);
        Evaluator evaluator(context);
        RelinKeys relin_keys = deserialize_relin_keys(env, relin_keys_bytes, context);
        galois_keys = deserialize_galois_keys(env, galois_keys_bytes, context);
        vector<Ciphertext> queries = deserialize_ciphertexts(env, query_list, context);
        vector<Plaintext> keyword_codewords = deserialize_plaintexts(env, encoded_keyword_codewords, context);
        vector<Plaintext> value_maps = deserialize_plaintexts(env, encoded_value_maps, context);
        vector<Plaintext> value_payloads = deserialize_plaintexts(env, encoded_value_payloads, context);
        if (queries.size() < 2) {
            throw invalid_argument("BKPIR AND requires at least two keyword queries");
        }
        if (value_payloads.empty()) {
            throw invalid_argument("encodedValuePayloads must not be empty");
        }
        vector<Ciphertext> encrypted_maps;
        encrypted_maps.reserve(queries.size());
        for (auto &query : queries) {
            encrypted_maps.push_back(compute_encrypted_value_map(
                evaluator, encryptor, context, parms, relin_keys, *galois_keys, query, keyword_codewords, value_maps,
                cw_weight
            ));
        }
        Ciphertext intersection = multiply_many_balanced(evaluator, relin_keys, encrypted_maps);
        jclass list_jcs = env->FindClass("java/util/ArrayList");
        jmethodID list_init = env->GetMethodID(list_jcs, "<init>", "()V");
        jobject list_obj = env->NewObject(list_jcs, list_init, "");
        jmethodID list_add = env->GetMethodID(list_jcs, "add", "(Ljava/lang/Object;)Z");
        for (Plaintext &value_payload : value_payloads) {
            Ciphertext response;
            evaluator.multiply_plain(intersection, value_payload, response);
            jbyteArray response_bytes = serialize_ciphertext(env, response);
            env->CallBooleanMethod(list_obj, list_add, response_bytes);
            env->DeleteLocalRef(response_bytes);
        }
        env->DeleteLocalRef(list_jcs);
        delete galois_keys;
        return list_obj;
    } catch (const exception &e) {
        if (galois_keys != nullptr) {
            delete galois_keys;
        }
        throw_java_runtime_exception(env, e.what());
        return nullptr;
    }
}

[[maybe_unused]] JNIEXPORT
jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_bkpir_BkPirNativeUtils_generateOrReply(
        JNIEnv *env, jclass, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jobject, jobject, jobject, jobject,
        jint) {
    throw_java_unsupported_exception(env, "BKPIR OR retrieval is not implemented yet");
    return nullptr;
}

[[maybe_unused]] JNIEXPORT
jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_bkpir_BkPirNativeUtils_generateNotReply(
        JNIEnv *env, jclass, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jobject, jobject, jobject, jobject,
        jint) {
    throw_java_unsupported_exception(env, "BKPIR NOT retrieval is not implemented yet");
    return nullptr;
}

[[maybe_unused]] JNIEXPORT
jlongArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_bkpir_BkPirNativeUtils_decryptReply(
        JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray sk_bytes, jbyteArray response_bytes) {
    // BKPIR decode: decrypt the response and decode BFV batching slots.
    try {
        EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
        SEALContext context = create_context_128(parms, "BKPIR", __func__);
        SecretKey secret_key = deserialize_secret_key(env, sk_bytes, context);
        Decryptor decryptor(context, secret_key);
        Ciphertext response = deserialize_ciphertext(env, response_bytes, context);
        int32_t noise_budget = decryptor.invariant_noise_budget(response);
        if (noise_budget == 0) {
            throw invalid_argument("noise budget is 0.");
        }
        BatchEncoder encoder(context);
        Plaintext pt;
        decryptor.decrypt(response, pt);
        vector<uint64_t> vec;
        encoder.decode(pt, vec);
        jlongArray result = env->NewLongArray((jsize) parms.poly_modulus_degree());
        jlong *arr = env->GetLongArrayElements(result, JNI_FALSE);
        for (uint32_t i = 0; i < parms.poly_modulus_degree(); i++) {
            arr[i] = (jlong) vec[i];
        }
        env->ReleaseLongArrayElements(result, arr, 0);
        return result;
    } catch (const exception &e) {
        throw_java_runtime_exception(env, e.what());
        return nullptr;
    }
}
