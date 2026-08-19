#include "edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_mmk_MmkStdKwPirNativeUtils.h"
#include "seal/seal.h"
#include "../../serialize.h"
#include "../../index_pir.h"
#include "../../utils.h"
#include <numeric>

using namespace seal;
using namespace std;

static void throw_java_exception(JNIEnv *env, const char *message) {
    jclass exception = env->FindClass("java/lang/Exception");
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

[[maybe_unused]] JNIEXPORT
jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_mmk_MmkStdKwPirNativeUtils_generateEncryptionParams(
        JNIEnv *env, jclass, jint poly_modulus_degree, jlong plain_modulus, jintArray) {
    // MMKPIR Setup: generate BFV encryption parameters.
    EncryptionParameters parms = create_default_bfv_parameters_128(
        static_cast<size_t>(poly_modulus_degree), static_cast<uint64_t>(plain_modulus)
    );
    SEALContext context = create_context_128(parms, "MMK", __func__);
    log_bfv_parameter_summary("[MMK-PARAM]", "MMK", context, false);
    return serialize_encryption_parms(env, parms);
}

[[maybe_unused]] JNIEXPORT
jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_mmk_MmkStdKwPirNativeUtils_keyGen(
        JNIEnv *env, jclass, jbyteArray parms_bytes) {
    // MMKPIR QueryGen setup: generate client/server evaluation keys.
    EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
    SEALContext context = create_context_128(parms, "MMK", __func__);
    KeyGenerator key_gen(context);
    const SecretKey& secret_key = key_gen.secret_key();
    Serializable<PublicKey> public_key = key_gen.create_public_key();
    Serializable<RelinKeys> relin_keys = key_gen.create_relin_keys();
    Serializable<GaloisKeys> galois_keys = key_gen.create_galois_keys();
    jclass list_jcs = env->FindClass("java/util/ArrayList");
    jmethodID list_init = env->GetMethodID(list_jcs, "<init>", "()V");
    jobject list_obj = env->NewObject(list_jcs, list_init, "");
    jmethodID list_add = env->GetMethodID(list_jcs, "add", "(Ljava/lang/Object;)Z");
    env->CallBooleanMethod(list_obj, list_add, serialize_secret_key(env, secret_key));
    env->CallBooleanMethod(list_obj, list_add, serialize_public_key(env, public_key));
    env->CallBooleanMethod(list_obj, list_add, serialize_relin_keys(env, relin_keys));
    env->CallBooleanMethod(list_obj, list_add, serialize_galois_keys(env, galois_keys));
    env->DeleteLocalRef(list_jcs);
    return list_obj;
}

[[maybe_unused]] JNIEXPORT
jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_mmk_MmkStdKwPirNativeUtils_generateQuery(
        JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jbyteArray sk_bytes,
        jlongArray query_codeword) {
    // MMKPIR QueryGen: encode the constant-weight query codeword and symmetrically encrypt it.
    EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
    SEALContext context = create_context_128(parms, "MMK", __func__);
    PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
    SecretKey secret_key = deserialize_secret_key(env, sk_bytes, context);
    Encryptor encryptor(context, public_key);
    encryptor.set_secret_key(secret_key);
    Plaintext query_pt = deserialize_plaintext_from_coeff(env, query_codeword, context);
    Serializable<Ciphertext> query_ct = encryptor.encrypt_symmetric(query_pt);
    return serialize_ciphertext(env, query_ct);
}

static vector<Plaintext> encode_coeff_plaintexts(JNIEnv *env, jobjectArray coeffs_list, const SEALContext& context) {
    return deserialize_plaintexts_from_coeff(env, coeffs_list, context);
}

[[maybe_unused]] JNIEXPORT
jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_mmk_MmkStdKwPirNativeUtils_preprocessDatabase(
        JNIEnv *env, jclass, jbyteArray parms_bytes, jobjectArray keyword_codewords,
        jobjectArray payload_plaintexts) {
    // MMKPIR Setup: encode DB_MMKPIR = {(y_i, p_i)} into BFV plaintexts.
    EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
    SEALContext context = create_context_128(parms, "MMK", __func__);
    vector<Plaintext> plaintexts = encode_coeff_plaintexts(env, keyword_codewords, context);
    vector<Plaintext> payloads = encode_coeff_plaintexts(env, payload_plaintexts, context);
    if (plaintexts.empty() || payloads.size() % plaintexts.size() != 0) {
        throw_java_exception(env, "payloadPlaintexts size must be a positive multiple of keywordCodewords size");
        return nullptr;
    }
    plaintexts.insert(plaintexts.end(), payloads.begin(), payloads.end());
    return serialize_plaintexts(env, plaintexts);
}

[[maybe_unused]] JNIEXPORT
jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_mmk_MmkStdKwPirNativeUtils_generateReply(
        JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray pk_bytes, jbyteArray relin_keys_bytes,
        jbyteArray galois_keys_bytes, jbyteArray query_bytes, jobject encoded_keyword_codewords,
        jobject encoded_payloads, jint payload_plaintext_num, jint cw_weight) {
    // MMKPIR Response: compute one encrypted response ciphertext for each payload plaintext block.
    EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
    SEALContext context = create_context_128(parms, "MMK", __func__);
    PublicKey public_key = deserialize_public_key(env, pk_bytes, context);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    RelinKeys relin_keys = deserialize_relin_keys(env, relin_keys_bytes, context);
    GaloisKeys *galois_keys = deserialize_galois_keys(env, galois_keys_bytes, context);
    Ciphertext query = deserialize_ciphertext(env, query_bytes, context);
    vector<Plaintext> keyword_codewords = deserialize_plaintexts(env, encoded_keyword_codewords, context);
    vector<Plaintext> payloads = deserialize_plaintexts(env, encoded_payloads, context);
    if (payload_plaintext_num <= 0) {
        delete galois_keys;
        throw_java_exception(env, "payloadPlaintextNum must be positive");
        return nullptr;
    }
    if (keyword_codewords.empty()
        || payloads.size() != keyword_codewords.size() * static_cast<size_t>(payload_plaintext_num)) {
        delete galois_keys;
        throw_java_exception(env, "encodedPayloads size must equal encodedKeywordCodewords size * payloadPlaintextNum");
        return nullptr;
    }
    if (cw_weight <= 0) {
        delete galois_keys;
        throw_java_exception(env, "cwWeight must be positive");
        return nullptr;
    }
    BatchEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    uint64_t inv_factorial = invert_mod(factorial_mod(static_cast<uint32_t>(cw_weight), parms.plain_modulus()),
                                        parms.plain_modulus());
    Plaintext inv_factorial_pt = encode_constant_plaintext(context, inv_factorial);
    jclass list_jcs = env->FindClass("java/util/ArrayList");
    jmethodID list_init = env->GetMethodID(list_jcs, "<init>", "()V");
    jobject list_obj = env->NewObject(list_jcs, list_init, "");
    jmethodID list_add = env->GetMethodID(list_jcs, "add", "(Ljava/lang/Object;)Z");
    for (int block_index = 0; block_index < payload_plaintext_num; block_index++) {
        Ciphertext result;
        bool has_result = false;
        for (size_t i = 0; i < keyword_codewords.size(); i++) {
            Ciphertext inner_product;
            evaluator.multiply_plain(query, keyword_codewords[i], inner_product);
            add_all_slots_inplace(evaluator, inner_product, *galois_keys, slot_count);
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
            Ciphertext selected_payload;
            evaluator.multiply_plain(
                eq, payloads[i * static_cast<size_t>(payload_plaintext_num) + block_index], selected_payload
            );
            if (has_result) {
                evaluator.add_inplace(result, selected_payload);
            } else {
                result = selected_payload;
                has_result = true;
            }
        }
        if (!has_result) {
            Plaintext zero_pt(parms.poly_modulus_degree());
            zero_pt.set_zero();
            Serializable<Ciphertext> zero_ct = encryptor.encrypt(zero_pt);
            env->CallBooleanMethod(list_obj, list_add, serialize_ciphertext(env, zero_ct));
        } else {
            env->CallBooleanMethod(list_obj, list_add, serialize_ciphertext(env, result));
        }
    }
    env->DeleteLocalRef(list_jcs);
    delete galois_keys;
    return list_obj;
}

[[maybe_unused]] JNIEXPORT
jlongArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_stdpir_kw_mmk_MmkStdKwPirNativeUtils_decryptReply(
        JNIEnv *env, jclass, jbyteArray parms_bytes, jbyteArray sk_bytes, jbyteArray response_bytes) {
    // MMKPIR Decode: decrypt the response and decode BFV batching slots.
    EncryptionParameters parms = deserialize_encryption_parms(env, parms_bytes);
    SEALContext context = create_context_128(parms, "MMK", __func__);
    SecretKey secret_key = deserialize_secret_key(env, sk_bytes, context);
    Decryptor decryptor(context, secret_key);
    Ciphertext response = deserialize_ciphertext(env, response_bytes, context);
    int32_t noise_budget = decryptor.invariant_noise_budget(response);
    jclass exception = env->FindClass("java/lang/Exception");
    if (noise_budget == 0) {
        env->ThrowNew(exception, "noise budget is 0.");
        return nullptr;
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
    env->DeleteLocalRef(exception);
    return result;
}
