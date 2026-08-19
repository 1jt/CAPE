#include <jni.h>

#ifndef _Included_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils
#define _Included_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils
#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateEncryptionParams
    (JNIEnv *, jclass, jint, jlong, jintArray);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_keyGen
    (JNIEnv *, jclass, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateColumnQuery
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jint, jint);

JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generatePackedColumnQuery
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jint, jint, jint);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateEncryptedRowBits
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jint, jint);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateLweToRgswKey
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jlongArray);

JNIEXPORT jlong JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_createLweToRgswKeyHandle
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jobject);

JNIEXPORT void JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_destroyLweToRgswKeyHandle
    (JNIEnv *, jclass, jlong);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_convertCompressedRowBitsToRgswWithHandle
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jlong, jobjectArray, jlongArray);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_convertCompressedRowBitsToRgsw
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jobject, jobjectArray, jlongArray);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateEncryptedBloomFilter
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jlongArray);

JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateEncryptedCoeffBloomFilter
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jlongArray);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateEncryptedCoeffBloomScalarBits
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jlongArray);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_encryptBloomFilter
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jlongArray);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_preprocessDatabase
    (JNIEnv *, jclass, jbyteArray, jobjectArray, jobjectArray);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateFusePirCandidateReply
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jobject, jobject, jobject, jint, jint, jint, jint);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateBloomInnerProductsForTest
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jobject, jobject);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generatePackedBloomInnerProductsForTest
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jobject, jobject);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateCtCtBloomInnerProducts
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jobject, jobject);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateCoeffCtCtBloomInnerProducts
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jint, jint);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateCoeffCtCtBloomInnerProductsFromGroups
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jobject, jint, jint, jint);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateCoeffCtCtBloomInnerProductsFromGroupQueries
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jobject, jobject, jint);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generatePackedCoeffCtCtBloomInnerProductsFromGroupQueries
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jobject, jobject, jint);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateFusedPackedCoeffCtCtBloomScores
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jobject, jobject, jobject, jobject, jint, jint,
     jint, jint, jint);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateFusedPackedCoeffCtCtBloomScoresGlobalTiled
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jobject, jobject, jobject, jobject, jint, jint,
     jint, jint, jint, jint);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateFusedPackedCoeffCtCtBloomScoresPackedBloom
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jobject, jobject, jobject, jobject, jint, jint,
     jint, jint, jint, jint, jint, jint);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateCoeffCtCtBloomInnerProductsFromBitReplies
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jobject, jobject, jint, jint);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_splitCandidateItemCiphertext
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jint, jint, jint, jint, jint);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_generateReplyForTest
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jobject, jobject, jobject, jobject, jobject, jint, jint,
     jint, jint);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_mergePackedValueAndScoreReplies
    (JNIEnv *, jclass, jbyteArray, jobject, jobject, jint, jint);

JNIEXPORT jlongArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_decryptReply
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray);

JNIEXPORT jlongArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_decryptCoeffReply
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray);

JNIEXPORT jlongArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_decryptPackedScoreCoeffReply
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_cape_CapePirNativeUtils_encryptCoeffPlain
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jlongArray);

#ifdef __cplusplus
}
#endif
#endif
