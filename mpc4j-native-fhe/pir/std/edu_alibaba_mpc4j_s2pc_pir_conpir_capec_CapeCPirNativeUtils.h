#include <jni.h>

#ifndef _Included_edu_alibaba_mpc4j_s2pc_pir_conpir_capec_CapeCPirNativeUtils
#define _Included_edu_alibaba_mpc4j_s2pc_pir_conpir_capec_CapeCPirNativeUtils
#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_capec_CapeCPirNativeUtils_generateCapeCCandidateReply
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jobject, jobject, jobject, jint, jint, jint, jint);

JNIEXPORT jobject JNICALL Java_edu_alibaba_mpc4j_s2pc_pir_conpir_capec_CapeCPirNativeUtils_generateCapeCFusedPackedCoeffCtCtBloomScoresPackedBloom
    (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jobject, jobject, jobject, jobject, jint, jint,
     jint, jint, jint, jint, jint, jint);

#ifdef __cplusplus
}
#endif
#endif
