package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir;

import org.junit.Assert;
import org.junit.Test;

import java.util.List;

/** Minimal artifact gate for setup-time LWE-to-RGSW JNI serialization. */
public class FusePirStdKwPirJniSetupTest {
    @Test
    public void testDefaultParamsLweToRgswSerialization() {
        FusePirStdKwPirParams params = new FusePirStdKwPirParams(FusePirStdKwPirParams.DEFAULT_PARAMS);
        params.initPirParams(8);
        List<byte[]> keyPair = FusePirStdKwPirNativeUtils.keyGen(params.encryptionParams);
        Assert.assertEquals(2, keyPair.size());
        long[] lweSecretKey = new long[32];
        for (int index = 0; index < lweSecretKey.length; index++) {
            lweSecretKey[index] = index & 1;
        }
        List<byte[]> evaluationKey = FusePirStdKwPirNativeUtils.generateLweToRgswKey(
            params.encryptionParams, keyPair.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX), lweSecretKey
        );
        Assert.assertEquals(lweSecretKey.length, evaluationKey.size());
        evaluationKey.forEach(item -> Assert.assertTrue(item.length > 0));
    }
}
