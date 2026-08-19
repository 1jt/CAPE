package edu.alibaba.mpc4j.s2pc.pir.conpir.bkpir;

import org.junit.Assert;
import org.junit.Test;

import java.util.List;

/**
 * BKPIR native utils test.
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
public class BkPirNativeUtilsTest {
    /**
     * poly modulus degree.
     */
    private static final int POLY_MODULUS_DEGREE = 8192;
    /**
     * plain modulus.
     */
    private static final long PLAIN_MODULUS = 65537L;
    /**
     * coeff modulus bits.
     */
    private static final int[] COEFF_MODULUS_BITS = new int[]{60, 40, 40, 60};

    @Test
    public void testQueryDecryptSmoke() {
        byte[] encryptionParams = BkPirNativeUtils.generateEncryptionParams(
            POLY_MODULUS_DEGREE, PLAIN_MODULUS, COEFF_MODULUS_BITS
        );
        Assert.assertTrue(encryptionParams.length > 0);
        List<byte[]> keyPair = BkPirNativeUtils.keyGen(encryptionParams);
        Assert.assertEquals(4, keyPair.size());
        long[] queryCodeword = new long[POLY_MODULUS_DEGREE];
        queryCodeword[0] = 1L;
        queryCodeword[7] = 1L;
        queryCodeword[1024] = 1L;
        queryCodeword[4096] = 1L;
        byte[] query = BkPirNativeUtils.generateQuery(
            encryptionParams,
            keyPair.get(BkPirNativeUtils.PUBLIC_KEY_INDEX),
            keyPair.get(BkPirNativeUtils.SECRET_KEY_INDEX),
            queryCodeword
        );
        Assert.assertTrue(query.length > 0);
        long[] decrypted = BkPirNativeUtils.decryptReply(
            encryptionParams, keyPair.get(BkPirNativeUtils.SECRET_KEY_INDEX), query
        );
        Assert.assertEquals(POLY_MODULUS_DEGREE, decrypted.length);
        Assert.assertEquals(1L, decrypted[0]);
        Assert.assertEquals(1L, decrypted[7]);
        Assert.assertEquals(1L, decrypted[1024]);
        Assert.assertEquals(1L, decrypted[4096]);
        Assert.assertEquals(0L, decrypted[1]);
    }
}
