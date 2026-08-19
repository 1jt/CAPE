package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.mmk;

import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * MMK standard keyword PIR utilities test.
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
public class MmkStdKwPirUtilsTest {
    /**
     * codeword length
     */
    private static final int W = 16;
    /**
     * Hamming weight
     */
    private static final int K = 4;

    @Test
    public void testCwEncodeLength() {
        long[] codeword = MmkStdKwPirUtils.cwEncode(BigInteger.ZERO, W, K);
        Assert.assertEquals(W, codeword.length);
    }

    @Test
    public void testCwEncodeHammingWeight() {
        long[] codeword = MmkStdKwPirUtils.cwEncode(BigInteger.valueOf(1024L), W, K);
        Assert.assertEquals(K, Arrays.stream(codeword).sum());
    }

    @Test
    public void testCwEncodeDifferentHash() {
        long[] codeword0 = MmkStdKwPirUtils.cwEncode(BigInteger.ZERO, W, K);
        long[] codeword1 = MmkStdKwPirUtils.cwEncode(BigInteger.ONE, W, K);
        Assert.assertFalse(Arrays.equals(codeword0, codeword1));
    }

    @Test
    public void testPayloadSplitDecode() {
        MmkStdKwPirParams params = MmkStdKwPirParams.DEFAULT_PARAMS;
        int payloadByteLength = 40_000;
        params.payloadCoeffNum = (int) Math.ceil(payloadByteLength * Byte.SIZE
            / (double) params.getPlainModulusBitLength());
        params.payloadPlaintextNum = 2;
        byte[] payload = new byte[payloadByteLength];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) i;
        }
        long[][] plaintexts = MmkStdKwPirUtils.encodePayload(payload, params);
        Assert.assertEquals(2, plaintexts.length);
        Assert.assertArrayEquals(payload, MmkStdKwPirUtils.decodePayload(plaintexts, payload.length, params));
    }
}
