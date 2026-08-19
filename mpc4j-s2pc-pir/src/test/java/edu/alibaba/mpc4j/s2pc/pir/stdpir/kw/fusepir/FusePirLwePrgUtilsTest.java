package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir;

import org.junit.Assert;
import org.junit.Test;

/**
 * FUSE_PIR LWE PRG utilities test.
 *
 * @author Weiran Liu
 * @date 2026/06/10
 */
public class FusePirLwePrgUtilsTest {

    @Test
    public void testExpandAConsistent() {
        byte[] seed = FusePirLwePrgUtils.generateSeed();
        long[] a0 = FusePirLwePrgUtils.expandA(seed, 7, 128, 1L << 32);
        long[] a1 = FusePirLwePrgUtils.expandA(seed, 7, 128, 1L << 32);
        Assert.assertArrayEquals(a0, a1);
    }

    @Test
    public void testExpandAIndexSeparated() {
        byte[] seed = FusePirLwePrgUtils.generateSeed();
        long[] a0 = FusePirLwePrgUtils.expandA(seed, 7, 128, 1L << 32);
        long[] a1 = FusePirLwePrgUtils.expandA(seed, 8, 128, 1L << 32);
        Assert.assertFalse(java.util.Arrays.equals(a0, a1));
    }

    @Test
    public void testBArraySerialize() {
        long[] bArray = new long[]{0L, 1L, 2L, 255L, (1L << 40) + 7L};
        byte[] serialized = FusePirLwePrgUtils.serializeBArray(bArray);
        Assert.assertEquals(bArray.length * Long.BYTES, serialized.length);
        Assert.assertArrayEquals(bArray, FusePirLwePrgUtils.deserializeBArray(serialized));
    }

    @Test
    public void testCompressedLweBitQuery() {
        byte[] seed = FusePirLwePrgUtils.generateSeed();
        long[] bArray = new long[]{3L, 5L, 7L};
        FusePirCompressedLweBitQuery query = new FusePirCompressedLweBitQuery(seed, bArray.length, 256, 1L << 32, bArray);
        Assert.assertArrayEquals(seed, query.getSeed());
        Assert.assertEquals(bArray.length, query.getBitNum());
        Assert.assertEquals(256, query.getLweDimension());
        Assert.assertEquals(1L << 32, query.getModulus());
        Assert.assertArrayEquals(bArray, query.getBArray());
        Assert.assertArrayEquals(bArray, FusePirLwePrgUtils.deserializeBArray(query.getBArrayBytes()));
    }

    @Test
    public void testCompressedLweBitQuerySerialization() {
        byte[] seed = FusePirLwePrgUtils.generateSeed();
        long[] bArray = new long[]{11L, 22L, 33L, 44L};
        FusePirCompressedLweBitQuery query = new FusePirCompressedLweBitQuery(seed, bArray.length, 512, 1L << 32, bArray);
        FusePirCompressedLweBitQuery decoded = FusePirCompressedLweBitQuery.fromByteArray(query.toByteArray());
        Assert.assertArrayEquals(seed, decoded.getSeed());
        Assert.assertEquals(query.getBitNum(), decoded.getBitNum());
        Assert.assertEquals(query.getLweDimension(), decoded.getLweDimension());
        Assert.assertEquals(query.getModulus(), decoded.getModulus());
        Assert.assertArrayEquals(bArray, decoded.getBArray());
    }

    @Test
    public void testCompressedLweBitQuerySerializedSize() {
        byte[] seed = FusePirLwePrgUtils.generateSeed();
        int bitNum = 13;
        long[] bArray = new long[bitNum];
        FusePirCompressedLweBitQuery query = new FusePirCompressedLweBitQuery(seed, bitNum, 630, 1L << 32, bArray);
        int expectedSize = Integer.BYTES * 5 + Long.BYTES + FusePirLwePrgUtils.SEED_BYTE_LENGTH + bitNum * Long.BYTES;
        Assert.assertEquals(expectedSize, query.toByteArray().length);
    }

    @Test
    public void testRecoverCompressedRowBitsDebugDecrypt() {
        int rowIndex = 5;
        int rowNum = 16;
        long[] secretKey = new long[64];
        for (int i = 0; i < secretKey.length; i++) {
            secretKey[i] = (i & 1);
        }
        FusePirCompressedLweBitQuery query = FusePirLwePrgUtils.generateCompressedRowBitQuery(
            rowIndex, rowNum, secretKey, 1L << 32, 1L << 31
        );
        int[] bits = FusePirLwePrgUtils.debugDecryptBits(
            FusePirLwePrgUtils.recoverLweBitCiphertexts(query), secretKey
        );
        Assert.assertEquals(FusePirLwePrgUtils.ceilLog2(rowNum), bits.length);
        for (int bitIndex = 0; bitIndex < bits.length; bitIndex++) {
            Assert.assertEquals((rowIndex >>> bitIndex) & 1, bits[bitIndex]);
        }
    }

}
