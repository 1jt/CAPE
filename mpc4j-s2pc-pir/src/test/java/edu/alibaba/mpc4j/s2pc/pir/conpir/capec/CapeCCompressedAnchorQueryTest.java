package edu.alibaba.mpc4j.s2pc.pir.conpir.capec;

import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

/**
 * CAPE_C compressed anchor query tests.
 *
 * @author Weiran Liu
 * @date 2026/07/07
 */
public class CapeCCompressedAnchorQueryTest {
    @Test
    public void testSerializationRoundTrip() {
        byte[] seed = new byte[CapeCPirUtils.SEED_BYTE_LENGTH];
        byte[] bArray = new byte[3 * (4 + 5) * Long.BYTES];
        for (int i = 0; i < seed.length; i++) {
            seed[i] = (byte) i;
        }
        for (int i = 0; i < bArray.length; i++) {
            bArray[i] = (byte) (i + 1);
        }
        CapeCCompressedAnchorQuery query = new CapeCCompressedAnchorQuery(
            seed, bArray, 4, 5, 3, CapeCPirUtils.LWE_DIMENSION, CapeCPirUtils.LWE_MODULUS, Long.BYTES
        );
        CapeCCompressedAnchorQuery decoded = CapeCCompressedAnchorQuery.fromByteArray(query.toByteArray());
        Assert.assertArrayEquals(seed, decoded.getSeed());
        Assert.assertArrayEquals(bArray, decoded.getBArray());
        Assert.assertEquals(4, decoded.getRowBitNum());
        Assert.assertEquals(5, decoded.getColBitNum());
        Assert.assertEquals(3, decoded.getBffHashNum());
        Assert.assertEquals(CapeCPirUtils.LWE_DIMENSION, decoded.getLweDimension());
        Assert.assertEquals(CapeCPirUtils.LWE_MODULUS, decoded.getLweModulus());
        Assert.assertEquals(Long.BYTES, decoded.getBElementByteLength());
        Assert.assertTrue(Arrays.equals(query.toByteArray(), decoded.toByteArray()));
    }
}
