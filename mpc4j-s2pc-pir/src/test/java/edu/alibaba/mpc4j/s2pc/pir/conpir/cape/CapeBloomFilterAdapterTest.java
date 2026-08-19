package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import org.junit.Assert;
import org.junit.Test;

import java.util.List;

/**
 * CAPE Bloom Filter adapter tests.
 *
 * @author Weiran Liu
 * @date 2026/06/06
 */
public class CapeBloomFilterAdapterTest {

    @Test
    public void testAdapterUsesCapeLocalBloomParams() {
        CapePirParams params = new CapePirParams(CapePirParams.DEFAULT_PARAMS);
        params.initPirParams(64, 1, 3, 3);
        CapeBloomFilterAdapter adapter = CapeBloomFilterAdapter.create(
            List.of("k1".getBytes(), "k2".getBytes(), "k3".getBytes()), params
        );
        Assert.assertEquals(CapePirParams.BLOOM_FALSE_POSITIVE_EXPONENT, params.getBloomHashNum());
        Assert.assertEquals(params.getBloomBitLength(), adapter.getBitLength());
        Assert.assertEquals(params.getBloomHashNum(), adapter.getHashNum());
        Assert.assertTrue(params.getBloomBitLength() < CapePirParams.bloomBitSize(params.getBloomExpectedInsertions(), 40));
    }

    @Test
    public void testBloomAdapter() {
        CapePirParams params = new CapePirParams(CapePirParams.DEFAULT_PARAMS);
        params.initPirParams(64, 1, 3, 3);
        CapeBloomFilterAdapter adapter = CapeBloomFilterAdapter.create(
            List.of("k1".getBytes(), "k2".getBytes(), "k3".getBytes()), params
        );
        Assert.assertTrue(adapter.mightContain("k1".getBytes()));
        Assert.assertTrue(adapter.mightContain("k2".getBytes()));
        Assert.assertTrue(adapter.mightContain("k3".getBytes()));
        long[] bitVector = adapter.toLongBitVector();
        Assert.assertEquals(params.getBloomBitLength(), bitVector.length);
        int countOnes = 0;
        for (long bit : bitVector) {
            Assert.assertTrue(bit == 0L || bit == 1L);
            countOnes += bit == 0L ? 0 : 1;
        }
        Assert.assertEquals(countOnes, adapter.countOnes());
        Assert.assertEquals(params.getBloomBitLength(), adapter.getBitLength());
        Assert.assertEquals(params.getBloomHashNum(), adapter.getHashNum());
        CapeBloomFilterAdapter deserialized = CapeBloomFilterAdapter.deserialize(adapter.serialize(), params);
        Assert.assertArrayEquals(adapter.toLongBitVector(), deserialized.toLongBitVector());
    }

    @Test
    public void testBloomAdapterDeduplicatesItems() {
        CapePirParams params = new CapePirParams(CapePirParams.DEFAULT_PARAMS);
        params.initPirParams(64, 1, 2, 2);
        CapeBloomFilterAdapter adapter = CapeBloomFilterAdapter.create(
            List.of("k1".getBytes(), "k1".getBytes(), "k2".getBytes()), params
        );
        Assert.assertTrue(adapter.mightContain("k1".getBytes()));
        Assert.assertTrue(adapter.mightContain("k2".getBytes()));
    }
}
