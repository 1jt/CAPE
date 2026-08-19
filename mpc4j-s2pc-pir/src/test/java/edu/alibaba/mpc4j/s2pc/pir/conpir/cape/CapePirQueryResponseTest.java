package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import org.junit.Assert;
import org.junit.Test;

import java.util.List;

/**
 * CAPE query / response object tests.
 *
 * @author Weiran Liu
 * @date 2026/06/06
 */
public class CapePirQueryResponseTest {

    @Test
    public void testQueryObject() {
        byte[] anchor = "k1".getBytes();
        List<byte[]> columnQueries = List.of(new byte[]{0x01}, new byte[]{0x02}, new byte[]{0x03});
        List<byte[]> compressedRowBits = List.of(new byte[]{0x04}, new byte[]{0x05});
        List<byte[]> encryptedCoeffBloomFilters = List.of(new byte[]{0x08});
        CapePirQuery query = new CapePirQuery(
            anchor, columnQueries, compressedRowBits, encryptedCoeffBloomFilters, 9, 3
        );
        Assert.assertArrayEquals(anchor, query.getAnchorKeywordBytes());
        Assert.assertEquals(columnQueries.size(), query.getFusePirColumnQueries().size());
        Assert.assertTrue(query.getFusePirBitColumnQueries().isEmpty());
        Assert.assertTrue(query.getFusePirEncryptedRowBits().isEmpty());
        Assert.assertEquals(compressedRowBits.size(), query.getCompressedRowBitQueries().size());
        Assert.assertTrue(query.getEncryptedBloomFilter().isEmpty());
        Assert.assertEquals(encryptedCoeffBloomFilters.size(), query.getEncryptedCoeffBloomFilters().size());
        Assert.assertEquals(9, query.getBloomOneCount());
        Assert.assertEquals(3, query.getBoolKeywordNum());
        List<byte[]> serverPayload = query.getServerPayload();
        Assert.assertEquals(
            columnQueries.size() + compressedRowBits.size() + encryptedCoeffBloomFilters.size(),
            serverPayload.size()
        );
        for (byte[] payloadItem : serverPayload) {
            Assert.assertFalse(java.util.Arrays.equals(anchor, payloadItem));
        }
        List<byte[]> legacyPayload = query.getServerPayloadWithPlainAnchorForTest();
        Assert.assertEquals(1 + serverPayload.size(), legacyPayload.size());
        Assert.assertArrayEquals(anchor, legacyPayload.get(0));
    }

    @Test
    public void testResponseObject() {
        List<byte[]> values = List.of(new byte[]{0x01}, new byte[]{0x02});
        List<byte[]> scores = List.of(new byte[]{0x03}, new byte[]{0x04});
        CapePirResponse response = new CapePirResponse(values, scores);
        Assert.assertEquals(values.size(), response.getEncryptedValuePayloads().size());
        Assert.assertEquals(scores.size(), response.getEncryptedBloomInnerProducts().size());
        Assert.assertArrayEquals(values.get(0), response.getEncryptedValuePayloads().get(0));
        Assert.assertArrayEquals(scores.get(1), response.getEncryptedBloomInnerProducts().get(1));
    }
}
