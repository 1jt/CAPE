package edu.alibaba.mpc4j.s2pc.pir.conpir.bkpir;

import org.junit.Assert;
import org.junit.Test;

import edu.alibaba.mpc4j.s2pc.pir.PirUtils;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * BKPIR utilities test.
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
public class BkPirUtilsTest {
    /**
     * codeword length.
     */
    private static final int W = 128;
    /**
     * constant weight.
     */
    private static final int K = 4;
    /**
     * slot count.
     */
    private static final int SLOT_COUNT = 32;
    /**
     * value space size.
     */
    private static final int VALUE_SPACE_SIZE = 16;

    @Test
    public void testCwEncodeLengthAndWeight() {
        long[] codeword = BkPirUtils.cwEncode(BigInteger.valueOf(123456789L), W, K);
        Assert.assertEquals(W, codeword.length);
        Assert.assertEquals(K, Arrays.stream(codeword).sum());
    }

    @Test
    public void testKeywordEncodeDeterministic() {
        byte[] keyword = "keyword_1".getBytes();
        BigInteger h0 = BkPirUtils.hashKeywordToBigInteger(keyword);
        BigInteger h1 = BkPirUtils.hashKeywordToBigInteger(keyword);
        Assert.assertEquals(h0, h1);
        Assert.assertArrayEquals(BkPirUtils.cwEncode(h0, W, K), BkPirUtils.cwEncode(h1, W, K));
    }

    @Test
    public void testEncodeValueMap() {
        Set<Integer> valueIndices = new HashSet<>(Arrays.asList(1, 7, 9));
        long[] valueMap = BkPirUtils.encodeValueMap(valueIndices, VALUE_SPACE_SIZE, SLOT_COUNT);
        Assert.assertEquals(SLOT_COUNT, valueMap.length);
        Assert.assertEquals(0L, valueMap[0]);
        Assert.assertEquals(1L, valueMap[1]);
        Assert.assertEquals(1L, valueMap[7]);
        Assert.assertEquals(1L, valueMap[9]);
        Assert.assertEquals(0L, valueMap[10]);
    }

    @Test
    public void testPlainAndTwoValueMaps() {
        long[] map0 = BkPirUtils.encodeValueMap(new HashSet<>(Arrays.asList(1, 3, 7)), VALUE_SPACE_SIZE, SLOT_COUNT);
        long[] map1 = BkPirUtils.encodeValueMap(new HashSet<>(Arrays.asList(2, 3, 7)), VALUE_SPACE_SIZE, SLOT_COUNT);
        long[] andResult = BkPirUtils.andValueMaps(map0, map1);
        long[] valuePayload = BkPirUtils.encodeValuePayload(VALUE_SPACE_SIZE, SLOT_COUNT);
        List<Integer> values = BkPirUtils.decodeAndResult(
            BkPirUtils.applyValuePayload(andResult, valuePayload), VALUE_SPACE_SIZE
        );
        Assert.assertEquals(Arrays.asList(3, 7), values);
    }

    @Test
    public void testPlainAndThreeValueMaps() {
        long[] map0 = BkPirUtils.encodeValueMap(new HashSet<>(Arrays.asList(1, 3, 7, 11)),
            VALUE_SPACE_SIZE, SLOT_COUNT);
        long[] map1 = BkPirUtils.encodeValueMap(new HashSet<>(Arrays.asList(2, 3, 7, 12)),
            VALUE_SPACE_SIZE, SLOT_COUNT);
        long[] map2 = BkPirUtils.encodeValueMap(new HashSet<>(Arrays.asList(3, 5, 7, 13)),
            VALUE_SPACE_SIZE, SLOT_COUNT);
        long[] andResult = BkPirUtils.andValueMaps(map0, map1, map2);
        long[] valuePayload = BkPirUtils.encodeValuePayload(VALUE_SPACE_SIZE, SLOT_COUNT);
        List<Integer> values = BkPirUtils.decodeAndResult(
            BkPirUtils.applyValuePayload(andResult, valuePayload), VALUE_SPACE_SIZE
        );
        Assert.assertEquals(Arrays.asList(3, 7), values);
    }

    @Test
    public void testRealValuePayload() {
        BkPirParams params = new BkPirParams(32, 65537L, new int[]{60, 40, 40, 60}, 4);
        params.valueSpaceSize = 4;
        params.valueByteLength = 2;
        params.valueByteNumPerPayloadPlaintext = 2;
        params.valueChunkNum = 1;
        params.payloadPlaintextNumPerChunk = 1;
        params.payloadPlaintextNum = 1;
        byte[] v0 = new byte[]{0x00, 0x11};
        byte[] v1 = new byte[]{0x22, 0x00};
        byte[] v2 = new byte[]{0x33, 0x44};
        byte[] v3 = new byte[]{0x55, 0x66};
        long[] andResult = BkPirUtils.encodeValueMap(new HashSet<>(Arrays.asList(0, 2)), 4, 32);
        long[][] payloads = BkPirUtils.encodeValuePayloads(Arrays.asList(v0, v1, v2, v3), params);
        long[][] selected = new long[payloads.length][];
        for (int blockIndex = 0; blockIndex < payloads.length; blockIndex++) {
            selected[blockIndex] = BkPirUtils.applyValuePayload(andResult, payloads[blockIndex]);
        }
        List<byte[]> values = BkPirUtils.decodeAndResultPayload(selected, 4, 2);
        Assert.assertEquals(2, values.size());
        Assert.assertArrayEquals(v0, values.get(0));
        Assert.assertArrayEquals(v2, values.get(1));
    }

    @Test
    public void testChunkedRealValuePayload() {
        BkPirParams params = new BkPirParams(4, 65537L, new int[]{60, 40, 40, 60}, 2);
        params.valueSpaceSize = 6;
        params.valueByteLength = 2;
        params.valueByteNumPerPayloadPlaintext = 2;
        params.valueChunkNum = 2;
        params.payloadPlaintextNumPerChunk = 1;
        params.payloadPlaintextNum = 2;
        byte[] v0 = new byte[]{0x00, 0x11};
        byte[] v1 = new byte[]{0x22, 0x00};
        byte[] v2 = new byte[]{0x33, 0x44};
        byte[] v3 = new byte[]{0x55, 0x66};
        byte[] v4 = new byte[]{0x77, 0x00};
        byte[] v5 = new byte[]{0x00, (byte) 0x88};
        List<byte[]> valueSpace = Arrays.asList(v0, v1, v2, v3, v4, v5);
        long[][] payloads = BkPirUtils.encodeValuePayloads(valueSpace, params);
        long[][] selected = new long[payloads.length][];
        long[] chunk0AndResult = BkPirUtils.encodeValueMap(new HashSet<>(Arrays.asList(2)), 4, 4);
        long[] chunk1AndResult = BkPirUtils.encodeValueMap(new HashSet<>(Arrays.asList(0, 1)), 2, 4);
        selected[0] = BkPirUtils.applyValuePayload(chunk0AndResult, payloads[0]);
        selected[1] = BkPirUtils.applyValuePayload(chunk1AndResult, payloads[1]);
        List<byte[]> values = BkPirUtils.decodeAndResultPayload(selected, 6, 2);
        Assert.assertEquals(3, values.size());
        Assert.assertArrayEquals(v2, values.get(0));
        Assert.assertArrayEquals(v4, values.get(1));
        Assert.assertArrayEquals(v5, values.get(2));
    }

    @Test
    public void testGenerateQueryFile() throws Exception {
        File queryFile = File.createTempFile("bkpir-query-", ".input");
        Assert.assertTrue(queryFile.delete());
        PirUtils.generateBkPirQueryInputFile(32, 5, 3, queryFile.getAbsolutePath());
        java.util.List<String> lines = Files.readAllLines(queryFile.toPath(), StandardCharsets.UTF_8);
        Assert.assertEquals(5, lines.size());
        for (String line : lines) {
            Assert.assertEquals(3, line.trim().split("\\s+").length);
        }
        Assert.assertTrue(queryFile.delete());
    }
}
