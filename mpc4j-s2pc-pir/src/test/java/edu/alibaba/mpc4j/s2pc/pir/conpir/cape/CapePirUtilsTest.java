package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * CAPE PIR utility tests.
 *
 * @author Weiran Liu
 * @date 2026/06/06
 */
public class CapePirUtilsTest {
    @Test
    public void testBloomFalsePositiveExponentIs10() {
        CapePirParams params = new CapePirParams(CapePirParams.DEFAULT_PARAMS);
        int keywordNum = 128;
        int maxValueKeywordSetSize = 3;
        params.initPirParams(keywordNum, 2, 3, 3, maxValueKeywordSetSize);
        Assert.assertEquals(CapePirParams.BLOOM_FALSE_POSITIVE_EXPONENT, params.getBloomFalsePositiveExponent());
        Assert.assertEquals(10, params.getBloomHashNum());
        Assert.assertEquals(maxValueKeywordSetSize, params.getBloomExpectedInsertions());
        Assert.assertEquals(CapePirParams.bloomBitSize(maxValueKeywordSetSize, 10), params.getBloomBitLength());
        Assert.assertTrue(params.getBloomBitLength() < CapePirParams.bloomBitSize(maxValueKeywordSetSize, 40));
        Assert.assertNotEquals(keywordNum, params.getBloomExpectedInsertions());
    }

    @Test
    public void testForwardIndex() {
        Map<ByteBuffer, List<byte[]>> keywordValueMap = createKeywordValueMap();
        Map<ByteBuffer, List<ByteBuffer>> forwardIndex = CapePirUtils.buildForwardIndex(keywordValueMap);
        Assert.assertEquals(3, forwardIndex.get(ByteBuffer.wrap("v1".getBytes())).size());
        Assert.assertTrue(forwardIndex.get(ByteBuffer.wrap("v1".getBytes())).contains(ByteBuffer.wrap("k1".getBytes())));
        Assert.assertTrue(forwardIndex.get(ByteBuffer.wrap("v1".getBytes())).contains(ByteBuffer.wrap("k2".getBytes())));
        Assert.assertTrue(forwardIndex.get(ByteBuffer.wrap("v1".getBytes())).contains(ByteBuffer.wrap("k3".getBytes())));
        Assert.assertEquals(2, forwardIndex.get(ByteBuffer.wrap("v2".getBytes())).size());
        Assert.assertTrue(forwardIndex.get(ByteBuffer.wrap("v2".getBytes())).contains(ByteBuffer.wrap("k1".getBytes())));
        Assert.assertTrue(forwardIndex.get(ByteBuffer.wrap("v2".getBytes())).contains(ByteBuffer.wrap("k3".getBytes())));
        Assert.assertEquals(1, forwardIndex.get(ByteBuffer.wrap("v3".getBytes())).size());
        Assert.assertTrue(forwardIndex.get(ByteBuffer.wrap("v3".getBytes())).contains(ByteBuffer.wrap("k1".getBytes())));
    }

    @Test
    public void testForwardIndexDeduplicatesRepeatedValuesPerKeyword() {
        Map<ByteBuffer, List<byte[]>> keywordValueMap = new LinkedHashMap<>();
        keywordValueMap.put(ByteBuffer.wrap("k1".getBytes()), List.of("v1".getBytes(), "v1".getBytes()));
        keywordValueMap.put(ByteBuffer.wrap("k2".getBytes()), List.of("v1".getBytes()));
        Map<ByteBuffer, List<ByteBuffer>> forwardIndex = CapePirUtils.buildForwardIndex(keywordValueMap);
        List<ByteBuffer> v1Keywords = forwardIndex.get(ByteBuffer.wrap("v1".getBytes()));
        Assert.assertEquals(2, v1Keywords.size());
        Assert.assertTrue(v1Keywords.contains(ByteBuffer.wrap("k1".getBytes())));
        Assert.assertTrue(v1Keywords.contains(ByteBuffer.wrap("k2".getBytes())));

        CapePirParams params = new CapePirParams(CapePirParams.DEFAULT_PARAMS);
        params.initPirParams(64, 1, 2, 2);
        Map<ByteBuffer, CapeBloomFilterAdapter> valueBloomFilters = CapePirUtils.buildValueBloomFilters(
            forwardIndex, params
        );
        Assert.assertTrue(valueBloomFilters.get(ByteBuffer.wrap("v1".getBytes())).mightContain("k1".getBytes()));
        Assert.assertTrue(valueBloomFilters.get(ByteBuffer.wrap("v1".getBytes())).mightContain("k2".getBytes()));
    }

    @Test
    public void testPlainBloomInnerProduct() {
        CapePirParams params = new CapePirParams(CapePirParams.DEFAULT_PARAMS);
        params.initPirParams(64, 2, 3, 3);
        Map<ByteBuffer, List<byte[]>> keywordValueMap = createKeywordValueMap();
        Map<ByteBuffer, List<ByteBuffer>> forwardIndex = CapePirUtils.buildForwardIndex(keywordValueMap);
        Map<ByteBuffer, CapeBloomFilterAdapter> valueBloomFilters = CapePirUtils.buildValueBloomFilters(
            forwardIndex, params
        );
        CapeBloomFilterAdapter queryBloomFilter = CapePirUtils.buildQueryBloomFilter(
            List.of(ByteBuffer.wrap("k2".getBytes()), ByteBuffer.wrap("k3".getBytes())), params
        );
        int n = queryBloomFilter.countOnes();
        long v1Score = CapePirUtils.innerProduct(
            queryBloomFilter.toLongBitVector(),
            valueBloomFilters.get(ByteBuffer.wrap("v1".getBytes())).toLongBitVector()
        );
        Assert.assertEquals(n, v1Score);
        long v3Score = CapePirUtils.innerProduct(
            queryBloomFilter.toLongBitVector(),
            valueBloomFilters.get(ByteBuffer.wrap("v3".getBytes())).toLongBitVector()
        );
        Assert.assertNotEquals(n, v3Score);
    }

    @Test
    public void testAttachAndParseBloomFilter() {
        CapePirParams params = new CapePirParams(CapePirParams.DEFAULT_PARAMS);
        params.initPirParams(64, 2, 3, 3);
        CapeBloomFilterAdapter bloomFilter = CapeBloomFilterAdapter.create(List.of("k1".getBytes()), params);
        byte[] value = "v1".getBytes();
        byte[] payload = CapePirUtils.attachBloomFilterToValue(value, bloomFilter, params);
        CapePirUtils.ValueWithBloomFilter parsed = CapePirUtils.parseValueWithBloomFilter(payload, params);
        Assert.assertArrayEquals(value, parsed.getValue());
        Assert.assertArrayEquals(bloomFilter.getStorage(), parsed.getBloomFilterBytes());
    }

    @Test
    public void testPayloadItemFormat() {
        CapePirParams params = new CapePirParams(CapePirParams.DEFAULT_PARAMS);
        params.initPirParams(64, 2, 3, 3);
        Map<ByteBuffer, List<byte[]>> keywordValueMap = new LinkedHashMap<>();
        byte[] zeroValue = new byte[]{0, 0};
        keywordValueMap.put(ByteBuffer.wrap("k1".getBytes()), List.of(zeroValue, "v1".getBytes()));
        keywordValueMap.put(ByteBuffer.wrap("k2".getBytes()), List.of("v1".getBytes()));
        keywordValueMap.put(ByteBuffer.wrap("k3".getBytes()), List.of("v1".getBytes()));

        Map<ByteBuffer, List<ByteBuffer>> forwardIndex = CapePirUtils.buildForwardIndex(keywordValueMap);
        Map<ByteBuffer, CapeBloomFilterAdapter> valueBloomFilters = CapePirUtils.buildValueBloomFilters(
            forwardIndex, params
        );
        byte[] payload = CapePirUtils.buildKeywordPayload(
            ByteBuffer.wrap("k1".getBytes()), keywordValueMap.get(ByteBuffer.wrap("k1".getBytes())),
            valueBloomFilters, params
        );
        List<CapePirUtils.ValueWithBloomFilter> items = CapePirUtils.parseKeywordPayloadItems(payload, params);
        Assert.assertEquals(2, items.size());
        Assert.assertTrue(items.get(0).isPresent());
        Assert.assertArrayEquals(zeroValue, items.get(0).getValue());
        Assert.assertArrayEquals(
            valueBloomFilters.get(ByteBuffer.wrap(zeroValue)).getStorage(), items.get(0).getBloomFilterBytes()
        );
        Assert.assertArrayEquals("v1".getBytes(), items.get(1).getValue());
        Assert.assertArrayEquals(
            valueBloomFilters.get(ByteBuffer.wrap("v1".getBytes())).getStorage(), items.get(1).getBloomFilterBytes()
        );
        Assert.assertTrue(valueBloomFilters.get(ByteBuffer.wrap("v1".getBytes())).mightContain(
            CapePirUtils.keywordToByteArray(ByteBuffer.wrap("k2".getBytes()))
        ));
        int paddingOffset = params.getFingerprintByteLength() + 2 * params.getPayloadItemByteLength();
        Assert.assertEquals(0, payload[paddingOffset]);
    }

    @Test
    public void testLongBinaryFuseFilterReconstructsBloomPayload() {
        CapePirParams params = new CapePirParams(CapePirParams.DEFAULT_PARAMS);
        params.initPirParams(3, 2, 3, 3);
        Map<ByteBuffer, List<byte[]>> keywordValueMap = createKeywordValueMap();
        Map<ByteBuffer, List<ByteBuffer>> forwardIndex = CapePirUtils.buildForwardIndex(keywordValueMap);
        Map<ByteBuffer, CapeBloomFilterAdapter> valueBloomFilters = CapePirUtils.buildValueBloomFilters(
            forwardIndex, params
        );
        Map<ByteBuffer, byte[]> combinedPayloadMap = new LinkedHashMap<>();
        Map<ByteBuffer, long[]> bloomPayloadMap = new LinkedHashMap<>();
        keywordValueMap.forEach((keyword, values) -> {
            combinedPayloadMap.put(keyword, CapePirUtils.buildKeywordPayload(keyword, values, valueBloomFilters, params));
            bloomPayloadMap.put(keyword, CapePirUtils.buildBloomOnlyLongPayload(values, valueBloomFilters, params));
        });
        CapePirUtils.BinaryFuseFilterData combinedBff = CapePirUtils.buildBinaryFuseFilters(
            combinedPayloadMap, params, new SecureRandom()
        );
        long[][] bloomBff = CapePirUtils.buildLongBinaryFuseFilters(
            bloomPayloadMap, CapePirUtils.bloomOnlyPayloadByteLength(params), params, combinedBff.getSeed()
        );

        for (Map.Entry<ByteBuffer, long[]> entry : bloomPayloadMap.entrySet()) {
            int[] positions = CapePirUtils.getHashPositions(
                entry.getKey(), keywordValueMap.size(), combinedBff.getSeed(), params
            );
            for (int blockIndex = 0; blockIndex < entry.getValue().length; blockIndex++) {
                long actual = 0L;
                for (int position : positions) {
                    actual = Math.floorMod(actual + bloomBff[blockIndex][position], params.getPlainModulus());
                }
                Assert.assertEquals(entry.getValue()[blockIndex], actual);
            }
        }
    }

    @Test
    public void testLongBffGraphReuseReconstruction() {
        CapePirParams params = new CapePirParams(CapePirParams.DEFAULT_PARAMS);
        params.initPirParams(5, 2, 3, 3);
        int payloadBlockNum = 4;
        Map<ByteBuffer, long[]> payloadMap = new LinkedHashMap<>();
        for (int keyIndex = 0; keyIndex < 5; keyIndex++) {
            long[] payload = new long[payloadBlockNum];
            for (int blockIndex = 0; blockIndex < payloadBlockNum; blockIndex++) {
                payload[blockIndex] = 17L * keyIndex + blockIndex + 1;
            }
            payloadMap.put(ByteBuffer.wrap(("k" + keyIndex).getBytes()), payload);
        }
        long[][] bff = null;
        byte[] seed = null;
        for (int attempt = 0; attempt < 32 && bff == null; attempt++) {
            byte[] candidateSeed = new byte[16];
            candidateSeed[15] = (byte) attempt;
            try {
                bff = CapePirUtils.buildLongBinaryFuseFilters(payloadMap, payloadBlockNum, params, candidateSeed);
                seed = candidateSeed;
            } catch (IllegalStateException ignored) {
                // Try another deterministic seed.
            }
        }
        Assert.assertNotNull(bff);
        Assert.assertNotNull(seed);
        Assert.assertEquals(payloadBlockNum, bff.length);
        for (Map.Entry<ByteBuffer, long[]> entry : payloadMap.entrySet()) {
            int[] positions = CapePirUtils.getHashPositions(entry.getKey(), payloadMap.size(), seed, params);
            for (int blockIndex = 0; blockIndex < payloadBlockNum; blockIndex++) {
                long actual = 0L;
                for (int position : positions) {
                    actual = Math.floorMod(actual + bff[blockIndex][position], params.getPlainModulus());
                }
                Assert.assertEquals(entry.getValue()[blockIndex], actual);
            }
        }
    }

    @Test
    public void testIndexedBloomPayloadProviderEqualsOldSmall() {
        CapePirParams params = new CapePirParams(CapePirParams.DEFAULT_PARAMS);
        params.initPirParams(3, 2, 3, 3);
        Map<ByteBuffer, List<byte[]>> keywordValueMap = createOrderedKeywordValueMap();
        Map<ByteBuffer, List<ByteBuffer>> forwardIndex = CapePirUtils.buildForwardIndex(keywordValueMap);
        Map<ByteBuffer, CapeBloomFilterAdapter> valueBloomFilters = CapePirUtils.buildValueBloomFilters(
            forwardIndex, params
        );
        CapePirServer.IndexedBloomPayloadPlan indexedPlan = new CapePirServer.IndexedBloomPayloadPlan(
            keywordValueMap, valueBloomFilters, params.getBloomBitLength(), params.getBloomPerPackedBlock()
        );
        int keyIndex = 0;
        for (Map.Entry<ByteBuffer, List<byte[]>> entry : keywordValueMap.entrySet()) {
            long[] oldPayload = CapePirUtils.buildBloomOnlyLongPayload(entry.getValue(), valueBloomFilters, params);
            for (int blockIndex = 0; blockIndex < oldPayload.length; blockIndex++) {
                Assert.assertEquals(oldPayload[blockIndex], indexedPlan.get(keyIndex, blockIndex));
            }
            keyIndex++;
        }
    }

    @Test
    public void testStreamingBloomOnlyBffEqualsMaterializedSmall() {
        CapePirParams params = new CapePirParams(CapePirParams.DEFAULT_PARAMS);
        params.initPirParams(3, 2, 3, 3);
        Map<ByteBuffer, List<byte[]>> keywordValueMap = createOrderedKeywordValueMap();
        Map<ByteBuffer, List<ByteBuffer>> forwardIndex = CapePirUtils.buildForwardIndex(keywordValueMap);
        Map<ByteBuffer, CapeBloomFilterAdapter> valueBloomFilters = CapePirUtils.buildValueBloomFilters(
            forwardIndex, params
        );
        Map<ByteBuffer, long[]> bloomPayloadMap = new LinkedHashMap<>();
        keywordValueMap.forEach((keyword, values) ->
            bloomPayloadMap.put(keyword, CapePirUtils.buildBloomOnlyLongPayload(values, valueBloomFilters, params))
        );
        int payloadBlockNum = CapePirUtils.bloomOnlyPayloadByteLength(params);
        long[][] materializedBff = null;
        byte[] seed = null;
        for (int attempt = 0; attempt < 32 && materializedBff == null; attempt++) {
            byte[] candidateSeed = new byte[16];
            candidateSeed[15] = (byte) attempt;
            try {
                materializedBff = CapePirUtils.buildLongBinaryFuseFilters(
                    bloomPayloadMap, payloadBlockNum, params, candidateSeed
                );
                seed = candidateSeed;
            } catch (IllegalStateException ignored) {
                // Try another deterministic seed.
            }
        }
        Assert.assertNotNull(materializedBff);
        Assert.assertNotNull(seed);
        CapePirServer.IndexedBloomPayloadPlan indexedPlan = new CapePirServer.IndexedBloomPayloadPlan(
            keywordValueMap, valueBloomFilters, params.getBloomBitLength(), params.getBloomPerPackedBlock()
        );
        long[] streamingSlotBlocks = CapePirUtils.assignLongStorageForBlockGroupForTest(
            keywordValueMap.keySet(), payloadBlockNum, params, seed, indexedPlan::get
        );
        int keyIndex = 0;
        for (Map.Entry<ByteBuffer, long[]> entry : bloomPayloadMap.entrySet()) {
            int[] positions = CapePirUtils.getHashPositions(entry.getKey(), keywordValueMap.size(), seed, params);
            for (int blockIndex = 0; blockIndex < payloadBlockNum; blockIndex++) {
                long materializedActual = 0L;
                long streamingActual = 0L;
                for (int position : positions) {
                    materializedActual = Math.floorMod(
                        materializedActual + materializedBff[blockIndex][position], params.getPlainModulus()
                    );
                    streamingActual = Math.floorMod(
                        streamingActual + streamingSlotBlocks[position * payloadBlockNum + blockIndex],
                        params.getPlainModulus()
                    );
                }
                Assert.assertEquals(entry.getValue()[blockIndex], materializedActual);
                Assert.assertEquals(entry.getValue()[blockIndex], streamingActual);
            }
            keyIndex++;
        }
    }

    @Test
    public void testValueAndBloomUseSameGraph() {
        CapePirParams params = new CapePirParams(CapePirParams.DEFAULT_PARAMS);
        params.initPirParams(3, 2, 3, 3);
        Map<ByteBuffer, List<byte[]>> keywordValueMap = createOrderedKeywordValueMap();
        Map<ByteBuffer, List<ByteBuffer>> forwardIndex = CapePirUtils.buildForwardIndex(keywordValueMap);
        Map<ByteBuffer, CapeBloomFilterAdapter> valueBloomFilters = CapePirUtils.buildValueBloomFilters(
            forwardIndex, params
        );
        CapePirServer.IndexedBloomPayloadPlan indexedPlan = new CapePirServer.IndexedBloomPayloadPlan(
            keywordValueMap, valueBloomFilters, params.getBloomBitLength(), params.getBloomPerPackedBlock()
        );
        Map<ByteBuffer, long[]> valueOnlyPayloadMap = new LinkedHashMap<>();
        keywordValueMap.forEach((keyword, values) -> valueOnlyPayloadMap.put(
            keyword, CapePirUtils.buildValueOnlyLongPayload(keyword, values, params)
        ));
        CapePirUtils.SameSeedFuseGraph<ByteBuffer> graph = null;
        byte[] seed = null;
        for (int attempt = 0; attempt < 32 && graph == null; attempt++) {
            byte[] candidateSeed = new byte[16];
            candidateSeed[15] = (byte) attempt;
            graph = CapePirUtils.buildSameSeedFuseGraph(indexedPlan.getKeysForTest(), params, candidateSeed);
            seed = candidateSeed;
        }
        Assert.assertNotNull(graph);
        Assert.assertNotNull(seed);
        List<ByteBuffer> keyList = indexedPlan.getKeysForTest();
        long[][] valueBff = CapePirUtils.buildLongBinaryFuseFilters(
            graph, CapePirUtils.valueOnlyPayloadBlockNum(params), params,
            (keyIndex, blockIndex) -> valueOnlyPayloadMap.get(keyList.get(keyIndex))[blockIndex]
        );
        int bloomPayloadBlockNum = CapePirUtils.bloomOnlyPayloadByteLength(params);
        long[] bloomGroup = CapePirUtils.assignLongStorageForBlockGroupForTest(
            keyList, bloomPayloadBlockNum, params, seed, indexedPlan::get
        );
        for (int keyIndex = 0; keyIndex < keyList.size(); keyIndex++) {
            ByteBuffer key = keyList.get(keyIndex);
            Assert.assertArrayEquals(
                CapePirUtils.getHashPositions(key, keyList.size(), seed, params),
                graph.getKeyPositions(keyIndex)
            );
            int[] positions = graph.getKeyPositions(keyIndex);
            long[] valuePayload = valueOnlyPayloadMap.get(key);
            for (int blockIndex = 0; blockIndex < valuePayload.length; blockIndex++) {
                long actual = 0L;
                for (int position : positions) {
                    actual = Math.floorMod(actual + valueBff[blockIndex][position], params.getPlainModulus());
                }
                Assert.assertEquals(valuePayload[blockIndex], actual);
            }
            long[] bloomPayload = CapePirUtils.buildBloomOnlyLongPayload(
                keywordValueMap.get(key), valueBloomFilters, params
            );
            for (int blockIndex = 0; blockIndex < bloomPayloadBlockNum; blockIndex++) {
                long actual = 0L;
                for (int position : positions) {
                    actual = Math.floorMod(
                        actual + bloomGroup[position * bloomPayloadBlockNum + blockIndex], params.getPlainModulus()
                    );
                }
                Assert.assertEquals(bloomPayload[blockIndex], actual);
            }
        }
    }

    @Test
    public void testLongBinaryFuseFilterMatrixLayout() {
        CapePirParams params = new CapePirParams(CapePirParams.DEFAULT_PARAMS);
        params.initPirParams(3, 2, 3, 3);
        Map<ByteBuffer, List<byte[]>> keywordValueMap = createKeywordValueMap();
        Map<ByteBuffer, List<ByteBuffer>> forwardIndex = CapePirUtils.buildForwardIndex(keywordValueMap);
        Map<ByteBuffer, CapeBloomFilterAdapter> valueBloomFilters = CapePirUtils.buildValueBloomFilters(
            forwardIndex, params
        );
        Map<ByteBuffer, byte[]> combinedPayloadMap = new LinkedHashMap<>();
        Map<ByteBuffer, long[]> bloomPayloadMap = new LinkedHashMap<>();
        keywordValueMap.forEach((keyword, values) -> {
            combinedPayloadMap.put(keyword, CapePirUtils.buildKeywordPayload(keyword, values, valueBloomFilters, params));
            bloomPayloadMap.put(keyword, CapePirUtils.buildBloomOnlyLongPayload(values, valueBloomFilters, params));
        });
        CapePirUtils.BinaryFuseFilterData combinedBff = CapePirUtils.buildBinaryFuseFilters(
            combinedPayloadMap, params, new SecureRandom()
        );
        long[][] bloomBff = CapePirUtils.buildLongBinaryFuseFilters(
            bloomPayloadMap, CapePirUtils.bloomOnlyPayloadByteLength(params), params, combinedBff.getSeed()
        );
        long[][][] matrices = CapePirUtils.matrixizePackedBff(
            bloomBff, params, CapePirUtils.bloomOnlyPayloadByteLength(params), params.getBlocksPerPackedMatrix()
        );

        for (Map.Entry<ByteBuffer, long[]> entry : bloomPayloadMap.entrySet()) {
            int[] positions = CapePirUtils.getHashPositions(
                entry.getKey(), keywordValueMap.size(), combinedBff.getSeed(), params
            );
            for (int blockIndex = 0; blockIndex < entry.getValue().length; blockIndex++) {
                int groupIndex = blockIndex / params.getBlocksPerPackedMatrix();
                int blockOffset = blockIndex % params.getBlocksPerPackedMatrix();
                long actual = 0L;
                for (int position : positions) {
                    int row = position % params.getMatrixRowNum();
                    int col = position / params.getMatrixRowNum();
                    actual = Math.floorMod(
                        actual + matrices[groupIndex][row][col * params.getBlocksPerPackedMatrix() + blockOffset],
                        params.getPlainModulus()
                    );
                }
                Assert.assertEquals(entry.getValue()[blockIndex], actual);
            }
        }
    }

    @Test
    public void testValueOnlyLongBinaryFuseFilterReconstructsPayload() {
        CapePirParams params = new CapePirParams(CapePirParams.DEFAULT_PARAMS);
        params.initPirParams(3, 2, 3, 3);
        Map<ByteBuffer, List<byte[]>> keywordValueMap = createKeywordValueMap();
        Map<ByteBuffer, long[]> valueOnlyPayloadMap = new LinkedHashMap<>();
        Map<ByteBuffer, byte[]> combinedPayloadMap = new LinkedHashMap<>();
        Map<ByteBuffer, List<ByteBuffer>> forwardIndex = CapePirUtils.buildForwardIndex(keywordValueMap);
        Map<ByteBuffer, CapeBloomFilterAdapter> valueBloomFilters = CapePirUtils.buildValueBloomFilters(
            forwardIndex, params
        );
        keywordValueMap.forEach((keyword, values) -> valueOnlyPayloadMap.put(
            keyword, CapePirUtils.buildValueOnlyLongPayload(keyword, values, params)
        ));
        keywordValueMap.forEach((keyword, values) -> combinedPayloadMap.put(
            keyword, CapePirUtils.buildKeywordPayload(keyword, values, valueBloomFilters, params)
        ));
        Map<ByteBuffer, byte[]> canonicalCombinedPayloadMap = CapePirUtils.toCanonicalBytePayloadMap(combinedPayloadMap);
        Map<ByteBuffer, long[]> canonicalValueOnlyPayloadMap = CapePirUtils.toCanonicalLongPayloadMap(
            valueOnlyPayloadMap
        );
        CapePirUtils.BinaryFuseFilterData combinedBff = CapePirUtils.buildBinaryFuseFilters(
            canonicalCombinedPayloadMap, params, new SecureRandom()
        );
        long[][] valueBff = CapePirUtils.buildLongBinaryFuseFilters(
            canonicalValueOnlyPayloadMap, CapePirUtils.valueOnlyPayloadBlockNum(params), params, combinedBff.getSeed()
        );
        for (Map.Entry<ByteBuffer, long[]> entry : valueOnlyPayloadMap.entrySet()) {
            int[] positions = CapePirUtils.getHashPositionsFromKeywordBytes(
                CapePirUtils.keywordToByteArray(entry.getKey()), keywordValueMap.size(), combinedBff.getSeed(), params
            );
            for (int blockIndex = 0; blockIndex < entry.getValue().length; blockIndex++) {
                long actual = 0;
                for (int position : positions) {
                    actual = Math.floorMod(
                        actual + valueBff[blockIndex][position], params.getPlainModulus()
                    );
                }
                Assert.assertEquals(entry.getValue()[blockIndex], actual);
            }
        }
    }

    private Map<ByteBuffer, List<byte[]>> createKeywordValueMap() {
        return Map.of(
            ByteBuffer.wrap("k1".getBytes()), List.of("v1".getBytes(), "v2".getBytes(), "v3".getBytes()),
            ByteBuffer.wrap("k2".getBytes()), List.of("v1".getBytes()),
            ByteBuffer.wrap("k3".getBytes()), List.of("v1".getBytes(), "v2".getBytes())
        );
    }

    private Map<ByteBuffer, List<byte[]>> createOrderedKeywordValueMap() {
        Map<ByteBuffer, List<byte[]>> keywordValueMap = new LinkedHashMap<>();
        keywordValueMap.put(
            ByteBuffer.wrap("k1".getBytes()), List.of("v1".getBytes(), "v2".getBytes(), "v3".getBytes())
        );
        keywordValueMap.put(ByteBuffer.wrap("k2".getBytes()), List.of("v1".getBytes()));
        keywordValueMap.put(ByteBuffer.wrap("k3".getBytes()), List.of("v1".getBytes(), "v2".getBytes()));
        return keywordValueMap;
    }
}
