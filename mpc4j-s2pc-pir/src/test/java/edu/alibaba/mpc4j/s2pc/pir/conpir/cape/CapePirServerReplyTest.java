package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import edu.alibaba.mpc4j.common.rpc.impl.memory.MemoryRpcManager;
import edu.alibaba.mpc4j.common.tool.utils.CommonUtils;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * CAPE PIR server reply tests.
 *
 * @author Weiran Liu
 * @date 2026/06/06
 */
public class CapePirServerReplyTest {

    @Test
    public void testServerReplySmall() throws Exception {
        TestContext context = createContext();
        try {
            List<ByteBuffer> queryKeywords = List.of(
                ByteBuffer.wrap("k1".getBytes()),
                ByteBuffer.wrap("k2".getBytes()),
                ByteBuffer.wrap("k3".getBytes())
            );
            CapePirQuery query = context.client.generateCapeQuery(queryKeywords);
            CapePirResponse response = context.server.generateReply(query);
            Assert.assertEquals(context.client.getCapeParams().getExpectedPackedResultCiphertextCount(),
                response.getPackedResultCiphertexts().size());
            Assert.assertTrue(response.getEncryptedValuePayloads().isEmpty());
            Assert.assertTrue(response.getEncryptedBloomInnerProducts().isEmpty());

            long[] resultCoeffs = decryptPackedResult(response, context);
            long[] valueCoeffs = java.util.Arrays.copyOf(resultCoeffs,
                context.client.getCapeParams().getValuePayloadCoeffNum());
            assertExpectedValuePayload(queryKeywords.get(0), valueCoeffs, context);
            List<byte[]> candidates = CapePirUtils.decodeValueOnlyPayload(
                CapePirUtils.keywordToByteArray(queryKeywords.get(0)),
                valueCoeffs,
                context.client.getCapeParams()
            );
            Assert.assertArrayEquals("v1".getBytes(), candidates.get(0));
            Assert.assertArrayEquals("v2".getBytes(), candidates.get(1));
            Assert.assertArrayEquals("v3".getBytes(), candidates.get(2));

            assertPackedBloomPayloadLayout(query, context);

            int n = query.getBloomOneCount();
            Map<ByteBuffer, Long> scoreMap = new LinkedHashMap<>();
            long[] packedScoreCoeffs = java.util.Arrays.copyOfRange(
                resultCoeffs, context.client.getCapeParams().getScoreOffset(),
                context.client.getCapeParams().getScoreOffset() + context.client.getCapeParams().getScoreCoeffNum()
            );
            for (int i = 0; i < candidates.size(); i++) {
                scoreMap.put(ByteBuffer.wrap(candidates.get(i)),
                    normalizePackedScore(packedScoreCoeffs[i], context.client.getCapeParams()));
            }
            Assert.assertEquals(n, scoreMap.get(ByteBuffer.wrap("v1".getBytes())).intValue());
            Assert.assertNotEquals(n, scoreMap.get(ByteBuffer.wrap("v2".getBytes())).intValue());
            Assert.assertNotEquals(n, scoreMap.get(ByteBuffer.wrap("v3".getBytes())).intValue());
        } finally {
            context.release();
        }
    }

    @Test
    public void testValueReplyCountMatchesValuePayloadOnly() throws Exception {
        TestContext context = createContext();
        try {
            CapePirParams params = context.client.getCapeParams();
            List<ByteBuffer> queryKeywords = List.of(
                ByteBuffer.wrap("k1".getBytes()),
                ByteBuffer.wrap("k2".getBytes()),
                ByteBuffer.wrap("k3".getBytes())
            );
            CapePirQuery query = context.client.generateCapeQuery(queryKeywords);
            CapePirResponse response = context.server.generateReply(query);
            int valuePayloadElementNum = CapePirUtils.valueOnlyPayloadBlockNum(params);
            Assert.assertEquals(params.getValuePayloadCoeffNum(), valuePayloadElementNum);
            Assert.assertEquals(params.getExpectedPackedResultCiphertextCount(),
                response.getPackedResultCiphertexts().size());
            Assert.assertEquals(1, params.getExpectedPackedResultCiphertextCount());
            Assert.assertEquals(1, params.getBloomPackedPayloadBlockNum());
            Assert.assertTrue(params.getBloomPackedCoefficientStride() > params.getValueBlocksPerPackedMatrix());
            Assert.assertTrue(response.getEncryptedBloomInnerProducts().isEmpty());
        } finally {
            context.release();
        }
    }

    @Test
    public void testValuePackingIndependentFromBloomPacking() throws Exception {
        TestContext context = createContext();
        try {
            CapePirParams params = context.client.getCapeParams();
            int expectedValueReplyCiphertextCount = expectedValueCiphertextCount(params);
            Assert.assertEquals(CommonUtils.getUnitNum(
                CapePirUtils.valueOnlyPayloadBlockNum(params), params.getValueBlocksPerPackedMatrix()
            ), expectedValueReplyCiphertextCount);
            Assert.assertNotEquals(params.getValueBlocksPerPackedMatrix(), params.getBloomPackedCoefficientStride());

            CapePirQuery threeKeywordQuery = context.client.generateCapeQuery(List.of(
                ByteBuffer.wrap("k1".getBytes()),
                ByteBuffer.wrap("k2".getBytes()),
                ByteBuffer.wrap("k3".getBytes())
            ));
            List<byte[]> threeKeywordResult = context.client.decodeResponse(
                threeKeywordQuery, context.server.generateReply(threeKeywordQuery)
            );
            Assert.assertEquals(1, threeKeywordResult.size());
            Assert.assertArrayEquals("v1".getBytes(), threeKeywordResult.get(0));
        } finally {
            context.release();
        }
        context = createContext(2);
        try {
            CapePirQuery twoKeywordQuery = context.client.generateCapeQuery(List.of(
                ByteBuffer.wrap("k1".getBytes()),
                ByteBuffer.wrap("k3".getBytes())
            ));
            List<byte[]> twoKeywordResult = context.client.decodeResponse(twoKeywordQuery, context.server.generateReply(twoKeywordQuery));
            Assert.assertTrue(twoKeywordResult.stream().anyMatch(value -> java.util.Arrays.equals("v1".getBytes(), value)));
            Assert.assertTrue(twoKeywordResult.stream().anyMatch(value -> java.util.Arrays.equals("v2".getBytes(), value)));
        } finally {
            context.release();
        }
    }

    @Test
    @Ignore("Legacy direct RGSW row-bit diagnostic is not used by the formal compressed-row CAPE path.")
    public void testAlignedParamsDirectRowBitsCandidateReply() throws Exception {
        TestContext context = createContext();
        try {
            List<ByteBuffer> queryKeywords = List.of(
                ByteBuffer.wrap("k1".getBytes()), ByteBuffer.wrap("k2".getBytes()), ByteBuffer.wrap("k3".getBytes())
            );
            CapePirQuery query = context.client.generateCapeQuery(queryKeywords);
            List<byte[]> directRowBits = generateDirectRowBits(queryKeywords.get(0), context);
            List<byte[]> directValueReply = context.server.generateValueCandidateReplyWithRowBitsForTest(
                query, directRowBits
            );
            Assert.assertEquals(expectedValueCiphertextCount(context.client.getCapeParams()), directValueReply.size());
            long[] directCoeffs = decryptValuePayloadSegments(directValueReply, context);
            assertExpectedValuePayload(queryKeywords.get(0), directCoeffs, context);
        } finally {
            context.release();
        }
    }

    @Test
    public void testAlignedParamsCompressedRowBitsCandidateReply() throws Exception {
        TestContext context = createContext();
        try {
            List<ByteBuffer> queryKeywords = List.of(
                ByteBuffer.wrap("k1".getBytes()), ByteBuffer.wrap("k2".getBytes()), ByteBuffer.wrap("k3".getBytes())
            );
            CapePirQuery query = context.client.generateCapeQuery(queryKeywords);
            List<byte[]> compressedRowBits = context.server.convertCompressedRowBitQueriesForTest(
                query.getCompressedRowBitQueries()
            );
            List<byte[]> compressedValueReply = context.server.generateValueCandidateReplyWithRowBitsForTest(
                query, compressedRowBits
            );
            Assert.assertEquals(expectedValueCiphertextCount(context.client.getCapeParams()), compressedValueReply.size());
            long[] compressedCoeffs = decryptValuePayloadSegments(compressedValueReply, context);
            assertExpectedValuePayload(queryKeywords.get(0), compressedCoeffs, context);
        } finally {
            context.release();
        }
    }

    @Test
    public void testAlignedParamsDirectVsCompressedRowBitsReplyEquivalence() throws Exception {
        TestContext context = createContext();
        try {
            List<ByteBuffer> queryKeywords = List.of(
                ByteBuffer.wrap("k1".getBytes()), ByteBuffer.wrap("k2".getBytes()), ByteBuffer.wrap("k3".getBytes())
            );
            CapePirQuery query = context.client.generateCapeQuery(queryKeywords);
            List<byte[]> directRowBits = generateDirectRowBits(queryKeywords.get(0), context);
            List<byte[]> compressedRowBits = context.server.convertCompressedRowBitQueriesForTest(
                query.getCompressedRowBitQueries()
            );
            long[] directCoeffs = decryptValuePayloadSegments(
                context.server.generateValueCandidateReplyWithRowBitsForTest(query, directRowBits), context
            );
            long[] compressedCoeffs = decryptValuePayloadSegments(
                context.server.generateValueCandidateReplyWithRowBitsForTest(query, compressedRowBits), context
            );
            int valuePayloadBlockNum = CapePirUtils.valueOnlyPayloadBlockNum(context.client.getCapeParams());
            for (int i = 0; i < valuePayloadBlockNum; i++) {
                Assert.assertEquals("direct/compressed coeff " + i, directCoeffs[i], compressedCoeffs[i]);
            }
        } finally {
            context.release();
        }
    }

    private TestContext createContext() throws Exception {
        return createContext(3);
    }

    private TestContext createContext(int boolKeywordNum) throws Exception {
        MemoryRpcManager rpcManager = new MemoryRpcManager(2);
        CapePirConfig serverConfig = new CapePirConfig.Builder().setBoolKeywordNum(boolKeywordNum).build();
        CapePirConfig clientConfig = new CapePirConfig.Builder().setBoolKeywordNum(boolKeywordNum).build();
        CapePirServer<ByteBuffer> server = new CapePirServer<>(
            rpcManager.getRpc(0), rpcManager.getRpc(1).ownParty(), serverConfig
        );
        server.init(createKeywordValueMap(), 1);
        CapePirClient<ByteBuffer> client = new CapePirClient<>(
            rpcManager.getRpc(1), rpcManager.getRpc(0).ownParty(), clientConfig
        );
        client.init(3, 2, 3, 1);
        client.setBffSeed(server.getBffSeed());
        client.getCapeParams().applySerializedBloomParams(server.getCapeParams().serializeBloomParams());
        server.setPublicKey(client.getPublicKey());
        server.setRelinKeys(client.getRelinKeys());
        server.setGaloisKeys(client.getGaloisKeys());
        server.setLweToRgswKey(client.getLweToRgswKey());
        Assert.assertTrue(server.getLweToRgswKeyHandleForTest() != 0L);
        Assert.assertTrue(server.isJavaLweToRgswKeyReleasedForTest());
        return new TestContext(server, client);
    }

    private void assertExpectedValuePayload(ByteBuffer anchorKeyword, long[] valueCoeffs, TestContext context) {
        long[] expectedValuePayload = CapePirUtils.buildValueOnlyLongPayload(
            anchorKeyword, createKeywordValueMap().get(anchorKeyword), context.client.getCapeParams()
        );
        for (int i = 0; i < expectedValuePayload.length; i++) {
            Assert.assertEquals("value-only coeff " + i, expectedValuePayload[i], valueCoeffs[i]);
        }
    }

    private void assertBloomPayload(CapePirQuery query, ByteBuffer anchorKeyword, TestContext context) {
        List<byte[]> encryptedBloomGroups = context.server.generateBloomPayloadGroupsForTest(query);
        long[] expectedBloomPayload = CapePirUtils.buildBloomOnlyLongPayload(
            createKeywordValueMap().get(anchorKeyword), context.server.getValueBloomFilters(),
            context.client.getCapeParams()
        );
        long[] actualBloomPayload = new long[expectedBloomPayload.length];
        int copied = 0;
        for (byte[] encryptedBloomGroup : encryptedBloomGroups) {
            long[] groupCoeffs = CapePirNativeUtils.decryptCoeffReply(
                context.client.getCapeParams().encryptionParams, context.client.getSecretKey(), encryptedBloomGroup
            );
            int copyLength = Math.min(context.client.getCapeParams().getBlocksPerPackedMatrix(),
                actualBloomPayload.length - copied);
            System.arraycopy(groupCoeffs, 0, actualBloomPayload, copied, copyLength);
            copied += copyLength;
        }
        for (int i = 0; i < expectedBloomPayload.length; i++) {
            Assert.assertEquals("bloom-only coeff " + i, expectedBloomPayload[i], actualBloomPayload[i]);
        }
    }

    private void assertPackedBloomPayloadLayout(CapePirQuery query, TestContext context) {
        CapePirParams params = context.client.getCapeParams();
        Assert.assertEquals(1, query.getEncryptedCoeffBloomFilters().size());
        Assert.assertEquals(1, params.getBloomPackedPayloadBlockNum());
        Assert.assertTrue(params.getBloomPackedPayloadBlockNum() < params.getScalarBloomPayloadBlockNumForTest());
        Assert.assertEquals(params.getBloomPerPackedBlock() * params.getBloomBitLength(),
            params.getBloomPackedCoefficientStride());
    }

    private long[] decryptValuePayloadSegments(List<byte[]> encryptedValuePayloads, TestContext context) {
        CapePirParams params = context.client.getCapeParams();
        Assert.assertEquals(expectedValueCiphertextCount(params), encryptedValuePayloads.size());
        long[] valueCoeffs = new long[CapePirUtils.valueOnlyPayloadBlockNum(params)];
        int copied = 0;
        for (byte[] encryptedValuePayload : encryptedValuePayloads) {
            long[] segmentCoeffs = CapePirNativeUtils.decryptCoeffReply(
                params.encryptionParams, context.client.getSecretKey(), encryptedValuePayload
            );
            int copyLength = Math.min(params.getValueBlocksPerPackedMatrix(), valueCoeffs.length - copied);
            System.arraycopy(segmentCoeffs, 0, valueCoeffs, copied, copyLength);
            copied += copyLength;
        }
        Assert.assertEquals(valueCoeffs.length, copied);
        return valueCoeffs;
    }

    private long[] decryptPackedResult(CapePirResponse response, TestContext context) {
        CapePirParams params = context.client.getCapeParams();
        Assert.assertEquals(params.getExpectedPackedResultCiphertextCount(), response.getPackedResultCiphertexts().size());
        long[] resultCoeffs = new long[params.getTotalResultCoeffNum()];
        int copied = 0;
        for (byte[] packedResultCiphertext : response.getPackedResultCiphertexts()) {
            long[] coeffs = CapePirNativeUtils.decryptCoeffReply(
                params.encryptionParams, context.client.getSecretKey(), packedResultCiphertext
            );
            int copyLength = Math.min(params.getPolyModulusDegree(), resultCoeffs.length - copied);
            System.arraycopy(coeffs, 0, resultCoeffs, copied, copyLength);
            copied += copyLength;
        }
        Assert.assertEquals(resultCoeffs.length, copied);
        return resultCoeffs;
    }

    private List<byte[]> generateDirectRowBits(ByteBuffer anchorKeyword, TestContext context) {
        int[] positions = CapePirUtils.getHashPositionsFromKeywordBytes(
            CapePirUtils.keywordToByteArray(anchorKeyword), context.client.getKeywordNum(), context.server.getBffSeed(),
            context.client.getCapeParams()
        );
        List<byte[]> rowBits = new java.util.ArrayList<>();
        for (int position : positions) {
            int row = position % context.client.getCapeParams().getMatrixRowNum();
            rowBits.addAll(CapePirNativeUtils.generateEncryptedRowBits(
                context.client.getCapeParams().encryptionParams, context.client.getPublicKey(),
                context.client.getSecretKey(), row, context.client.getCapeParams().getMatrixRowNum()
            ));
        }
        return rowBits;
    }

    private Map<ByteBuffer, List<byte[]>> createKeywordValueMap() {
        Map<ByteBuffer, List<byte[]>> keywordValueMap = new LinkedHashMap<>();
        keywordValueMap.put(ByteBuffer.wrap("k1".getBytes()), List.of("v1".getBytes(), "v2".getBytes(), "v3".getBytes()));
        keywordValueMap.put(ByteBuffer.wrap("k2".getBytes()), List.of("v1".getBytes()));
        keywordValueMap.put(ByteBuffer.wrap("k3".getBytes()), List.of("v1".getBytes(), "v2".getBytes()));
        return keywordValueMap;
    }

    private static long normalizePackedScore(long packedScore, CapePirParams params) {
        long inverseScale = inverseMod(params.getPolyModulusDegree() % params.getPlainModulus(), params.getPlainModulus());
        return Math.floorMod(packedScore * inverseScale, params.getPlainModulus());
    }

    private static long blockToLong(byte[] payload, int blockIndex, CapePirParams params) {
        int offset = blockIndex * params.getPayloadBlockByteLength();
        int copyByteLength = Math.min(params.getPayloadBlockByteLength(), payload.length - offset);
        long value = 0L;
        for (int i = 0; i < params.getPayloadBlockByteLength(); i++) {
            int byteValue = i < copyByteLength ? payload[offset + i] & 0xFF : 0;
            value = (value << Byte.SIZE) | byteValue;
        }
        return value;
    }

    private static int expectedValueCiphertextCount(CapePirParams params) {
        return CapePirUtils.valueOnlyPayloadBlockNum(params) <= params.getPolyModulusDegree()
            ? 1
            : CommonUtils.getUnitNum(CapePirUtils.valueOnlyPayloadBlockNum(params),
                params.getValueBlocksPerPackedMatrix());
    }

    private static long inverseMod(long value, long modulus) {
        long t = 0;
        long newT = 1;
        long r = modulus;
        long newR = Math.floorMod(value, modulus);
        while (newR != 0) {
            long quotient = r / newR;
            long nextT = t - quotient * newT;
            t = newT;
            newT = nextT;
            long nextR = r - quotient * newR;
            r = newR;
            newR = nextR;
        }
        if (r != 1) {
            throw new IllegalStateException("packed score scale is not invertible");
        }
        return Math.floorMod(t, modulus);
    }

    private record TestContext(CapePirServer<ByteBuffer> server, CapePirClient<ByteBuffer> client) {
        private void release() {
            server.releaseLargeStateForTest();
            client.releaseLargeKeysForTest();
            System.gc();
        }
    }
}
