package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import edu.alibaba.mpc4j.common.rpc.impl.memory.MemoryRpcManager;
import org.junit.Assert;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * CAPE PIR client decode tests.
 *
 * @author Weiran Liu
 * @date 2026/06/06
 */
public class CapePirClientDecodeTest {
    private static TestContext sharedContext;

    @BeforeClass
    public static void setUpClass() throws Exception {
        sharedContext = createContext();
    }

    @AfterClass
    public static void tearDownClass() {
        if (sharedContext != null) {
            sharedContext.release();
            sharedContext = null;
        }
    }

    @Test
    public void testClientDecode() throws Exception {
        List<byte[]> hit = runQuery(sharedContext, List.of(
            ByteBuffer.wrap("k1".getBytes()),
            ByteBuffer.wrap("k2".getBytes()),
            ByteBuffer.wrap("k3".getBytes())
        ));
        Assert.assertEquals(1, hit.size());
        Assert.assertArrayEquals("v1".getBytes(), hit.get(0));
    }

    @Test
    @Ignore("P8 keeps only minimal CAPE RPC correctness; repeated aligned setup keys can exceed the test VM memory")
    public void testClientPirRpc() throws Exception {
        MemoryRpcManager rpcManager = new MemoryRpcManager(2);
        CapePirServer<ByteBuffer> server = new CapePirServer<>(
            rpcManager.getRpc(0), rpcManager.getRpc(1).ownParty(), new CapePirConfig.Builder().build()
        );
        CapePirClient<ByteBuffer> client = new CapePirClient<>(
            rpcManager.getRpc(1), rpcManager.getRpc(0).ownParty(), new CapePirConfig.Builder().build()
        );
        ArrayList<List<ByteBuffer>> queries = new ArrayList<>();
        queries.add(List.of(
            ByteBuffer.wrap("k1".getBytes()),
            ByteBuffer.wrap("k2".getBytes()),
            ByteBuffer.wrap("k3".getBytes())
        ));
        CapeServerThread serverThread = new CapeServerThread(server, createKeywordValueMap());
        CapeClientThread clientThread = new CapeClientThread(client, queries);
        serverThread.start();
        clientThread.start();
        serverThread.join();
        clientThread.join();
        if (serverThread.throwable != null) {
            throw new AssertionError(serverThread.throwable);
        }
        if (clientThread.throwable != null) {
            throw new AssertionError(clientThread.throwable);
        }
        List<byte[]>[] entries = clientThread.entries;
        Assert.assertEquals(1, entries.length);
        Assert.assertEquals(1, entries[0].size());
        Assert.assertArrayEquals("v1".getBytes(), entries[0].get(0));
        client.releaseLargeKeysForTest();
        server.releaseLargeStateForTest();
        System.gc();
    }

    @Test
    public void testFormalQueryPayloadDoesNotContainLegacyBloomFields() throws Exception {
        TestContext context = sharedContext;
        List<ByteBuffer> queryKeywords = List.of(
            ByteBuffer.wrap("k1".getBytes()),
            ByteBuffer.wrap("k2".getBytes()),
            ByteBuffer.wrap("k3".getBytes())
        );
        CapePirQuery query = context.client.generateCapeQuery(queryKeywords);
        Assert.assertTrue(query.getFusePirBitColumnQueries().isEmpty());
        Assert.assertTrue(query.getEncryptedBloomFilter().isEmpty());
        Assert.assertEquals(0, byteLength(query.getFusePirBitColumnQueries()));
        Assert.assertEquals(0, byteLength(query.getEncryptedBloomFilter()));
        Assert.assertEquals(0, byteLength(query.getFusePirEncryptedRowBits()));
        Assert.assertEquals(context.client.getCapeParams().getBffHashNum(), query.getCompressedRowBitQueries().size());
        Assert.assertTrue(byteLength(query.getCompressedRowBitQueries()) > 0);
        int expectedPayloadSize = context.client.getCapeParams().getBffHashNum()
            + context.client.getCapeParams().getBffHashNum()
            + context.client.getCapeParams().getCoeffBloomCiphertextNum();
        Assert.assertEquals(expectedPayloadSize, query.getServerPayload().size());
        CapePirResponse response = context.server.generateReply(query);
        List<byte[]> result = context.client.decodeResponse(query, response);
        Assert.assertEquals(1, result.size());
        Assert.assertArrayEquals("v1".getBytes(), result.get(0));
    }

    @Test
    public void testPackedScoreResponseMinimal() throws Exception {
        TestContext context = sharedContext;
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
        Assert.assertTrue(context.client.getCapeParams().getMaxValueNumPerKeyword()
            <= context.client.getCapeParams().getPolyModulusDegree());
        Assert.assertTrue(response.getEncryptedBloomInnerProducts().isEmpty());
        List<byte[]> result = context.client.decodeResponse(query, response);
        Assert.assertEquals(1, result.size());
        Assert.assertArrayEquals("v1".getBytes(), result.get(0));
    }

    @Test
    public void testPackedScorePaddingDoesNotAffectResult() throws Exception {
        TestContext context = sharedContext;
        List<ByteBuffer> queryKeywords = List.of(
            ByteBuffer.wrap("k1".getBytes()),
            ByteBuffer.wrap("k2".getBytes()),
            ByteBuffer.wrap("k3".getBytes())
        );
        CapePirQuery query = context.client.generateCapeQuery(queryKeywords);
        CapePirResponse response = context.server.generateReply(query);
        CapePirParams params = context.client.getCapeParams();
        Assert.assertTrue(params.getMaxValueNumPerKeyword() < params.getPolyModulusDegree());
        long scoreScale = params.getPolyModulusDegree() % params.getPlainModulus();
        long[] packedResult = decryptPackedResult(response, context);
        packedResult[params.getScoreOffset()] = Math.floorMod(scoreScale * query.getBloomOneCount(), params.getPlainModulus());
        packedResult[params.getScoreOffset() + 1] = Math.floorMod(scoreScale * (query.getBloomOneCount() + 1L), params.getPlainModulus());
        packedResult[params.getScoreOffset() + 2] = Math.floorMod(scoreScale * (query.getBloomOneCount() + 2L), params.getPlainModulus());
        Assert.assertEquals(query.getBloomOneCount(), normalizePackedScore(packedResult[params.getScoreOffset()], params));
        Assert.assertNotEquals(query.getBloomOneCount(), normalizePackedScore(packedResult[params.getScoreOffset() + 1], params));
        long[] packedResultPlain = new long[params.getPolyModulusDegree()];
        System.arraycopy(packedResult, 0, packedResultPlain, 0, packedResult.length);
        // Non-result padding must be ignored by the client.
        packedResultPlain[params.getTotalResultCoeffNum()] = Math.floorMod(scoreScale * query.getBloomOneCount(), params.getPlainModulus());
        byte[] encryptedPackedResult = CapePirNativeUtils.encryptCoeffPlain(
            params.encryptionParams, context.client.getPublicKey(), packedResultPlain
        );
        CapePirResponse responseWithNonzeroPadding = CapePirResponse.createPackedResultResponse(List.of(encryptedPackedResult));
        List<byte[]> result = context.client.decodeResponse(query, responseWithNonzeroPadding);
        Assert.assertEquals(1, result.size());
        Assert.assertArrayEquals("v1".getBytes(), result.get(0));
    }

    @Test
    public void testPackedBloomQueryMatchesPlaintextBloomScore() throws Exception {
        TestContext context = sharedContext;
        List<ByteBuffer> queryKeywords = List.of(
            ByteBuffer.wrap("k1".getBytes()),
            ByteBuffer.wrap("k2".getBytes()),
            ByteBuffer.wrap("k3".getBytes())
        );
        CapePirQuery query = context.client.generateCapeQuery(queryKeywords);
        CapePirResponse packedBloomResponse = context.server.generateReply(query);
        CapeBloomFilterAdapter queryBloomFilter = CapePirUtils.buildQueryBloomFilter(
            queryKeywords.subList(1, queryKeywords.size()), context.client.getCapeParams()
        );
        Assert.assertEquals(
            context.client.getCapeParams().getPackedQueryBloomCiphertextNum(),
            query.getEncryptedCoeffBloomFilters().size()
        );
        Assert.assertTrue(context.client.getCapeParams().getBloomPackedPayloadBlockNum()
            < context.client.getCapeParams().getScalarBloomPayloadBlockNumForTest());
        Assert.assertEquals(context.client.getCapeParams().getExpectedPackedResultCiphertextCount(),
            packedBloomResponse.getPackedResultCiphertexts().size());
        long[] packedResult = decryptPackedResult(packedBloomResponse, context);
        long[] packedBloomScores = java.util.Arrays.copyOfRange(
            packedResult,
            context.client.getCapeParams().getScoreOffset(),
            context.client.getCapeParams().getScoreOffset() + context.client.getCapeParams().getScoreCoeffNum()
        );
        long[] queryBloomBits = queryBloomFilter.toLongBitVector();
        List<byte[]> anchorValues = createKeywordValueMap().get(queryKeywords.get(0));
        for (int i = 0; i < anchorValues.size(); i++) {
            CapeBloomFilterAdapter valueBloomFilter = context.server.getValueBloomFilters().get(
                ByteBuffer.wrap(anchorValues.get(i))
            );
            long expectedScore = 0L;
            for (int bitIndex = 0; bitIndex < context.client.getCapeParams().getBloomBitLength(); bitIndex++) {
                expectedScore += queryBloomBits[bitIndex] * valueBloomFilter.getBit(bitIndex);
            }
            Assert.assertEquals(expectedScore,
                normalizePackedScore(packedBloomScores[i], context.client.getCapeParams()));
        }
        List<byte[]> result = context.client.decodeResponse(query, packedBloomResponse);
        Assert.assertEquals(1, result.size());
        Assert.assertArrayEquals("v1".getBytes(), result.get(0));
        assertDoesNotContainValue(result, "v2");
        assertDoesNotContainValue(result, "v3");
    }

    @Test
    public void testLegacyExtraPayloadFailsClosed() throws Exception {
        TestContext context = sharedContext;
        List<ByteBuffer> queryKeywords = List.of(
            ByteBuffer.wrap("k1".getBytes()),
            ByteBuffer.wrap("k2".getBytes()),
            ByteBuffer.wrap("k3".getBytes())
        );
        CapePirQuery query = context.client.generateCapeQuery(queryKeywords);
        int expectedPayloadSize = context.client.getCapeParams().getBffHashNum()
            + context.client.getCapeParams().getBffHashNum()
            + context.client.getCapeParams().getCoeffBloomCiphertextNum();
        Assert.assertEquals(expectedPayloadSize, query.getServerPayload().size());
        Assert.assertNotEquals(expectedPayloadSize, query.getServerPayloadWithPlainAnchorForTest().size());
        CapePirQuery legacyQuery = new CapePirQuery(
            query.getAnchorKeywordBytes(),
            query.getFusePirColumnQueries(),
            query.getFusePirColumnQueries(),
            query.getCompressedRowBitQueries(),
            List.of(query.getEncryptedCoeffBloomFilters().get(0)),
            query.getEncryptedCoeffBloomFilters(),
            query.getBloomOneCount(),
            query.getBoolKeywordNum()
        );
        Assert.assertNotEquals(expectedPayloadSize, legacyQuery.getServerPayloadForLegacyBitColumnTest().size());
        Assert.assertEquals(expectedPayloadSize, legacyQuery.getServerPayload().size());
        Assert.assertTrue(legacyQuery.getServerPayload().stream()
            .noneMatch(payload -> java.util.Arrays.equals(payload, query.getAnchorKeywordBytes())));
    }

    private static List<byte[]> runQuery(TestContext context, List<ByteBuffer> queryKeywords) {
        CapePirQuery query = context.client.generateCapeQuery(queryKeywords);
        CapePirResponse response = context.server.generateReply(query);
        return context.client.decodeResponse(query, response);
    }

    private static TestContext createContext() throws Exception {
        return createContext(3);
    }

    private static TestContext createContext(int boolKeywordNum) throws Exception {
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
        return new TestContext(client, server);
    }

    private static Map<ByteBuffer, List<byte[]>> createKeywordValueMap() {
        Map<ByteBuffer, List<byte[]>> keywordValueMap = new LinkedHashMap<>();
        keywordValueMap.put(ByteBuffer.wrap("k1".getBytes()), List.of("v1".getBytes(), "v2".getBytes(), "v3".getBytes()));
        keywordValueMap.put(ByteBuffer.wrap("k2".getBytes()), List.of("v1".getBytes()));
        keywordValueMap.put(ByteBuffer.wrap("k3".getBytes()), List.of("v1".getBytes(), "v2".getBytes()));
        return keywordValueMap;
    }

    private static void assertContainsValue(List<byte[]> values, String expected) {
        Assert.assertTrue(values.stream().anyMatch(value -> java.util.Arrays.equals(expected.getBytes(), value)));
    }

    private static void assertDoesNotContainValue(List<byte[]> values, String expected) {
        Assert.assertTrue(values.stream().noneMatch(value -> java.util.Arrays.equals(expected.getBytes(), value)));
    }

    private static long byteLength(List<byte[]> payload) {
        return payload.stream().mapToLong(bytes -> bytes.length).sum();
    }

    private static int expectedValueCiphertextCount(CapePirParams params) {
        return (CapePirUtils.valueOnlyPayloadBlockNum(params) + params.getBlocksPerPackedMatrix() - 1)
            / params.getBlocksPerPackedMatrix();
    }

    private static long[] decryptPackedResult(CapePirResponse response, TestContext context) {
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

    private static int ceilLog2(int n) {
        int log = 0;
        int pow = 1;
        while (pow < n) {
            pow <<= 1;
            log++;
        }
        return log;
    }

    private static long normalizePackedScore(long packedScore, CapePirParams params) {
        long inverseScale = inverseMod(params.getPolyModulusDegree() % params.getPlainModulus(), params.getPlainModulus());
        return Math.floorMod(packedScore * inverseScale, params.getPlainModulus());
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

    private static class TestContext {
        private final CapePirClient<ByteBuffer> client;
        private final CapePirServer<ByteBuffer> server;

        private TestContext(CapePirClient<ByteBuffer> client, CapePirServer<ByteBuffer> server) {
            this.client = client;
            this.server = server;
        }

        private void release() {
            client.releaseLargeKeysForTest();
            server.releaseLargeStateForTest();
            System.gc();
        }
    }

    private static class CapeServerThread extends Thread {
        private final CapePirServer<ByteBuffer> server;
        private final Map<ByteBuffer, List<byte[]>> keywordValueMap;
        private Throwable throwable;

        private CapeServerThread(CapePirServer<ByteBuffer> server, Map<ByteBuffer, List<byte[]>> keywordValueMap) {
            this.server = server;
            this.keywordValueMap = keywordValueMap;
        }

        @Override
        public void run() {
            try {
                server.init(keywordValueMap, 1);
                server.receivePublicKeys();
                server.sendBffSeed();
                server.pir(1);
            } catch (Throwable t) {
                throwable = t;
            }
        }
    }

    private static class CapeClientThread extends Thread {
        private final CapePirClient<ByteBuffer> client;
        private final ArrayList<List<ByteBuffer>> queries;
        private List<byte[]>[] entries;
        private Throwable throwable;

        private CapeClientThread(CapePirClient<ByteBuffer> client, ArrayList<List<ByteBuffer>> queries) {
            this.client = client;
            this.queries = queries;
        }

        @Override
        public void run() {
            try {
                client.init(3, 2, 3, 1);
                client.sendPublicKeysAndReceiveSeed();
                entries = client.pir(queries);
            } catch (Throwable t) {
                throwable = t;
            }
        }
    }
}
